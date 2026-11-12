// SPDX-License-Identifier: MIT
using System.Security.AccessControl;
using System.Security.Principal;
using Vitrine.Core.Config;

namespace Vitrine.Platform;

/// <summary>
/// Prüft, ob Dateien und Ordner nur von Administratoren geändert werden können (Gerätekonfiguration, Plugins). Hintergrund:
/// Normale Benutzer dürfen unter %ProgramData% Ordner anlegen; wer einen Ordner anlegt, besitzt ihn und kann dessen Rechte
/// jederzeit wieder ändern. Eine Datei gilt deshalb nur als geschützt, wenn Datei, Ordner und übergeordneter Ordner
/// Administratoren, SYSTEM oder TrustedInstaller gehören, keine Verknüpfungen sind und kein anderes Konto Rechte zum
/// Ändern, Löschen, Umbenennen oder Rechte-Ändern hat.
/// </summary>
public sealed class AdminOnlyFiles : IConfigFileGuard
{
    private static readonly HashSet<string> Trusted = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-32-544",  // Administratoren
        "S-1-5-18",      // SYSTEM
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
        "S-1-3-0",       // ERSTELLER-BESITZER (nur in vererbbaren Einträgen)
        "S-1-3-4",       // BESITZERRECHTE (gilt für den Besitzer, der hier vertrauenswürdig sein muss)
    };

    // Rechte, mit denen jemand eine Datei ändern oder ersetzen kann
    private const FileSystemRights FileWrite = FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes | FileSystemRights.Delete | FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    // Bei Ordnern: Anlegen neuer Dateien ist erlaubt (eine fremde neue Datei fiele selbst durch die Prüfung),
    // Löschen/Umbenennen von Einträgen und Rechte-Ändern nicht
    private const FileSystemRights DirWrite = FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    public string? ReadProtected(string file, long maxBytes)
    {
        if (!File.Exists(file)) return null;
        // Erst öffnen (andere dürfen nicht schreiben), dann am offenen Handle prüfen und daraus lesen: Ein Austausch der
        // Datei zwischen Prüfen und Lesen hat so keine Wirkung.
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint) || LinkCount(fs) != 1 ||
            !IsSafe(fs.GetAccessControl(), FileWrite) || !DirectoryIsProtected(new FileInfo(file).Directory!))
            throw new UnauthorizedAccessException(file);
        if (fs.Length > maxBytes) throw new InvalidDataException(file);
        using var reader = new StreamReader(fs);
        return reader.ReadToEnd();
    }

    /// <summary>Anzahl der festen Links; mehr als einer heißt, die Datei steht auch an einem anderen, evtl. offenen Ort.</summary>
    private static uint LinkCount(FileStream fs) =>
        GetFileInformationByHandle(fs.SafeFileHandle, out var info) ? info.NumberOfLinks : 0;

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, out ByHandleFileInformation info);

    public bool IsProtected(string file)
    {
        var fi = new FileInfo(file);
        if (!fi.Exists || fi.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
        if (!IsSafe(fi.GetAccessControl(), FileWrite)) return false;
        return DirectoryIsProtected(fi.Directory!);
    }

    /// <summary>Ordner und sein übergeordneter Ordner (z. B. Plugins neben der Exe).</summary>
    public bool DirectoryIsProtected(string dir) => DirectoryIsProtected(new DirectoryInfo(dir));

    private static bool DirectoryIsProtected(DirectoryInfo dir)
    {
        foreach (var d in new[] { dir, dir.Parent })
        {
            if (d is null) continue;
            if (!d.Exists || d.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
            if (!IsSafe(d.GetAccessControl(), DirWrite)) return false;
        }
        return true;
    }

    private static bool IsSafe(FileSystemSecurity security, FileSystemRights dangerous)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value;
        if (owner is null || !Trusted.Contains(owner)) return false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
            if (Trusted.Contains(rule.IdentityReference.Value)) continue;
            if ((rule.FileSystemRights & dangerous) != 0) return false;
        }
        return true;
    }

    public void PrepareDirectory(string directory)
    {
        var dir = new DirectoryInfo(Path.GetFullPath(directory));
        // Erst den übergeordneten Ordner prüfen: Ist er eine Verknüpfung, würde CreateDirectory woanders anlegen.
        if (dir.Parent is { Exists: true } parent)
        {
            if (parent.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException(parent.FullName);
            Tighten(parent);
        }
        dir.Create();
        dir.Refresh();
        if (dir.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException(dir.FullName);
        Secure(dir);
    }

    /// <summary>
    /// Nach dem Schreiben als Administrator: Besitzer Administratoren und nur die vom Ordner geerbten Rechte – eigene
    /// Einträge eines Benutzers (z. B. auf einer vorher angelegten Datei) fallen weg.
    /// </summary>
    public void Protect(string file)
    {
        var fi = new FileInfo(file);
        if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException(fi.FullName);
        var fs = new FileSecurity();
        fs.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        fs.SetAccessRuleProtection(false, false);
        fi.SetAccessControl(fs);
    }

    /// <summary>
    /// Der eigene Ordner (…\Vitrine): Hatte ihn ein Benutzer angelegt oder sind die Rechte zu weit, bekommt er Besitzer
    /// Administratoren und geschützte Rechte (Administratoren und SYSTEM voll, Benutzer lesen).
    /// </summary>
    private static void Secure(DirectoryInfo d)
    {
        if (IsSafe(d.GetAccessControl(), DirWrite)) return;
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var ds = new DirectorySecurity();
        ds.SetOwner(admins);
        ds.SetAccessRuleProtection(true, false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        ds.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        d.SetAccessControl(ds);
    }

    /// <summary>
    /// Der gemeinsame übergeordnete Ordner (…\ICT-Baden, auch von anderen Produkten genutzt): nur Besitzer auf
    /// Administratoren setzen und eigene Einträge anderer Konten mit Lösch- oder Rechte-Ändern-Rechten entfernen; die
    /// übrigen Rechte und die Vererbung bleiben.
    /// </summary>
    private static void Tighten(DirectoryInfo d)
    {
        var ds = d.GetAccessControl();
        if (IsSafe(ds, DirWrite)) return;
        ds.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (FileSystemAccessRule rule in ds.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !Trusted.Contains(rule.IdentityReference.Value) &&
                (rule.FileSystemRights & DirWrite) != 0)
                ds.RemoveAccessRuleSpecific(rule);
        d.SetAccessControl(ds);
        if (!IsSafe(d.GetAccessControl(), DirWrite)) throw new UnauthorizedAccessException(d.FullName); // z. B. geerbte Rechte
    }
}
