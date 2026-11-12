// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using Vitrine.Core.About;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Platform;
using Vitrine.Services.Auth;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Ablage der Sicherheitsschlüssel als Datei %ProgramData%\ICT-Baden\Vitrine\fido-credentials.json. Schreibt nur der Dienst
/// (SYSTEM): neue Datei, dann umbenennen; Besitzer SYSTEM, Rechte ohne Vererbung (SYSTEM voll, Administratoren lesen; Benutzer
/// nicht – die Datei nennt Personen; seit der Prüfung vom 2026-10-30). Gelesen wird nur, wenn normale Benutzer Datei und
/// Ordner nicht ändern können (<see cref="AdminOnlyFiles"/>,
/// sonst VIT-0420) – wie die Gerätekonfiguration.
/// </summary>
internal sealed class ProtectedFidoStoreFile(string? path = null) : IFidoStoreFile
{
    public const long MaxBytes = 4 * 1024 * 1024;

    private readonly string _path = path ?? AppPaths.FidoCredentialsFile;
    private readonly AdminOnlyFiles _guard = new();

    public string? Read()
    {
        try { return _guard.ReadProtected(_path, MaxBytes); }
        catch (UnauthorizedAccessException) { throw new FidoStoreException(ErrorCodes.FidoStoreNotProtected, $"{_path} can be changed by users"); }
    }

    /// <summary>Rechte der Datei: Besitzer SYSTEM, ohne Vererbung, SYSTEM voll, Administratoren lesen.</summary>
    private static FileSecurity Security()
    {
        var sec = new FileSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        sec.SetOwner(system);
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.Read, AccessControlType.Allow));
        return sec;
    }

    /// <summary>
    /// Beim Start des Dienstes: Eine vorhandene Datei bekommt die aktuellen Rechte (bis 2026-10-30 durften Benutzer sie lesen).
    /// Nur wenn sie geschützt ist – eine von Benutzern änderbare Datei bleibt unangetastet (VIT-0420).
    /// </summary>
    public void RestrictExisting()
    {
        var fi = new FileInfo(_path);
        if (!fi.Exists || fi.Attributes.HasFlag(FileAttributes.ReparsePoint) || !_guard.IsProtected(_path)) return;
        fi.SetAccessControl(Security());
    }

    public void Write(string json)
    {
        var dir = Path.GetDirectoryName(_path)!;
        _guard.PrepareDirectory(dir);
        var tmp = Path.Combine(dir, $".fido-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var w = new StreamWriter(fs, new UTF8Encoding(false)))
                w.Write(json);
            new FileInfo(tmp).SetAccessControl(Security());
            File.Move(tmp, _path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}

/// <summary>
/// Konten für Sicherheitsschlüssel im Dienst: Name → SID (LookupAccountName), Kontostatus und Gruppen über eine
/// S4U-Anmeldung (LsaLogonUser mit KERB_S4U_LOGON für Domänenkonten bzw. MSV1_0_S4U_LOGON für lokale Konten; nur ein
/// Token zur Identifikation, kein Kennwort). Konten nur in Microsoft Entra ID (S-1-12-1-…): S4U geht nicht – dann die
/// lokalen Gruppen dieses Rechners, in denen das Konto direkt Mitglied ist; Kontostatus und Entra-Gruppen sind unbekannt.
/// </summary>
internal sealed class WindowsFidoAccounts(Func<VitrineConfig> config) : IFidoAccounts
{
    public FidoAccount? Lookup(string input)
    {
        var text = input.Trim();
        if (text.Length == 0) return null;
        string? sid;
        try
        {
            sid = text.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(text).Value
                : new NTAccount(AccountNames.ForLookup(text, Environment.MachineName)).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or ArgumentException or SystemException) { return null; }
        if (sid is null) return null;
        // Nur Benutzerkonten, keine Gruppen oder Computer
        if (!IsUser(sid)) return null;
        string name;
        try { name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException) { name = text; }

        string? upn = null;
        int bs = text.IndexOf('\\');
        var tail = bs >= 0 ? text[(bs + 1)..] : text;
        if (tail.Contains('@')) upn = tail;
        else if (!IsLocal(sid) && !FidoPeople.IsEntraOnly(sid)) upn = TranslateToUpn(name);
        return new FidoAccount(sid, name, upn);
    }

    public Task<FidoResolution> ResolveAsync(string sid, string name, string? upn, CancellationToken ct = default) =>
        Task.Run(() => Resolve(sid, name, upn), ct);

    private FidoResolution Resolve(string sid, string name, string? upn)
    {
        if (FidoPeople.IsEntraOnly(sid)) return LocalGroups(sid, name);
        int bs = name.IndexOf('\\');
        var domain = bs > 0 ? name[..bs] : Environment.MachineName;
        var user = bs >= 0 ? name[(bs + 1)..] : name;
        bool local = IsLocal(sid);
        int error = S4U(local ? "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" : "Kerberos",
            local ? user : upn ?? user, local ? Environment.MachineName : upn is null ? domain : null, out var identity);
        if (error != 0) return FidoResolution.Failed(FidoPeople.StateForWin32Error(error), $"S4U Win32 error {error}");
        using (identity)
        {
            // Konto mit gleichem Namen, aber anderer SID (gelöscht und neu angelegt): nicht dieselbe Person
            if (!string.Equals(identity!.User?.Value, sid, StringComparison.OrdinalIgnoreCase))
                return FidoResolution.Failed(FidoAccountState.NotFound, "account has another SID now");
            var groups = WindowsAccounts.GetGroupSids(identity);
            // Bei Netzwerk-Anmeldungen lokaler Administratoren ist die Gruppe nur „deny only“ – Mitglied ist das Konto trotzdem
            foreach (var c in identity.Claims.Where(c => c.Type == ClaimTypes.DenyOnlySid)) groups.Add(c.Value);
            return new FidoResolution(FidoAccountState.Ok, identity.Name, groups, FidoGroupsSource.Live);
        }
    }

    /// <summary>Entra-Konto: direkte Mitgliedschaft in Administratoren, Benutzer und den lokalen Gruppen aus Unlock.AllowedGroups.</summary>
    private FidoResolution LocalGroups(string sid, string name)
    {
        var dir = new LocalGroupDirectory();
        string? machine;
        try { machine = dir.MachineSid; } catch (Exception ex) when (ex is SystemException) { machine = null; }
        var candidates = new List<string> { WindowsAccounts.AdministratorsSid, "S-1-5-32-545" };
        foreach (var g in config().Unlock.AllowedGroups.Where(g => !string.IsNullOrWhiteSpace(g)))
            if (WindowsAccounts.ToSid(g.Trim()) is { } gs && EntraLocalGroups.IsLocalGroupSid(gs, machine)) candidates.Add(gs);
        var groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool anyRead = false;
        foreach (var g in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            IReadOnlyCollection<string>? members;
            try { members = dir.MemberSids(g); } catch (Exception ex) when (ex is SystemException) { members = null; }
            if (members is null) continue;
            anyRead = true;
            if (members.Contains(sid, StringComparer.OrdinalIgnoreCase)) groups.Add(g);
        }
        // Lokale Gruppen nicht lesbar: wie „offline“ (Zwischenspeicher mit Altersgrenze)
        if (!anyRead) return FidoResolution.Failed(FidoAccountState.Offline, "local groups not readable");
        string resolved = name;
        try { resolved = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; } catch (Exception ex) when (ex is IdentityNotMappedException or SystemException) { }
        return new FidoResolution(FidoAccountState.Ok, resolved, groups, FidoGroupsSource.Local);
    }

    private static string? _machineSid;

    /// <summary>Lokales Konto dieses Rechners (SID der Kontendomäne des Rechners)?</summary>
    private static bool IsLocal(string sid)
    {
        _machineSid ??= new LocalGroupDirectory().MachineSid ?? "";
        return _machineSid.Length > 0 && sid.StartsWith(_machineSid + "-", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUser(string sid)
    {
        var bytes = new byte[SecurityIdentifier.MaxBinaryLength];
        new SecurityIdentifier(sid).GetBinaryForm(bytes, 0);
        int cchName = 256, cchDomain = 256;
        var n = new StringBuilder(cchName);
        var d = new StringBuilder(cchDomain);
        // SidTypeUser = 1; Entra-Konten können je nach Windows-Version unbekannt sein, sind aber Benutzer (S-1-12-1-…)
        if (!LookupAccountSidW(null, bytes, n, ref cchName, d, ref cchDomain, out int use)) return FidoPeople.IsEntraOnly(sid);
        return use == 1;
    }

    /// <summary>„DOMÄNE\name“ → UPN über TranslateName (braucht den Domänencontroller); null, wenn nicht möglich.</summary>
    private static string? TranslateToUpn(string samName)
    {
        uint size = 512;
        var sb = new StringBuilder((int)size);
        return TranslateNameW(samName, 2 /* NameSamCompatible */, 8 /* NameUserPrincipal */, sb, ref size) ? sb.ToString() : null;
    }

    // ---------- S4U ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    /// <summary>KERB_S4U_LOGON und MSV1_0_S4U_LOGON haben dieselbe Form.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct S4U_LOGON
    {
        public int MessageType; // KerbS4ULogon = 12, MsV1_0S4ULogon = 12
        public uint Flags;
        public UNICODE_STRING Name;
        public UNICODE_STRING Domain;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QUOTA_LIMITS
    {
        public nint PagedPoolLimit;
        public nint NonPagedPoolLimit;
        public nint MinimumWorkingSetSize;
        public nint MaximumWorkingSetSize;
        public nint PagefileLimit;
        public long TimeLimit;
    }

    /// <summary>S4U-Anmeldung (Netzwerk); 0 und ein Token zur Identifikation, sonst ein Win32-Fehler.</summary>
    private static int S4U(string package, string name, string? domain, out WindowsIdentity? identity)
    {
        identity = null;
        int status = LsaConnectUntrusted(out var lsa);
        if (status != 0) return LsaNtStatusToWinError(status);
        var packageName = Marshal.StringToHGlobalAnsi(package);
        var origin = Marshal.StringToHGlobalAnsi("Vitrine");
        nint buffer = 0;
        try
        {
            var pkg = new LSA_STRING { Length = (ushort)package.Length, MaximumLength = (ushort)(package.Length + 1), Buffer = packageName };
            status = LsaLookupAuthenticationPackage(lsa, ref pkg, out uint packageId);
            if (status != 0) return LsaNtStatusToWinError(status);

            int head = Marshal.SizeOf<S4U_LOGON>();
            var nameBytes = Encoding.Unicode.GetBytes(name);
            var domainBytes = domain is null ? [] : Encoding.Unicode.GetBytes(domain);
            int size = head + nameBytes.Length + domainBytes.Length;
            buffer = Marshal.AllocHGlobal(size);
            Marshal.Copy(nameBytes, 0, buffer + head, nameBytes.Length);
            if (domainBytes.Length > 0) Marshal.Copy(domainBytes, 0, buffer + head + nameBytes.Length, domainBytes.Length);
            var logon = new S4U_LOGON
            {
                MessageType = 12,
                Name = new UNICODE_STRING { Length = (ushort)nameBytes.Length, MaximumLength = (ushort)nameBytes.Length, Buffer = buffer + head },
                Domain = domain is null ? default
                    : new UNICODE_STRING { Length = (ushort)domainBytes.Length, MaximumLength = (ushort)domainBytes.Length, Buffer = buffer + head + nameBytes.Length },
            };
            Marshal.StructureToPtr(logon, buffer, false);

            var originName = new LSA_STRING { Length = 7, MaximumLength = 8, Buffer = origin };
            var source = new TOKEN_SOURCE { SourceName = "Vitrine\0"u8.ToArray() };
            AllocateLocallyUniqueId(out source.SourceIdentifier);
            status = LsaLogonUser(lsa, ref originName, 3 /* Network */, packageId, buffer, (uint)size, 0, ref source,
                out var profile, out _, out _, out var token, out _, out int subStatus);
            if (profile != 0) LsaFreeReturnBuffer(profile);
            if (status != 0)
            {
                if (token != 0) Native.CloseHandle(token);
                if ((uint)status == 0xC000006E && subStatus != 0) status = subStatus; // Kontoeinschränkung: genauer Grund
                return LsaNtStatusToWinError(status);
            }
            try { identity = new WindowsIdentity(token); }
            finally { Native.CloseHandle(token); }
            return 0;
        }
        finally
        {
            if (buffer != 0) Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(packageName);
            Marshal.FreeHGlobal(origin);
            LsaDeregisterLogonProcess(lsa);
        }
    }

    [DllImport("secur32.dll")]
    private static extern int LsaConnectUntrusted(out nint lsaHandle);

    [DllImport("secur32.dll")]
    private static extern int LsaLookupAuthenticationPackage(nint lsaHandle, ref LSA_STRING packageName, out uint authenticationPackage);

    [DllImport("secur32.dll")]
    private static extern int LsaLogonUser(nint lsaHandle, ref LSA_STRING originName, int logonType, uint authenticationPackage,
        nint authenticationInformation, uint authenticationInformationLength, nint localGroups, ref TOKEN_SOURCE sourceContext,
        out nint profileBuffer, out uint profileBufferLength, out LUID logonId, out nint token, out QUOTA_LIMITS quotas, out int subStatus);

    [DllImport("secur32.dll")]
    private static extern int LsaFreeReturnBuffer(nint buffer);

    [DllImport("secur32.dll")]
    private static extern int LsaDeregisterLogonProcess(nint lsaHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(int status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocateLocallyUniqueId(out LUID luid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountSidW(string? systemName, byte[] sid, StringBuilder name, ref int cchName,
        StringBuilder referencedDomainName, ref int cchReferencedDomainName, out int use);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool TranslateNameW(string accountName, int accountNameFormat, int desiredNameFormat, StringBuilder translatedName, ref uint size);
}
