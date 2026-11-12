// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;
using Vitrine.Core.About;
using Vitrine.Core.Audit;

namespace Vitrine.Platform;

/// <summary>
/// Zustand des Protokolls unter HKLM\SOFTWARE\ICT-Baden\Vitrine\Audit (#15). Schreiben darf nur SYSTEM (der Dienst legt den
/// Schlüssel mit dieser Zugriffsliste an), lesen alle – --verify-log braucht die Anker. Administratoren können den
/// Schlüssel übernehmen und ändern (docs/gxp.md).
/// </summary>
public static class AuditState
{
    /// <summary>1 = der Dienst schreibt das Protokoll (Format 3), 0 oder fehlt = die App schreibt selbst.</summary>
    public const string ServiceValue = "Service";
    public const string CurrentKeyValue = "CurrentKey";
    public const string KeyPrefix = "Key.";
    public const string AnchorPrefix = "Anchor.";

    /// <summary>Schreibt laut Registry der Dienst das Protokoll? (Ob er läuft, sagt die Dienstverwaltung.)</summary>
    public static bool ServiceWrites() => Core.Service.AuditServiceDecision.ServiceWrites(ServiceValueRaw());

    /// <summary>Rohwert „Service“ (null = Schlüssel oder Wert fehlt, nicht lesbar).</summary>
    public static object? ServiceValueRaw()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AppPaths.AuditStateKey);
            return key?.GetValue(ServiceValue);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return null; }
    }

    /// <summary>Nur im Dienst: Schlüssel mit Zugriffsliste anlegen bzw. die Zugriffsliste erneuern.</summary>
    public static RegistryKey OpenForService()
    {
        var security = new RegistrySecurity();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        security.SetAccessRuleProtection(true, false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit;
        security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), RegistryRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), RegistryRights.ReadKey, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), RegistryRights.ReadKey, inherit, PropagationFlags.None, AccessControlType.Allow));
        // Übergeordneten Schlüssel normal anlegen (gehört der MSI)
        Registry.LocalMachine.CreateSubKey(AppPaths.ProductKey)?.Dispose();
        var key = Registry.LocalMachine.CreateSubKey(AppPaths.AuditStateKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.None, security);
        key.SetAccessControl(security);
        return key;
    }

    public static void SetServiceWrites(bool on)
    {
        using var key = OpenForService();
        key.SetValue(ServiceValue, on ? 1 : 0, RegistryValueKind.DWord);
    }

    /// <summary>Öffentliche Schlüssel aus der Registry (ohne Dienst lesbar, für --export-audit-key und die Prüfung).</summary>
    public static List<AuditPublicKey> PublicKeys(RegistryKey? key = null)
    {
        var list = new List<AuditPublicKey>();
        try
        {
            using var own = key is null ? Registry.LocalMachine.OpenSubKey(AppPaths.AuditStateKey) : null;
            var k = key ?? own;
            if (k is null) return list;
            foreach (var name in k.GetValueNames().Where(n => n.StartsWith(KeyPrefix, StringComparison.Ordinal)))
                if (k.GetValue(name) is string v && ParseKey(v) is { } parsed) list.Add(parsed.Public);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return list.OrderBy(p => p.Created ?? DateTimeOffset.MinValue).ToList();
    }

    /// <summary>„CNG-Name|Base64(SubjectPublicKeyInfo)|angelegt (ISO 8601)“.</summary>
    internal static (string CngName, AuditPublicKey Public)? ParseKey(string value)
    {
        var parts = value.Split('|');
        if (parts.Length != 3) return null;
        try
        {
            DateTimeOffset? created = DateTimeOffset.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var c) ? c : null;
            return (parts[0], AuditPublicKey.From(Convert.FromBase64String(parts[1]), created));
        }
        catch (FormatException) { return null; }
    }

    internal static string FormatKey(string cngName, AuditPublicKey k) =>
        $"{cngName}|{Convert.ToBase64String(k.SubjectPublicKeyInfo)}|{(k.Created ?? DateTimeOffset.UtcNow).ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)}";

    /// <summary>
    /// Nur im Dienst: Protokollordner so schützen, dass Benutzer nur lesen (SYSTEM und Administratoren voll). OWNER RIGHTS nur
    /// lesen: Wer früher (Format 2) eine Datei angelegt hat, darf deren Rechte nicht mehr ändern.
    /// </summary>
    public static void ProtectLogFolder(string dir)
    {
        Directory.CreateDirectory(dir);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        const InheritanceFlags both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, both, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-3-4"), FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, both, PropagationFlags.None, AccessControlType.Allow));
        // SetNamedSecurityInfo gibt die vererbbaren Einträge an vorhandene Dateien weiter (deren Einträge sind nur geerbt)
        new DirectoryInfo(dir).SetAccessControl(sec);
    }

    /// <summary>
    /// Nur im Dienst, wenn er das Protokoll nicht (mehr) schreibt (SERVICE=0, Schlüssel nicht ladbar): wieder die Rechte der
    /// MSI mit SERVICE=0 – Benutzer dürfen Dateien anlegen und anhängen, sonst gingen die Einträge der Apps in den
    /// ungeschützten Ordner pro Benutzer. SDDL wie Komponente LogsFolder in installer/Package.wxs.
    /// </summary>
    public static void AllowAppendForUsers(string dir)
    {
        Directory.CreateDirectory(dir);
        var sec = new DirectorySecurity();
        sec.SetSecurityDescriptorSddlForm(AppendSddl, AccessControlSections.Access);
        new DirectoryInfo(dir).SetAccessControl(sec);
    }

    /// <summary>Rechte des Protokollordners ohne Dienst (Format 2): Benutzer anlegen und anhängen, nicht ändern.</summary>
    public const string AppendSddl = "D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1200ab;;;BU)(A;OIIO;0x12008d;;;BU)(A;OICI;0x1200a9;;;OW)";

    /// <summary>Ist das der Standardordner des Protokolls (%ProgramData%\ICT-Baden\Vitrine\Logs)?</summary>
    public static bool IsDefaultLogFolder(string dir) =>
        string.Equals(Path.GetFullPath(dir).TrimEnd('\\'), Path.GetFullPath(AppPaths.MachineLogDir).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
}

/// <summary>Anker unter HKLM\…\Audit, Werte „Anchor.yyyy-MM“ = „Nummer|Hash“. Ohne <c>writable</c> nur lesen (App, --verify-log).</summary>
public sealed class RegistryAnchorStore(bool writable = false) : IAuditAnchorStore
{
    public AuditAnchor? Get(string month) => All().FirstOrDefault(a => a.Month == month);

    public void Set(AuditAnchor anchor)
    {
        if (!writable) throw new InvalidOperationException("read-only");
        using var key = Registry.LocalMachine.OpenSubKey(AppPaths.AuditStateKey, writable: true) ?? AuditState.OpenForService();
        key.SetValue(AuditState.AnchorPrefix + anchor.Month, $"{anchor.Seq.ToString(CultureInfo.InvariantCulture)}|{anchor.Hash}", RegistryValueKind.String);
    }

    public IReadOnlyList<AuditAnchor> All()
    {
        var list = new List<AuditAnchor>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AppPaths.AuditStateKey);
            if (key is null) return list;
            foreach (var name in key.GetValueNames().Where(n => n.StartsWith(AuditState.AnchorPrefix, StringComparison.Ordinal)))
            {
                if (key.GetValue(name) is not string v || v.Split('|') is not [var seq, var hash]) continue;
                if (long.TryParse(seq, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
                    list.Add(new AuditAnchor(name[AuditState.AnchorPrefix.Length..], n, hash));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return list.OrderBy(a => a.Month, StringComparer.Ordinal).ToList();
    }
}

/// <summary>
/// Schlüssel des Protokolls als CNG-Maschinenschlüssel (Microsoft Software Key Storage Provider), nicht exportierbar,
/// Zugriff nur für SYSTEM. Angelegt beim ersten Start des Dienstes; die öffentlichen Schlüssel stehen zusätzlich in der
/// Registry (<see cref="AuditState"/>) und in audit-keys.json. Administratoren können die Zugriffsliste übernehmen und mit
/// dem Schlüssel signieren – das steht in docs/gxp.md.
/// </summary>
public sealed class CngAuditKeyStore : IAuditKeyStore
{
    private sealed class Signer(CngKey key, AuditPublicKey pub) : IAuditSigner
    {
        public AuditPublicKey PublicKey { get; } = pub;

        public byte[] Sign(byte[] data)
        {
            using var ec = new ECDsaCng(key);
            return ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    private readonly object _gate = new();
    private Signer? _current;

    public IAuditSigner Current()
    {
        lock (_gate)
        {
            if (_current is not null) return _current;
            using var reg = AuditState.OpenForService();
            if (reg.GetValue(AuditState.CurrentKeyValue) is string id &&
                reg.GetValue(AuditState.KeyPrefix + id) is string v && AuditState.ParseKey(v) is { } parsed &&
                CngKey.Exists(parsed.CngName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
            {
                var key = CngKey.Open(parsed.CngName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);
                return _current = new Signer(key, parsed.Public);
            }
            return CreateNextLocked(reg);
        }
    }

    public IAuditSigner CreateNext()
    {
        lock (_gate)
        {
            using var reg = AuditState.OpenForService();
            return CreateNextLocked(reg);
        }
    }

    private Signer CreateNextLocked(RegistryKey reg)
    {
        var name = $"{AppPaths.AuditKeyName}.{DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture)}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}";
        var p = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
        };
        // Nur SYSTEM (NCRYPT_SECURITY_DESCR_PROPERTY mit DACL_SECURITY_INFORMATION)
        var sd = new RawSecurityDescriptor("D:P(A;;GA;;;SY)");
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        p.Parameters.Add(new CngProperty("Security Descr", bytes, (CngPropertyOptions)0x4));
        CngKey key;
        try { key = CngKey.Create(CngAlgorithm.ECDsaP256, name, p); }
        catch (CryptographicException)
        {
            // Ältere Anbieter ohne die Eigenschaft beim Anlegen: Standardrechte für Maschinenschlüssel (SYSTEM, Administratoren)
            p.Parameters.Clear();
            key = CngKey.Create(CngAlgorithm.ECDsaP256, name, p);
        }
        byte[] spki;
        using (var ec = new ECDsaCng(key)) spki = ec.ExportSubjectPublicKeyInfo();
        var pub = AuditPublicKey.From(spki, DateTimeOffset.UtcNow);
        reg.SetValue(AuditState.KeyPrefix + pub.Id, AuditState.FormatKey(name, pub), RegistryValueKind.String);
        reg.SetValue(AuditState.CurrentKeyValue, pub.Id, RegistryValueKind.String);
        return _current = new Signer(key, pub);
    }

    public IReadOnlyList<AuditPublicKey> PublicKeys() => AuditState.PublicKeys();
}
