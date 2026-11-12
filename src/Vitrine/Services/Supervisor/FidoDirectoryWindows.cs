// SPDX-License-Identifier: MIT
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Vitrine.Core.About;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Sicherheitsschlüssel im Active Directory über LDAP (System.DirectoryServices.Protocols). Domänencontroller über den
/// DC-Locator (DsGetDcName) – keiner fest eingetragen; Anmeldung mit Negotiate (Kerberos), Signieren und Verschlüsseln.
/// Lesen als Dienst (LocalSystem = Computerkonto), Schreiben als registrierende Person (Token der Kennwort-Anmeldung oder
/// Benutzer und Kennwort, nur für die Anmeldung). Container: <c>CN=SecurityKeys,</c> unter <c>Fido.DirectoryContainer</c>
/// bzw. <c>CN=Vitrine,CN=Program Data,&lt;Domäne&gt;</c>. Entscheidungen (Format, Prüfung, Fehlercodes) in
/// <see cref="FidoDirectoryCodec"/>/<see cref="FidoDirectoryStore"/>.
/// </summary>
internal sealed class LdapFidoDirectory(Func<FidoSettings> settings) : IFidoDirectory
{
    private const string Filter = "(&(objectClass=serviceConnectionPoint)(keywords=" + FidoDirectoryCodec.Marker + "))";
    private static readonly string[] Attributes = ["cn", "keywords", "serviceBindingInformation", "description"];
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    public string? Location { get; private set; }

    public Task<IReadOnlyList<FidoDirectoryEntry>> ReadAllAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        using var conn = Connect(null, out var keysDn);
        var list = new List<FidoDirectoryEntry>();
        var request = new SearchRequest(keysDn, Filter, SearchScope.OneLevel, Attributes);
        var paging = new PageResultRequestControl(500);
        request.Controls.Add(paging);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var response = (SearchResponse)Send(conn, request);
            foreach (SearchResultEntry e in response.Entries) list.Add(ToEntry(e));
            var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
            if (cookie is not { Length: > 0 }) break;
            paging.Cookie = cookie;
        }
        return (IReadOnlyList<FidoDirectoryEntry>)list;
    }, ct);

    public Task<FidoDirectoryEntry?> ReadAsync(string cn, CancellationToken ct = default) => Task.Run(() =>
    {
        using var conn = Connect(null, out var keysDn);
        return Read(conn, keysDn, cn);
    }, ct);

    public Task<IFidoDirectoryWriter> OpenWriterAsync(FidoWriteCredential credential, CancellationToken ct = default) => Task.Run(() =>
    {
        var conn = Connect(credential, out var keysDn);
        try
        {
            return (IFidoDirectoryWriter)new Writer(conn, keysDn, WhoAmI(conn));
        }
        catch
        {
            conn.Dispose();
            throw;
        }
    }, ct);

    // ================= Verbindung =================

    /// <summary>Verbinden und anmelden; <paramref name="keysDn"/> = DN von CN=SecurityKeys.</summary>
    private LdapConnection Connect(FidoWriteCredential? credential, out string keysDn)
    {
        var dc = LocateDomainController();
        LdapConnection? conn = null;
        try
        {
            NetworkCredential? network = null;
            if (credential is { User: { } user, Password: { } password })
            {
                int bs = user.IndexOf('\\');
                network = bs > 0 ? new NetworkCredential(user[(bs + 1)..], password, user[..bs]) : new NetworkCredential(user, password);
            }
            conn = new LdapConnection(new LdapDirectoryIdentifier(dc, 389, fullyQualifiedDnsHostName: true, connectionless: false), network,
                AuthType.Negotiate) { AutoBind = false, Timeout = Timeout };
            conn.SessionOptions.ProtocolVersion = 3;
            conn.SessionOptions.Signing = true;
            conn.SessionOptions.Sealing = true;
            conn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            var bound = conn;
            if (credential?.Token is WindowsIdentity identity)
                // Kerberos als registrierende Person: Anmeldung unter ihrem Token (Interaktiv-Anmeldung des Dienstes, mit Anmeldedaten)
                WindowsIdentity.RunImpersonated(identity.AccessToken, () => bound.Bind());
            else if (credential is not null && network is null)
                throw new FidoStoreException(ErrorCodes.FidoDirectoryCredentialRequired, "no usable credential of the registrar");
            else
                conn.Bind();
            keysDn = "CN=SecurityKeys," + ContainerDn(conn);
            Location = keysDn;
            return conn;
        }
        catch (Exception ex)
        {
            conn?.Dispose();
            throw Map(ex);
        }
    }

    /// <summary>Fido.DirectoryContainer oder CN=Vitrine,CN=Program Data,&lt;defaultNamingContext&gt;.</summary>
    private string ContainerDn(LdapConnection conn)
    {
        var configured = settings().DirectoryContainer?.Trim();
        if (!string.IsNullOrEmpty(configured)) return configured;
        var root = (SearchResponse)Send(conn, new SearchRequest("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext"));
        var nc = root.Entries.Count > 0 ? First(root.Entries[0], "defaultNamingContext") : null;
        if (string.IsNullOrEmpty(nc)) throw new FidoStoreException(ErrorCodes.FidoDirectoryNotConfigured, "defaultNamingContext not readable");
        return "CN=Vitrine,CN=Program Data," + nc;
    }

    private static DirectoryResponse Send(LdapConnection conn, DirectoryRequest request)
    {
        try { return conn.SendRequest(request, Timeout); }
        catch (Exception ex) { throw Map(ex); }
    }

    private static FidoStoreException Map(Exception ex) => ex switch
    {
        FidoStoreException f => f,
        DirectoryOperationException op => new FidoStoreException(FidoDirectoryCodec.CodeForLdapResult((int)op.Response.ResultCode),
            $"LDAP {op.Response.ResultCode}: {op.Message}", ex),
        LdapException ldap => new FidoStoreException(FidoDirectoryCodec.CodeForLdapResult(ldap.ErrorCode), $"LDAP {ldap.ErrorCode}: {ldap.Message}", ex),
        DirectoryException or TimeoutException or System.ComponentModel.Win32Exception or InvalidOperationException =>
            new FidoStoreException(ErrorCodes.FidoDirectoryUnavailable, ex.Message, ex),
        UnauthorizedAccessException or System.Security.SecurityException => new FidoStoreException(ErrorCodes.FidoDirectoryAccessDenied, ex.Message, ex),
        _ => new FidoStoreException(ErrorCodes.FidoDirectoryUnavailable, ex.Message, ex),
    };

    /// <summary>„Wer bin ich“ (RFC 4532) → SID der angemeldeten Identität.</summary>
    private static string WhoAmI(LdapConnection conn)
    {
        var response = (ExtendedResponse)Send(conn, new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"));
        var text = response.ResponseValue is { } v ? Encoding.UTF8.GetString(v) : "";
        if (text.StartsWith("u:", StringComparison.Ordinal)) text = text[2..];
        try { return new NTAccount(text).Translate(typeof(SecurityIdentifier)).Value; }
        catch (Exception ex) when (ex is IdentityNotMappedException or ArgumentException or SystemException)
        {
            throw new FidoStoreException(ErrorCodes.FidoDirectoryIdentityMismatch, $"identity '{text}' of the directory connection not resolvable", ex);
        }
    }

    private static FidoDirectoryEntry? Read(LdapConnection conn, string keysDn, string cn)
    {
        var safe = new string(cn.Where(char.IsAsciiHexDigit).ToArray()).ToLowerInvariant();
        if (safe.Length == 0) return null;
        try
        {
            var r = (SearchResponse)Send(conn, new SearchRequest($"CN={safe},{keysDn}", "(objectClass=serviceConnectionPoint)", SearchScope.Base, Attributes));
            return r.Entries.Count == 0 ? null : ToEntry(r.Entries[0]);
        }
        catch (FidoStoreException ex) when (ex.InnerException is DirectoryOperationException { Response.ResultCode: ResultCode.NoSuchObject })
        {
            // Objekt gibt es nicht (der Container schon: sonst wäre das Lesen davor gescheitert)
            return null;
        }
    }

    private static FidoDirectoryEntry ToEntry(SearchResultEntry e) =>
        new(First(e, "cn") ?? "", All(e, "keywords"), All(e, "serviceBindingInformation"), First(e, "description"));

    private static string[] All(SearchResultEntry e, string name) =>
        e.Attributes[name] is { } a ? a.GetValues(typeof(string)).Cast<string>().ToArray() : [];

    private static string? First(SearchResultEntry e, string name) => All(e, name).FirstOrDefault();

    // ================= Schreiben =================

    private sealed class Writer(LdapConnection conn, string keysDn, string boundSid) : IFidoDirectoryWriter
    {
        public string BoundSid { get; } = boundSid;

        public Task<FidoDirectoryEntry?> ReadAsync(string cn, CancellationToken ct = default) => Task.Run(() => Read(conn, keysDn, cn), ct);

        public Task CreateAsync(FidoDirectoryEntry entry, CancellationToken ct = default) => Task.Run(() =>
        {
            var attributes = new List<DirectoryAttribute>
            {
                new("objectClass", "serviceConnectionPoint"),
                new("keywords", entry.Keywords.Cast<object>().ToArray()),
                new("serviceBindingInformation", entry.BindingInformation.Cast<object>().ToArray()),
            };
            if (!string.IsNullOrEmpty(entry.Description)) attributes.Add(new DirectoryAttribute("description", entry.Description));
            Send(conn, new AddRequest(Dn(entry), attributes.ToArray()));
        }, ct);

        public Task ReplaceAsync(FidoDirectoryEntry entry, CancellationToken ct = default) => Task.Run(() =>
        {
            static DirectoryAttributeModification Replace(string name, IEnumerable<string> values)
            {
                var m = new DirectoryAttributeModification { Name = name, Operation = DirectoryAttributeOperation.Replace };
                foreach (var v in values) m.Add(v);
                return m;
            }
            Send(conn, new ModifyRequest(Dn(entry),
                Replace("keywords", entry.Keywords),
                Replace("serviceBindingInformation", entry.BindingInformation),
                Replace("description", entry.Description is { Length: > 0 } d ? [d] : [])));
        }, ct);

        private string Dn(FidoDirectoryEntry entry)
        {
            var cn = new string(entry.Cn.Where(char.IsAsciiHexDigit).ToArray()).ToLowerInvariant();
            if (cn.Length != 64) throw new FidoStoreException(ErrorCodes.FidoStoreError, "invalid key ID");
            return $"CN={cn},{keysDn}";
        }

        public void Dispose() => conn.Dispose();
    }

    // ================= Domänencontroller =================

    /// <summary>Domänencontroller über den DC-Locator (DNS-Name); nicht Domänenmitglied → VIT-0474, keiner erreichbar → VIT-0471.</summary>
    private static string LocateDomainController()
    {
        if (!DomainJoined()) throw new FidoStoreException(ErrorCodes.FidoDirectoryNotConfigured, "this computer is not a member of an Active Directory domain");
        int error = DsGetDcNameW(null, null, 0, null, DsDirectoryServiceRequired | DsReturnDnsName, out var info);
        if (error != 0)
            error = DsGetDcNameW(null, null, 0, null, DsDirectoryServiceRequired | DsReturnDnsName | DsForceRediscovery, out info);
        if (error != 0) throw new FidoStoreException(ErrorCodes.FidoDirectoryUnavailable, $"no domain controller found (Win32 {error})");
        try
        {
            var dc = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(info);
            return (dc.DomainControllerName ?? "").TrimStart('\\');
        }
        finally { NetApiBufferFree(info); }
    }

    private static bool DomainJoined()
    {
        if (NetGetJoinInformation(null, out var name, out int status) != 0) return false;
        NetApiBufferFree(name);
        return status == 3; // NetSetupDomainName
    }

    private const uint DsForceRediscovery = 0x1;
    private const uint DsDirectoryServiceRequired = 0x10;
    private const uint DsReturnDnsName = 0x40000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DOMAIN_CONTROLLER_INFO
    {
        public string? DomainControllerName;
        public string? DomainControllerAddress;
        public uint DomainControllerAddressType;
        public Guid DomainGuid;
        public string? DomainName;
        public string? DnsForestName;
        public uint Flags;
        public string? DcSiteName;
        public string? ClientSiteName;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int DsGetDcNameW(string? computerName, string? domainName, nint domainGuid, string? siteName, uint flags, out nint info);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGetJoinInformation(string? server, out nint name, out int status);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(nint buffer);
}

/// <summary>
/// Signaturzähler je Rechner unter HKLM\SOFTWARE\ICT-Baden\Vitrine\FidoCounters (nur SYSTEM): Wert = SHA-256 der
/// Credential-ID, Inhalt „Zähler|letzte Nutzung (ISO 8601)“.
/// </summary>
internal sealed class RegistryFidoCounterStore : IFidoCounterStore
{
    private readonly object _gate = new();

    public FidoCounter? Get(string idHash)
    {
        lock (_gate)
        {
            using var key = Registry.LocalMachine.OpenSubKey(AppPaths.FidoCountersKey);
            if (key?.GetValue(idHash) is not string v) return null;
            var parts = v.Split('|');
            if (!uint.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var count)) return null;
            DateTimeOffset? used = parts.Length > 1 && DateTimeOffset.TryParse(parts[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)
                ? t : null;
            return new FidoCounter(count, used);
        }
    }

    public void Set(string idHash, FidoCounter counter)
    {
        lock (_gate)
        {
            using var key = Open();
            key.SetValue(idHash, string.Create(CultureInfo.InvariantCulture,
                $"{counter.SignCount}|{counter.LastUsedAt?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)}"), RegistryValueKind.String);
        }
    }

    private static RegistryKey Open()
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new RegistrySecurity();
        security.SetOwner(system);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new RegistryAccessRule(system, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None,
            AccessControlType.Allow));
        Registry.LocalMachine.CreateSubKey(AppPaths.ProductKey)?.Dispose();
        var key = Registry.LocalMachine.CreateSubKey(AppPaths.FidoCountersKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.None, security);
        key.SetAccessControl(security);
        return key;
    }
}
