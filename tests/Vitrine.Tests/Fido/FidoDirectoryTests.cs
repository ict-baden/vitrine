// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;
using Vitrine.Tests.Audit;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Fido;

/// <summary>Active Directory im Speicher: Objekte nach cn, Anmeldung zum Schreiben über Token oder Kennwort.</summary>
internal sealed class FakeDirectory : IFidoDirectory
{
    public readonly Dictionary<string, FidoDirectoryEntry> Objects = new(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, (string Password, string Sid)> Accounts = new(StringComparer.OrdinalIgnoreCase);
    public string? Down;
    public int ReadAlls, Reads, Writers;
    public readonly List<FakeWriter> Opened = new();

    public string? Location => "CN=SecurityKeys,CN=Vitrine,CN=Program Data,DC=contoso,DC=com";

    private void Check()
    {
        if (Down is { } code) throw new FidoStoreException(code, "directory down");
    }

    public Task<IReadOnlyList<FidoDirectoryEntry>> ReadAllAsync(CancellationToken ct = default)
    {
        ReadAlls++;
        Check();
        return Task.FromResult<IReadOnlyList<FidoDirectoryEntry>>(Objects.Values.Where(o => FidoDirectoryCodec.ParseKeywords(o.Keywords).IsVitrine).ToList());
    }

    public Task<FidoDirectoryEntry?> ReadAsync(string cn, CancellationToken ct = default)
    {
        Reads++;
        Check();
        return Task.FromResult(Objects.GetValueOrDefault(cn));
    }

    public Task<IFidoDirectoryWriter> OpenWriterAsync(FidoWriteCredential credential, CancellationToken ct = default)
    {
        Writers++;
        Check();
        string sid;
        if (credential.Token is FakeToken t) sid = t.Sid;
        else if (credential.User is { } u && Accounts.TryGetValue(u, out var a) && a.Password == credential.Password) sid = a.Sid;
        else throw new FidoStoreException(ErrorCodes.FidoDirectoryAccessDenied, "LDAP 49");
        var w = new FakeWriter(this, sid);
        Opened.Add(w);
        return Task.FromResult<IFidoDirectoryWriter>(w);
    }

    /// <summary>Objekt direkt ändern (wie ein anderer Rechner oder ein Administrator).</summary>
    public void Revoke(string cn, string reason)
    {
        var c = FidoDirectoryCodec.Decode(Objects[cn]).Credential!;
        c.Status = FidoCredentialStatus.Revoked;
        c.RevokeReason = reason;
        Objects[cn] = FidoDirectoryCodec.Encode(c);
    }
}

internal sealed class FakeWriter(FakeDirectory dir, string sid) : IFidoDirectoryWriter
{
    public string BoundSid { get; } = sid;
    public bool Disposed;

    public Task<FidoDirectoryEntry?> ReadAsync(string cn, CancellationToken ct = default) => Task.FromResult(dir.Objects.GetValueOrDefault(cn));

    public Task CreateAsync(FidoDirectoryEntry entry, CancellationToken ct = default)
    {
        Assert.False(Disposed);
        if (!dir.Objects.TryAdd(entry.Cn, entry)) throw new FidoStoreException(ErrorCodes.FidoKeyAlreadyRegistered, "LDAP 68");
        return Task.CompletedTask;
    }

    public Task ReplaceAsync(FidoDirectoryEntry entry, CancellationToken ct = default)
    {
        Assert.False(Disposed);
        dir.Objects[entry.Cn] = entry;
        return Task.CompletedTask;
    }

    public void Dispose() => Disposed = true;
}

internal sealed class FakeToken(string sid) : IDisposable
{
    public string Sid { get; } = sid;
    public bool Disposed;
    public void Dispose() => Disposed = true;
}

internal sealed class MemoryCounters : IFidoCounterStore
{
    public readonly Dictionary<string, FidoCounter> Values = new(StringComparer.OrdinalIgnoreCase);
    public FidoCounter? Get(string idHash) => Values.GetValueOrDefault(idHash);
    public void Set(string idHash, FidoCounter counter) => Values[idHash] = counter;
}

/// <summary>
/// Sicherheitsschlüssel im Active Directory: Format der Objekte (Version, Stichwörter, Stücke, Status), Abgleich und
/// Zwischenspeicher (frisch, fällig, erzwungen, ohne AD), Zähler je Rechner, Schreiben nur als registrierende Person,
/// zwei Rechner mit derselben Domäne. Kein echtes LDAP.
/// </summary>
public sealed class FidoDirectoryTests : IDisposable
{
    private const string Rp = FidoSettings.DefaultRpId;
    private const string OperatorSid = "S-1-5-21-1-1-1-1001";
    private const string AdminSid = "S-1-5-21-1-1-1-500";
    private const string Admins = "S-1-5-32-544";

    private static readonly AuditClient OperatorClient = new(2, @"LAB\operator", OperatorSid, 4711);
    private static readonly AuditClient AdminClient = new(3, @"LAB\admin", AdminSid, 4712);
    private static readonly AuthOutcome Registrar = new()
    {
        Success = true, UserName = @"LAB\admin", UserId = AdminSid, IsAdministrator = true, Groups = [Admins],
    };

    private readonly FakeDirectory _dir = new();
    private readonly VitrineConfig _config = new();
    private DateTimeOffset _now = new(2026, 10, 30, 8, 0, 0, TimeSpan.Zero);
    private readonly TestAuthenticator _key = new();
    private readonly List<string> _log = new();

    public FidoDirectoryTests()
    {
        _config.Fido.Store = FidoStoreKind.ActiveDirectory;
        _dir.Accounts[@"LAB\admin"] = (AdPassword, AdminSid);
        _dir.Accounts[@"LAB\other"] = (AdPassword, "S-1-5-21-1-1-1-777");
    }

    public void Dispose() => _key.Dispose();

    /// <summary>Ein Rechner: eigener Zwischenspeicher, eigene Zähler, gemeinsames AD.</summary>
    private sealed record Machine(FidoDirectoryStore Store, MemoryStoreFile Cache, MemoryCounters Counters, FidoService Fido, List<FidoAuditEvent> Events);

    private Machine NewMachine(string name = "LAB-PC-07", MemoryStoreFile? cache = null, Action<FidoAuditEvent>? audit = null)
    {
        cache ??= new MemoryStoreFile();
        var counters = new MemoryCounters();
        var store = new FidoDirectoryStore(_dir, cache, counters, () => _config.Fido, () => _now, _log.Add);
        var accounts = new FakeAccounts();
        accounts.Add(@"LAB\operator", OperatorSid, "operator@contoso.com", "S-1-5-32-545");
        accounts.Add(@"LAB\admin", AdminSid, null, Admins);
        var events = new List<FidoAuditEvent>();
        var fido = new FidoService(store, store, accounts, new RoleCheck(() => _config), () => _config.Fido, e => { events.Add(e); audit?.Invoke(e); },
            () => _now, name);
        return new Machine(store, cache, counters, fido, events);
    }

    private static FidoCredential Cred(TestAuthenticator key, string person = OperatorSid, string? cert = null) => new()
    {
        CredentialId = key.CredentialIdB64, IdHash = FidoProtocol.IdHash(key.CredentialId), RpId = Rp,
        PublicKey = FidoProtocol.ToBase64Url(key.CoseKey()), Algorithm = -7, Aaguid = TestAuthenticator.DefaultAaguid.ToString("D"),
        AttestationFormat = "packed", AttestationVerified = true, AttestationCertificate = cert, UserHandle = "aGFuZGxl",
        PersonSid = person, PersonName = @"LAB\operator", PersonUpn = "operator@contoso.com", Label = "Key 1", Reason = "New lab operator",
        RegisteredAt = new DateTimeOffset(2026, 10, 29, 9, 0, 0, TimeSpan.Zero), RegisteredBySid = AdminSid, RegisteredByName = @"LAB\admin",
        RegisteredOn = "LAB-PC-01", SignCount = 42, LastUsedAt = DateTimeOffset.UnixEpoch,
    };

    private const string AdPassword = "Directory-Pa55";

    private static FidoWriteCredential Password(string user = @"LAB\admin", string password = AdPassword) => FidoWriteCredential.FromPassword(user, password)!;

    private static async Task<FidoCredential> RegisterAsync(Machine m, TestAuthenticator key, FidoWriteCredential? credential)
    {
        var begin = await m.Fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key 1", "New lab operator, badge 17", directory: credential);
        Assert.True(begin.Ok, begin.Problem);
        var (cd, att) = key.Register(Rp, begin.Value!.Challenge);
        var done = await m.Fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.True(done.Ok, done.Problem);
        return done.Value!;
    }

    private async Task<FidoResult<AuthOutcome>> UnlockAsync(Machine m, TestAuthenticator? key = null, uint? counter = null)
    {
        var ch = await m.Fido.ChallengeAsync(OperatorClient, FidoPurpose.Unlock);
        Assert.True(ch.Ok, ch.Problem);
        return await m.Fido.VerifyAsync(OperatorClient, FidoPurpose.Unlock, (key ?? _key).Assert(Rp, ch.Value!.Challenge, counter: counter));
    }

    // ================= Format =================

    [Fact]
    public void Objekt_enthaelt_Stichwoerter_cn_und_alle_Angaben_ohne_Zaehler()
    {
        var c = Cred(_key);
        var e = FidoDirectoryCodec.Encode(c);
        Assert.Equal(c.IdHash, e.Cn);
        Assert.Equal(["VitrineFidoCredential", "status=active", "rp=vitrine"], e.Keywords);
        Assert.Null(e.Description);
        Assert.All(e.BindingInformation, v => Assert.StartsWith("vitrine-fido:1:", v));
        Assert.DoesNotContain(e.BindingInformation, v => v.Contains("signCount", StringComparison.OrdinalIgnoreCase) || v.Contains("lastUsed", StringComparison.OrdinalIgnoreCase));

        var back = FidoDirectoryCodec.Decode(e).Credential!;
        Assert.Equal(c.CredentialId, back.CredentialId);
        Assert.Equal(c.PublicKey, back.PublicKey);
        Assert.Equal(c.Algorithm, back.Algorithm);
        Assert.Equal(c.Aaguid, back.Aaguid);
        Assert.Equal(c.AttestationFormat, back.AttestationFormat);
        Assert.True(back.AttestationVerified);
        Assert.Equal(c.PersonSid, back.PersonSid);
        Assert.Equal(c.PersonUpn, back.PersonUpn);
        Assert.Equal(c.PersonName, back.PersonName);
        Assert.Equal(c.Label, back.Label);
        Assert.Equal(c.RegisteredAt, back.RegisteredAt);
        Assert.Equal(c.RegisteredBySid, back.RegisteredBySid);
        Assert.Equal(c.RegisteredOn, back.RegisteredOn);
        Assert.True(back.IsActive);
        Assert.Equal(0u, back.SignCount);
        Assert.Null(back.LastUsedAt);
    }

    [Fact]
    public void Grosser_Inhalt_in_Stuecken_in_beliebiger_Reihenfolge()
    {
        var c = Cred(_key, cert: "CN=" + new string('x', 3000));
        var e = FidoDirectoryCodec.Encode(c);
        Assert.True(e.BindingInformation.Count >= 4);
        // Mehrwertige Attribute haben im AD keine Reihenfolge; fremde Werte stören nicht
        var shuffled = e with { BindingInformation = [.. e.BindingInformation.Reverse(), "something else"] };
        Assert.Equal(c.AttestationCertificate, FidoDirectoryCodec.Decode(shuffled).Credential!.AttestationCertificate);

        Assert.Contains("missing", FidoDirectoryCodec.Decode(e with { BindingInformation = e.BindingInformation.Skip(1).ToList() }).Problem);
        Assert.Contains("twice", FidoDirectoryCodec.Decode(e with { BindingInformation = [.. e.BindingInformation, e.BindingInformation[0]] }).Problem);
        Assert.NotNull(FidoDirectoryCodec.Decode(e with { BindingInformation = [] }).Problem);
    }

    [Fact]
    public void Unbekannte_Version_wird_nicht_gelesen()
    {
        var e = FidoDirectoryCodec.Encode(Cred(_key));
        var json = string.Concat(e.BindingInformation.Select(v => v[(v.IndexOf(':', "vitrine-fido:1:".Length) + 1)..]));
        var v2 = json.Replace("\"v\":1", "\"v\":2", StringComparison.Ordinal);
        Assert.Contains("version 2", FidoDirectoryCodec.Decode(e with { BindingInformation = ["vitrine-fido:1:0/1:" + v2] }).Problem);
        Assert.Contains("version 2", FidoDirectoryCodec.Decode(e with { BindingInformation = ["vitrine-fido:2:0/1:" + json] }).Problem);
        Assert.Contains("version", FidoDirectoryCodec.Decode(e with { BindingInformation = ["vitrine-fido:1:0/1:" + json.Replace("\"v\":1,", "", StringComparison.Ordinal)] }).Problem);
        // Zusätzliche Felder derselben Version stören nicht
        Assert.True(FidoDirectoryCodec.Decode(e with { BindingInformation = ["vitrine-fido:1:0/1:" + json.Replace("{", "{\"future\":true,", StringComparison.Ordinal)] }).Ok);
    }

    [Fact]
    public void Kennung_RP_ID_und_Pflichtangaben_werden_geprueft()
    {
        var e = FidoDirectoryCodec.Encode(Cred(_key));
        Assert.Contains("SHA-256", FidoDirectoryCodec.Decode(e with { Cn = new string('a', 64) }).Problem);
        Assert.Contains("RP ID", FidoDirectoryCodec.Decode(e with { Keywords = ["VitrineFidoCredential", "status=active", "rp=other"] }).Problem);
        Assert.Contains("RP ID", FidoDirectoryCodec.Decode(e with { Keywords = ["VitrineFidoCredential", "status=active"] }).Problem);
        Assert.Contains("keyword", FidoDirectoryCodec.Decode(e with { Keywords = ["status=active", "rp=vitrine"] }).Problem);
        var noPerson = Cred(_key, person: "");
        Assert.Contains("person", FidoDirectoryCodec.Decode(FidoDirectoryCodec.Encode(noPerson)).Problem);
    }

    [Theory]
    [InlineData("status=active", "active", true)]
    [InlineData("status=revoked", "active", false)]
    [InlineData("status=active", "revoked", false)]
    [InlineData(null, "active", false)]
    [InlineData("status=unknown", "active", false)]
    public void Aktiv_nur_wenn_Stichwort_und_Inhalt_aktiv_sagen(string? keyword, string payload, bool active)
    {
        var c = Cred(_key);
        if (payload == "revoked") c.Status = FidoCredentialStatus.Revoked;
        var e = FidoDirectoryCodec.Encode(c);
        var keywords = new List<string> { "vitrinefidocredential", "rp=vitrine" };
        if (keyword is not null) keywords.Add(keyword);
        Assert.Equal(active, FidoDirectoryCodec.Decode(e with { Keywords = keywords }).Credential!.IsActive);
    }

    [Fact]
    public void Stichwoerter_lesen()
    {
        var k = FidoDirectoryCodec.ParseKeywords(["VITRINEFIDOCREDENTIAL", "Status=Revoked", "rp=vitrine", "other"]);
        Assert.Equal(new FidoDirectoryKeywords(true, "revoked", "vitrine"), k);
        // Widersprüchliche Angaben gelten als fehlend
        Assert.Null(FidoDirectoryCodec.ParseKeywords(["VitrineFidoCredential", "status=active", "status=revoked"]).Status);
        Assert.False(FidoDirectoryCodec.ParseKeywords(null).IsVitrine);
    }

    [Theory]
    [InlineData(49, ErrorCodes.FidoDirectoryAccessDenied)]
    [InlineData(50, ErrorCodes.FidoDirectoryAccessDenied)]
    [InlineData(32, ErrorCodes.FidoDirectoryNotConfigured)]
    [InlineData(68, ErrorCodes.FidoKeyAlreadyRegistered)]
    [InlineData(81, ErrorCodes.FidoDirectoryUnavailable)]
    [InlineData(85, ErrorCodes.FidoDirectoryUnavailable)]
    public void LDAP_Ergebnis_wird_Fehlercode(int ldap, string code) => Assert.Equal(code, FidoDirectoryCodec.CodeForLdapResult(ldap));

    // ================= Abgleich und Zwischenspeicher =================

    [Fact]
    public async Task Abgleich_liest_gueltige_Objekte_und_meldet_ungueltige_einmal()
    {
        var good = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[good.Cn] = good;
        using var other = new TestAuthenticator();
        var bad = FidoDirectoryCodec.Encode(Cred(other)) with { BindingInformation = ["vitrine-fido:1:0/2:{"] };
        _dir.Objects[bad.Cn] = bad;
        var m = NewMachine();

        var list = await m.Store.ListAsync();
        Assert.Equal(good.Cn, Assert.Single(list).IdHash);
        Assert.Single(_log, l => l.StartsWith(ErrorCodes.FidoDirectoryEntryInvalid, StringComparison.Ordinal) && l.Contains(bad.Cn));
        Assert.Equal(_now, m.Store.Info.LastSync);
        Assert.Null(m.Store.Info.SyncError);
        Assert.Equal(_dir.Location, m.Store.Info.Location);

        _now = _now.AddMinutes(20);
        await m.Store.SyncAsync(false);
        Assert.Single(_log, l => l.StartsWith(ErrorCodes.FidoDirectoryEntryInvalid, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Abgleich_erst_nach_SyncMinutes_erzwungen_hoechstens_alle_30_Sekunden()
    {
        var m = NewMachine();
        await m.Store.SyncAsync(false);
        Assert.Equal(1, _dir.ReadAlls);
        _now = _now.AddMinutes(14);
        await m.Store.SyncAsync(false);
        Assert.Equal(1, _dir.ReadAlls);
        _now = _now.AddMinutes(1);
        await m.Store.SyncAsync(false);
        Assert.Equal(2, _dir.ReadAlls);

        _now = _now.AddSeconds(10);
        await m.Store.SyncAsync(true);
        Assert.Equal(2, _dir.ReadAlls);
        _now = _now.AddSeconds(25);
        await m.Store.SyncAsync(true);
        Assert.Equal(3, _dir.ReadAlls);

        _config.Fido.SyncMinutes = 60;
        _now = _now.AddMinutes(30);
        await m.Store.SyncAsync(false);
        Assert.Equal(3, _dir.ReadAlls);
    }

    [Fact]
    public async Task Ohne_AD_gilt_der_Zwischenspeicher_auch_nach_Neustart()
    {
        var reg = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[reg.Cn] = reg;
        var cache = new MemoryStoreFile();
        var m = NewMachine(cache: cache);
        Assert.Single(await m.Store.ListAsync());
        Assert.Contains(reg.Cn, cache.Content);

        // AD weg, Dienst neu gestartet: Schlüssel aus dem Zwischenspeicher, Fehler einmal im Protokoll
        _dir.Down = ErrorCodes.FidoDirectoryUnavailable;
        _now = _now.AddHours(2);
        var restarted = NewMachine(cache: cache);
        Assert.Single(await restarted.Store.ListAsync());
        await restarted.Store.SyncAsync(false);
        Assert.StartsWith(ErrorCodes.FidoDirectoryUnavailable, restarted.Store.Info.SyncError);
        Assert.Equal(_now.AddHours(-2), restarted.Store.Info.LastSync);
        Assert.Single(_log, l => l.StartsWith(ErrorCodes.FidoDirectoryUnavailable, StringComparison.Ordinal));

        // Wiederholung frühestens nach einer Minute
        int reads = _dir.ReadAlls;
        _now = _now.AddSeconds(30);
        await restarted.Store.SyncAsync(false);
        Assert.Equal(reads, _dir.ReadAlls);
        _now = _now.AddSeconds(31);
        _dir.Down = null;
        await restarted.Store.SyncAsync(false);
        Assert.Equal(reads + 1, _dir.ReadAlls);
        Assert.Null(restarted.Store.Info.SyncError);
    }

    [Fact]
    public async Task Ohne_AD_und_ohne_Zwischenspeicher_keine_Schluessel()
    {
        _dir.Objects[FidoDirectoryCodec.Encode(Cred(_key)).Cn] = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Down = ErrorCodes.FidoDirectoryNotConfigured;
        var m = NewMachine();
        Assert.Empty(await m.Store.ListAsync());
        Assert.Null(m.Store.Info.LastSync);
        Assert.StartsWith(ErrorCodes.FidoDirectoryNotConfigured, m.Store.Info.SyncError);
        var ch = await m.Fido.ChallengeAsync(OperatorClient, FidoPurpose.Unlock);
        Assert.Equal(ErrorCodes.FidoNoKeys, ch.Code);
    }

    [Fact]
    public async Task Ungeschuetzter_Zwischenspeicher_wird_verworfen_und_neu_geschrieben()
    {
        var cache = new MemoryStoreFile { Unprotected = true };
        var reg = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[reg.Cn] = reg;
        var m = NewMachine(cache: cache);
        Assert.Single(await m.Store.ListAsync());
        Assert.Contains(_log, l => l.StartsWith(ErrorCodes.FidoStoreNotProtected, StringComparison.Ordinal));
        Assert.Equal(1, cache.Writes);
    }

    [Fact]
    public async Task Zaehler_bleiben_auf_dem_Rechner()
    {
        var reg = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[reg.Cn] = reg;
        var m = NewMachine();
        await m.Store.SyncAsync(false);
        Assert.True(await m.Store.TouchAsync(reg.Cn, 7, _now));
        Assert.Equal(new FidoCounter(7, _now), m.Counters.Values[reg.Cn]);
        var c = (await m.Store.GetAsync(reg.Cn))!;
        Assert.Equal(7u, c.SignCount);
        Assert.Equal(_now, c.LastUsedAt);
        // Weder im AD noch im Zwischenspeicher
        Assert.Equal(reg, _dir.Objects[reg.Cn]);
        Assert.DoesNotContain("\"SignCount\": 7", m.Cache.Content);
        // Rückgabe ist eine Kopie
        c.Status = FidoCredentialStatus.Revoked;
        Assert.True((await m.Store.GetAsync(reg.Cn))!.IsActive);
    }

    [Fact]
    public async Task Bekannter_Schluessel_wird_bei_erreichbarem_AD_frisch_gelesen()
    {
        var reg = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[reg.Cn] = reg;
        var m = NewMachine();
        await m.Store.SyncAsync(false);

        _dir.Revoke(reg.Cn, "Key lost on 2026-10-30");
        Assert.False((await m.Store.GetAsync(reg.Cn))!.IsActive);
        Assert.False((await m.Store.ListAsync()).Single().IsActive);

        _dir.Objects.Remove(reg.Cn);
        Assert.Null(await m.Store.GetAsync(reg.Cn));
        Assert.Empty(await m.Store.ListAsync());
    }

    [Fact]
    public async Task Ohne_AD_keine_Einzelabfrage_fuer_bekannte_Schluessel()
    {
        var reg = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[reg.Cn] = reg;
        var m = NewMachine();
        await m.Store.SyncAsync(false);
        _dir.Down = ErrorCodes.FidoDirectoryUnavailable;
        Assert.NotNull(await m.Store.GetAsync(reg.Cn)); // eine Abfrage scheitert, danach offline
        int reads = _dir.Reads;
        Assert.NotNull(await m.Store.GetAsync(reg.Cn));
        Assert.Equal(reads, _dir.Reads);
    }

    [Fact]
    public async Task Unbekannte_Kennung_wird_gezielt_gesucht_aber_begrenzt()
    {
        var m = NewMachine();
        await m.Store.SyncAsync(false);
        var reg = FidoDirectoryCodec.Encode(Cred(_key));
        _dir.Objects[reg.Cn] = reg; // gerade auf einem anderen Rechner registriert

        Assert.NotNull(await m.Store.GetAsync(reg.Cn));
        Assert.Single(await m.Store.ListAsync());

        // Dieselbe unbekannte Kennung höchstens einmal je Minute, insgesamt begrenzt
        var unknown = new string('b', 64);
        Assert.Null(await m.Store.GetAsync(unknown));
        int reads = _dir.Reads;
        Assert.Null(await m.Store.GetAsync(unknown));
        Assert.Equal(reads, _dir.Reads);
        for (int i = 0; i < FidoDirectoryStore.MaxLookups + 5; i++) await m.Store.GetAsync(i.ToString("x64"));
        Assert.True(_dir.Reads - reads <= FidoDirectoryStore.MaxLookups);
    }

    // ================= Schreiben =================

    [Fact]
    public async Task Schreiben_nur_mit_Anmeldedaten_der_registrierenden_Person()
    {
        var m = NewMachine();
        Assert.True(m.Store.RequiresWriteCredential);
        var e1 = await Assert.ThrowsAsync<FidoStoreException>(() => m.Store.AddAsync(Cred(_key)));
        Assert.Equal(ErrorCodes.FidoDirectoryCredentialRequired, e1.Code);
        var e2 = await Assert.ThrowsAsync<FidoStoreException>(() => m.Store.OpenWriterAsync(null, AdminSid));
        Assert.Equal(ErrorCodes.FidoDirectoryCredentialRequired, e2.Code);
        var e3 = await Assert.ThrowsAsync<FidoStoreException>(() => m.Store.OpenWriterAsync(Password(password: "wrong"), AdminSid));
        Assert.Equal(ErrorCodes.FidoDirectoryAccessDenied, e3.Code);
        // Angemeldet als jemand anderes: abgelehnt, Verbindung geschlossen
        var e4 = await Assert.ThrowsAsync<FidoStoreException>(() => m.Store.OpenWriterAsync(Password(@"LAB\other"), AdminSid));
        Assert.Equal(ErrorCodes.FidoDirectoryIdentityMismatch, e4.Code);
        Assert.True(_dir.Opened.Last().Disposed);
        Assert.Empty(_dir.Objects);
    }

    [Fact]
    public async Task Anlegen_und_Widerrufen_im_AD()
    {
        var m = NewMachine();
        using (var w = await m.Store.OpenWriterAsync(Password(), AdminSid))
        {
            await m.Store.AddAsync(Cred(_key), w);
            var dup = await Assert.ThrowsAsync<FidoStoreException>(() => m.Store.AddAsync(Cred(_key), w));
            Assert.Equal(ErrorCodes.FidoKeyAlreadyRegistered, dup.Code);
        }
        var cn = FidoProtocol.IdHash(_key.CredentialId);
        Assert.True(FidoDirectoryCodec.Decode(_dir.Objects[cn]).Credential!.IsActive);
        Assert.Equal(new FidoCounter(42, null), m.Counters.Values[cn]);

        using (var w = await m.Store.OpenWriterAsync(FidoWriteCredential.FromToken(new FakeToken(AdminSid)), AdminSid))
        {
            Assert.True(await m.Store.RevokeAsync(cn, new FidoRevocation(_now, AdminSid, @"LAB\admin", "Key lost on 2026-10-30"), w));
            Assert.False(await m.Store.RevokeAsync(cn, new FidoRevocation(_now, AdminSid, @"LAB\admin", "again"), w));
        }
        var o = _dir.Objects[cn];
        Assert.Contains("status=revoked", o.Keywords);
        Assert.Equal("Key lost on 2026-10-30", o.Description);
        var revoked = FidoDirectoryCodec.Decode(o).Credential!;
        Assert.Equal(AdminSid, revoked.RevokedBySid);
        Assert.False((await m.Store.ListAsync()).Single().IsActive);
    }

    // ================= Zwei Rechner, eine Domäne =================

    [Fact]
    public async Task Einmal_registriert_gilt_auf_allen_Rechnern_Zaehler_je_Rechner()
    {
        var a = NewMachine("LAB-PC-01");
        var b = NewMachine("LAB-PC-02");
        await b.Store.SyncAsync(false); // B kannte den Schlüssel noch nicht

        var c = await RegisterAsync(a, _key, Password());
        var reg = a.Events.Single(e => e.Type == AuditEventType.FidoKeyRegistered);
        Assert.Equal("activeDirectory", reg.Data["store"]);
        Assert.Contains(c.IdHash, _dir.Objects.Keys);
        Assert.True(_dir.Opened.Single().Disposed);

        // B: Challenge mit Abgleich (die App fragt so nach, wenn der Schlüssel keinen der bekannten enthielt)
        _now = _now.AddMinutes(1);
        var ch = await b.Fido.ChallengeAsync(OperatorClient, FidoPurpose.Unlock, refresh: true);
        Assert.Contains(_key.CredentialIdB64, ch.Value!.AllowCredentials);
        var onB = await b.Fido.VerifyAsync(OperatorClient, FidoPurpose.Unlock, _key.Assert(Rp, ch.Value.Challenge, counter: 10));
        Assert.True(onB.Ok, onB.Problem);
        Assert.True((await UnlockAsync(a, counter: 11)).Ok);

        // Zähler je Rechner: B hat 10 gesehen, ein kleinerer Wert ist dort verdächtig, auf A (11) auch
        var clone = await UnlockAsync(b, counter: 5);
        Assert.Equal(ErrorCodes.FidoCloneSuspected, clone.Code);
        Assert.Equal(10u, b.Counters.Values[c.IdHash].SignCount);
        Assert.Equal(11u, a.Counters.Values[c.IdHash].SignCount);
    }

    [Fact]
    public async Task Widerruf_auf_einem_Rechner_gilt_sofort_auf_dem_anderen()
    {
        var a = NewMachine("LAB-PC-01");
        var b = NewMachine("LAB-PC-02");
        var c = await RegisterAsync(a, _key, Password());
        await b.Store.SyncAsync(true);
        Assert.True((await UnlockAsync(b)).Ok);

        var revoked = await a.Fido.RevokeAsync(AdminClient, Registrar, c.IdHash, "Key lost on 2026-10-30", directory: Password());
        Assert.True(revoked.Ok, revoked.Problem);
        Assert.Equal("activeDirectory", a.Events.Single(e => e.Type == AuditEventType.FidoKeyRevoked).Data["store"]);

        // B hat den Schlüssel noch als aktiv im Zwischenspeicher, liest ihn bei der Anmeldung aber frisch
        var r = await UnlockAsync(b);
        Assert.Equal(ErrorCodes.FidoKeyRevoked, r.Code);
    }

    [Fact]
    public async Task Registrieren_ohne_Anmeldedaten_wird_abgelehnt_und_protokolliert()
    {
        var m = NewMachine();
        var begin = await m.Fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key 1", "New lab operator, badge 17");
        Assert.Equal(ErrorCodes.FidoDirectoryCredentialRequired, begin.Code);
        var e = m.Events.Single(e => e.Type == AuditEventType.FidoKeyRejected);
        Assert.Equal(ErrorCodes.FidoDirectoryCredentialRequired, e.Data["code"]);

        var other = await m.Fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key 1", "New lab operator, badge 17",
            directory: Password(@"LAB\other"));
        Assert.Equal(ErrorCodes.FidoDirectoryIdentityMismatch, other.Code);
        Assert.Empty(_dir.Objects);

        var revoke = await m.Fido.RevokeAsync(AdminClient, Registrar, new string('c', 64), "Key lost on 2026-10-30");
        Assert.Equal(ErrorCodes.FidoKeyUnknown, revoke.Code);
    }

    [Fact]
    public async Task Abgelaufene_Registrierung_schliesst_die_Verbindung()
    {
        var m = NewMachine();
        var begin = await m.Fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key 1", "New lab operator, badge 17",
            directory: Password());
        Assert.True(begin.Ok);
        Assert.False(_dir.Opened.Single().Disposed);
        _now = _now.Add(FidoProtocol.RegistrationLifetime).AddSeconds(1);
        var done = await m.Fido.CompleteRegistrationAsync(AdminClient, begin.Value!.RegistrationId, "e30", "oA");
        Assert.Equal(ErrorCodes.FidoRegistrationExpired, done.Code);
        Assert.True(_dir.Opened.Single().Disposed);
    }

    [Fact]
    public async Task Status_nennt_Ablage_und_letzten_Abgleich()
    {
        var m = NewMachine();
        var s = await m.Fido.StatusAsync();
        Assert.Equal(FidoStoreKind.ActiveDirectory, s.Store!.Kind);
        Assert.Equal(_now, s.Store.LastSync);
        Assert.True(m.Fido.RequiresWriteCredential);

        var local = new JsonFidoStore(new MemoryStoreFile());
        Assert.Equal(FidoStoreKind.Local, ((IFidoCredentialStore)local).Info.Kind);
        Assert.False(((IFidoCredentialStore)local).RequiresWriteCredential);
    }

    [Fact]
    public void Bericht_nennt_Ablage_Container_und_letzten_Abgleich()
    {
        var local = Vitrine.Core.Governance.AuthorizationReport.FidoStoreText(new FidoSettings(), null);
        var info = new FidoStoreInfo(FidoStoreKind.ActiveDirectory, _now, null, _dir.Location);
        var ad = Vitrine.Core.Governance.AuthorizationReport.FidoStoreText(_config.Fido, info);
        Assert.DoesNotContain("Active Directory", local);
        Assert.Contains(_dir.Location!, ad);
        Assert.Contains(_now.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture), ad);
        _config.Fido.DirectoryContainer = "CN=Vitrine,OU=Lab,DC=contoso,DC=com";
        Assert.Contains("OU=Lab", Vitrine.Core.Governance.AuthorizationReport.FidoStoreText(_config.Fido, null));
    }

    // ================= Pipe des Dienstes =================

    private sealed class TokenVerifier : ISignatureVerifier
    {
        public readonly List<FakeToken> Tokens = new();

        public Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid) =>
            Task.FromResult(secret != "right" ? AuthOutcome.Fail("wrong", "VIT-0101")
                : new AuthOutcome { Success = true, UserName = @"LAB\admin", UserId = AdminSid, IsAdministrator = true, Groups = [Admins] });

        public async Task<(AuthOutcome Outcome, IDisposable? Token)> WindowsWithTokenAsync(string user, string? domain, string secret, string clientSid)
        {
            var t = new FakeToken(AdminSid);
            Tokens.Add(t);
            return (await WindowsAsync(user, domain, secret, clientSid), t);
        }

        public Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh) => Task.FromResult<string?>(null);
        public string? ResolveSid(string name) => null;
    }

    [Fact]
    public async Task Pipe_Token_der_Kennwort_Anmeldung_schreibt_ins_AD_und_wird_freigegeben()
    {
        using var dir = new TempDir();
        _config.Unlock.Methods = ["windows", "fido"];
        var log = new SignedAuditLog(() => new AuditSettings { Directory = dir.Path, EventLog = false }, new MemoryKeyStore(), new MemoryAnchorStore(),
            null, () => _now, "LAB-PC-07");
        var verifier = new TokenVerifier();
        var broker = new AuditBroker(log, verifier, () => _config, () => _now);
        broker.Fido = NewMachine().Fido;
        Task<JsonObject> Send(JsonObject req) => broker.HandleAsync(AdminClient with { IsAdministrator = true }, req.ToJsonString());

        var v = await Send(new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        Assert.Equal("token", (string)v["details"]!["directoryCredential"]!);
        var token = verifier.Tokens.Single();
        Assert.False(token.Disposed);

        var begin = await Send(new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = (string)v["ticket"]!, ["account"] = @"LAB\operator", ["label"] = "Key 1",
            ["reason"] = "New lab operator, badge 17",
        });
        Assert.True((bool)begin["ok"]!, begin.ToJsonString());
        Assert.True(token.Disposed); // nur für die Anmeldung am AD
        var (cd, att) = _key.Register(Rp, (string)begin["challenge"]!);
        var done = await Send(new JsonObject
        {
            ["op"] = "fido-register-complete", ["registrationId"] = (string)begin["registrationId"]!,
            ["clientDataJSON"] = FidoProtocol.ToBase64Url(cd), ["attestationObject"] = FidoProtocol.ToBase64Url(att),
        });
        Assert.True((bool)done["ok"]!, done.ToJsonString());
        Assert.Single(_dir.Objects);

        var status = await Send(new JsonObject { ["op"] = "fido-status" });
        Assert.Equal("ActiveDirectory", (string)status["store"]!);
        Assert.NotNull(status["lastSync"]);
        var ch = await Send(new JsonObject { ["op"] = "fido-challenge", ["purpose"] = "unlock" });
        Assert.True((bool)ch["refreshable"]!);

        // Signatur-Tickets behalten kein Token; abgelaufene Registrar-Tickets geben es frei
        await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        Assert.Single(verifier.Tokens);
        await Send(new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        _now = _now.Add(AuditBroker.TicketLifetime).AddSeconds(1);
        await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        Assert.All(verifier.Tokens, t => Assert.True(t.Disposed));
    }

    [Fact]
    public async Task Pipe_Kennwort_aus_der_Anfrage_wenn_kein_Token()
    {
        using var dir = new TempDir();
        _config.Unlock.Methods = ["windows", "fido"];
        var log = new SignedAuditLog(() => new AuditSettings { Directory = dir.Path, EventLog = false }, new MemoryKeyStore(), new MemoryAnchorStore(),
            null, () => _now, "LAB-PC-07");
        // Prüfer ohne Token (z. B. Microsoft-Anmeldung der registrierenden Person): Kennwort für das AD kommt aus der Anfrage
        var broker = new AuditBroker(log, new TokenlessVerifier(), () => _config, () => _now);
        broker.Fido = NewMachine(audit: broker.WriteFidoEvent).Fido;
        Task<JsonObject> Send(JsonObject req) => broker.HandleAsync(AdminClient, req.ToJsonString());
        var v = await Send(new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        Assert.Null(v["details"]!["directoryCredential"]);

        var noPassword = await Send(new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = (string)v["ticket"]!, ["account"] = @"LAB\operator", ["label"] = "Key 1",
            ["reason"] = "New lab operator, badge 17",
        });
        Assert.Equal(ErrorCodes.FidoDirectoryCredentialRequired, (string)noPassword["code"]!);

        var v2 = await Send(new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        var begin = await Send(new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = (string)v2["ticket"]!, ["account"] = @"LAB\operator", ["label"] = "Key 1",
            ["reason"] = "New lab operator, badge 17", ["directoryUser"] = @"LAB\admin", ["directoryPassword"] = AdPassword,
        });
        Assert.True((bool)begin["ok"]!, begin.ToJsonString());
        var written = File.ReadAllText(Directory.GetFiles(dir.Path, "*.jsonl").Single());
        Assert.Contains(ErrorCodes.FidoDirectoryCredentialRequired, written);
        Assert.DoesNotContain(AdPassword, written);
    }

    private sealed class TokenlessVerifier : ISignatureVerifier
    {
        public Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid) =>
            Task.FromResult(new AuthOutcome { Success = true, UserName = @"LAB\admin", UserId = AdminSid, IsAdministrator = true, Groups = [Admins] });

        public Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh) => Task.FromResult<string?>(null);
        public string? ResolveSid(string name) => null;
    }
}
