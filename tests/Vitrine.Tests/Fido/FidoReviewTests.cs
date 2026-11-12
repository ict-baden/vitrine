// SPDX-License-Identifier: MIT
using System.Formats.Cbor;
using System.Security.Cryptography;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;

namespace Vitrine.Tests.Fido;

/// <summary>
/// Befunde der unabhängigen Prüfung vom 2026-10-30: eigenes Konto bei Microsoft-Registrierenden, Aussperren fremder
/// Personen mit gefälschten Antworten, Challenge-Flut, RSA-Exponent, Höchstzahl bei gleichzeitigen Registrierungen,
/// langsamer Domänencontroller, Zweck nur bei offenem Dialog.
/// </summary>
public sealed class FidoReviewTests : IDisposable
{
    private const string Rp = FidoSettings.DefaultRpId;
    private const string OperatorSid = "S-1-5-21-1-1-1-1001";
    private const string AdminSid = "S-1-5-21-1-1-1-500";
    private const string NurseSid = "S-1-5-21-1-1-1-1003";
    private const string EntraOid = "11111111-2222-3333-4444-555555555555";

    private static readonly AuditClient Session2 = new(2, @"LAB\operator", OperatorSid, 4711);
    private static readonly AuditClient Session3 = new(3, @"LAB\admin", AdminSid, 4712);
    private static readonly AuditClient Attacker = new(5, @"LAB\nurse", NurseSid, 4713);

    private static readonly AuthOutcome Registrar = new()
    {
        Success = true, UserName = @"LAB\admin", UserId = AdminSid, IsAdministrator = true, Groups = ["S-1-5-32-544"],
    };

    private readonly VitrineConfig _config = new();
    private readonly FakeAccounts _accounts = new();
    private readonly List<FidoAuditEvent> _events = new();
    private DateTimeOffset _now = new(2026, 10, 30, 8, 0, 0, TimeSpan.Zero);
    private readonly TestAuthenticator _key = new();

    public FidoReviewTests()
    {
        _accounts.Add(@"LAB\operator", OperatorSid, "operator@contoso.com", "S-1-5-21-1-1-1-3001");
        _accounts.Add(@"LAB\admin", AdminSid, "admin@contoso.com", "S-1-5-32-544");
        _accounts.Add(@"LAB\nurse", NurseSid, null);
        _accounts.Add(@"AzureAD\entra@contoso.com", EntraClaims.SidFromObjectId(EntraOid)!, "entra@contoso.com");
    }

    public void Dispose() => _key.Dispose();

    private FidoService Service(IFidoCredentialStore? store = null)
    {
        var json = new JsonFidoStore(new MemoryStoreFile());
        return new FidoService(store ?? json, (store as IFidoGroupCache) ?? json, _accounts, new RoleCheck(() => _config), () => _config.Fido,
            _events.Add, () => _now, "LAB-PC-07");
    }

    private async Task<FidoCredential> RegisterAsync(FidoService fido, TestAuthenticator key, string account = @"LAB\operator")
    {
        var begin = await fido.BeginRegistrationAsync(Session3, Registrar, account, "Key 1", "New lab operator, badge 17");
        Assert.True(begin.Ok, begin.Problem);
        var (cd, att) = key.Register(Rp, begin.Value!.Challenge);
        var done = await fido.CompleteRegistrationAsync(Session3, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.True(done.Ok, done.Problem);
        return done.Value!;
    }

    private static async Task<FidoResult<AuthOutcome>> UnlockAsync(FidoService fido, AuditClient client, Func<string, FidoAssertion> answer)
    {
        var ch = await fido.ChallengeAsync(client, FidoPurpose.Unlock);
        Assert.True(ch.Ok, ch.Problem);
        return await fido.VerifyAsync(client, FidoPurpose.Unlock, answer(ch.Value!.Challenge));
    }

    // ================= H1: eigenes Konto =================

    [Fact]
    public async Task Microsoft_Registrierende_koennen_nicht_fuer_sich_selbst_registrieren()
    {
        var fido = Service();
        _config.Roles.Registrars = ["S-1-5-21-1-1-1-3099"];
        // Microsoft-Anmeldung: UserId ist die Objekt-ID (GUID), nicht die SID
        var entra = new AuthOutcome
        {
            Success = true, UserName = "entra@contoso.com", UserId = EntraOid, Groups = ["S-1-5-21-1-1-1-3099"],
            Details = new Dictionary<string, string> { ["oid"] = EntraOid },
        };
        var r = await fido.BeginRegistrationAsync(Session3, entra, @"AzureAD\entra@contoso.com", "Key", "Own key for maintenance");
        Assert.Equal(ErrorCodes.FidoSelfRegistration, r.Code);
    }

    [Fact]
    public async Task Hybride_Registrierende_ueber_onprem_sid_und_UPN_erkannt()
    {
        var fido = Service();
        _config.Roles.Registrars = ["S-1-5-21-1-1-1-3099"];
        var hybrid = new AuthOutcome
        {
            Success = true, UserName = "admin@contoso.com", UserId = "99999999-2222-3333-4444-555555555555", Groups = ["S-1-5-21-1-1-1-3099"],
            Details = new Dictionary<string, string> { [EntraClaims.OnPremSidDetail] = AdminSid },
        };
        Assert.Equal(ErrorCodes.FidoSelfRegistration, (await fido.BeginRegistrationAsync(Session3, hybrid, @"LAB\admin", "Key", "Own key for maintenance")).Code);

        // Ohne onprem_sid: der UPN als Rückfall
        var upnOnly = new AuthOutcome
        {
            Success = true, UserName = "admin@contoso.com", UserId = "99999999-2222-3333-4444-555555555555", Groups = ["S-1-5-21-1-1-1-3099"],
        };
        Assert.Equal(ErrorCodes.FidoSelfRegistration, (await fido.BeginRegistrationAsync(Session3, upnOnly, @"LAB\admin", "Key", "Own key for maintenance")).Code);

        // Für eine andere Person geht es
        Assert.True((await fido.BeginRegistrationAsync(Session3, hybrid, @"LAB\operator", "Key", "New lab operator, badge 17")).Ok);
    }

    [Fact]
    public void Registrierende_ohne_SID_werden_abgelehnt()
    {
        var person = new FidoAccount(OperatorSid, @"LAB\operator", null);
        Assert.NotNull(FidoPeople.SelfRegistration(person, new AuthOutcome { Success = true, UserName = "plugin-user" }));
        Assert.Null(FidoPeople.SelfRegistration(person, Registrar));
        var (sids, _) = FidoPeople.Identities(new AuthOutcome { Success = true, UserId = EntraOid });
        Assert.Contains(EntraClaims.SidFromObjectId(EntraOid)!, sids);
    }

    // ================= M1: Aussperren mit gefälschten Antworten =================

    [Fact]
    public async Task Gefaelschte_Antworten_sperren_nur_die_anfragende_Sitzung()
    {
        _config.Fido.MaxFailedAttempts = 3;
        var fido = Service();
        await RegisterAsync(fido, _key);
        // Ein Programm in einer anderen Sitzung kennt die Credential-ID und schickt Unsinn bzw. gelöschte UV-Flags ohne gültige Signatur
        for (int i = 0; i < 3; i++)
        {
            var r = await UnlockAsync(fido, Attacker, ch => _key.Assert(Rp, ch, flags: 0x01, tamperSignature: s => { s[^1] ^= 1; return s; }));
            Assert.Equal(ErrorCodes.FidoAssertionInvalid, r.Code);
        }
        // Die anfragende Sitzung ist gesperrt …
        Assert.Equal(ErrorCodes.FidoBlocked, (await fido.ChallengeAsync(Attacker, FidoPurpose.Unlock)).Code);
        // … Schlüssel und Person nicht
        Assert.True((await UnlockAsync(fido, Session2, ch => _key.Assert(Rp, ch))).Ok);
    }

    [Fact]
    public async Task Fehler_mit_gueltiger_Signatur_zaehlen_gegen_Schluessel_und_Person()
    {
        _config.Fido.MaxFailedAttempts = 2;
        var fido = Service();
        await RegisterAsync(fido, _key);
        // Vom Schlüssel signiert, aber ohne PIN: stammt vom Schlüssel selbst
        for (int i = 0; i < 2; i++)
            Assert.Equal(ErrorCodes.FidoUserVerificationMissing, (await UnlockAsync(fido, Attacker, ch => _key.Assert(Rp, ch, flags: 0x01))).Code);
        Assert.Equal(ErrorCodes.FidoBlocked, (await UnlockAsync(fido, Session2, ch => _key.Assert(Rp, ch))).Code);
    }

    [Fact]
    public async Task Challenges_je_Sitzung_begrenzt()
    {
        var fido = Service();
        await RegisterAsync(fido, _key);
        for (int i = 0; i < FidoService.MaxChallengesPerMinute; i++)
            Assert.True((await fido.ChallengeAsync(Attacker, FidoPurpose.Unlock)).Ok);
        Assert.Equal(ErrorCodes.ServiceTooManyChecks, (await fido.ChallengeAsync(Attacker, FidoPurpose.Unlock)).Code);
        Assert.True((await fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Ok);
        _now += TimeSpan.FromMinutes(1.1);
        Assert.True((await fido.ChallengeAsync(Attacker, FidoPurpose.Unlock)).Ok);
    }

    // ================= L3: RSA-Exponent =================

    [Theory]
    [InlineData(new byte[] { 0x01 })]
    [InlineData(new byte[] { 0x03 })]
    [InlineData(new byte[] { 0x01, 0x00, 0x00, 0x01 })]
    public void RSA_nur_mit_Exponent_65537(byte[] exponent)
    {
        using var rsa = RSA.Create(2048);
        byte[] Cose(byte[] e)
        {
            var w = new CborWriter(CborConformanceMode.Lax);
            w.WriteStartMap(4);
            w.WriteInt32(1); w.WriteInt32(3);
            w.WriteInt32(3); w.WriteInt32(-257);
            w.WriteInt32(-1); w.WriteByteString(rsa.ExportParameters(false).Modulus!);
            w.WriteInt32(-2); w.WriteByteString(e);
            w.WriteEndMap();
            return w.Encode();
        }
        Assert.Throws<NotSupportedException>(() => CoseKey.Parse(Cose(exponent)));
        Assert.Equal(FidoProtocol.AlgRs256, CoseKey.Parse(Cose([0x01, 0x00, 0x01])).Algorithm);
        Assert.Equal(FidoProtocol.AlgRs256, CoseKey.Parse(Cose([0x00, 0x01, 0x00, 0x01])).Algorithm);
    }

    // ================= L4: Höchstzahl bei gleichzeitigen Registrierungen =================

    /// <summary>Ablage, deren Ablegen dauert (Netzwerk, AD) – so überschneiden sich zwei Registrierungen.</summary>
    private sealed class SlowStore(JsonFidoStore inner) : IFidoCredentialStore, IFidoGroupCache
    {
        public Task<FidoCredential?> GetAsync(string idHash, CancellationToken ct = default) => inner.GetAsync(idHash, ct);
        public Task<IReadOnlyList<FidoCredential>> ListAsync(string? personSid = null, CancellationToken ct = default) => inner.ListAsync(personSid, ct);
        public async Task AddAsync(FidoCredential credential, IFidoStoreWriter? writer = null, CancellationToken ct = default)
        {
            await Task.Delay(150, ct);
            await inner.AddAsync(credential, writer, ct);
        }
        public Task<bool> RevokeAsync(string idHash, FidoRevocation revocation, IFidoStoreWriter? writer = null, CancellationToken ct = default) =>
            inner.RevokeAsync(idHash, revocation, writer, ct);
        public Task<bool> TouchAsync(string idHash, uint signCount, DateTimeOffset usedAt, CancellationToken ct = default) =>
            inner.TouchAsync(idHash, signCount, usedAt, ct);
        Task<FidoGroupSnapshot?> IFidoGroupCache.GetAsync(string sid, CancellationToken ct) => ((IFidoGroupCache)inner).GetAsync(sid, ct);
        public Task SetAsync(FidoGroupSnapshot snapshot, CancellationToken ct = default) => inner.SetAsync(snapshot, ct);
    }

    [Fact]
    public async Task Gleichzeitige_Registrierungen_ueberschreiten_die_Hoechstzahl_nicht()
    {
        _config.Fido.MaxKeysPerPerson = 1;
        var inner = new JsonFidoStore(new MemoryStoreFile());
        var fido = Service(new SlowStore(inner));
        using var second = new TestAuthenticator();
        var a = await fido.BeginRegistrationAsync(Session3, Registrar, @"LAB\operator", "Key A", "New lab operator, badge 17");
        var otherAdmin = Session3 with { Session = 4 };
        var b = await fido.BeginRegistrationAsync(otherAdmin, Registrar, @"LAB\operator", "Key B", "New lab operator, badge 17");
        Assert.True(a.Ok && b.Ok);
        var (cda, atta) = _key.Register(Rp, a.Value!.Challenge);
        var (cdb, attb) = second.Register(Rp, b.Value!.Challenge);
        var results = await Task.WhenAll(
            Task.Run(() => fido.CompleteRegistrationAsync(Session3, a.Value.RegistrationId, FidoProtocol.ToBase64Url(cda), FidoProtocol.ToBase64Url(atta))),
            Task.Run(() => fido.CompleteRegistrationAsync(otherAdmin, b.Value.RegistrationId, FidoProtocol.ToBase64Url(cdb), FidoProtocol.ToBase64Url(attb))));
        Assert.Single(results, r => r.Ok);
        Assert.Single(results, r => r.Code == ErrorCodes.FidoTooManyKeys);
        Assert.Single(await inner.ListAsync(OperatorSid));
    }

    // ================= L5: langsamer Domänencontroller =================

    [Fact]
    public async Task Haengende_Aufloesung_haelt_andere_Schluessel_nicht_auf_und_endet_als_offline()
    {
        var fido = Service();
        fido.ResolveTimeout = TimeSpan.FromSeconds(30);
        using var nurseKey = new TestAuthenticator();
        await RegisterAsync(fido, _key);
        await RegisterAsync(fido, nurseKey, @"LAB\nurse");
        var hanging = new TaskCompletionSource<FidoResolution>(TaskCreationOptions.RunContinuationsAsynchronously);
        _accounts.Hanging[OperatorSid] = hanging;

        var slow = UnlockAsync(fido, Session2, ch => _key.Assert(Rp, ch));
        await Task.Delay(50);
        Assert.False(slow.IsCompleted);
        // Ein anderer Schlüssel wird trotzdem sofort geprüft
        var other = UnlockAsync(fido, Attacker, ch => nurseKey.Assert(Rp, ch));
        Assert.Same(other, await Task.WhenAny(other, Task.Delay(TimeSpan.FromSeconds(5))));
        Assert.True((await other).Ok);

        hanging.SetResult(new FidoResolution(FidoAccountState.Ok, @"LAB\operator", ["S-1-5-21-1-1-1-3001"], FidoGroupsSource.Live));
        Assert.True((await slow).Ok);

        // Zeitlimit: Auflösung dauert zu lange → wie ohne Domänencontroller (hier mit Zwischenspeicher von eben)
        fido.ResolveTimeout = TimeSpan.FromMilliseconds(100);
        _accounts.Hanging[OperatorSid] = new TaskCompletionSource<FidoResolution>();
        var late = await UnlockAsync(fido, Session2, ch => _key.Assert(Rp, ch));
        Assert.True(late.Ok, late.Problem);
        Assert.Equal(FidoGroupsSource.Cached, late.Value!.Details["groupsSource"]);
    }

    // ================= L2: Zweck nur bei offenem Dialog =================

    [Fact]
    public void Signatur_und_Registrar_nur_bei_offenem_Dialog()
    {
        var gate = new FidoPurposeGate();
        Assert.True(gate.Allows(FidoPurpose.Unlock));
        Assert.True(gate.Allows(FidoPurpose.Admin));
        Assert.False(gate.Allows(FidoPurpose.Signature));
        Assert.False(gate.Allows(FidoPurpose.Registrar));
        var open = gate.Open(FidoPurpose.Signature);
        Assert.True(gate.Allows(FidoPurpose.Signature));
        Assert.False(gate.Allows(FidoPurpose.Registrar));
        open.Dispose();
        open.Dispose(); // doppelt freigegeben zählt einmal
        Assert.False(gate.Allows(FidoPurpose.Signature));
        using (gate.Open(FidoPurpose.Registrar)) Assert.True(gate.Allows(FidoPurpose.Registrar));
        Assert.False(gate.Allows(FidoPurpose.Registrar));
    }
}
