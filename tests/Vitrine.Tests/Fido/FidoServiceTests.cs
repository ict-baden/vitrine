// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Governance;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;

namespace Vitrine.Tests.Fido;

/// <summary>
/// Sicherheitsschlüssel im Dienst: Registrieren (Rollen, eigenes Konto, Höchstzahl, Modelle), Anmelden mit allen
/// Manipulationen (RP ID, Flags, Challenge, Signatur, Zähler, Widerruf, Modell, Ablauf, Wiederholung), Sperre nach
/// Fehlversuchen und Gruppen ohne Domänencontroller. Nachgebauter Schlüssel, keine echten WebAuthn-Aufrufe.
/// </summary>
public sealed class FidoServiceTests : IDisposable
{
    private const string Rp = FidoSettings.DefaultRpId;
    private const string OperatorSid = "S-1-5-21-1-1-1-1001";
    private const string AdminSid = "S-1-5-21-1-1-1-500";
    private const string Admins = "S-1-5-32-544";
    private const string LabGroup = "S-1-5-21-1-1-1-3001";

    private static readonly AuditClient Session2 = new(2, @"LAB\operator", OperatorSid, 4711);
    private static readonly AuditClient AdminClient = new(3, @"LAB\admin", AdminSid, 4712);

    private static readonly AuthOutcome Registrar = new()
    {
        Success = true, UserName = @"LAB\admin", UserId = AdminSid, IsAdministrator = true, Groups = [Admins],
    };

    private readonly MemoryStoreFile _file = new();
    private readonly JsonFidoStore _store;
    private readonly FakeAccounts _accounts = new();
    private readonly VitrineConfig _config = new();
    private FidoSettings _settings => _config.Fido;
    private readonly List<FidoAuditEvent> _events = new();
    private DateTimeOffset _now = new(2026, 10, 30, 8, 0, 0, TimeSpan.Zero);
    private readonly FidoService _fido;
    private readonly TestAuthenticator _key = new();

    public FidoServiceTests()
    {
        _store = new JsonFidoStore(_file);
        _accounts.Add(@"LAB\operator", OperatorSid, "operator@contoso.com", LabGroup, "S-1-5-32-545");
        _accounts.Add(@"LAB\admin", AdminSid, null, Admins);
        _fido = new FidoService(_store, _store, _accounts, new RoleCheck(() => _config), () => _settings, _events.Add, () => _now, "LAB-PC-07");
    }

    public void Dispose() => _key.Dispose();

    private async Task<FidoCredential> RegisterAsync(TestAuthenticator? key = null, string account = @"LAB\operator", string fmt = "packed")
    {
        key ??= _key;
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, account, "Key 1", "New lab operator, badge 17");
        Assert.True(begin.Ok, begin.Problem);
        var (cd, att) = key.Register(Rp, begin.Value!.Challenge, fmt);
        var done = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.True(done.Ok, done.Problem);
        return done.Value!;
    }

    private async Task<FidoResult<AuthOutcome>> UnlockAsync(Func<string, FidoAssertion>? assertion = null, AuditClient? client = null,
        FidoPurpose purpose = FidoPurpose.Unlock)
    {
        var ch = await _fido.ChallengeAsync(client ?? Session2, purpose);
        Assert.True(ch.Ok, ch.Problem);
        return await _fido.VerifyAsync(client ?? Session2, purpose, (assertion ?? (c => _key.Assert(Rp, c)))(ch.Value!.Challenge));
    }

    // ================= Registrieren =================

    [Fact]
    public async Task Registrieren_legt_Schluessel_mit_allen_Angaben_ab_und_protokolliert()
    {
        var c = await RegisterAsync();
        Assert.Equal(FidoProtocol.IdHash(_key.CredentialId), c.IdHash);
        Assert.Equal(OperatorSid, c.PersonSid);
        Assert.Equal(@"LAB\operator", c.PersonName);
        Assert.Equal("operator@contoso.com", c.PersonUpn);
        Assert.Equal(AdminSid, c.RegisteredBySid);
        Assert.Equal("LAB-PC-07", c.RegisteredOn);
        Assert.Equal(TestAuthenticator.DefaultAaguid.ToString("D"), c.Aaguid);
        Assert.Equal("packed", c.AttestationFormat);
        Assert.True(c.AttestationVerified);
        Assert.Equal(FidoProtocol.AlgEs256, c.Algorithm);
        Assert.Equal(Rp, c.RpId);
        Assert.True(c.IsActive);
        var stored = await _store.GetAsync(c.IdHash);
        Assert.NotNull(stored);
        var e = Assert.Single(_events);
        Assert.Equal(AuditEventType.FidoKeyRegistered, e.Type);
        Assert.Equal(AuditAssurance.Verified, e.Assurance);
        Assert.Equal(@"LAB\admin", e.Actor);
        Assert.Equal(c.IdHash, e.Data["keyId"]);
        Assert.Equal(OperatorSid, e.Data["personSid"]);
        // Gruppen von der Registrierung liegen im Zwischenspeicher
        var snap = await ((IFidoGroupCache)_store).GetAsync(OperatorSid);
        Assert.Contains(LabGroup, snap!.Groups);
    }

    [Fact]
    public async Task Attestierung_none_wird_festgehalten_aber_nicht_als_geprueft()
    {
        var c = await RegisterAsync(fmt: "none");
        Assert.Equal("none", c.AttestationFormat);
        Assert.False(c.AttestationVerified);
    }

    [Fact]
    public async Task Packed_mit_falscher_Signatur_wird_abgelehnt()
    {
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17");
        var (cd, att) = _key.Register(Rp, begin.Value!.Challenge, corruptSignature: true);
        var done = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.Equal(ErrorCodes.FidoRegistrationInvalid, done.Code);
        Assert.Contains(_events, e => e.Type == AuditEventType.FidoKeyRejected);
        Assert.Empty(await _store.ListAsync());
    }

    [Theory]
    [InlineData("wrong-challenge", null, (byte)0x45)]
    [InlineData(null, "https://vitrine", (byte)0x45)]
    [InlineData(null, null, (byte)0x41)] // ohne UV (keine PIN)
    public async Task Registrierung_mit_falschen_Daten_wird_abgelehnt(string? challenge, string? origin, byte flags)
    {
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17");
        var (cd, att) = _key.Register(Rp, challenge ?? begin.Value!.Challenge, flags: flags, origin: origin);
        var done = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value!.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.False(done.Ok);
        Assert.Empty(await _store.ListAsync());
    }

    [Fact]
    public async Task Registrierung_gilt_nur_einmal_und_nur_in_derselben_Sitzung()
    {
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17");
        var (cd, att) = _key.Register(Rp, begin.Value!.Challenge);
        var other = await _fido.CompleteRegistrationAsync(Session2, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.Equal(ErrorCodes.FidoRegistrationExpired, other.Code);
        // Nach dem Fehlversuch ist sie verbraucht
        var again = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.Equal(ErrorCodes.FidoRegistrationExpired, again.Code);
    }

    [Fact]
    public async Task Registrierung_laeuft_nach_fuenf_Minuten_ab()
    {
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17");
        _now += TimeSpan.FromMinutes(6);
        var (cd, att) = _key.Register(Rp, begin.Value!.Challenge);
        var done = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.Equal(ErrorCodes.FidoRegistrationExpired, done.Code);
    }

    [Fact]
    public async Task Nur_Registrierende_duerfen_registrieren()
    {
        var notAdmin = new AuthOutcome { Success = true, UserName = @"LAB\operator", UserId = OperatorSid, Groups = [LabGroup] };
        var r = await _fido.BeginRegistrationAsync(Session2, notAdmin, @"LAB\admin", "Key", "Replacement for broken key");
        Assert.Equal(ErrorCodes.FidoNotRegistrar, r.Code);
        Assert.Equal(AuditEventType.FidoKeyRejected, Assert.Single(_events).Type);
    }

    [Fact]
    public async Task Eigenes_Konto_nur_mit_Fido_AllowSelfRegistration()
    {
        var r = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\admin", "Key", "Own key for maintenance");
        Assert.Equal(ErrorCodes.FidoSelfRegistration, r.Code);
        _settings.AllowSelfRegistration = true;
        Assert.True((await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\admin", "Key", "Own key for maintenance")).Ok);
    }

    [Theory]
    [InlineData("", "New lab operator, badge 17")]
    [InlineData("Key", "short")]
    [InlineData("Key", "         ")]
    public async Task Bezeichnung_und_Begruendung_sind_Pflicht(string label, string reason)
    {
        var r = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", label, reason);
        Assert.Equal(ErrorCodes.FidoReasonTooShort, r.Code);
    }

    [Fact]
    public async Task Unbekanntes_oder_gesperrtes_Konto_wird_nicht_registriert()
    {
        Assert.Equal(ErrorCodes.FidoAccountNotFound, (await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\nobody", "Key", "New lab operator, badge 17")).Code);
        _accounts.State[OperatorSid] = FidoResolution.Failed(FidoAccountState.Disabled, "1331");
        Assert.Equal(ErrorCodes.FidoAccountUnusable, (await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17")).Code);
    }

    [Fact]
    public async Task Hoechstzahl_je_Person()
    {
        _settings.MaxKeysPerPerson = 1;
        await RegisterAsync();
        var r = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key 2", "Second key for night shift");
        Assert.Equal(ErrorCodes.FidoTooManyKeys, r.Code);
    }

    [Fact]
    public async Task Ausschlussliste_enthaelt_alle_Schluessel_und_doppelte_Registrierung_wird_abgelehnt()
    {
        await RegisterAsync();
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Again", "Second key for night shift");
        Assert.Contains(_key.CredentialIdB64, begin.Value!.ExcludeCredentials);
        var (cd, att) = _key.Register(Rp, begin.Value.Challenge);
        var done = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.Equal(ErrorCodes.FidoKeyAlreadyRegistered, done.Code);
    }

    [Fact]
    public async Task Modell_nicht_in_der_Liste_wird_nicht_registriert()
    {
        _settings.AllowedModels = ["00000000-0000-0000-0000-000000000001"];
        var begin = await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17");
        var (cd, att) = _key.Register(Rp, begin.Value!.Challenge);
        var done = await _fido.CompleteRegistrationAsync(AdminClient, begin.Value.RegistrationId, FidoProtocol.ToBase64Url(cd), FidoProtocol.ToBase64Url(att));
        Assert.Equal(ErrorCodes.FidoModelNotAllowed, done.Code);
        _settings.AllowedModels = [TestAuthenticator.DefaultAaguid.ToString("B").ToUpperInvariant()]; // Schreibweise egal
        await RegisterAsync();
    }

    // ================= Anmelden =================

    [Fact]
    public async Task Entsperren_liefert_Person_Gruppen_und_Angaben_fuers_Protokoll()
    {
        var c = await RegisterAsync();
        _events.Clear();
        var r = await UnlockAsync();
        Assert.True(r.Ok, r.Problem);
        var who = r.Value!;
        Assert.Equal(@"LAB\operator", who.UserName);
        Assert.Equal("operator", who.DisplayName);
        Assert.Equal(OperatorSid, who.UserId);
        Assert.Contains(LabGroup, who.Groups);
        Assert.False(who.IsAdministrator);
        Assert.True(who.IsSessionUser);
        Assert.Equal("fido", who.Details["method"]);
        Assert.Equal(c.IdHash, who.Details["keyId"]);
        Assert.Equal("Key 1", who.Details["credential"]);
        Assert.Equal(c.Aaguid, who.Details["aaguid"]);
        Assert.Equal(FidoGroupsSource.Live, who.Details["groupsSource"]);
        Assert.Empty(_events);
        Assert.Equal(1u, (await _store.GetAsync(c.IdHash))!.SignCount);
        Assert.Equal(_now, (await _store.GetAsync(c.IdHash))!.LastUsedAt);
    }

    [Fact]
    public async Task Administrator_ueber_die_Gruppe_und_andere_Person_als_der_Sitzungsbenutzer()
    {
        _settings.AllowSelfRegistration = true;
        await RegisterAsync(account: @"LAB\admin");
        var r = await UnlockAsync();
        Assert.True(r.Value!.IsAdministrator);
        Assert.False(r.Value.IsSessionUser);
    }

    [Fact]
    public async Task Keine_Challenge_ohne_registrierte_Schluessel()
    {
        var ch = await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock);
        Assert.Equal(ErrorCodes.FidoNoKeys, ch.Code);
    }

    public static TheoryData<string, string> Manipulationen => new()
    {
        { "rpIdHash", ErrorCodes.FidoAssertionInvalid },
        { "ohne UV", ErrorCodes.FidoUserVerificationMissing },
        { "ohne UP", ErrorCodes.FidoUserVerificationMissing },
        { "Challenge im clientData", ErrorCodes.FidoAssertionInvalid },
        { "Typ create", ErrorCodes.FidoAssertionInvalid },
        { "Signatur", ErrorCodes.FidoAssertionInvalid },
        { "fremder Schlüssel signiert", ErrorCodes.FidoAssertionInvalid },
    };

    [Theory]
    [MemberData(nameof(Manipulationen))]
    public async Task Manipulierte_Antwort_wird_abgelehnt(string what, string code)
    {
        var c = await RegisterAsync();
        _events.Clear();
        using var other = new TestAuthenticator();
        var r = await UnlockAsync(ch => what switch
        {
            "rpIdHash" => _key.Assert(Rp, ch, authRpId: "contoso.com"),
            "ohne UV" => _key.Assert(Rp, ch, flags: 0x01),
            "ohne UP" => _key.Assert(Rp, ch, flags: 0x04),
            "Challenge im clientData" => _key.Assert(Rp, ch, clientChallenge: FidoProtocol.NewChallenge()),
            "Typ create" => _key.Assert(Rp, ch, type: FidoProtocol.TypeCreate),
            "Signatur" => _key.Assert(Rp, ch, tamperSignature: s => { s[^1] ^= 1; return s; }),
            _ => other.Assert(Rp, ch) with { CredentialId = _key.CredentialIdB64 },
        });
        Assert.Equal(code, r.Code);
        var e = Assert.Single(_events);
        Assert.Equal(AuditEventType.FidoKeyRejected, e.Type);
        Assert.Equal(c.IdHash, e.Data["keyId"]);
        Assert.Equal(code, e.Data["code"]);
        Assert.Equal(0u, (await _store.GetAsync(c.IdHash))!.SignCount);
    }

    [Fact]
    public async Task Zaehler_nicht_gestiegen_heisst_moeglicher_Klon()
    {
        var c = await RegisterAsync();
        Assert.True((await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 10))).Ok);
        _events.Clear();
        var r = await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 10));
        Assert.Equal(ErrorCodes.FidoCloneSuspected, r.Code);
        Assert.Equal(AuditEventType.FidoCloneSuspected, Assert.Single(_events).Type);
        Assert.Equal(ErrorCodes.FidoCloneSuspected, (await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 3))).Code);
        Assert.Equal(ErrorCodes.FidoCloneSuspected, (await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 0))).Code);
        Assert.Equal(10u, (await _store.GetAsync(c.IdHash))!.SignCount);
        Assert.True((await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 11))).Ok);
    }

    [Fact]
    public async Task Schluessel_ohne_Zaehler_melden_immer_null()
    {
        await RegisterAsync();
        Assert.True((await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 0))).Ok);
        Assert.True((await UnlockAsync(ch => _key.Assert(Rp, ch, counter: 0))).Ok);
    }

    [Fact]
    public async Task Widerrufener_Schluessel_wird_abgelehnt_und_steht_nicht_in_der_Challenge()
    {
        var c = await RegisterAsync();
        var revoked = await _fido.RevokeAsync(AdminClient, Registrar, c.IdHash, "Key lost on 2026-10-29");
        Assert.True(revoked.Ok);
        var e = _events[^1];
        Assert.Equal(AuditEventType.FidoKeyRevoked, e.Type);
        Assert.Equal("Key lost on 2026-10-29", e.Data["reason"]);
        var stored = await _store.GetAsync(c.IdHash);
        Assert.Equal(FidoCredentialStatus.Revoked, stored!.Status);
        Assert.Equal(AdminSid, stored.RevokedBySid);
        Assert.Equal(ErrorCodes.FidoNoKeys, (await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Code);

        // Ein zweiter (aktiver) Schlüssel sorgt für eine Challenge; der widerrufene wird trotzdem abgelehnt
        using var second = new TestAuthenticator();
        await RegisterAsync(second);
        var r = await UnlockAsync();
        Assert.Equal(ErrorCodes.FidoKeyRevoked, r.Code);
        Assert.Equal(ErrorCodes.FidoKeyRevoked, (await _fido.RevokeAsync(AdminClient, Registrar, c.IdHash, "Key lost on 2026-10-29")).Code);
    }

    [Fact]
    public async Task Widerrufen_nur_durch_Registrierende_mit_Begruendung()
    {
        var c = await RegisterAsync();
        var notAdmin = new AuthOutcome { Success = true, UserName = @"LAB\operator", UserId = OperatorSid };
        Assert.Equal(ErrorCodes.FidoNotRegistrar, (await _fido.RevokeAsync(Session2, notAdmin, c.IdHash, "Key lost on 2026-10-29")).Code);
        Assert.Equal(ErrorCodes.FidoReasonTooShort, (await _fido.RevokeAsync(AdminClient, Registrar, c.IdHash, "lost")).Code);
        Assert.Equal(ErrorCodes.FidoKeyUnknown, (await _fido.RevokeAsync(AdminClient, Registrar, "00", "Key lost on 2026-10-29")).Code);
    }

    [Fact]
    public async Task Modell_spaeter_nicht_mehr_zugelassen()
    {
        await RegisterAsync();
        _settings.AllowedModels = ["00000000-0000-0000-0000-000000000001"];
        Assert.Equal(ErrorCodes.FidoModelNotAllowed, (await UnlockAsync()).Code);
        _settings.AllowedModels = ["kein-guid"]; // nur ungültige Einträge: nichts zugelassen
        Assert.Equal(ErrorCodes.FidoModelNotAllowed, (await UnlockAsync()).Code);
    }

    [Fact]
    public async Task Challenge_laeuft_ab_gilt_einmal_und_nur_fuer_Sitzung_und_Zweck()
    {
        await RegisterAsync();
        var ch = (await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Value!.Challenge;
        _now += TimeSpan.FromMinutes(3);
        Assert.Equal(ErrorCodes.FidoChallengeInvalid, (await _fido.VerifyAsync(Session2, FidoPurpose.Unlock, _key.Assert(Rp, ch))).Code);

        // Wiederholung derselben Antwort
        ch = (await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Value!.Challenge;
        var a = _key.Assert(Rp, ch);
        Assert.True((await _fido.VerifyAsync(Session2, FidoPurpose.Unlock, a)).Ok);
        Assert.Equal(ErrorCodes.FidoChallengeInvalid, (await _fido.VerifyAsync(Session2, FidoPurpose.Unlock, a)).Code);

        // Andere Sitzung, anderer Zweck
        ch = (await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Value!.Challenge;
        Assert.Equal(ErrorCodes.FidoChallengeInvalid, (await _fido.VerifyAsync(AdminClient, FidoPurpose.Unlock, _key.Assert(Rp, ch))).Code);
        ch = (await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Value!.Challenge;
        Assert.Equal(ErrorCodes.FidoChallengeInvalid, (await _fido.VerifyAsync(Session2, FidoPurpose.Signature, _key.Assert(Rp, ch))).Code);
    }

    [Fact]
    public async Task Unbekannter_Schluessel_und_unvollstaendige_Antwort()
    {
        await RegisterAsync();
        using var stranger = new TestAuthenticator();
        Assert.Equal(ErrorCodes.FidoKeyUnknown, (await UnlockAsync(ch => stranger.Assert(Rp, ch))).Code);
        Assert.Equal(ErrorCodes.FidoAssertionInvalid, (await UnlockAsync(ch => _key.Assert(Rp, ch) with { Signature = "" })).Code);
    }

    [Fact]
    public async Task Andere_RP_ID_nach_der_Registrierung_gilt_nicht()
    {
        await RegisterAsync();
        _settings.RpId = "lab.contoso.com";
        Assert.Equal(ErrorCodes.FidoNoKeys, (await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock)).Code);
        var status = await _fido.StatusAsync();
        Assert.Equal(0, status.Active);
        Assert.Equal(1, status.OtherRpId);
    }

    [Fact]
    public async Task Sperre_nach_Fehlversuchen_und_wieder_frei_nach_der_Wartezeit()
    {
        _settings.MaxFailedAttempts = 3;
        _settings.BlockMinutes = 5;
        await RegisterAsync();
        for (int i = 0; i < 3; i++)
            Assert.Equal(ErrorCodes.FidoAssertionInvalid, (await UnlockAsync(ch => _key.Assert(Rp, ch, tamperSignature: s => { s[^1] ^= 1; return s; }))).Code);
        // Ungültige Signaturen sperren die anfragende Sitzung (nicht Schlüssel und Person): keine Challenge mehr
        var blocked = await _fido.ChallengeAsync(Session2, FidoPurpose.Unlock);
        Assert.Equal(ErrorCodes.FidoBlocked, blocked.Code);
        Assert.Equal("5", blocked.Problem);
        _now += TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1);
        Assert.True((await UnlockAsync()).Ok);
    }

    [Fact]
    public async Task Sperre_gilt_auch_fuer_den_zweiten_Schluessel_der_Person()
    {
        _settings.MaxFailedAttempts = 2;
        await RegisterAsync();
        using var second = new TestAuthenticator();
        await RegisterAsync(second);
        for (int i = 0; i < 2; i++)
            await UnlockAsync(ch => _key.Assert(Rp, ch, flags: 0x01));
        Assert.Equal(ErrorCodes.FidoBlocked, (await UnlockAsync(ch => second.Assert(Rp, ch))).Code);
    }

    [Fact]
    public async Task Erfolg_setzt_die_Zaehlung_zurueck()
    {
        _settings.MaxFailedAttempts = 2;
        await RegisterAsync();
        await UnlockAsync(ch => _key.Assert(Rp, ch, flags: 0x01));
        Assert.True((await UnlockAsync()).Ok);
        await UnlockAsync(ch => _key.Assert(Rp, ch, flags: 0x01));
        Assert.True((await UnlockAsync()).Ok);
    }

    // ================= Gruppen ohne Domänencontroller =================

    [Fact]
    public async Task Ohne_Domaenencontroller_gelten_frische_Gruppen_aus_dem_Zwischenspeicher()
    {
        await RegisterAsync();
        _accounts.State[OperatorSid] = FidoResolution.Failed(FidoAccountState.Offline, "1311");
        _now += TimeSpan.FromHours(23);
        var r = await UnlockAsync();
        Assert.True(r.Ok, r.Problem);
        Assert.Equal(FidoGroupsSource.Cached, r.Value!.Details["groupsSource"]);
        Assert.Contains(LabGroup, r.Value.Groups);
        Assert.True(r.Value.Details.ContainsKey("groupsResolvedAt"));

        _now += TimeSpan.FromHours(2); // jetzt 25 h alt
        var old = await UnlockAsync();
        Assert.Equal(ErrorCodes.FidoOfflineTooLong, old.Code);
        Assert.Equal(AuditEventType.FidoKeyRejected, _events[^1].Type);
    }

    [Fact]
    public async Task Gelungene_Aufloesung_erneuert_den_Zwischenspeicher()
    {
        await RegisterAsync();
        _now += TimeSpan.FromHours(20);
        Assert.True((await UnlockAsync()).Ok); // live: Zeitpunkt jetzt
        _accounts.State[OperatorSid] = FidoResolution.Failed(FidoAccountState.Offline, "1311");
        _now += TimeSpan.FromHours(20);
        Assert.True((await UnlockAsync()).Ok);
    }

    [Fact]
    public async Task Ohne_Zwischenspeicher_und_ohne_Domaenencontroller_abgelehnt()
    {
        _accounts.State[OperatorSid] = FidoResolution.Failed(FidoAccountState.Offline, "1311");
        await RegisterAsync(); // registriert, aber ohne Gruppen
        Assert.Equal(ErrorCodes.FidoOfflineTooLong, (await UnlockAsync()).Code);
    }

    [Theory]
    [InlineData(FidoAccountState.Disabled)]
    [InlineData(FidoAccountState.LockedOut)]
    [InlineData(FidoAccountState.Expired)]
    [InlineData(FidoAccountState.NotFound)]
    public async Task Deaktiviertes_gesperrtes_oder_abgelaufenes_Konto_wird_abgelehnt(FidoAccountState state)
    {
        await RegisterAsync();
        _accounts.State[OperatorSid] = FidoResolution.Failed(state, "test");
        var r = await UnlockAsync();
        Assert.Equal(ErrorCodes.FidoAccountUnusable, r.Code);
        Assert.Contains(state.ToString().ToLowerInvariant(), r.Problem);
    }

    [Fact]
    public void Zwischenspeicher_Alter_genau_an_der_Grenze()
    {
        var now = DateTimeOffset.UtcNow;
        var offline = FidoResolution.Failed(FidoAccountState.Offline, null);
        var snap = new FidoGroupSnapshot { Sid = OperatorSid, Groups = [LabGroup], ResolvedAt = now - TimeSpan.FromHours(24) };
        Assert.True(FidoPeople.Decide(offline, snap, now, 24).Allowed);
        snap.ResolvedAt = now - TimeSpan.FromHours(24) - TimeSpan.FromSeconds(1);
        Assert.False(FidoPeople.Decide(offline, snap, now, 24).Allowed);
        Assert.False(FidoPeople.Decide(offline, new FidoGroupSnapshot { ResolvedAt = now }, now, 0).Allowed); // 0 = nie offline
        // Zeitpunkt in der Zukunft (Uhr verstellt): nicht vertrauen
        Assert.False(FidoPeople.Decide(offline, new FidoGroupSnapshot { ResolvedAt = now + TimeSpan.FromHours(5) }, now, 24).Allowed);
    }

    [Theory]
    [InlineData(1331, FidoAccountState.Disabled)]
    [InlineData(1909, FidoAccountState.LockedOut)]
    [InlineData(1793, FidoAccountState.Expired)]
    [InlineData(1330, FidoAccountState.Expired)]
    [InlineData(1317, FidoAccountState.NotFound)]
    [InlineData(1311, FidoAccountState.Offline)]
    [InlineData(1355, FidoAccountState.Offline)]
    [InlineData(1722, FidoAccountState.Offline)]
    [InlineData(5, FidoAccountState.Restricted)]
    public void Windows_Fehler_der_S4U_Anmeldung(int error, FidoAccountState state) =>
        Assert.Equal(state, FidoPeople.StateForWin32Error(error));

    [Fact]
    public void Entra_Konten_erkennt_man_an_der_SID()
    {
        Assert.True(FidoPeople.IsEntraOnly("S-1-12-1-1234-5678-9012-3456"));
        Assert.False(FidoPeople.IsEntraOnly(OperatorSid));
        Assert.False(FidoPeople.IsEntraOnly(null));
    }

    [Fact]
    public async Task Registrierende_kommen_aus_der_Rollenpruefung_Roles_Registrars()
    {
        // Ohne Rollengruppe: lokale Administratoren (Security.LocalAdministratorsArePrivileged, Standard)
        var operatorRegistrar = new AuthOutcome { Success = true, UserName = @"LAB\operator2", UserId = "S-1-5-21-1-1-1-1002", Groups = [LabGroup] };
        Assert.Equal(ErrorCodes.FidoNotRegistrar, (await _fido.BeginRegistrationAsync(Session2, operatorRegistrar, @"LAB\admin", "Key", "New lab operator, badge 17")).Code);
        // Mitglied von Roles.Registrars darf registrieren
        _config.Roles.Registrars = [LabGroup];
        Assert.True((await _fido.BeginRegistrationAsync(Session2, operatorRegistrar, @"LAB\admin", "Key", "New lab operator, badge 17")).Ok);
        // Administratoren ohne Vorrecht: nur noch über die Rollengruppe
        _config.Security.LocalAdministratorsArePrivileged = false;
        Assert.Equal(ErrorCodes.FidoNotRegistrar, (await _fido.BeginRegistrationAsync(AdminClient, Registrar, @"LAB\operator", "Key", "New lab operator, badge 17")).Code);
    }

    [Fact]
    public async Task Entsperren_mit_Schluessel_wechselt_die_verantwortliche_Person()
    {
        _settings.AllowSelfRegistration = true;
        await RegisterAsync();                         // Schlüssel des Sitzungsbenutzers (operator)
        using var adminKey = new TestAuthenticator();
        await RegisterAsync(adminKey, @"LAB\admin");
        var t = new ResponsibilityTracker();
        t.Begin(@"LAB\operator", OperatorSid, "operator", _now);

        var own = (await UnlockAsync()).Value!;
        Assert.Null(t.Unlocked(AuthResults.Verified(own, "fido"), "fido", _now));

        var other = (await UnlockAsync(ch => adminKey.Assert(Rp, ch))).Value!;
        var change = t.Unlocked(AuthResults.Verified(other, "fido"), "fido", _now);
        Assert.NotNull(change);
        Assert.Equal(@"LAB\admin", change!.To.UserName);
        Assert.Equal("fido", change.To.Method);
        Assert.Equal(AdminSid, t.Current!.Key);
    }
}
