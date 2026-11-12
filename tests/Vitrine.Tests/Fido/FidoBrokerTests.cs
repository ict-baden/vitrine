// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Service;
using Vitrine.Tests.Audit;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Fido;

/// <summary>
/// Sicherheitsschlüssel über die Protokoll-Pipe des Dienstes: Registrieren nur mit einem Ticket „registrar“, Signatur
/// mit Stufe „verified“, Tickets nicht zweckfremd einsetzbar, Ereignisse nur vom Dienst.
/// </summary>
public sealed class FidoBrokerTests : IDisposable
{
    private const string OperatorSid = "S-1-5-21-1-1-1-1001";
    private const string AdminSid = "S-1-5-21-1-1-1-500";

    private sealed class Verifier : ISignatureVerifier
    {
        public Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid) =>
            Task.FromResult(secret != "right" ? AuthOutcome.Fail("wrong", "VIT-0101")
                : user == "admin"
                    ? new AuthOutcome { Success = true, UserName = @"LAB\admin", UserId = AdminSid, IsAdministrator = true, Groups = ["S-1-5-32-544"] }
                    : new AuthOutcome { Success = true, UserName = $@"LAB\{user}", UserId = "S-1-5-21-1-1-1-1002" });

        public Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh) => Task.FromResult<string?>(null);
        public string? ResolveSid(string name) => null;
    }

    private readonly TempDir _dir = new();
    private readonly VitrineConfig _config = new();
    private readonly DateTimeOffset _now = new(2026, 10, 30, 8, 0, 0, TimeSpan.Zero);
    private readonly AuditBroker _broker;
    private readonly FakeAccounts _accounts = new();
    private readonly TestAuthenticator _key = new();
    private static readonly AuditClient Admin = new(3, @"LAB\admin", AdminSid, 4712, IsAdministrator: true);
    private static readonly AuditClient Operator = new(2, @"LAB\operator", OperatorSid, 4711);

    public FidoBrokerTests()
    {
        _config.Unlock.Methods = ["windows", "fido"];
        var log = new SignedAuditLog(() => new AuditSettings { Directory = _dir.Path, EventLog = false }, new MemoryKeyStore(), new MemoryAnchorStore(),
            null, () => _now, "LAB-PC-07");
        _broker = new AuditBroker(log, new Verifier(), () => _config, () => _now);
        var store = new JsonFidoStore(new MemoryStoreFile());
        _accounts.Add(@"LAB\operator", OperatorSid, null, "S-1-5-21-1-1-1-3001");
        _broker.Fido = new FidoService(store, store, _accounts, new Vitrine.Core.Auth.RoleCheck(() => _config), () => _config.Fido, _broker.WriteFidoEvent,
            () => _now, "LAB-PC-07");
    }

    public void Dispose()
    {
        _key.Dispose();
        _dir.Dispose();
    }

    private List<AuditEntry> Entries() =>
        File.ReadAllLines(Path.Combine(_dir.Path, "audit-2026-10.jsonl")).Select(l => AuditLog.Parse(l)!).ToList();

    private Task<JsonObject> Send(AuditClient client, JsonObject req) => _broker.HandleAsync(client, req.ToJsonString());

    private async Task<string> RegistrarTicketAsync(AuditClient client, string user = "admin")
    {
        var v = await Send(client, new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "windows", ["user"] = user, ["secret"] = "right" });
        Assert.True((bool)v["ok"]!, v.ToJsonString());
        return (string)v["ticket"]!;
    }

    private async Task RegisterAsync()
    {
        var begin = await Send(Admin, new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = await RegistrarTicketAsync(Admin), ["account"] = @"LAB\operator", ["label"] = "Key 1",
            ["reason"] = "New lab operator, badge 17",
        });
        Assert.True((bool)begin["ok"]!, begin.ToJsonString());
        var (cd, att) = _key.Register((string)begin["rpId"]!, (string)begin["challenge"]!);
        var done = await Send(Admin, new JsonObject
        {
            ["op"] = "fido-register-complete", ["registrationId"] = (string)begin["registrationId"]!,
            ["clientDataJSON"] = FidoProtocol.ToBase64Url(cd), ["attestationObject"] = FidoProtocol.ToBase64Url(att),
        });
        Assert.True((bool)done["ok"]!, done.ToJsonString());
    }

    private static JsonObject AssertionRequest(string op, FidoAssertion a, string? purpose = null) => new()
    {
        ["op"] = op, ["challenge"] = a.Challenge, ["credentialId"] = a.CredentialId, ["authenticatorData"] = a.AuthenticatorData,
        ["clientDataJSON"] = a.ClientDataJson, ["signature"] = a.Signature, ["purpose"] = purpose,
    };

    private async Task<string> ChallengeAsync(AuditClient client, string purpose)
    {
        var c = await Send(client, new JsonObject { ["op"] = "fido-challenge", ["purpose"] = purpose });
        Assert.True((bool)c["ok"]!, c.ToJsonString());
        return (string)c["challenge"]!;
    }

    [Fact]
    public async Task Registrieren_Entsperren_und_Signieren_ueber_die_Pipe()
    {
        await RegisterAsync();
        var reg = Entries().Single(e => e.Event == AuditEventType.FidoKeyRegistered);
        Assert.Equal(AuditAssurance.Verified, reg.Assurance);
        Assert.Equal(@"LAB\admin", reg.Actor);
        Assert.Equal("fido", reg.Method);
        Assert.Equal(OperatorSid, reg.Data!["personSid"]);

        var status = await Send(Operator, new JsonObject { ["op"] = "fido-status" });
        Assert.Equal(1, (int)status["active"]!);
        Assert.Null(status["location"]);
        Assert.False((bool)status["mayList"]!);
        // Liste nur mit Rolle (Registrierende, Einstellungs-Administratoren, Prüfer)
        var refused = await Send(Operator, new JsonObject { ["op"] = "fido-list" });
        Assert.Equal("VIT-0427", (string)refused["code"]!);
        var list = await Send(Admin, new JsonObject { ["op"] = "fido-list" });
        var k = Assert.Single((JsonArray)list["keys"]!)!;
        Assert.Equal("Key 1", (string)k["label"]!);
        Assert.Null(k["publicKey"]);

        // Entsperren: Person mit Gruppen, ohne Ticket
        var ch = await ChallengeAsync(Operator, "unlock");
        var u = await Send(Operator, AssertionRequest("fido-assert", _key.Assert("vitrine", ch)));
        Assert.True((bool)u["ok"]!, u.ToJsonString());
        Assert.Equal(@"LAB\operator", (string)u["user"]!);
        Assert.Contains("S-1-5-21-1-1-1-3001", ((JsonArray)u["groups"]!).Select(g => (string)g!));
        Assert.Null(u["ticket"]);
        Assert.Equal("live", (string)u["details"]!["groupsSource"]!);

        // Signatur: verify mit method fido → Ticket → sign, Stufe verified
        ch = await ChallengeAsync(Operator, "signature");
        var req = AssertionRequest("verify", _key.Assert("vitrine", ch));
        req["method"] = "fido";
        var v = await Send(Operator, req);
        Assert.True((bool)v["ok"]!, v.ToJsonString());
        Assert.Equal(AuditAssurance.Verified, (string)v["assurance"]!);
        var s = await Send(Operator, new JsonObject { ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "Release batch 4711" });
        Assert.True((bool)s["ok"]!, s.ToJsonString());
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.SignatureGranted, e.Event);
        Assert.Equal("fido", e.Method);
        Assert.Equal(AuditAssurance.Verified, e.Assurance);
        Assert.Equal(@"LAB\operator", e.Actor);
        Assert.Equal("Key 1", e.Data!["credential"]);
    }

    [Fact]
    public async Task Ticket_einer_Signatur_registriert_nicht_und_umgekehrt()
    {
        var v = await Send(Admin, new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "admin", ["secret"] = "right" });
        var begin = await Send(Admin, new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = (string)v["ticket"]!, ["account"] = @"LAB\operator", ["label"] = "Key", ["reason"] = "New lab operator, badge 17",
        });
        Assert.Equal("VIT-0313", (string)begin["code"]!);

        var registrar = await RegistrarTicketAsync(Admin);
        var s = await Send(Admin, new JsonObject { ["op"] = "sign", ["ticket"] = registrar, ["reason"] = "Release batch 4711" });
        Assert.Equal("VIT-0313", (string)s["code"]!);
    }

    [Fact]
    public async Task Ticket_gilt_nur_in_der_eigenen_Sitzung()
    {
        var t = await RegistrarTicketAsync(Admin);
        var begin = await Send(Operator, new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = t, ["account"] = @"LAB\operator", ["label"] = "Key", ["reason"] = "New lab operator, badge 17",
        });
        Assert.Equal("VIT-0313", (string)begin["code"]!);
    }

    [Fact]
    public async Task Registrierende_Person_muss_Registrar_sein_und_vom_Dienst_geprueft()
    {
        var v = await Send(Operator, new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "windows", ["user"] = "operator", ["secret"] = "right" });
        Assert.Equal("VIT-0416", (string)v["code"]!);
        Assert.Equal(AuditEventType.UnlockFailed, Entries()[^1].Event);

        // Hello oder Plugin: vom Dienst nicht prüfbar, also nie Registrar
        _config.Unlock.Methods = ["windows", "fido", "hello"];
        var h = await Send(Admin, new JsonObject { ["op"] = "verify", ["purpose"] = "registrar", ["method"] = "hello" });
        Assert.Equal("VIT-0319", (string)h["code"]!);
    }

    [Fact]
    public async Task Ohne_Sicherheitsschluessel_Dienst_VIT_0402()
    {
        var log = new SignedAuditLog(() => new AuditSettings { Directory = _dir.Path, EventLog = false }, new MemoryKeyStore(), new MemoryAnchorStore(),
            null, () => _now, "LAB-PC-07");
        var broker = new AuditBroker(log, new Verifier(), () => _config, () => _now);
        var r = await broker.HandleAsync(Operator, new JsonObject { ["op"] = "fido-challenge", ["purpose"] = "unlock" }.ToJsonString());
        Assert.Equal("VIT-0402", (string)r["code"]!);
    }

    [Fact]
    public async Task Ablehnung_traegt_der_Dienst_ein_und_die_App_nicht_noch_einmal()
    {
        await RegisterAsync();
        var ch = await ChallengeAsync(Operator, "unlock");
        var r = await Send(Operator, AssertionRequest("fido-assert", _key.Assert("vitrine", ch, flags: 0x01)));
        Assert.Equal("VIT-0410", (string)r["code"]!);
        Assert.True((bool)r["audited"]!);
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.FidoKeyRejected, e.Event);
        Assert.Equal(AuditAssurance.Service, e.Assurance);
        Assert.Equal(2, e.Session);
    }

    [Fact]
    public async Task Ereignisse_der_Schluessel_darf_die_App_nicht_schreiben()
    {
        foreach (var type in new[] { "FidoKeyRegistered", "FidoKeyRevoked", "FidoKeyRejected", "FidoCloneSuspected" })
        {
            var r = await Send(Operator, new JsonObject { ["op"] = "write", ["event"] = type });
            Assert.Equal("VIT-0315", (string)r["code"]!);
        }
    }

    [Fact]
    public async Task Liste_fuer_Pruefer_ueber_die_Gruppen_des_Tokens()
    {
        await RegisterAsync();
        _config.Roles.Auditors = ["S-1-5-21-1-1-1-3333"];
        var auditor = Operator with { Groups = ["S-1-5-21-1-1-1-3333"] };
        var list = await Send(auditor, new JsonObject { ["op"] = "fido-list" });
        Assert.True((bool)list["ok"]!, list.ToJsonString());
        Assert.True((bool)(await Send(auditor, new JsonObject { ["op"] = "fido-status" }))["mayList"]!);
        // Nicht erhöht gestartete Administratoren: Mitgliedschaft „nur verweigern“ im Token zählt für das Lesen
        var admin = Operator with { Groups = ["S-1-5-32-544"] };
        Assert.True((bool)(await Send(admin, new JsonObject { ["op"] = "fido-list" }))["ok"]!);
    }

    [Fact]
    public async Task Widerrufen_ueber_die_Pipe()
    {
        await RegisterAsync();
        var keyId = (string)((JsonArray)(await Send(Admin, new JsonObject { ["op"] = "fido-list" }))["keys"]!)[0]!["keyId"]!;
        var r = await Send(Admin, new JsonObject { ["op"] = "fido-revoke", ["ticket"] = await RegistrarTicketAsync(Admin), ["keyId"] = keyId, ["reason"] = "Key lost on 2026-10-29" });
        Assert.True((bool)r["ok"]!, r.ToJsonString());
        Assert.Equal(AuditEventType.FidoKeyRevoked, Entries()[^1].Event);
        var c = await Send(Operator, new JsonObject { ["op"] = "fido-challenge", ["purpose"] = "unlock" });
        Assert.Equal("VIT-0401", (string)c["code"]!);
    }

    [Fact]
    public async Task Unbekannter_Zweck_der_Challenge()
    {
        await RegisterAsync();
        var r = await Send(Operator, new JsonObject { ["op"] = "fido-challenge", ["purpose"] = "1" });
        Assert.False((bool)r["ok"]!);
        r = await Send(Operator, new JsonObject { ["op"] = "fido-challenge", ["purpose"] = "everything" });
        Assert.False((bool)r["ok"]!);
    }
}
