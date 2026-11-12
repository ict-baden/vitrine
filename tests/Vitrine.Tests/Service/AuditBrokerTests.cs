// SPDX-License-Identifier: MIT
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Service;
using Vitrine.Tests.Audit;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Service;

/// <summary>
/// Protokoll-Pipe des Dienstes (#15): Die Sitzungs-App darf Ereignisse melden, aber weder Zeit, Nummer und
/// Sitzungsbenutzer setzen noch Signaturen ohne geprüfte Anmeldung eintragen. Ohne echte Anmeldung (Attrappe statt LogonUser)
/// und ohne Netzwerk (selbst erzeugter Mandantenschlüssel statt der JWKS von Microsoft).
/// </summary>
public sealed class AuditBrokerTests : IDisposable
{
    private const string Tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    private const string ClientId = "11111111-2222-3333-4444-555555555555";

    private sealed class FakeVerifier(RSA tenantKey) : ISignatureVerifier
    {
        public int WindowsCalls;
        public int KeyFetches;
        public bool KeysReachable = true;

        public Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid)
        {
            WindowsCalls++;
            return Task.FromResult(secret == "right"
                ? new AuthOutcome { Success = true, UserName = $"{domain ?? "CONTOSO"}\\{user}", UserId = "S-1-5-21-9-9-9-1105", IsSessionUser = false }
                : AuthOutcome.Fail("wrong", "VIT-0101"));
        }

        public Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh)
        {
            KeyFetches++;
            if (!KeysReachable) return Task.FromResult<string?>(null);
            var p = tenantKey.ExportParameters(false);
            var jwks = new JsonObject
            {
                ["keys"] = new JsonArray(new JsonObject
                {
                    ["kty"] = "RSA", ["kid"] = "k1", ["n"] = Base64Url.EncodeToString(p.Modulus), ["e"] = Base64Url.EncodeToString(p.Exponent),
                }),
            };
            return Task.FromResult<string?>(jwks.ToJsonString());
        }

        public string? ResolveSid(string name) => null;
    }

    private readonly TempDir _dir = new();
    private readonly MemoryKeyStore _keys = new();
    private readonly MemoryAnchorStore _anchors = new();
    private readonly RSA _tenantKey = RSA.Create(2048);
    private readonly FakeVerifier _verifier;
    private readonly AuditBroker _broker;
    private readonly VitrineConfig _config = new();
    private DateTimeOffset _now = new(2026, 10, 19, 8, 0, 0, TimeSpan.Zero);
    private static readonly AuditClient Operator = new(2, @"LAB\operator", "S-1-5-21-1-1-1-1001", 4711);

    public AuditBrokerTests()
    {
        _verifier = new FakeVerifier(_tenantKey);
        _config.Entra.ClientId = ClientId;
        _config.Entra.TenantId = Tenant;
        var log = new SignedAuditLog(() => new AuditSettings { Directory = _dir.Path, EventLog = false }, _keys, _anchors, null, () => _now, "LAB-PC-07");
        _broker = new AuditBroker(log, _verifier, () => _config, () => _now);
    }

    public void Dispose()
    {
        _tenantKey.Dispose();
        _dir.Dispose();
    }

    private List<AuditEntry> Entries() =>
        File.ReadAllLines(Path.Combine(_dir.Path, "audit-2026-10.jsonl")).Select(l => AuditLog.Parse(l)!).ToList();

    private Task<JsonObject> Send(JsonObject req, AuditClient? client = null) => _broker.HandleAsync(client ?? Operator, req.ToJsonString());

    [Fact]
    public async Task Ereignis_der_App_bekommt_Zeit_Nummer_und_Benutzer_vom_Dienst()
    {
        var r = await Send(new JsonObject
        {
            ["op"] = "write", ["id"] = 7, ["event"] = "Unlocked", ["actor"] = "LAB\\operator", ["method"] = "windows",
            // Versuche, Benutzer, Zeit, Nummer und Stufe selbst zu setzen
            ["sessionUser"] = "CONTOSO\\qa-lead", ["time"] = "2020-01-01T00:00:00Z", ["seq"] = 999, ["assurance"] = "verified",
        });
        Assert.True((bool)r["ok"]!);
        Assert.Equal(7, (long)r["id"]!);
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.Unlocked, e.Event);
        Assert.Equal(@"LAB\operator", e.SessionUser);
        Assert.Equal(2, e.Session);
        Assert.Equal(_now, e.Time);
        Assert.Equal(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), e.ClientTime);
        Assert.Equal(AuditAssurance.Client, e.Assurance);
        Assert.Equal((long)r["seq"]!, e.Seq);
        Assert.Equal(2, e.Seq);
    }

    [Fact]
    public async Task Zeit_der_App_nahe_der_Dienstzeit_wird_nicht_extra_vermerkt()
    {
        await Send(new JsonObject { ["op"] = "write", ["event"] = "Locked", ["time"] = _now.AddSeconds(1).ToString("O") });
        Assert.Null(Entries()[^1].ClientTime);
    }

    [Theory]
    [InlineData("SignatureGranted")]
    [InlineData("ServiceStarted")]
    [InlineData("AuditKeyRotated")]
    [InlineData("AuditFormatSwitched")]
    [InlineData("AgentConnected")]
    public async Task Ereignisse_des_Dienstes_darf_die_App_nicht_schreiben(string type)
    {
        var r = await Send(new JsonObject { ["op"] = "write", ["event"] = type, ["actor"] = "CONTOSO\\qa-lead" });
        Assert.False((bool)r["ok"]!);
        Assert.Equal("VIT-0315", (string)r["code"]!);
        var last = Entries()[^1];
        Assert.Equal(AuditEventType.Error, last.Event);
        Assert.StartsWith("VIT-0315", last.Detail);
        Assert.DoesNotContain(Entries(), e => e.Event.ToString() == type && e.Actor == "CONTOSO\\qa-lead");
    }

    [Fact]
    public async Task Unbekanntes_Ereignis_und_kaputtes_JSON_werden_abgelehnt()
    {
        Assert.False((bool)(await Send(new JsonObject { ["op"] = "write", ["event"] = "999" }))["ok"]!);
        Assert.False((bool)(await _broker.HandleAsync(Operator, "{nope"))["ok"]!);
        Assert.False((bool)(await Send(new JsonObject { ["op"] = "delete" }))["ok"]!);
    }

    [Fact]
    public async Task Windows_Kennwort_prueft_der_Dienst_und_die_Signatur_nennt_die_gepruefte_Person()
    {
        var v = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["domain"] = "CONTOSO", ["secret"] = "right" });
        Assert.True((bool)v["ok"]!, v.ToJsonString());
        Assert.Equal(1, _verifier.WindowsCalls);
        Assert.Equal(AuditAssurance.Verified, (string)v["assurance"]!);
        var s = await Send(new JsonObject
        {
            ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "Release batch 4711", ["meaning"] = "Approved",
            // Person im Antrag wird ignoriert: Sie kommt aus dem Ticket
            ["actor"] = "CONTOSO\\someone-else",
        });
        Assert.True((bool)s["ok"]!, s.ToJsonString());
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.SignatureGranted, e.Event);
        Assert.Equal(@"CONTOSO\qa-lead", e.Actor);
        Assert.Equal("windows", e.Method);
        Assert.Equal(AuditAssurance.Verified, e.Assurance);
        Assert.Equal("Release batch 4711 – Approved", e.Detail);
        Assert.Equal(@"LAB\operator", e.SessionUser);
        Assert.Equal(e.Hash, (string)s["hash"]!);

        // Ticket nur einmal
        var again = await Send(new JsonObject { ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "x" });
        Assert.Equal("VIT-0313", (string)again["code"]!);
    }

    [Fact]
    public async Task Signatur_ohne_Ticket_oder_mit_erfundenem_Ticket_gibt_es_nicht()
    {
        var r = await Send(new JsonObject { ["op"] = "sign", ["ticket"] = new string('a', 64), ["reason"] = "x" });
        Assert.Equal("VIT-0313", (string)r["code"]!);
        Assert.DoesNotContain(File.Exists(Path.Combine(_dir.Path, "audit-2026-10.jsonl")) ? Entries() : [], e => e.Event == AuditEventType.SignatureGranted);
    }

    [Fact]
    public async Task Ticket_gilt_nur_in_der_Sitzung_die_es_bekam_und_nur_kurz()
    {
        var v = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "right" });
        var other = new AuditClient(3, @"LAB\other", "S-1-5-21-1-1-1-1002", 99);
        Assert.Equal("VIT-0313", (string)(await Send(new JsonObject { ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "x" }, other))["code"]!);

        var v2 = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "right" });
        _now += AuditBroker.TicketLifetime + TimeSpan.FromSeconds(1);
        Assert.Equal("VIT-0313", (string)(await Send(new JsonObject { ["op"] = "sign", ["ticket"] = (string)v2["ticket"]!, ["reason"] = "x" }))["code"]!);
    }

    [Fact]
    public async Task Fehlgeschlagene_Pruefung_schreibt_der_Dienst_selbst()
    {
        var r = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["domain"] = "CONTOSO", ["secret"] = "wrong" });
        Assert.False((bool)r["ok"]!);
        Assert.True((bool)r["audited"]!);
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.SignatureFailed, e.Event);
        Assert.Equal(@"CONTOSO\qa-lead", e.Actor);
        Assert.Equal("VIT-0101", e.Detail);
    }

    [Fact]
    public async Task Zu_viele_Pruefungen_werden_gebremst()
    {
        for (int i = 0; i < AuditBroker.MaxChecksPerMinute; i++)
            await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "wrong" });
        var r = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "right" });
        Assert.Equal("VIT-0314", (string)r["code"]!);
        Assert.Equal(AuditBroker.MaxChecksPerMinute, _verifier.WindowsCalls);
        _now += TimeSpan.FromMinutes(1.1);
        Assert.True((bool)(await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "right" }))["ok"]!);
    }

    [Fact]
    public async Task Windows_Hello_gilt_nur_fuer_den_Sitzungsbenutzer_und_ist_von_der_App_bezeugt()
    {
        var v = await Send(new JsonObject { ["op"] = "verify", ["method"] = "hello", ["actor"] = "CONTOSO\\qa-lead", ["userId"] = "S-1-5-21-9" });
        Assert.Equal(@"LAB\operator", (string)v["user"]!);
        Assert.Equal(AuditAssurance.Client, (string)v["assurance"]!);
        await Send(new JsonObject { ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "x" });
        var e = Entries()[^1];
        Assert.Equal(@"LAB\operator", e.Actor);
        Assert.Equal(Operator.Sid, e.Data!["userId"]);
        Assert.Equal(AuditAssurance.Client, e.Assurance);
    }

    [Fact]
    public async Task Plugin_ist_von_der_App_bezeugt_und_gemeinsames_Geheimnis_gilt_nicht()
    {
        _config.Unlock.Methods.Add("acme-lims");
        var v = await Send(new JsonObject { ["op"] = "verify", ["method"] = "acme-lims", ["actor"] = "CONTOSO\\qa-lead" });
        Assert.Equal(AuditAssurance.Client, (string)v["assurance"]!);
        var shared = await Send(new JsonObject { ["op"] = "verify", ["method"] = "acme-lims", ["actor"] = "Lab", ["shared"] = "true" });
        Assert.Equal("VIT-0144", (string)shared["code"]!);
        Assert.Equal("VIT-0319", (string)(await Send(new JsonObject { ["op"] = "verify", ["method"] = "pin" }))["code"]!);
    }

    [Theory]
    [InlineData("pin")]
    [InlineData("")]
    [InlineData("made-up-plugin")]
    public async Task Abgelehnte_Verfahren_stehen_als_von_der_App_gemeldet_im_Protokoll(string method)
    {
        // Prüfung vom 2026-10-26: Vorher „verified“ mit der von der App gelieferten Person
        var r = await Send(new JsonObject { ["op"] = "verify", ["method"] = method, ["user"] = "CONTOSO\\qa-lead", ["actor"] = "CONTOSO\\qa-lead" });
        Assert.Equal("VIT-0319", (string)r["code"]!);
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.SignatureFailed, e.Event);
        Assert.Equal(AuditAssurance.Client, e.Assurance);
    }

    [Fact]
    public async Task Hello_nur_wenn_es_unter_den_Verfahren_steht()
    {
        _config.Unlock.Methods = ["windows"];
        Assert.Equal("VIT-0319", (string)(await Send(new JsonObject { ["op"] = "verify", ["method"] = "hello" }))["code"]!);
    }

    [Fact]
    public async Task Gemeinsames_Geheimnis_eines_Plugins_ist_nicht_geprueft()
    {
        _config.Unlock.Methods.Add("acme-lims");
        await Send(new JsonObject { ["op"] = "verify", ["method"] = "acme-lims", ["actor"] = "Lab", ["shared"] = "true" });
        Assert.Equal(AuditAssurance.Client, Entries()[^1].Assurance);
    }

    [Fact]
    public async Task Fehlgeschlagenes_Windows_Kennwort_hat_der_Dienst_geprueft()
    {
        await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "wrong" });
        Assert.Equal(AuditAssurance.Verified, Entries()[^1].Assurance);
    }

    [Fact]
    public async Task Nicht_geschriebener_Eintrag_ist_ein_Fehler_damit_die_App_ihn_behaelt()
    {
        await Send(new JsonObject { ["op"] = "write", ["event"] = "Locked" });
        Directory.Delete(_dir.Path, recursive: true);
        File.WriteAllText(_dir.Path, "x"); // Ordner nicht anlegbar
        try
        {
            var r = await Send(new JsonObject { ["op"] = "write", ["event"] = "Unlocked" });
            Assert.False((bool)r["ok"]!);
            Assert.Equal("VIT-0322", (string)r["code"]!);
        }
        finally
        {
            File.Delete(_dir.Path);
            Directory.CreateDirectory(_dir.Path);
        }
    }

    [Fact]
    public async Task Domaenenliste_gilt_auch_im_Dienst()
    {
        _config.Unlock.AllowedDomains = ["FABRIKAM"];
        var r = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["domain"] = "CONTOSO", ["secret"] = "right" });
        Assert.False((bool)r["ok"]!);
        Assert.Equal("VIT-0141", (string)r["code"]!);
    }

    // ---------------- Microsoft Entra ID ----------------

    /// <summary>Nonce des Dienstes für diese Sitzung (wie die App vor der Microsoft-Anmeldung).</summary>
    private string Challenge(AuditClient? client = null) =>
        (string)_broker.HandleAsync(client ?? Operator, new JsonObject { ["op"] = "challenge" }.ToJsonString()).GetAwaiter().GetResult()["nonce"]!;

    /// <param name="nonce">null = eine frische Nonce des Dienstes; "" = keine im Token.</param>
    private string Token(Action<JsonObject>? change = null, RSA? key = null, string kid = "k1", string? nonce = null)
    {
        nonce ??= Challenge();
        var payload = new JsonObject
        {
            ["iss"] = $"https://login.microsoftonline.com/{Tenant}/v2.0", ["aud"] = ClientId, ["tid"] = Tenant,
            ["oid"] = "0b9e8a7f-1111-2222-3333-444444444444", ["preferred_username"] = "qa-lead@contoso.com", ["name"] = "QA lead",
            ["iat"] = _now.ToUnixTimeSeconds() - 30, ["nbf"] = _now.ToUnixTimeSeconds() - 30, ["exp"] = _now.ToUnixTimeSeconds() + 3600,
            ["auth_time"] = _now.ToUnixTimeSeconds() - 20,
            ["amr"] = new JsonArray("pwd", "mfa"), ["uti"] = Guid.NewGuid().ToString(),
        };
        if (nonce.Length > 0) payload["nonce"] = nonce;
        change?.Invoke(payload);
        var header = new JsonObject { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = kid };
        var signing = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." +
                      Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var sig = (key ?? _tenantKey).SignData(Encoding.ASCII.GetBytes(signing), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signing + "." + Base64Url.EncodeToString(sig);
    }

    private Task<JsonObject> Entra(string token) => Send(new JsonObject { ["op"] = "verify", ["method"] = "entra", ["idToken"] = token });

    [Fact]
    public async Task Entra_Token_mit_gueltiger_Signatur_gilt_als_geprueft()
    {
        var v = await Entra(Token());
        Assert.True((bool)v["ok"]!, v.ToJsonString());
        Assert.Equal("qa-lead@contoso.com", (string)v["user"]!);
        Assert.Equal(AuditAssurance.Verified, (string)v["assurance"]!);
        Assert.Equal("pwd mfa", (string)v["details"]!["amr"]!);
        await Send(new JsonObject { ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "x" });
        var e = Entries()[^1];
        Assert.Equal("qa-lead@contoso.com", e.Actor);
        Assert.Equal("entra", e.Method);
        Assert.Equal(Tenant, e.Data!["tid"]);
    }

    [Fact]
    public async Task Entra_Token_ohne_Nonce_des_Dienstes_wird_abgelehnt()
    {
        // Prüfung vom 2026-10-26: Wer die App steuert, holt mit der Browser-Sitzung einer anderen Person ein frisches Token
        var r = await Entra(Token(nonce: ""));
        Assert.Equal("VIT-0311", (string)r["code"]!);
        Assert.Contains("nonce", (string)r["error"]!);
        Assert.Contains("nonce", (string)(await Entra(Token(nonce: "0123456789abcdef")))["error"]!);
    }

    [Fact]
    public async Task Nonce_gilt_nur_fuer_die_Sitzung_die_sie_bekam_und_nur_einmal()
    {
        var other = new AuditClient(3, @"LAB\other", "S-1-5-21-1-1-1-1002", 99);
        Assert.Contains("nonce", (string)(await Entra(Token(nonce: Challenge(other))))["error"]!);
        var nonce = Challenge();
        Assert.True((bool)(await Entra(Token(nonce: nonce)))["ok"]!);
        Assert.Contains("nonce", (string)(await Entra(Token(nonce: nonce)))["error"]!);
    }

    [Fact]
    public async Task Nonce_laeuft_ab()
    {
        var nonce = Challenge();
        _now += AuditBroker.ChallengeLifetime + TimeSpan.FromSeconds(1);
        Assert.Contains("nonce", (string)(await Entra(Token(nonce: nonce)))["error"]!);
    }

    [Fact]
    public async Task Entra_Token_ohne_auth_time_wird_abgelehnt()
    {
        var r = await Entra(Token(p => p.Remove("auth_time")));
        Assert.Equal("VIT-0320", (string)r["code"]!);
    }

    [Fact]
    public async Task Anmeldung_vor_der_Signaturanfrage_gilt_nicht_mit_ForceFreshSignIn()
    {
        // SSO: frisches Token, aber die Person hat sich vor 10 Minuten angemeldet
        var r = await Entra(Token(p => p["auth_time"] = _now.ToUnixTimeSeconds() - 600));
        Assert.Equal("VIT-0321", (string)r["code"]!);
        // Ohne ForceFreshSignIn gilt nur das Höchstalter
        _config.Entra.ForceFreshSignIn = false;
        _config.Entra.MaxAuthAgeSeconds = 900;
        Assert.True((bool)(await Entra(Token(p => p["auth_time"] = _now.ToUnixTimeSeconds() - 600)))["ok"]!);
        _config.Entra.MaxAuthAgeSeconds = 300;
        Assert.Equal("VIT-0321", (string)(await Entra(Token(p => p["auth_time"] = _now.ToUnixTimeSeconds() - 600)))["code"]!);
    }

    [Fact]
    public async Task Entra_Token_nur_einmal()
    {
        var t = Token();
        Assert.True((bool)(await Entra(t))["ok"]!);
        var again = await Entra(t);
        Assert.Equal("VIT-0311", (string)again["code"]!);
        Assert.Contains("already used", (string)again["error"]!);
    }

    [Theory]
    [InlineData("aud", "audience")]
    [InlineData("iss", "issuer")]
    [InlineData("iat", "not issued just now")]
    [InlineData("exp", "expired")]
    public async Task Entra_Token_mit_falschen_Angaben_wird_abgelehnt(string claim, string problem)
    {
        var t = Token(p =>
        {
            switch (claim)
            {
                case "aud": p["aud"] = "99999999-0000-0000-0000-000000000000"; break;
                case "iss": p["iss"] = "https://sts.example.com/"; break;
                case "iat": p["iat"] = _now.ToUnixTimeSeconds() - 3600; break;
                case "exp": p["exp"] = _now.ToUnixTimeSeconds() - 3600; break;
            }
        });
        var r = await Entra(t);
        Assert.Equal("VIT-0311", (string)r["code"]!);
        Assert.Contains(problem, (string)r["error"]!);
        Assert.Equal(AuditEventType.SignatureFailed, Entries()[^1].Event);
    }

    [Fact]
    public async Task Selbst_signiertes_oder_veraendertes_Entra_Token_wird_abgelehnt()
    {
        using var attacker = RSA.Create(2048);
        Assert.Contains("signature invalid", (string)(await Entra(Token(key: attacker)))["error"]!);
        var parts = Token().Split('.');
        var payload = JsonNode.Parse(Base64Url.DecodeFromChars(parts[1]))!.AsObject();
        payload["preferred_username"] = "ceo@contoso.com";
        var forged = parts[0] + "." + Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString())) + "." + parts[2];
        Assert.Contains("signature invalid", (string)(await Entra(forged))["error"]!);
        // Unbekannter Schlüssel: einmal neu holen, dann ablehnen
        var before = _verifier.KeyFetches;
        Assert.Contains("unknown signing key", (string)(await Entra(Token(kid: "k9")))["error"]!);
        Assert.Equal(before + 2, _verifier.KeyFetches);
    }

    [Fact]
    public async Task Entra_Token_eines_fremden_Mandanten_holt_gar_keine_Schluessel()
    {
        var r = await Entra(Token(p => { p["tid"] = "00000000-1111-2222-3333-444444444444"; }));
        Assert.Equal("VIT-0113", (string)r["code"]!);
        Assert.Equal(0, _verifier.KeyFetches);
    }

    [Fact]
    public async Task Ohne_Schluessel_von_Microsoft_keine_Entra_Signatur()
    {
        _verifier.KeysReachable = false;
        Assert.Equal("VIT-0312", (string)(await Entra(Token()))["code"]!);
    }

    [Fact]
    public async Task Signatur_wird_abgelehnt_wenn_sie_nicht_eingetragen_werden_kann()
    {
        var v = await Send(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = "qa-lead", ["secret"] = "right" });
        // Protokollordner verschwindet und ist nicht anlegbar: Datei statt Ordner
        Directory.Delete(_dir.Path, recursive: true);
        File.WriteAllText(_dir.Path, "x");
        try
        {
            var s = await Send(new JsonObject { ["op"] = "sign", ["ticket"] = (string)v["ticket"]!, ["reason"] = "x" });
            Assert.Equal("VIT-0300", (string)s["code"]!);
        }
        finally
        {
            File.Delete(_dir.Path);
            Directory.CreateDirectory(_dir.Path);
        }
    }

    [Fact]
    public async Task Schluesselwechsel_nur_mit_Administratorrechten()
    {
        await Send(new JsonObject { ["op"] = "write", ["event"] = "Locked" });
        var before = _keys.Current().PublicKey.Id;
        Assert.Equal("VIT-0142", (string)(await Send(new JsonObject { ["op"] = "rotate" }))["code"]!);
        Assert.Equal(before, _keys.Current().PublicKey.Id);
        var r = await Send(new JsonObject { ["op"] = "rotate" }, Operator with { IsAdministrator = true });
        Assert.True((bool)r["ok"]!, r.ToJsonString());
        Assert.NotEqual(before, _keys.Current().PublicKey.Id);
        var e = Entries()[^1];
        Assert.Equal(AuditEventType.AuditKeyRotated, e.Event);
        Assert.Equal(before, e.Key);
    }

    [Fact]
    public void Entra_Claims_werden_wie_bei_MSAL_gelesen()
    {
        var claims = EntraIdToken.Claims(new JsonObject { ["amr"] = new JsonArray("pwd", "mfa"), ["auth_time"] = 1700000000, ["name"] = "x" });
        Assert.Equal(["pwd", "mfa"], claims.Where(c => c.Key == "amr").Select(c => c.Value));
        Assert.Equal("1700000000", claims.Single(c => c.Key == "auth_time").Value);
        Assert.Null(EntraIdToken.Peek("abc"));
    }
}
