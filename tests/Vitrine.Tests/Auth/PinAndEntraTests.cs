// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Auth;

public sealed class PinProviderTests
{
    private static Task<AuthOutcome> Try(string? hash, string? secret) =>
        new PinProvider(() => new UnlockSettings { PinHash = hash }).AuthenticateAsync(new AuthRequest { Secret = secret }, CancellationToken.None);

    [Fact]
    public async Task Richtiges_Kennwort_entsperrt_als_gemeinsames_Geheimnis()
    {
        var hash = PinProvider.Hash("geheim-123");
        Assert.StartsWith("pbkdf2-sha256$210000$", hash);
        var ok = await Try(hash, "geheim-123");
        Assert.True(ok.Success);
        Assert.True(UnlockPolicy.IsShared(ok));
        var wrong = await Try(hash, "geheim-124");
        Assert.False(wrong.Success);
        Assert.Equal("VIT-0131", wrong.ErrorCode);
    }

    [Fact]
    public async Task Ohne_Hash_oder_Eingabe_klare_Fehler()
    {
        Assert.Equal("VIT-0130", (await Try(null, "x")).ErrorCode);
        Assert.Equal("VIT-0107", (await Try(PinProvider.Hash("abcdef"), "")).ErrorCode);
        Assert.False(await new PinProvider(() => new UnlockSettings()).IsAvailableAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData("klartext")]
    [InlineData("pbkdf2-sha256$x$AAAA$AAAA")]
    [InlineData("pbkdf2-sha256$210000$kein-base64$AAAA")]
    [InlineData("md5$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAA==")]
    public void Kaputte_Hashes_gelten_als_falsch_statt_abzustuerzen(string stored) =>
        Assert.False(PinProvider.Verify("egal", stored));

    [Fact]
    public void Unsichere_Hashes_aus_einer_praeparierten_Konfiguration_gelten_als_falsch()
    {
        // 1 Runde und ein leerer Schlüssel würden sonst jedes Kennwort bzw. eine sehr schnelle Suche erlauben
        var salt = Convert.ToBase64String(new byte[16]);
        var key = Convert.ToBase64String(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("a", new byte[16], 1, System.Security.Cryptography.HashAlgorithmName.SHA256, 32));
        Assert.False(PinProvider.Verify("a", $"pbkdf2-sha256$1${salt}${key}"));
        Assert.False(PinProvider.Verify("a", $"pbkdf2-sha256$210000${salt}$"));
        Assert.False(PinProvider.Verify("a", $"pbkdf2-sha256$2000000000${salt}${key}"));
    }
}

public sealed class EntraClaimsTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);
    private const string Tenant = "aaaaaaaa-0000-0000-0000-000000000001";

    private static EntraSignIn SignIn(params (string type, string value)[] claims) =>
        new(claims.Select(c => new KeyValuePair<string, string>(c.type, c.value)).ToList(), null, null, null);

    private static (string, string)[] Base(string tid = Tenant, string upn = "jdoe@contoso.com") =>
        [("tid", tid), ("oid", "oid-1"), ("preferred_username", upn), ("name", "J. Doe"),
         ("auth_time", Now.AddSeconds(-30).ToUnixTimeSeconds().ToString())];

    [Fact]
    public void Konfigurierter_Mandant_als_GUID_wird_erzwungen()
    {
        var s = new EntraSettings { TenantId = Tenant };
        Assert.True(EntraClaims.Evaluate(SignIn(Base()), s, null, Now).Success);
        var other = EntraClaims.Evaluate(SignIn(Base(tid: "bbbbbbbb-0000-0000-0000-000000000002")), s, null, Now);
        Assert.False(other.Success);
        Assert.Equal("VIT-0113", other.ErrorCode);
    }

    [Theory]
    [InlineData("organizations")]
    [InlineData("common")]
    [InlineData("contoso.onmicrosoft.com")]
    [InlineData("")]
    public void Ohne_festgelegten_Mandanten_wird_jede_Anmeldung_abgelehnt(string tenantId)
    {
        // Prüfung vom 2026-10-21: „organizations“ ohne AllowedTenants nahm jedes Konto jeder Organisation an
        var s = new EntraSettings { TenantId = tenantId };
        Assert.False(EntraClaims.TenantPinned(s));
        var r = EntraClaims.Evaluate(SignIn(Base()), s, null, Now);
        Assert.False(r.Success);
        Assert.Equal("VIT-0117", r.ErrorCode);
        // Domänen oder Tippfehler in der Liste legen keinen Mandanten fest
        s.AllowedTenants = ["contoso.com", " ", "not-a-guid"];
        Assert.Equal("VIT-0117", EntraClaims.Evaluate(SignIn(Base()), s, null, Now).ErrorCode);
    }

    [Fact]
    public void Organizations_mit_Liste_laesst_nur_die_festgelegten_Mandanten_zu()
    {
        var s = new EntraSettings { TenantId = "organizations", AllowedTenants = [Tenant.ToUpperInvariant(), "{bbbbbbbb-0000-0000-0000-000000000002}"] };
        Assert.True(EntraClaims.TenantPinned(s));
        Assert.True(EntraClaims.Evaluate(SignIn(Base()), s, null, Now).Success);
        Assert.True(EntraClaims.Evaluate(SignIn(Base(tid: "bbbbbbbb-0000-0000-0000-000000000002")), s, null, Now).Success);
        var other = EntraClaims.Evaluate(SignIn(Base(tid: "cccccccc-0000-0000-0000-000000000003")), s, null, Now);
        Assert.Equal("VIT-0113", other.ErrorCode);
    }

    [Fact]
    public void Ohne_tid_bei_eingeschraenkten_Mandanten_abgelehnt()
    {
        var s = new EntraSettings { TenantId = Tenant };
        Assert.False(EntraClaims.Evaluate(SignIn(("oid", "x")), s, null, Now).Success);
    }

    [Fact]
    public void Zu_alte_Anmeldung_wird_abgelehnt()
    {
        var s = new EntraSettings { TenantId = Tenant, MaxAuthAgeSeconds = 300 };
        var old = Base().Where(c => c.Item1 != "auth_time").Append(("auth_time", Now.AddMinutes(-10).ToUnixTimeSeconds().ToString())).ToArray();
        var r = EntraClaims.Evaluate(SignIn(old), s, null, Now);
        Assert.Equal("VIT-0114", r.ErrorCode);
        s.MaxAuthAgeSeconds = 0;
        Assert.True(EntraClaims.Evaluate(SignIn(old), s, null, Now).Success);
    }

    [Fact]
    public void Admin_ueber_App_Rolle_oder_Globaler_Administrator()
    {
        var s = new EntraSettings { TenantId = Tenant };
        Assert.False(EntraClaims.Evaluate(SignIn(Base()), s, null, Now).IsAdministrator);
        Assert.True(EntraClaims.Evaluate(SignIn([.. Base(), ("roles", "Vitrine.Admin")]), s, null, Now).IsAdministrator);
        Assert.True(EntraClaims.Evaluate(SignIn([.. Base(), ("wids", EntraClaims.GlobalAdminRoleTemplate)]), s, null, Now).IsAdministrator);
    }

    [Fact]
    public void Kein_Administrator_ohne_festgelegten_Mandanten_oder_ueber_Gruppennamen()
    {
        var open = new EntraSettings { TenantId = "organizations" };
        Assert.False(EntraClaims.Evaluate(SignIn([.. Base(), ("roles", "Vitrine.Admin")]), open, null, Now).Success);
        Assert.False(EntraClaims.Evaluate(SignIn([.. Base(), ("wids", EntraClaims.GlobalAdminRoleTemplate)]), open, null, Now).Success);
        var pinned = new EntraSettings { TenantId = Tenant };
        Assert.False(EntraClaims.Evaluate(SignIn([.. Base(), ("groups", "Vitrine.Admin")]), pinned, null, Now).IsAdministrator);
        open.AllowedTenants = [Tenant];
        Assert.True(EntraClaims.Evaluate(SignIn([.. Base(), ("roles", "Vitrine.Admin")]), open, null, Now).IsAdministrator);
    }

    [Fact]
    public void Gruppen_und_Rollen_landen_in_Groups()
    {
        var r = EntraClaims.Evaluate(SignIn([.. Base(), ("groups", "g-1"), ("roles", "Vitrine.Unlock")]), new EntraSettings { TenantId = Tenant }, null, Now);
        Assert.Contains("g-1", r.Groups);
        Assert.Contains("vitrine.unlock", r.Groups, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(Tenant, r.Details["tid"]);
    }

    [Fact]
    public void SID_aus_der_Objekt_ID_wie_Windows_sie_bildet()
    {
        // Byte-Reihenfolge wie Guid.ToByteArray (wie in Microsofts Umrechnung per PowerShell und Buffer.BlockCopy)
        Assert.Equal("S-1-12-1-1-2-3-4", EntraClaims.SidFromObjectId("00000001-0002-0000-0300-000004000000"));
        Assert.Equal("S-1-12-1-4294967295-4294967295-4294967295-4294967295", EntraClaims.SidFromObjectId("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        Assert.Null(EntraClaims.SidFromObjectId("oid-1"));
        Assert.Null(EntraClaims.SidFromObjectId(null));
    }

    [Fact]
    public void Sitzungsbenutzer_ueber_unveraenderliche_Kennungen_nicht_den_UPN()
    {
        // Prüfung vom 2026-10-21: preferred_username ist änderbar und nicht eindeutig
        var s = new EntraSettings { TenantId = Tenant };
        const string oid = "00000001-0002-0000-0300-000004000000";
        (string, string)[] entraJoined = [.. Base().Where(c => c.Item1 != "oid"), ("oid", oid)];
        Assert.True(EntraClaims.Evaluate(SignIn(entraJoined), s, "S-1-12-1-1-2-3-4", Now).IsSessionUser);
        Assert.False(EntraClaims.Evaluate(SignIn(entraJoined), s, "S-1-12-1-1-2-3-5", Now).IsSessionUser);

        // Hybrid: onprem_sid (optionaler Claim) gleich der SID der Sitzung
        (string, string)[] hybrid = [.. Base(), ("onprem_sid", "S-1-5-21-1-2-3-1104")];
        Assert.True(EntraClaims.Evaluate(SignIn(hybrid), s, "s-1-5-21-1-2-3-1104", Now).IsSessionUser);
        Assert.False(EntraClaims.Evaluate(SignIn(hybrid), s, "S-1-5-21-1-2-3-1105", Now).IsSessionUser);

        // Gleicher UPN wie die Sitzung reicht nicht mehr
        Assert.False(EntraClaims.Evaluate(SignIn(Base()), s, "jdoe@contoso.com", Now).IsSessionUser);
        Assert.False(EntraClaims.Evaluate(SignIn(Base()), s, null, Now).IsSessionUser);
    }

    [Theory]
    [InlineData("c1", "", false, "c1")]
    [InlineData(" C7 ", "", false, "c7")]
    [InlineData("c1", "c2", true, "c2")]
    [InlineData("c1", "c2", false, "c1")]
    [InlineData("", "c2", false, null)]
    [InlineData("", "c2", true, "c2")]
    [InlineData("x1", "", false, null)]
    [InlineData("c1\"}", "", false, null)]
    [InlineData("c100", "", false, null)]
    public void Authentifizierungskontext(string general, string signature, bool forSignature, string? expected)
    {
        var s = new EntraSettings { AuthenticationContext = general, SignatureAuthenticationContext = signature };
        Assert.Equal(expected, EntraClaims.AuthContextFor(s, forSignature));
    }

    [Theory]
    [InlineData("x1", "", false, "x1")]
    [InlineData("c100", "", false, "c100")]
    [InlineData("c0", "", false, "c0")]
    [InlineData("c1", "C2 ", true, null)]
    [InlineData("c1", "cc", true, "cc")]
    [InlineData("c1", "cc", false, null)]
    [InlineData("", "", true, null)]
    public void Ungueltiger_Kontext_wird_erkannt_statt_still_weggelassen(string general, string signature, bool forSignature, string? invalid)
    {
        // Prüfung vom 2026-10-20: Ein Tippfehler schaltete die Anforderung (z. B. Passkey für Signaturen) still ab
        var s = new EntraSettings { AuthenticationContext = general, SignatureAuthenticationContext = signature };
        Assert.Equal(invalid, EntraClaims.InvalidAuthContext(s, forSignature));
        if (invalid is not null) Assert.Null(EntraClaims.AuthContextFor(s, forSignature));
    }

    [Fact]
    public void Ungueltiger_Kontext_steht_in_den_Meldungen_beim_Laden()
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.File("machine.json"), """{ "Entra": { "SignatureAuthenticationContext": "passkey" } }""");
        var store = new ConfigStore(new ConfigFiles(dir.File("machine.json"), dir.File("old.json"), dir.File("user.json"), dir.File("olduser.json")), []);
        store.Load();
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0116", StringComparison.Ordinal) && e.Contains("passkey", StringComparison.Ordinal));
    }

    [Fact]
    public void Claims_Anfrage_fuer_den_Kontext()
    {
        var json = System.Text.Json.Nodes.JsonNode.Parse(EntraClaims.AuthContextClaims("c1"))!;
        Assert.Equal("c1", json["access_token"]!["acrs"]!["value"]!.GetValue<string>());
        Assert.True(json["access_token"]!["acrs"]!["essential"]!.GetValue<bool>());
    }

    [Fact]
    public void Erfuellter_Kontext_muss_passen_wenn_Entra_ihn_meldet()
    {
        var s = new EntraSettings { TenantId = Tenant };
        Assert.True(EntraClaims.Evaluate(SignIn([.. Base(), ("acrs", "c1")]), s, null, Now, "c1").Success);
        Assert.True(EntraClaims.Evaluate(SignIn(Base()), s, null, Now, "c1").Success); // ohne Claim: Entra setzt durch
        var r = EntraClaims.Evaluate(SignIn([.. Base(), ("acrs", "c2")]), s, null, Now, "c1");
        Assert.False(r.Success);
        Assert.Equal("VIT-0115", r.ErrorCode);
    }

    [Fact]
    public void Verfahren_stehen_im_Protokoll_keine_Token()
    {
        var s = new EntraSettings { TenantId = Tenant };
        var r = EntraClaims.Evaluate(SignIn([.. Base(), ("amr", "fido"), ("amr", "mfa")]), s, null, Now);
        Assert.Equal("fido mfa", r.Details["amr"]);
        Assert.Empty(r.Tokens);
        var withTokens = r.WithTokens(new Dictionary<string, string> { ["id_token"] = "x" });
        Assert.Equal("x", withTokens.Tokens["id_token"]);
        Assert.Equal(r.UserName, withTokens.UserName);
        Assert.DoesNotContain("id_token", withTokens.Details.Keys);
    }
}
