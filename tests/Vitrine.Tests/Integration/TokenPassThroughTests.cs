// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Integration;

namespace Vitrine.Tests.Integration;

/// <summary>
/// Weitergabe der Entra-Anmeldung an Fachanwendungen (docs/interface.md, „Tokens for the application“): Die Token des
/// Anbieters müssen Prüfung, Signatur und Antwort der Schnittstelle überstehen. Bis 2026-10-20 baute die Prüfung das
/// Ergebnis ohne Token neu auf, und idToken/accessToken kamen nie an.
/// </summary>
public sealed class TokenPassThroughTests
{
    private static AuthOutcome FromProvider() => new AuthOutcome
    {
        Success = true,
        UserName = "jdoe@contoso.com",
        DisplayName = "Lab operator",
        UserId = "11111111-2222-3333-4444-555555555555",
        TenantId = "66666666-7777-8888-9999-000000000000",
        Details = new Dictionary<string, string> { ["tid"] = "66666666-7777-8888-9999-000000000000", ["amr"] = "fido" },
    }.WithTokens(new Dictionary<string, string>
    {
        ["id_token"] = "eyJ.id.token",
        ["access_token"] = "eyJ.access.token",
        ["expires_on"] = "2026-10-20T10:00:00.0000000+00:00",
        ["scopes"] = "api://lims/Sign",
    });

    [Fact]
    public void Token_ueberstehen_Pruefung_Signatur_und_Antwort()
    {
        var verified = AuthResults.Verified(FromProvider(), "entra");
        var signed = AuthResults.Signed(verified, "abc123", 42);
        var answer = PipeProtocol.SignatureAnswer(signed, "Release batch 4711", "Approved", new DateTimeOffset(2026, 10, 20, 9, 0, 0, TimeSpan.Zero));

        Assert.Equal("eyJ.id.token", (string?)answer["idToken"]);
        Assert.Equal("eyJ.access.token", (string?)answer["accessToken"]);
        Assert.Equal("2026-10-20T10:00:00.0000000+00:00", (string?)answer["expiresOn"]);
        Assert.Equal("api://lims/Sign", (string?)answer["scopes"]);
        Assert.Equal("entra", (string?)answer["method"]);
        Assert.Equal("42", (string?)answer["auditSeq"]);
        Assert.Equal("abc123", (string?)answer["auditHash"]);
        Assert.Equal("fido", (string?)answer["amr"]);
        Assert.Equal("jdoe@contoso.com", (string?)answer["user"]);
        Assert.Equal("2026-10-20T09:00:00.0000000+00:00", (string?)answer["time"]);
        Assert.True((bool)answer["ok"]!);
    }

    [Fact]
    public void Ohne_Token_enthaelt_die_Antwort_keine_Tokenfelder()
    {
        var plain = new AuthOutcome { Success = true, UserName = @"CONTOSO\jdoe" };
        var answer = PipeProtocol.SignatureAnswer(AuthResults.Signed(AuthResults.Verified(plain, "windows"), "h", 1), "x", null, DateTimeOffset.UnixEpoch);
        foreach (var (_, field) in PipeProtocol.TokenFields) Assert.False(answer.ContainsKey(field), field);
    }

    [Fact]
    public void Token_stehen_nicht_in_den_Angaben_fuers_Protokoll()
    {
        var signed = AuthResults.Signed(AuthResults.Verified(FromProvider(), "entra"), "h", 1);
        Assert.DoesNotContain(signed.Details.Values, v => v.StartsWith("eyJ", StringComparison.Ordinal));
        Assert.DoesNotContain("id_token", signed.Details.Keys);
    }

    [Fact]
    public void Kopie_uebernimmt_jede_Eigenschaft()
    {
        // Kommt in AuthOutcome eine Eigenschaft dazu, muss AuthOutcomeExtensions.Copy sie mitnehmen
        var original = FromProvider();
        var copy = AuthResults.Verified(original, "entra");
        foreach (var prop in typeof(AuthOutcome).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (prop.Name == nameof(AuthOutcome.Details)) continue;
            Assert.Equal(prop.GetValue(original), prop.GetValue(copy));
        }
        Assert.Equal("entra", copy.Details["method"]);
        Assert.Equal("fido", copy.Details["amr"]);
    }
}
