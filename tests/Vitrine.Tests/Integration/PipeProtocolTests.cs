// SPDX-License-Identifier: MIT
using Vitrine.Core.About;
using Vitrine.Core.Integration;

namespace Vitrine.Tests.Integration;

public sealed class PipeProtocolTests
{
    [Fact]
    public void Gueltige_Befehle()
    {
        Assert.True(PipeProtocol.Parse("""{"cmd":"status"}""").IsValid);
        Assert.Equal("lock", PipeProtocol.Parse("""{"cmd":" LOCK ","trigger":"MES"}""").Command);
        var sign = PipeProtocol.Parse("""{"cmd":"authenticate","reason":"Release batch 4711","meaning":"Approved","requester":"LIMS"}""");
        Assert.True(sign.IsValid);
        Assert.Equal("Release batch 4711", sign.Reason);
        Assert.Equal("LIMS", sign.Requester);
    }

    [Theory]
    [InlineData("{ kaputt", "VIT-0201")]
    [InlineData("[1,2]", "VIT-0202")]
    [InlineData("\"lock\"", "VIT-0202")]
    [InlineData("""{"cmd":5}""", "VIT-0204")]
    [InlineData("""{"cmd":"format-c"}""", "VIT-0204")]
    [InlineData("""{}""", "VIT-0204")]
    [InlineData("""{"cmd":"sign"}""", "VIT-0203")]
    [InlineData("""{"cmd":"authenticate","reason":"  "}""", "VIT-0203")]
    [InlineData("""{"cmd":"authenticate","reason":{"x":1}}""", "VIT-0203")]
    public void Fehler_mit_Code(string line, string code)
    {
        var r = PipeProtocol.Parse(line);
        Assert.False(r.IsValid);
        Assert.Equal(code, r.ErrorCode);
        Assert.Equal(code, PipeProtocol.Error(r.ErrorCode!, r.Error!)["code"]!.GetValue<string>());
    }

    [Fact]
    public void Zu_lange_Felder_werden_abgelehnt()
    {
        var reason = new string('x', PipeProtocol.MaxFieldLength + 1);
        Assert.Equal("VIT-0208", PipeProtocol.Parse($$"""{"cmd":"sign","reason":"{{reason}}"}""").ErrorCode);
    }

    [Fact]
    public void Steuerzeichen_werden_entfernt()
    {
        var r = PipeProtocol.Parse("""{"cmd":"sign","reason":"Batch\n4711\u001b[2J","requester":"\tLIMS"}""");
        Assert.Equal("Batch 4711 [2J", r.Reason);
        Assert.Equal("LIMS", r.Requester);
    }

    [Fact]
    public async Task Zeilen_mit_Laengengrenze()
    {
        var reader = new BoundedLineReader(new StringReader("eins\r\nzwei\ndrei"), 10);
        Assert.Equal("eins", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("zwei", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("drei", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));

        var tooLong = new BoundedLineReader(new StringReader(new string('a', 11) + "\n"), 10);
        await Assert.ThrowsAsync<LineTooLongException>(() => tooLong.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public void Namen_nach_Richtlinie_12()
    {
        Assert.Equal("ICT-Baden.Vitrine.3", AppPaths.PipeName(3));
        Assert.Equal(@"Local\ICT-Baden.Vitrine.SingleInstance", AppPaths.SingleInstanceMutex);
        Assert.Equal(@"SOFTWARE\Policies\ICT-Baden\Vitrine", AppPaths.PolicyKey);
        Assert.Equal(@"SOFTWARE\Policies\Vitrine", AppPaths.LegacyPolicyKey);
        Assert.Equal("ICT-Baden Vitrine", AppPaths.EventSource);
    }
}

public sealed class PipeScopeTests
{
    [Fact]
    public void Scopes_als_Liste_oder_Text()
    {
        Assert.Equal(["api://lims/Sign", "openid"], PipeProtocol.Parse("""{"cmd":"sign","reason":"x","scopes":["api://lims/Sign","openid","openid"]}""").Scopes);
        Assert.Equal(["api://lims/Sign", "api://lims/Read"], PipeProtocol.Parse("""{"cmd":"sign","reason":"x","scopes":"api://lims/Sign  api://lims/Read"}""").Scopes);
        Assert.Empty(PipeProtocol.Parse("""{"cmd":"sign","reason":"x"}""").Scopes);
    }

    [Theory]
    [InlineData("""{"cmd":"sign","reason":"x","scopes":[1]}""")]
    [InlineData("""{"cmd":"sign","reason":"x","scopes":{"a":1}}""")]
    [InlineData("""{"cmd":"sign","reason":"x","scopes":["a b"]}""")]
    [InlineData("""{"cmd":"sign","reason":"x","scopes":["a","b","c","d","e","f","g","h","i","j","k"]}""")]
    public void Ungueltige_Scopes(string line) => Assert.Equal("VIT-0211", PipeProtocol.Parse(line).ErrorCode);

    [Fact]
    public void Nur_erlaubte_Scopes_einer_Ressource()
    {
        string[] allowed = ["api://lims/Sign", "api://lims/Read", "User.Read"];
        Assert.Null(PipeProtocol.CheckScopes([], []));
        Assert.Null(PipeProtocol.CheckScopes(["API://LIMS/sign", "openid", "profile"], allowed));
        Assert.Equal("VIT-0211", PipeProtocol.CheckScopes(["api://lims/Admin"], allowed)?.Code);
        Assert.Equal("VIT-0211", PipeProtocol.CheckScopes(["api://lims/Sign"], [])?.Code);
        Assert.Equal("VIT-0212", PipeProtocol.CheckScopes(["api://lims/Sign", "User.Read"], allowed)?.Code);
    }

    [Fact]
    public void Ohne_Freigabeliste_gibt_es_kein_Zugriffstoken_auch_nicht_fuer_OpenID()
    {
        // Befund der Prüfung vom 2026-10-20: ["openid","profile"] ergab bei leerer Liste ein Zugriffstoken
        Assert.Equal("VIT-0211", PipeProtocol.CheckScopes(["openid", "profile"], [])?.Code);
        Assert.Equal("VIT-0211", PipeProtocol.CheckScopes(["openid"], [" ", ""])?.Code);
        Assert.Equal("VIT-0211", PipeProtocol.CheckScopes(["openid", "offline_access"], ["api://lims/Sign"])?.Code);
    }

    [Theory]
    [InlineData("api://lims/Sign", "api://lims")]
    [InlineData("https://contoso.com/api/.default", "https://contoso.com/api")]
    [InlineData("User.Read", "https://graph.microsoft.com")]
    [InlineData("https://graph.microsoft.com/User.Read", "https://graph.microsoft.com")]
    public void Ressource_eines_Scopes(string scope, string resource) => Assert.Equal(resource, PipeProtocol.ResourceOf(scope));
}
