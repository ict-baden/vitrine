// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Auth;

/// <summary>Wer nach erfolgreicher Anmeldung entsperren, signieren oder Admin-Aktionen freigeben darf.</summary>
public sealed class UnlockPolicyTests
{
    private static AuthOutcome Person(string user = "CONTOSO\\jdoe", string? id = "S-1-5-21-1-2-3-1001", bool session = false,
        bool admin = false, params string[] groups) => new()
    {
        Success = true, UserName = user, DisplayName = "J. Doe", UserId = id, IsSessionUser = session, IsAdministrator = admin, Groups = groups,
    };

    private static readonly AuthOutcome Shared = new()
    {
        Success = true, UserName = "Unlock password", Details = new Dictionary<string, string> { [UnlockPolicy.SharedSecretDetail] = "true" },
    };

    [Fact]
    public void Standard_Sitzungsbenutzer_und_Administratoren()
    {
        var s = new UnlockSettings();
        Assert.True(UnlockPolicy.Evaluate(Person(session: true), s).Allowed);
        Assert.True(UnlockPolicy.Evaluate(Person(admin: true), s).Allowed);
        var other = UnlockPolicy.Evaluate(Person(), s);
        Assert.False(other.Allowed);
        Assert.Equal("VIT-0140", other.Code);
    }

    [Fact]
    public void Nichts_erlaubt_heisst_niemand()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.None };
        Assert.False(UnlockPolicy.Evaluate(Person(session: true, admin: true), s).Allowed);
    }

    [Fact]
    public void Fehlgeschlagene_Anmeldung_behaelt_Meldung_und_Code()
    {
        var d = UnlockPolicy.Evaluate(AuthOutcome.Fail("falsch", "ACME-0001"), new UnlockSettings { Allowed = UnlockAllowed.AnyAuthenticated });
        Assert.False(d.Allowed);
        Assert.Equal("falsch", d.Reason);
        Assert.Equal("ACME-0001", d.Code);
    }

    [Fact]
    public void Gemeinsames_Kennwort_entsperrt_aber_nie_fuer_Admin_Aktionen()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.None };
        Assert.True(UnlockPolicy.Evaluate(Shared, s).Allowed);
        var admin = UnlockPolicy.Evaluate(Shared, s, requireAdmin: true);
        Assert.False(admin.Allowed);
        Assert.Equal("VIT-0143", admin.Code);
    }

    [Fact]
    public void Admin_Aktion_braucht_Administrator()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.AnyAuthenticated };
        Assert.Equal("VIT-0142", UnlockPolicy.Evaluate(Person(session: true), s, requireAdmin: true).Code);
        Assert.True(UnlockPolicy.Evaluate(Person(admin: true), s, requireAdmin: true).Allowed);
    }

    [Theory]
    [InlineData("CONTOSO\\jdoe", true)]
    [InlineData("contoso\\jdoe", true)]
    [InlineData("jdoe@contoso.com", true)]
    [InlineData("jdoe@fabrikam.com", false)]
    [InlineData("FABRIKAM\\jdoe", false)]
    [InlineData("jdoe", false)]
    [InlineData("\\jdoe", false)]
    public void Domaenen_einschraenkung_gilt_vor_allen_anderen_Regeln(string user, bool allowed)
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.AnyAuthenticated, AllowedDomains = ["CONTOSO", " contoso.com "] };
        var d = UnlockPolicy.Evaluate(Person(user, admin: true), s);
        Assert.Equal(allowed, d.Allowed);
        if (!allowed) Assert.Equal("VIT-0141", d.Code);
    }

    [Fact]
    public void Domaenen_einschraenkung_gilt_auch_fuer_Administratoren_bei_Admin_Aktionen()
    {
        var s = new UnlockSettings { AllowedDomains = ["CONTOSO"] };
        Assert.False(UnlockPolicy.Evaluate(Person("FABRIKAM\\admin", admin: true), s, requireAdmin: true).Allowed);
    }

    [Fact]
    public void Konten_nach_Name_ID_oder_aufgeloester_SID()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.Users, AllowedUsers = ["contoso\\JDOE"] };
        Assert.True(UnlockPolicy.Evaluate(Person(), s).Allowed);
        s.AllowedUsers = ["S-1-5-21-1-2-3-1001"];
        Assert.True(UnlockPolicy.Evaluate(Person(), s).Allowed);
        s.AllowedUsers = ["CONTOSO\\alias"];
        Assert.False(UnlockPolicy.Evaluate(Person(), s).Allowed);
        Assert.True(UnlockPolicy.Evaluate(Person(), s, resolveSid: n => n == "CONTOSO\\alias" ? "S-1-5-21-1-2-3-1001" : null).Allowed);
    }

    [Fact]
    public void Konto_ohne_ID_passt_nicht_auf_leere_Eintraege()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.Users, AllowedUsers = ["", "  "] };
        Assert.False(UnlockPolicy.Evaluate(Person(id: null), s).Allowed);
    }

    [Fact]
    public void Gruppen_nach_Name_Objekt_ID_Rolle_oder_SID()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.Groups, AllowedGroups = ["Vitrine.Unlock"] };
        Assert.True(UnlockPolicy.Evaluate(Person(groups: "vitrine.unlock"), s).Allowed);
        Assert.False(UnlockPolicy.Evaluate(Person(groups: "QA"), s).Allowed);
        s.AllowedGroups = ["LAB\\QA"];
        Assert.True(UnlockPolicy.Evaluate(Person(groups: "S-1-5-21-9-9-9-500"), s, resolveSid: _ => "S-1-5-21-9-9-9-500").Allowed);
    }

    [Fact]
    public void Gruppen_und_Konten_nur_wenn_die_Art_eingeschaltet_ist()
    {
        var s = new UnlockSettings { Allowed = UnlockAllowed.SessionUser, AllowedGroups = ["QA"], AllowedUsers = ["CONTOSO\\jdoe"] };
        Assert.False(UnlockPolicy.Evaluate(Person(groups: "QA"), s).Allowed);
    }

    [Fact]
    public void Ablehnung_nennt_die_Person_in_der_Sprache_der_Oberflaeche()
    {
        using var _ = new UiCulture("de");
        var d = UnlockPolicy.Evaluate(Person(), new UnlockSettings());
        Assert.Equal("J. Doe darf diesen Arbeitsplatz nicht entsperren. (VIT-0140)", d.Reason);
    }
}
