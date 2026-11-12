// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Tests.Auth;

/// <summary>Lokale Gruppen (z. B. „Vitrine-Entsperrer“) für Anmeldungen mit Microsoft Entra ID – mit Attrappe statt NetLocalGroupGetMembers.</summary>
public sealed class EntraLocalGroupsTests
{
    private const string Machine = "S-1-5-21-100-200-300";
    private const string Entsperrer = Machine + "-1005";
    private const string Oid = "00000001-0002-0000-0300-000004000000";
    private const string UserSid = "S-1-12-1-1-2-3-4";
    private const string GroupOid = "00000005-0006-0000-0700-000008000000";
    private const string GroupSid = "S-1-12-1-5-6-7-8";

    private sealed class FakeDirectory : ILocalGroupDirectory
    {
        public Dictionary<string, string[]> Members { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Queries { get; } = [];
        public string? MachineSid { get; init; } = Machine;

        public IReadOnlyCollection<string>? MemberSids(string groupSid)
        {
            Queries.Add(groupSid);
            if (groupSid == "S-1-5-21-100-200-300-666") throw new InvalidOperationException("Zugriff verweigert");
            return Members.TryGetValue(groupSid, out var m) ? m : null;
        }
    }

    private static AuthOutcome Entra(string? oid = Oid, params string[] groups) => new()
    {
        Success = true, UserName = "jdoe@contoso.com", UserId = oid, TenantId = "tid", Groups = groups,
        Details = new Dictionary<string, string> { ["oid"] = oid ?? "" },
    };

    private static string? Resolve(string name) => name switch
    {
        "Vitrine-Entsperrer" or @".\Vitrine-Entsperrer" or @"LAB-PC-07\Vitrine-Entsperrer" => Entsperrer,
        @"CONTOSO\QA" => "S-1-5-21-9-9-9-1200",
        _ => null,
    };

    private static readonly UnlockSettings GroupsOnly = new() { Allowed = UnlockAllowed.Groups, AllowedGroups = ["Vitrine-Entsperrer"] };

    [Theory]
    [InlineData("S-1-5-32-544", true)]
    [InlineData("S-1-5-32-555", true)]
    [InlineData(Machine + "-1005", true)]
    [InlineData("s-1-5-21-100-200-300-1005", true)]
    [InlineData("S-1-5-21-100-200-3000-1005", false)] // andere Domäne mit gleichem Anfang
    [InlineData("S-1-5-21-9-9-9-1200", false)]        // Domänengruppe
    [InlineData("S-1-12-1-5-6-7-8", false)]           // Entra-Gruppe
    [InlineData(Machine, false)]                      // die Domäne selbst
    [InlineData("S-1-5-32", false)]
    [InlineData("S-1-5-32-", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Lokale_Gruppe_an_der_SID_erkannt(string? sid, bool local) =>
        Assert.Equal(local, EntraLocalGroups.IsLocalGroupSid(sid, Machine));

    [Fact]
    public void Ohne_Rechner_SID_nur_vordefinierte_Gruppen()
    {
        Assert.True(EntraLocalGroups.IsLocalGroupSid("S-1-5-32-544", null));
        Assert.False(EntraLocalGroups.IsLocalGroupSid(Entsperrer, null));
    }

    [Fact]
    public void SIDs_der_Person_aus_oid_und_groups_Claim_ohne_App_Rollen()
    {
        var sids = EntraLocalGroups.PersonSids(Entra(Oid, GroupOid, "Vitrine.Admin"));
        Assert.Equal(new[] { GroupSid, UserSid }.Order(), sids.Order());
    }

    [Fact]
    public void App_Rolle_mit_GUID_als_Wert_ist_keine_Entra_Gruppe()
    {
        // Rolle mit dem Wert der Objekt-ID einer Gruppe: früher zur SID der Gruppe umgerechnet und damit Mitglied in deren
        // lokalen Gruppen. Jetzt zählt nur der groups-Claim (EntraClaims hält die Rollen in Details["roles"] fest).
        var claims = new List<KeyValuePair<string, string>>
        {
            new("tid", "11111111-1111-1111-1111-111111111111"), new("oid", Oid), new("roles", GroupOid),
            new("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };
        var o = EntraClaims.Evaluate(new EntraSignIn(claims, null, null, null),
            new EntraSettings { TenantId = "11111111-1111-1111-1111-111111111111" }, null, DateTimeOffset.UtcNow);
        Assert.True(o.Success);
        Assert.Contains(GroupOid, o.Groups); // für Unlock.AllowedGroups gilt die Rolle weiter
        Assert.Equal([UserSid], EntraLocalGroups.PersonSids(o));

        var dir = new FakeDirectory { Members = { [Entsperrer] = [GroupSid] } };
        Assert.False(UnlockPolicy.Evaluate(EntraLocalGroups.Expand(o, GroupsOnly.AllowedGroups, Resolve, dir), GroupsOnly, resolveSid: Resolve).Allowed);

        // Dieselbe GUID im groups-Claim: echte Gruppe, zählt
        claims.Add(new("groups", GroupOid));
        claims.RemoveAll(c => c.Key == "roles");
        var g = EntraClaims.Evaluate(new EntraSignIn(claims, null, null, null),
            new EntraSettings { TenantId = "11111111-1111-1111-1111-111111111111" }, null, DateTimeOffset.UtcNow);
        Assert.Contains(GroupSid, EntraLocalGroups.PersonSids(g));
    }

    [Theory]
    [InlineData("Vitrine-Entsperrer")]
    [InlineData(@".\Vitrine-Entsperrer")]
    [InlineData(@"LAB-PC-07\Vitrine-Entsperrer")]
    [InlineData(Entsperrer)]
    public void Konto_direkt_in_lokaler_Gruppe_darf_entsperren(string entry)
    {
        var dir = new FakeDirectory { Members = { [Entsperrer] = ["S-1-5-21-100-200-300-500", UserSid] } };
        var rules = new UnlockSettings { Allowed = UnlockAllowed.Groups, AllowedGroups = [entry] };

        // Vorher: Entra-Ergebnis kennt die lokale Gruppe nicht
        Assert.False(UnlockPolicy.Evaluate(Entra(), rules, resolveSid: Resolve).Allowed);

        var o = EntraLocalGroups.Expand(Entra(), rules.AllowedGroups, Resolve, dir);
        Assert.Contains(Entsperrer, o.Groups);
        Assert.Equal(Entsperrer, o.Details[EntraLocalGroups.Detail]);
        Assert.Equal(Oid, o.Details["oid"]);
        Assert.False(o.IsAdministrator);
        Assert.True(UnlockPolicy.Evaluate(o, rules, resolveSid: Resolve).Allowed);
    }

    [Fact]
    public void Entra_Gruppe_in_lokaler_Gruppe_zaehlt_nur_mit_groups_Claim()
    {
        var dir = new FakeDirectory { Members = { [Entsperrer] = [GroupSid] } };
        var mit = EntraLocalGroups.Expand(Entra(Oid, GroupOid), GroupsOnly.AllowedGroups, Resolve, dir);
        Assert.True(UnlockPolicy.Evaluate(mit, GroupsOnly, resolveSid: Resolve).Allowed);

        // Überlauf (_claim_names statt groups) oder Claim nicht konfiguriert: keine Gruppen, kein Treffer (kein Graph-Aufruf)
        var ohne = EntraLocalGroups.Expand(Entra(), GroupsOnly.AllowedGroups, Resolve, dir);
        Assert.False(UnlockPolicy.Evaluate(ohne, GroupsOnly, resolveSid: Resolve).Allowed);
        Assert.False(ohne.Details.ContainsKey(EntraLocalGroups.Detail));
    }

    [Fact]
    public void Kein_Mitglied_bleibt_abgelehnt()
    {
        var dir = new FakeDirectory { Members = { [Entsperrer] = ["S-1-12-1-9-9-9-9"] } };
        var o = EntraLocalGroups.Expand(Entra(Oid, GroupOid), GroupsOnly.AllowedGroups, Resolve, dir);
        Assert.Equal(ErrorCodes.NotAllowedToUnlock, UnlockPolicy.Evaluate(o, GroupsOnly, resolveSid: Resolve).Code);
    }

    [Fact]
    public void Domaenengruppen_und_unbekannte_Namen_werden_nicht_abgefragt()
    {
        var dir = new FakeDirectory();
        EntraLocalGroups.Expand(Entra(), [@"CONTOSO\QA", "gibt-es-nicht", GroupOid, "S-1-12-1-5-6-7-8"], Resolve, dir);
        Assert.Equal(["S-1-5-32-544"], dir.Queries);
    }

    [Fact]
    public void Mitglieder_je_Aufruf_nur_einmal_gelesen()
    {
        var dir = new FakeDirectory { Members = { [Entsperrer] = ["S-1-12-1-9-9-9-9"] } };
        EntraLocalGroups.Expand(Entra(), ["Vitrine-Entsperrer", @".\Vitrine-Entsperrer", Entsperrer, "S-1-5-32-544"], Resolve, dir);
        Assert.Equal(1, dir.Queries.Count(q => q == Entsperrer));
        Assert.Equal(1, dir.Queries.Count(q => q == "S-1-5-32-544"));

        // Neuer Versuch: neu gelesen (kein Zwischenspeicher über Versuche)
        EntraLocalGroups.Expand(Entra(), ["Vitrine-Entsperrer"], Resolve, dir);
        Assert.Equal(2, dir.Queries.Count(q => q == Entsperrer));
    }

    [Fact]
    public void Fehler_beim_Lesen_heisst_kein_Mitglied()
    {
        var dir = new FakeDirectory();
        var o = EntraLocalGroups.Expand(Entra(), ["S-1-5-21-100-200-300-666"], Resolve, dir);
        Assert.Empty(o.Groups);
        Assert.False(o.IsAdministrator);
    }

    [Fact]
    public void Lokale_Administratoren_machen_zum_Administrator()
    {
        var rules = new UnlockSettings { Allowed = UnlockAllowed.Administrators };
        var dir = new FakeDirectory { Members = { ["S-1-5-32-544"] = ["S-1-5-21-100-200-300-500", GroupSid] } };

        Assert.Equal(ErrorCodes.AdminRequired, UnlockPolicy.Evaluate(Entra(Oid, GroupOid), rules, requireAdmin: true).Code);
        var o = EntraLocalGroups.Expand(Entra(Oid, GroupOid), [], Resolve, dir);
        Assert.True(o.IsAdministrator);
        Assert.Contains("S-1-5-32-544", o.Groups);
        Assert.Equal("S-1-5-32-544", o.Details[EntraLocalGroups.Detail]);
        Assert.True(UnlockPolicy.Evaluate(o, rules).Allowed);
        Assert.True(UnlockPolicy.Evaluate(o, rules, requireAdmin: true).Allowed);
    }

    [Fact]
    public void Administrator_aus_Rollen_bleibt_erhalten()
    {
        var admin = new AuthOutcome { Success = true, UserId = Oid, IsAdministrator = true, Groups = [] };
        var o = EntraLocalGroups.Expand(admin, ["Vitrine-Entsperrer"], Resolve, new FakeDirectory { Members = { [Entsperrer] = [UserSid] } });
        Assert.True(o.IsAdministrator);
    }

    [Fact]
    public void Fehlgeschlagen_oder_ohne_oid_unveraendert()
    {
        var dir = new FakeDirectory { Members = { ["S-1-5-32-544"] = [UserSid] } };
        var failed = AuthOutcome.Fail("x", "VIT-0101");
        Assert.Same(failed, EntraLocalGroups.Expand(failed, [], Resolve, dir));
        var noOid = Entra(oid: "kein-guid");
        Assert.Same(noOid, EntraLocalGroups.Expand(noOid, [], Resolve, dir));
        Assert.Empty(dir.Queries);
    }

    [Fact]
    public void Token_bleiben_erhalten()
    {
        var o = Entra().WithTokens(new Dictionary<string, string> { ["id_token"] = "t" });
        var dir = new FakeDirectory { Members = { [Entsperrer] = [UserSid] } };
        Assert.Equal("t", EntraLocalGroups.Expand(o, GroupsOnly.AllowedGroups, Resolve, dir).Tokens["id_token"]);
    }
}
