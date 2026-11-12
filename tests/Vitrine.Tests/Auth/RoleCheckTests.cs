// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Tests.Auth;

/// <summary>Rollen (Roles.*), Security.LocalAdministratorsArePrivileged und Notfall-Anmeldung (Unlock.BypassGroups).</summary>
public sealed class RoleCheckTests
{
    private const string Machine = "S-1-5-21-100-200-300";
    private const string QaGroup = "S-1-5-21-9-9-9-2001";
    private const string AuditGroup = "S-1-5-21-9-9-9-2002";
    private const string KeyGroup = "S-1-5-21-9-9-9-2003";
    private const string EmergencyGroup = "S-1-5-21-9-9-9-2004";
    private const string LocalAuditors = Machine + "-1010";
    private const string Oid = "00000001-0002-0000-0300-000004000000";
    private const string EntraUserSid = "S-1-12-1-1-2-3-4";

    private static AuthOutcome Person(bool admin = false, string user = "CONTOSO\\jdoe", params string[] groups) => new()
    {
        Success = true, UserName = user, DisplayName = "J. Doe", UserId = "S-1-5-21-1-2-3-1001", IsAdministrator = admin, Groups = groups,
    };

    private static readonly AuthOutcome Shared = new()
    {
        Success = true, UserName = "Unlock password", IsAdministrator = true,
        Details = new Dictionary<string, string> { [UnlockPolicy.SharedSecretDetail] = "true" },
    };

    private static string? Resolve(string name) => name switch
    {
        "CONTOSO\\QA" => QaGroup,
        "CONTOSO\\Auditors" => AuditGroup,
        "Vitrine-Prüfer" => LocalAuditors,
        _ => null,
    };

    private static VitrineConfig Config(Action<VitrineConfig>? change = null)
    {
        var c = new VitrineConfig();
        change?.Invoke(c);
        return c;
    }

    private static RoleCheck Check(VitrineConfig c, ILocalGroupDirectory? dir = null) =>
        new(() => c, Resolve, dir is null ? null : () => dir);

    private sealed class FakeDirectory : ILocalGroupDirectory
    {
        public Dictionary<string, string[]> Members { get; } = new(StringComparer.OrdinalIgnoreCase);
        public string? MachineSid => Machine;
        public IReadOnlyCollection<string>? MemberSids(string groupSid) => Members.TryGetValue(groupSid, out var m) ? m : null;
    }

    [Fact]
    public void Standard_wie_bisher_Administratoren_haben_alle_Rollen_andere_keine()
    {
        var roles = Check(Config());
        Assert.True(roles.IsConfigAdmin(Person(admin: true)));
        Assert.True(roles.IsRegistrar(Person(admin: true)));
        Assert.True(roles.IsAuditor(Person(admin: true)));
        Assert.Empty(roles.RolesOf(Person()));
        // Ohne Rollengruppen bleibt die bisherige Meldung „Administrator erforderlich“
        Assert.Equal(ErrorCodes.AdminRequired, roles.Decide(Person(), [VitrineRole.ConfigAdmin]).Code);
    }

    [Fact]
    public void Rollengruppen_ergaenzen_die_Administratoren()
    {
        var c = Config(c =>
        {
            c.Roles.ConfigAdmins = ["CONTOSO\\QA"];
            c.Roles.Auditors = [AuditGroup];
            c.Roles.Registrars = ["  ", KeyGroup];
        });
        var roles = Check(c);
        Assert.True(roles.IsConfigAdmin(Person(groups: QaGroup)));
        Assert.True(roles.IsAuditor(Person(groups: QaGroup))); // Einstellungs-Administratoren sind auch Prüfer
        Assert.False(roles.IsRegistrar(Person(groups: QaGroup)));

        var auditor = Person(groups: AuditGroup);
        Assert.True(roles.IsAuditor(auditor));
        Assert.False(roles.IsConfigAdmin(auditor));
        Assert.True(roles.Decide(auditor, [VitrineRole.ConfigAdmin, VitrineRole.Auditor]).Allowed);
        var denied = roles.Decide(auditor, [VitrineRole.ConfigAdmin]);
        Assert.Equal(ErrorCodes.RoleRequired, denied.Code);

        Assert.True(roles.IsRegistrar(Person(groups: KeyGroup)));
        Assert.True(roles.IsConfigAdmin(Person(admin: true)));
    }

    [Fact]
    public void Ohne_Administratorenrechte_nur_noch_Rollengruppen()
    {
        var c = Config(c =>
        {
            c.Security.LocalAdministratorsArePrivileged = false;
            c.Roles.ConfigAdmins = [QaGroup];
        });
        var roles = Check(c);
        Assert.Empty(roles.RolesOf(Person(admin: true)));
        Assert.Equal(ErrorCodes.RoleRequired, roles.Decide(Person(admin: true), [VitrineRole.ConfigAdmin]).Code);
        Assert.True(roles.IsConfigAdmin(Person(admin: true, groups: QaGroup)));
        Assert.False(roles.IsRegistrar(Person(admin: true, groups: QaGroup)));
    }

    [Fact]
    public void Gemeinsames_Kennwort_Fehlschlag_und_fremde_Domaene_haben_keine_Rollen()
    {
        var c = Config(c => c.Unlock.AllowedDomains = ["CONTOSO"]);
        var roles = Check(c);
        Assert.Empty(roles.RolesOf(Shared));
        Assert.Equal(ErrorCodes.PersonalAdminRequired, roles.Decide(Shared, [VitrineRole.ConfigAdmin]).Code);
        Assert.Empty(roles.RolesOf(AuthOutcome.Fail("x", ErrorCodes.WrongCredentials)));
        Assert.Equal(ErrorCodes.WrongCredentials, roles.Decide(AuthOutcome.Fail("x", ErrorCodes.WrongCredentials), [VitrineRole.Auditor]).Code);
        var foreign = Person(admin: true, user: "FABRIKAM\\admin");
        Assert.Empty(roles.RolesOf(foreign));
        Assert.Equal(ErrorCodes.DomainNotAllowed, roles.Decide(foreign, [VitrineRole.ConfigAdmin]).Code);
    }

    [Fact]
    public void Microsoft_Anmeldung_ueber_lokale_Gruppe_mit_Entra_Mitglied()
    {
        var c = Config(c => c.Roles.Auditors = ["Vitrine-Prüfer"]);
        var dir = new FakeDirectory();
        dir.Members[LocalAuditors] = [EntraUserSid];
        var entra = new AuthOutcome { Success = true, UserName = "jdoe@contoso.com", UserId = Oid };
        Assert.True(Check(c, dir).IsAuditor(entra));
        Assert.False(Check(c).IsAuditor(entra)); // ohne Verzeichnis keine lokalen Gruppen
        Assert.False(Check(c, dir).IsConfigAdmin(entra));
    }

    [Fact]
    public void Warnung_wenn_niemand_Einstellungen_aendern_kann()
    {
        Assert.Empty(RoleCheck.Warnings(Config()));
        Assert.Equal([ErrorCodes.NoConfigAdmin], RoleCheck.Warnings(Config(c => c.Security.LocalAdministratorsArePrivileged = false)));
        Assert.Empty(RoleCheck.Warnings(Config(c => { c.Security.LocalAdministratorsArePrivileged = false; c.Roles.ConfigAdmins = [QaGroup]; })));
        // Einstellungen für alle offen: niemand ist ausgesperrt
        Assert.Empty(RoleCheck.Warnings(Config(c => { c.Security.LocalAdministratorsArePrivileged = false; c.Security.SettingsAdminOnly = false; })));
    }

    [Fact]
    public void Alle_Gruppen_fuer_die_Entra_Ergaenzung()
    {
        var c = Config(c =>
        {
            c.Unlock.AllowedGroups = ["A", "b"];
            c.Unlock.BypassGroups = ["B", " "];
            c.Roles.Auditors = ["C"];
        });
        Assert.Equal(["A", "b", "C"], RoleCheck.AllGroups(c));
    }

    // ---- Notfall-Anmeldung ----

    private static VitrineConfig Emergency(Action<VitrineConfig>? change = null) => Config(c =>
    {
        c.Unlock.BypassGroups = [EmergencyGroup];
        change?.Invoke(c);
    });

    [Fact]
    public void Notfall_nur_mit_Gruppe_Begruendung_und_Windows_Kennwort()
    {
        var c = Emergency();
        var member = Person(groups: EmergencyGroup);
        const string reason = "Instrument alarm, operator absent";
        Assert.True(EmergencyAccess.Enabled(c.Unlock));
        Assert.True(EmergencyAccess.Evaluate(member, "windows", c, reason, Resolve).Allowed);
        Assert.Equal(ErrorCodes.ReasonTooShort, EmergencyAccess.Evaluate(member, "windows", c, "kurz", Resolve).Code);
        Assert.Equal(ErrorCodes.ReasonTooShort, EmergencyAccess.Evaluate(member, "windows", c, "  \n\t  ", Resolve).Code);
        Assert.Equal(ErrorCodes.EmergencyNeedsWindowsPassword, EmergencyAccess.Evaluate(member, "hello", c, reason, Resolve).Code);
        Assert.Equal(ErrorCodes.EmergencyNotAllowed, EmergencyAccess.Evaluate(Person(), "windows", c, reason, Resolve).Code);
        Assert.Equal(ErrorCodes.EmergencyNeedsWindowsPassword, EmergencyAccess.Evaluate(Shared, "windows", c, reason, Resolve).Code);
    }

    [Fact]
    public void Notfall_aus_ohne_Gruppen_auch_fuer_Administratoren()
    {
        var c = Config();
        Assert.False(EmergencyAccess.Enabled(c.Unlock));
        Assert.Equal(ErrorCodes.EmergencyNotAllowed, EmergencyAccess.Evaluate(Person(admin: true), "windows", c, "Instrument alarm", Resolve).Code);
    }

    [Fact]
    public void Notfall_Administratoren_nur_solange_privilegiert()
    {
        Assert.True(EmergencyAccess.Evaluate(Person(admin: true), "windows", Emergency(), "Instrument alarm", Resolve).Allowed);
        var off = Emergency(c => c.Security.LocalAdministratorsArePrivileged = false);
        Assert.False(EmergencyAccess.Evaluate(Person(admin: true), "windows", off, "Instrument alarm", Resolve).Allowed);
    }

    [Fact]
    public void Notfall_Mindestlaenge_und_Domaenen()
    {
        var c = Emergency(c => { c.Unlock.BypassReasonMinLength = 0; c.Unlock.AllowedDomains = ["CONTOSO"]; });
        Assert.True(EmergencyAccess.Evaluate(Person(groups: EmergencyGroup), "windows", c, "x", Resolve).Allowed);
        Assert.False(EmergencyAccess.Evaluate(Person(groups: EmergencyGroup), "windows", c, "", Resolve).Allowed);
        Assert.Equal(ErrorCodes.DomainNotAllowed,
            EmergencyAccess.Evaluate(Person(user: "FABRIKAM\\x", groups: EmergencyGroup), "windows", c, "x", Resolve).Code);
    }

    [Fact]
    public void Notfall_Ergebnis_traegt_Markierung_und_bereinigte_Begruendung()
    {
        var marked = EmergencyAccess.Mark(Person(), "  Alarm\r\nam Gerät  ");
        Assert.True(EmergencyAccess.IsEmergency(marked));
        Assert.Equal("Alarm am Gerät", marked.Details[EmergencyAccess.ReasonDetail]);
        Assert.Equal("windows", marked.Details["method"]);
        Assert.False(EmergencyAccess.IsEmergency(Person()));
    }
}
