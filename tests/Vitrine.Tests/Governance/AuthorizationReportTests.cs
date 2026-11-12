// SPDX-License-Identifier: MIT
using System.Globalization;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Governance;

namespace Vitrine.Tests.Governance;

/// <summary>Berechtigungsbericht mit Attrappe statt Windows-Gruppenabfrage.</summary>
public sealed class AuthorizationReportTests
{
    private const string Machine = "S-1-5-21-100-200-300";

    private sealed class FakeResolver : IGroupResolver
    {
        public List<string> Asked { get; } = [];

        public GroupResolution Resolve(string entry)
        {
            Asked.Add(entry);
            return entry switch
            {
                "CONTOSO\\QA" => new(entry, GroupKind.Domain, "S-1-5-21-9-9-9-2001", "CONTOSO\\QA", ["CONTOSO\\supervisor", "CONTOSO\\=cmd"]),
                "Vitrine-Prüfer" => new(entry, GroupKind.Local, Machine + "-1010", "LAB-PC-07\\Vitrine-Prüfer", []),
                AuthorizationReport.AdministratorsSid => new(entry, GroupKind.Local, entry, "BUILTIN\\Administrators", ["LAB-PC-07\\admin"]),
                "11111111-2222-3333-4444-555555555555" => new(entry, GroupKind.Entra, null, null, null),
                "broken" => throw new InvalidOperationException("Zugriff verweigert"),
                _ => new(entry, GroupKind.Unknown, null, null, null),
            };
        }
    }

    private static T InCulture<T>(string culture, Func<T> f)
    {
        var (c, ui) = (CultureInfo.CurrentCulture, CultureInfo.CurrentUICulture);
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
            return f();
        }
        finally { (CultureInfo.CurrentCulture, CultureInfo.CurrentUICulture) = (c, ui); }
    }

    private static (AuthorizationReport report, FakeResolver resolver) Build(Action<VitrineConfig>? change = null, Func<string, bool>? managed = null)
    {
        var cfg = new VitrineConfig();
        cfg.Unlock.Allowed |= UnlockAllowed.Groups;
        cfg.Unlock.AllowedGroups = ["CONTOSO\\QA", "11111111-2222-3333-4444-555555555555"];
        cfg.Unlock.BypassGroups = ["Vitrine-Prüfer", "broken"];
        cfg.Roles.Auditors = ["CONTOSO\\QA"];
        change?.Invoke(cfg);
        var resolver = new FakeResolver();
        var report = AuthorizationReport.Build(cfg, managed ?? (p => p == "Roles.Auditors"), resolver, "LAB-PC-07", "LAB\\qa-lead",
            new DateTimeOffset(2026, 10, 30, 9, 15, 0, TimeSpan.Zero), "0.5.0");
        return (report, resolver);
    }

    [Fact]
    public void Bericht_enthaelt_Regeln_Gruppen_Mitglieder_Herkunft_und_Unterschriften()
    {
        var html = InCulture("en", () => Build().report.ToHtml());
        Assert.Contains("Vitrine authorization report – LAB-PC-07", html);
        Assert.Contains("LAB\\qa-lead", html);
        Assert.Contains("2026-10-30 09:15:00 UTC", html);
        Assert.Contains("CONTOSO\\supervisor", html);
        Assert.Contains("members are managed in Entra ID", html);
        Assert.Contains("members could not be determined", html); // „broken“ wirft – der Bericht entsteht trotzdem
        Assert.Contains("LAB-PC-07\\admin", html);                 // lokale Administratoren aufgelöst
        Assert.Contains("Group Policy", html);                     // Roles.Auditors per Richtlinie
        Assert.Contains("Approved by", html);
        Assert.Contains("<html lang=\"en\">", html);
    }

    [Fact]
    public void Bericht_in_der_Sprache_der_Oberflaeche()
    {
        var html = InCulture("de-DE", () => Build().report.ToHtml());
        Assert.Contains("Vitrine-Berechtigungsbericht – LAB-PC-07", html);
        Assert.Contains("Freigegeben", html);
        Assert.Contains("Notfall-Anmeldung", html);
    }

    [Fact]
    public void Jede_Gruppe_wird_nur_einmal_abgefragt()
    {
        var (_, resolver) = InCulture("en", () => Build());
        Assert.Equal(resolver.Asked.Count, resolver.Asked.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains(AuthorizationReport.AdministratorsSid, resolver.Asked);
    }

    [Fact]
    public void Ohne_privilegierte_Administratoren_und_Gruppen_steht_Niemand()
    {
        var html = InCulture("en", () => Build(c =>
        {
            c.Security.LocalAdministratorsArePrivileged = false;
            c.Unlock.Allowed = UnlockAllowed.SessionUser;
            c.Roles.Auditors = [];
        }).report);
        var roles = html.Sections.Single(s => s.Title == "Roles");
        Assert.Equal("Nobody", roles.Rows.Single(r => r.Setting == "Roles.ConfigAdmins").Value);
        Assert.DoesNotContain(roles.Rows, r => r.Setting.Length == 0); // keine Zeile „lokale Administratoren“
    }

    [Fact]
    public void Html_ist_maskiert()
    {
        var html = InCulture("en", () => Build(c => c.Unlock.Methods = ["<script>alert(1)</script>"]).report.ToHtml());
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void Csv_mit_Anfuehrungszeichen_und_ohne_Formeln()
    {
        var csv = InCulture("en", () => Build().report.ToCsv());
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("Section,Setting,Description,Value,Source,Group,Members", lines[0]);
        Assert.Contains(lines, l => l.StartsWith("Who may unlock,Unlock.AllowedGroups,", StringComparison.Ordinal) && l.Contains("CONTOSO\\supervisor"));
        Assert.Equal("\"a,b\"", AuthorizationReport.Cell("a,b"));
        Assert.Equal("\"x \"\"y\"\"\"", AuthorizationReport.Cell("x \"y\""));
        Assert.Equal("'=1+1", AuthorizationReport.Cell("=1+1"));
        Assert.Equal("'@x", AuthorizationReport.Cell("@x"));
    }

    [Theory]
    [InlineData("11111111-2222-3333-4444-555555555555", null, GroupKind.Entra)]
    [InlineData("AzureAD\\Group", "S-1-12-1-1-2-3-4", GroupKind.Entra)]
    [InlineData("Administrators", "S-1-5-32-544", GroupKind.Local)]
    [InlineData("Vitrine-Prüfer", Machine + "-1010", GroupKind.Local)]
    [InlineData("CONTOSO\\QA", "S-1-5-21-9-9-9-2001", GroupKind.Domain)]
    [InlineData("Vitrine.Unlock", null, GroupKind.Unknown)]
    [InlineData("S-1-5-21-9-9-9-2001", null, GroupKind.Domain)]
    public void Einordnung_der_Gruppeneintraege(string entry, string? sid, GroupKind expected) =>
        Assert.Equal(expected, GroupEntries.Classify(entry, sid, Machine));

    [Fact]
    public void Objekt_ID_aus_Entra_SID_und_zurueck()
    {
        const string oid = "00000001-0002-0000-0300-000004000000";
        var sid = EntraClaims.SidFromObjectId(oid)!;
        Assert.Equal(oid, GroupEntries.ObjectIdFromSid(sid));
        Assert.Null(GroupEntries.ObjectIdFromSid("S-1-5-21-1-2-3"));
        Assert.Null(GroupEntries.ObjectIdFromSid("S-1-12-1-1-2-x-4"));
    }
}
