// SPDX-License-Identifier: MIT
using System.Globalization;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Governance;

namespace Vitrine.Tests.Governance;

/// <summary>Verantwortliche Person, Begründungen, Unterschied der Einstellungen.</summary>
public sealed class GovernanceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 30, 8, 0, 0, TimeSpan.Zero);

    private static AuthOutcome Who(string user, string? id, string? display = null) => new()
    {
        Success = true, UserName = user, UserId = id, DisplayName = display,
    };

    [Fact]
    public void Verantwortung_beginnt_beim_Sitzungsbenutzer_und_wechselt_nur_bei_anderer_Person()
    {
        var t = new ResponsibilityTracker();
        t.Begin("LAB\\operator", "S-1-5-21-1-1-1-1001", "Lab operator", T0);
        Assert.Equal(ResponsibilityTracker.SessionSignIn, t.Current!.Method);

        // Gleiche Person (SID) entsperrt: kein Wechsel, „seit“ bleibt
        Assert.Null(t.Unlocked(Who("lab\\OPERATOR", "S-1-5-21-1-1-1-1001"), "windows", T0.AddHours(1)));
        Assert.Equal(T0, t.Current!.Since);

        var change = t.Unlocked(Who("LAB\\supervisor", "S-1-5-21-1-1-1-1002", "QA supervisor"), "entra", T0.AddHours(2));
        Assert.NotNull(change);
        Assert.Equal("LAB\\operator", change!.From!.UserName);
        Assert.Equal("QA supervisor", change.To.Name);
        Assert.Equal(T0.AddHours(2), t.Current!.Since);
        Assert.Equal("LAB\\operator -> LAB\\supervisor", ResponsibilityTracker.AuditDetail(change));
        var data = ResponsibilityTracker.AuditData(change);
        Assert.Equal("LAB\\operator", data["fromUser"]);
        Assert.Equal("LAB\\supervisor", data["toUser"]);
        Assert.Equal("entra", data["method"]);
        Assert.Equal("2026-10-30T08:00:00.0000000Z", data["fromSince"]);
    }

    [Fact]
    public void Entra_Objekt_ID_und_Windows_SID_desselben_Kontos_sind_dieselbe_Person()
    {
        const string oid = "00000001-0002-0000-0300-000004000000";
        var t = new ResponsibilityTracker();
        t.Begin("AzureAD\\JDoe", "S-1-12-1-1-2-3-4", null, T0);
        Assert.Null(t.Unlocked(Who("jdoe@contoso.com", oid), "entra", T0.AddMinutes(5)));
        Assert.Equal("AzureAD\\JDoe", t.Current!.Name);
    }

    [Fact]
    public void Gemeinsames_Kennwort_macht_niemanden_verantwortlich_und_ist_ein_Wechsel()
    {
        var t = new ResponsibilityTracker();
        t.Begin("LAB\\operator", "S-1-5-21-1-1-1-1001", null, T0);
        var shared = new AuthOutcome
        {
            Success = true, UserName = "Unlock password", Details = new Dictionary<string, string> { [UnlockPolicy.SharedSecretDetail] = "true" },
        };
        var change = t.Unlocked(shared, "pin", T0.AddMinutes(1));
        Assert.Equal(ResponsibilityTracker.SharedKey, change!.To.Key);
        Assert.Null(t.Unlocked(shared, "pin", T0.AddMinutes(2)));
    }

    [Fact]
    public void Ohne_bekannte_Person_und_nach_Abmelden()
    {
        var t = new ResponsibilityTracker();
        var change = t.Unlocked(Who("LAB\\a", null), "windows", T0);
        Assert.Null(change!.From);
        Assert.Equal("(none) -> LAB\\a", ResponsibilityTracker.AuditDetail(change));
        Assert.False(ResponsibilityTracker.AuditData(change).ContainsKey("fromUser"));
        Assert.Null(t.Unlocked(AuthOutcome.Fail("x"), "windows", T0));
        t.Reset();
        Assert.Null(t.Current);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("   ", null)]
    [InlineData(" a\tb\r\n c ", "a b c")]
    public void Begruendung_bereinigt(string? input, string? expected) => Assert.Equal(expected, Reasons.Normalize(input));

    [Fact]
    public void Begruendung_Laenge()
    {
        Assert.Equal(Reasons.MaxLength, Reasons.Normalize(new string('x', 2000))!.Length);
        Assert.Equal(1, Reasons.EffectiveMinLength(-5));
        Assert.Equal(Reasons.MaxLength, Reasons.EffectiveMinLength(10_000));
        Assert.True(Reasons.IsSufficient("0123456789", 10));
        Assert.False(Reasons.IsSufficient("   012345678  ", 10));
        Assert.False(Reasons.IsSufficient(null, 0));
    }

    [Fact]
    public void Unterschied_der_Einstellungen_mit_alt_und_neu()
    {
        var before = new VitrineConfig();
        var after = new VitrineConfig();
        after.Lock.IdleMinutes = 10;
        after.Unlock.Methods = ["windows"];
        after.Roles.Auditors = ["CONTOSO\\Auditors"];
        after.Appearance.Message = "Measurement running";
        var changes = ConfigDiff.Compute(before, after);
        Assert.Equal(["Appearance.Message", "Lock.IdleMinutes", "Roles.Auditors", "Unlock.Methods"], changes.Select(c => c.Path));
        var idle = changes.Single(c => c.Path == "Lock.IdleMinutes");
        Assert.Equal(("0", "10"), (idle.Old, idle.New));
        Assert.Equal(("[\"entra\",\"windows\",\"hello\"]", "[\"windows\"]"),
            (changes.Single(c => c.Path == "Unlock.Methods").Old, changes.Single(c => c.Path == "Unlock.Methods").New));
        var message = changes.Single(c => c.Path == "Appearance.Message");
        Assert.Null(message.Old);
        Assert.Equal("Measurement running", message.New);
        Assert.Empty(ConfigDiff.Compute(after, after));
    }

    [Fact]
    public void Geheimnisse_erscheinen_nie_im_Klartext()
    {
        var before = new VitrineConfig();
        var after = new VitrineConfig();
        after.Unlock.PinHash = "pbkdf2-sha256$600000$c2FsdA==$aGFzaA==";
        var c = Assert.Single(ConfigDiff.Compute(before, after));
        Assert.True(c.Masked);
        Assert.Null(c.Old);
        Assert.Equal(ConfigDiff.Hidden, c.New);
        var data = ConfigDiff.ToAuditData([c], "Neues Kennwort");
        Assert.DoesNotContain(data.Values, v => v.Contains("pbkdf2", StringComparison.Ordinal));
        Assert.Equal("(not set) -> (hidden)", data["Unlock.PinHash"]);

        // Geändert: beide Seiten verborgen, aber als Änderung erkennbar
        var changed = new VitrineConfig();
        changed.Unlock.PinHash = "pbkdf2-sha256$600000$b3RoZXI=$b3RoZXI=";
        Assert.Equal((ConfigDiff.Hidden, ConfigDiff.Hidden), (ConfigDiff.Compute(after, changed)[0].Old, ConfigDiff.Compute(after, changed)[0].New));
        Assert.True(ConfigDiff.IsSecret("Foo.ServicePassword"));
        Assert.False(ConfigDiff.IsSecret("Lock.Hotkey"));
    }

    [Fact]
    public void Protokolldaten_passen_in_die_Grenzen_des_Dienstes()
    {
        var many = Enumerable.Range(0, 50).Select(i => new ConfigChange($"Section.Value{i:00}", "a", new string('b', 1000), false)).ToList();
        var data = ConfigDiff.ToAuditData(many, "Wartung laut Änderungsantrag");
        Assert.True(data.Count <= 32);
        Assert.Equal("50", data["changes"]);
        Assert.Equal("Wartung laut Änderungsantrag", data["reason"]);
        Assert.Contains("Section.Value49", data["more"]);
        Assert.All(data, kv => Assert.True(kv.Key.Length <= 64 && kv.Value.Length <= 500));

        // Genau so viele, dass alles passt: kein „more“
        var fit = many.Take(30).ToList();
        var d2 = ConfigDiff.ToAuditData(fit, null);
        Assert.False(d2.ContainsKey("more"));
        Assert.Equal(31, d2.Count);
        Assert.Equal("Settings saved: 30 change(s)", ConfigDiff.Summary(fit));
    }

    [Fact]
    public void Zusammenfassung_ohne_Aenderung() => Assert.Equal("Settings saved (no changes)", ConfigDiff.Summary([]));

    [Fact]
    public void Kultur_unabhaengige_Zeit_im_Protokoll()
    {
        var old = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            var t = new ResponsibilityTracker();
            t.Begin("a", "S-1-5-21-1", null, T0);
            var change = t.Unlocked(Who("b", "S-1-5-21-2"), "windows", T0)!;
            Assert.Equal("2026-10-30T08:00:00.0000000Z", ResponsibilityTracker.AuditData(change)["fromSince"]);
        }
        finally { CultureInfo.CurrentCulture = old; }
    }
}
