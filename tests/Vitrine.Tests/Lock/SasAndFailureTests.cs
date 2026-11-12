// SPDX-License-Identifier: MIT
using Vitrine.Core.Config;
using Vitrine.Core.Lock;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Lock;

/// <summary>Strg+Alt+Entf-Einschränkungen: setzen, sichern, wiederherstellen – auch nach Absturz und mit kaputter Sicherung.</summary>
public sealed class SasRestrictionsTests : IDisposable
{
    private const string System = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string Explorer = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private readonly TempDir _dir = new();
    private readonly FakeStore _store = new();

    public void Dispose() => _dir.Dispose();

    private SasRestrictions Sas() => new(_store, _dir.File("sas-backup.json"));

    [Fact]
    public void Setzen_und_genau_den_vorherigen_Zustand_zurueckholen()
    {
        _store.Values[(System, "DisableTaskMgr")] = 0; // vorher bewusst „aus“
        var sas = Sas();
        sas.Apply();
        Assert.Equal(1, _store.Values[(System, "DisableTaskMgr")]);
        Assert.Equal(1, _store.Values[(System, "DisableChangePassword")]);
        Assert.Equal(1, _store.Values[(Explorer, "NoLogoff")]);
        Assert.Equal(1, _store.Values[(Explorer, "NoClose")]);

        sas.Restore();
        Assert.Equal(0, _store.Values[(System, "DisableTaskMgr")]);
        Assert.False(_store.Values.ContainsKey((System, "DisableChangePassword")));
        Assert.False(_store.Values.ContainsKey((Explorer, "NoLogoff")));
        Assert.False(_store.Values.ContainsKey((Explorer, "NoClose")));
        Assert.False(sas.IsApplied);
    }

    [Fact]
    public void NoClose_wird_auf_den_Wert_vor_der_Sperre_zurueckgesetzt()
    {
        _store.Values[(Explorer, "NoClose")] = 1; // per Richtlinie ohnehin ausgeblendet
        var sas = Sas();
        sas.Apply();
        sas.Restore();
        Assert.Equal(1, _store.Values[(Explorer, "NoClose")]);
    }

    [Fact]
    public void Sicherung_einer_aelteren_Version_ohne_NoClose_wird_ergaenzt()
    {
        // Sicherung von vor 2026-10-21 (ohne NoClose), z. B. nach einem Absturz während der Sperre
        File.WriteAllText(_dir.File("sas-backup.json"), """
            { "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|DisableTaskMgr": null,
              "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|DisableChangePassword": null,
              "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer|NoLogoff": null }
            """);
        var sas = Sas();
        sas.Apply();
        Assert.Equal(1, _store.Values[(Explorer, "NoClose")]);
        sas.Restore();
        Assert.Empty(_store.Values); // NoClose bleibt nicht stehen
    }

    [Fact]
    public void Scheitert_die_Sicherung_werden_die_Werte_trotzdem_gesetzt()
    {
        // Prüfung vom 2026-10-21: eine als Ordner angelegte „.tmp“ verhinderte alle Einschränkungen
        Directory.CreateDirectory(_dir.File("sas-backup.json.tmp"));
        var sas = Sas();
        sas.Apply();
        Assert.Equal(1, _store.Values[(System, "DisableTaskMgr")]);
        Assert.Equal(1, _store.Values[(Explorer, "NoClose")]);
        sas.Restore();
        Assert.Empty(_store.Values);
    }

    [Fact]
    public void Ohne_schreibbare_Sicherung_stellt_die_Instanz_aus_dem_Speicher_wieder_her()
    {
        // Weder Sicherung noch Markierung schreibbar (Ordner fehlt und lässt sich nicht anlegen: Pfad unter einer Datei)
        File.WriteAllText(_dir.File("blocker"), "");
        _store.Values[(Explorer, "NoClose")] = 1; // per Richtlinie gesetzt
        var sas = new SasRestrictions(_store, Path.Combine(_dir.File("blocker"), "sas-backup.json"));
        sas.Apply();
        Assert.Equal(1, _store.Values[(System, "DisableTaskMgr")]);
        sas.Restore();
        Assert.False(_store.Values.ContainsKey((System, "DisableTaskMgr")));
        Assert.Equal(1, _store.Values[(Explorer, "NoClose")]); // Wert der Richtlinie bleibt
    }

    [Fact]
    public void Zweites_Setzen_ueberschreibt_die_Sicherung_nicht()
    {
        var sas = Sas();
        sas.Apply();
        sas.Apply(); // z. B. nach einem Absturz ohne Aufräumen
        sas.Restore();
        Assert.Empty(_store.Values);
    }

    [Fact]
    public void Vorher_angelegte_Sicherung_verhindert_das_Setzen_nicht()
    {
        File.WriteAllText(_dir.File("sas-backup.json"), "{}");
        Sas().Apply();
        Assert.Equal(1, _store.Values[(System, "DisableTaskMgr")]);
    }

    [Fact]
    public void Wiederherstellen_nach_Absturz_durch_neue_Instanz()
    {
        Sas().Apply();
        Sas().Restore(); // Start nach Absturz bzw. Wächter
        Assert.Empty(_store.Values);
    }

    [Fact]
    public void Kaputte_Sicherung_hebt_die_Einschraenkungen_trotzdem_auf()
    {
        Sas().Apply();
        File.WriteAllText(_dir.File("sas-backup.json"), "{ kaputt");
        Sas().Restore();
        Assert.Empty(_store.Values);
        Assert.False(File.Exists(_dir.File("sas-backup.json")));
    }

    [Fact]
    public void Fremde_Eintraege_in_der_Sicherung_werden_nie_geschrieben()
    {
        File.WriteAllText(_dir.File("sas-backup.json"), """{ "Software\\Evil|Run": 1, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|DisableTaskMgr": null }""");
        _store.Values[(System, "DisableTaskMgr")] = 1;
        Sas().Restore();
        Assert.Empty(_store.Values);
        Assert.DoesNotContain(_store.Writes, w => w.key.Contains("Evil"));
    }

    [Fact]
    public void Ohne_Schreibrecht_bleibt_die_Sicherung_und_nichts_stuerzt()
    {
        _store.ThrowOnSet = true;
        var sas = Sas();
        sas.Apply();
        Assert.True(sas.IsApplied);
        _store.ThrowOnSet = false;
        sas.Restore();
        Assert.False(sas.IsApplied);
    }

    [Fact]
    public void Ohne_Sicherung_wird_nichts_angefasst()
    {
        _store.Values[(System, "DisableTaskMgr")] = 1; // von der IT per GPO gesetzt
        Sas().Restore();
        Assert.Equal(1, _store.Values[(System, "DisableTaskMgr")]);
    }

    private sealed class FakeStore : IUserPolicyStore
    {
        public Dictionary<(string key, string value), int> Values { get; } = new();
        public List<(string key, string value)> Writes { get; } = new();
        public bool ThrowOnSet { get; set; }

        public int? Get(string key, string value) => Values.TryGetValue((key, value), out var v) ? v : null;

        public void Set(string key, string value, int data)
        {
            if (ThrowOnSet) throw new UnauthorizedAccessException();
            Writes.Add((key, value));
            Values[(key, value)] = data;
        }

        public void Delete(string key, string value)
        {
            Writes.Add((key, value));
            Values.Remove((key, value));
        }
    }
}

public sealed class FailurePolicyTests
{
    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 0)]
    [InlineData(3, 2)]
    [InlineData(4, 4)]
    [InlineData(5, 8)]
    [InlineData(6, 16)]
    [InlineData(7, 30)]
    [InlineData(1000, 30)]
    public void Wartezeit_waechst_ab_dem_dritten_Versuch(int failed, int seconds) =>
        Assert.Equal(TimeSpan.FromSeconds(seconds), FailurePolicy.Delay(failed, new SecuritySettings()));

    [Fact]
    public void Ohne_ProgressiveDelay_keine_Wartezeit() =>
        Assert.Equal(TimeSpan.Zero, FailurePolicy.Delay(10, new SecuritySettings { ProgressiveDelay = false }));

    [Fact]
    public void Massnahme_erst_mit_Aktion_und_Grenze()
    {
        var s = new SecuritySettings { MaxFailedAttempts = 3, FailureAction = FailureAction.LockWorkstation };
        Assert.False(FailurePolicy.TriggersAction(2, s));
        Assert.True(FailurePolicy.TriggersAction(3, s));
        Assert.True(FailurePolicy.TriggersAction(4, s));
        Assert.Equal(1, FailurePolicy.Remaining(2, s));
        Assert.True(FailurePolicy.ShouldWarn(FailurePolicy.Remaining(2, s)));
        Assert.False(FailurePolicy.ShouldWarn(FailurePolicy.Remaining(0, s)));

        Assert.False(FailurePolicy.TriggersAction(99, new SecuritySettings { MaxFailedAttempts = 3 })); // Aktion „Nichts“
        Assert.Null(FailurePolicy.Remaining(1, new SecuritySettings { MaxFailedAttempts = 0, FailureAction = FailureAction.LogOff }));
    }
}

public sealed class ScriptEnvironmentTests
{
    [Theory]
    [InlineData("CONTOSO\\jdoe", "CONTOSO\\jdoe")]
    [InlineData("jdoe@contoso.com", "jdoe@contoso.com")]
    [InlineData("x&calc", "x_calc")]
    [InlineData("a|b>c<d^e%PATH%!x!\"(y)`", "a_b_c_d_e_PATH__x___y__")]
    [InlineData("line\r\nbreak", "line__break")]
    public void Sonderzeichen_von_cmd_werden_ersetzt(string input, string expected) =>
        Assert.Equal(expected, ScriptEnvironment.Clean(input));

    [Fact]
    public void Variablen_mit_Praefix_und_Laengengrenze()
    {
        var env = ScriptEnvironment.Build("failed", new DateTimeOffset(2026, 10, 19, 10, 0, 0, TimeSpan.FromHours(2)),
            new Dictionary<string, string?> { ["user"] = new string('a', 1000), ["code"] = "VIT-0101", ["method"] = null });
        Assert.Equal("failed", env["VITRINE_EVENT"]);
        Assert.Equal("2026-10-19T08:00:00.0000000+00:00", env["VITRINE_TIME"]);
        Assert.Equal(ScriptEnvironment.MaxValueLength, env["VITRINE_USER"].Length);
        Assert.Equal("VIT-0101", env["VITRINE_CODE"]);
        Assert.Equal("", env["VITRINE_METHOD"]);
    }
}

public sealed class FailureThrottleTests
{
    [Fact]
    public void Wartezeit_bleibt_ueber_Dialoge_hinweg_bis_zum_Entsperren()
    {
        var t = new FailureThrottle();
        var s = new SecuritySettings();
        var now = new DateTimeOffset(2026, 10, 19, 8, 0, 0, TimeSpan.Zero);
        t.RecordFailure(now, s);
        t.RecordFailure(now, s);
        Assert.Null(t.Remaining(now));
        Assert.Equal(TimeSpan.FromSeconds(2), t.RecordFailure(now, s));
        Assert.Equal(TimeSpan.FromSeconds(2), t.Remaining(now)); // neuer Dialog: gilt weiter
        Assert.Null(t.Remaining(now.AddSeconds(2)));
        Assert.Equal(3, t.Failed);
        t.Reset();
        Assert.Equal(0, t.Failed);
        Assert.Null(t.Remaining(now));
    }
}
