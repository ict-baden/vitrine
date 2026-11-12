// SPDX-License-Identifier: MIT
using Vitrine.Core.About;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;

namespace Vitrine.Tests.Lock;

/// <summary>
/// Win+L abschalten (DisableLockWorkstation, Issue #16): setzen, merken, zurücksetzen, fremde Werte nie anfassen – und vor
/// jedem LockWorkStation-Rückfall den eigenen Wert entfernen. Nur Attrappen, keine Registry.
/// </summary>
public sealed class LockWorkstationPolicyTests
{
    private const string Key = LockWorkstationPolicy.Key;
    private const string Value = LockWorkstationPolicy.Value;
    private readonly FakeUser _user = new();
    private readonly FakeMachine _machine = new();

    private LockWorkstationPolicy Policy() => new(_user, _machine);

    private int? Current => _user.Get(Key, Value);
    private int? Marker => _user.Get(AppPaths.UserStateKey, LockWorkstationPolicy.MarkerValue);

    [Fact]
    public void Sperre_setzt_den_Wert_und_Entsperren_entfernt_ihn_wieder()
    {
        var p = Policy();
        Assert.Equal(WinLockStatus.Applied, p.Hold(WinLockReason.Lock));
        Assert.Equal(1, Current);
        Assert.Equal(LockWorkstationPolicy.NotSet, Marker);
        Assert.True(p.IsApplied);

        p.Release(WinLockReason.Lock);
        Assert.Null(Current);
        Assert.Null(Marker);
        Assert.False(p.IsApplied);
    }

    [Fact]
    public void Vorheriger_Wert_0_wird_zurueckgeschrieben()
    {
        _user.Values[(Key, Value)] = 0;
        var p = Policy();
        p.Hold(WinLockReason.Lock);
        Assert.Equal(1, Current);
        p.Release(WinLockReason.Lock);
        Assert.Equal(0, Current);
        Assert.Null(Marker);
    }

    [Fact]
    public void Schon_gesetzter_Wert_einer_Richtlinie_wird_nie_ueberschrieben_oder_geloescht()
    {
        _user.Values[(Key, Value)] = 1; // GPO oder Administrator
        var p = Policy();
        Assert.Equal(WinLockStatus.AlreadyDisabled, p.Hold(WinLockReason.Lock));
        Assert.Empty(_user.Writes);
        p.Release(WinLockReason.Lock);
        Assert.Equal(1, Current);

        // Auch vor einem Rückfall nicht löschen: dann Sitzung trennen statt LockWorkStation
        p.Hold(WinLockReason.Lock);
        var plan = p.BeforeFallbackLock();
        Assert.Equal(1, Current);
        Assert.False(plan.RevertedOwnValue);
        Assert.Equal(FallbackLockMethod.DisconnectSession, plan.Method);
        Assert.Equal("HKCU", plan.BlockedBy);
        Assert.Empty(_user.Writes);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    public void Computerrichtlinie_vorhanden_HKCU_bleibt_unberuehrt(int machine)
    {
        _machine.Values[(Key, Value)] = machine;
        var p = Policy();
        Assert.Equal(WinLockStatus.MachinePolicy, p.Hold(WinLockReason.Lock));
        Assert.Empty(_user.Writes);
        Assert.Null(Current);
    }

    [Fact]
    public void Computerrichtlinie_mit_1_fuehrt_im_Rueckfall_zum_Trennen()
    {
        _machine.Values[(Key, Value)] = 1;
        var plan = Policy().BeforeFallbackLock();
        Assert.Equal(FallbackLockMethod.DisconnectSession, plan.Method);
        Assert.Equal("HKLM", plan.BlockedBy);
    }

    [Fact]
    public void Vor_dem_Rueckfall_wird_der_eigene_Wert_entfernt_und_dann_gesperrt()
    {
        // Wichtigster Punkt des Issues: LockWorkStation() tut nichts, solange DisableLockWorkstation = 1 ist
        var p = Policy();
        p.Hold(WinLockReason.Lock);
        var plan = p.BeforeFallbackLock();
        Assert.Null(Current);
        Assert.Null(Marker);
        Assert.True(plan.RevertedOwnValue);
        Assert.Equal(FallbackLockMethod.LockWorkstation, plan.Method);
        Assert.Null(plan.BlockedBy);
        // Grund bleibt: nach dem Entsperren von Windows wieder setzen
        Assert.True(p.Held);
        Assert.Equal(WinLockStatus.Applied, p.Apply());
        Assert.Equal(1, Current);
    }

    [Fact]
    public void Rueckfall_ohne_eigenen_Wert_sperrt_mit_LockWorkStation()
    {
        var plan = Policy().BeforeFallbackLock();
        Assert.Equal(new FallbackLockPlan(FallbackLockMethod.LockWorkstation, false, null), plan);
        Assert.Empty(_user.Writes);
    }

    [Fact]
    public void Wachter_oder_Start_nach_Absturz_entfernt_den_Wert_mit_neuer_Instanz()
    {
        Policy().Hold(WinLockReason.Lock);
        // Absturz: neue Instanz ohne Gründe im Speicher – der Merkwert in der Registry reicht
        var plan = Policy().BeforeFallbackLock();
        Assert.True(plan.RevertedOwnValue);
        Assert.Null(Current);

        Policy().Hold(WinLockReason.ReplaceWinL);
        Assert.True(Policy().Revert()); // Start nach Absturz, Dienst über HKU\<SID>
        Assert.Null(Current);
        Assert.Null(Marker);
        Assert.False(Policy().Revert()); // zweites Mal: nichts zu tun
    }

    [Fact]
    public void Inzwischen_fremd_geaenderter_Wert_bleibt()
    {
        var p = Policy();
        p.Hold(WinLockReason.Lock);
        _user.Values[(Key, Value)] = 0; // z. B. Gruppenrichtlinie während der Sperre aktualisiert
        Assert.False(p.Revert());
        Assert.Equal(0, Current);
        Assert.Null(Marker);
    }

    [Fact]
    public void Mehrere_Gruende_ReplaceWinL_haelt_den_Wert_ueber_das_Entsperren()
    {
        var p = Policy();
        p.Hold(WinLockReason.ReplaceWinL);
        p.Hold(WinLockReason.Lock);
        p.Release(WinLockReason.Lock); // entsperrt, ReplaceWinL bleibt
        Assert.Equal(1, Current);
        Assert.Equal(LockWorkstationPolicy.NotSet, Marker); // Zustand vor Vitrine bleibt gemerkt
        p.Release(WinLockReason.ReplaceWinL);
        Assert.Null(Current);
    }

    [Fact]
    public void Programmende_entfernt_den_Wert_auch_mit_ReplaceWinL()
    {
        var p = Policy();
        p.Hold(WinLockReason.ReplaceWinL);
        p.Hold(WinLockReason.Lock);
        p.ReleaseAll();
        Assert.Null(Current);
        Assert.False(p.Held);
        Assert.Equal(WinLockStatus.Off, p.Apply());
        Assert.Null(Current);
    }

    [Fact]
    public void Ohne_Merkwert_wird_nichts_gesetzt()
    {
        // Lässt sich der vorherige Zustand nicht merken, bliebe der Wert womöglich für immer – also gar nicht setzen
        _user.FailKey = AppPaths.UserStateKey;
        var p = Policy();
        Assert.Equal(WinLockStatus.Failed, p.Hold(WinLockReason.Lock));
        Assert.Null(Current);
    }

    [Fact]
    public void Scheitert_das_Setzen_bleibt_kein_Merkwert_zurueck()
    {
        _user.FailKey = Key;
        var p = Policy();
        Assert.Equal(WinLockStatus.Failed, p.Hold(WinLockReason.Lock));
        Assert.Null(Marker);
        Assert.Null(Current);
    }

    [Fact]
    public void Vorhandener_Merkwert_behaelt_den_Zustand_vor_Vitrine()
    {
        _user.Values[(Key, Value)] = 0;
        Policy().Hold(WinLockReason.Lock); // Absturz danach
        var p = Policy();
        Assert.Equal(WinLockStatus.Applied, p.Hold(WinLockReason.Lock)); // nicht 1 als „vorher“ merken
        Assert.Equal(0, Marker);
        p.Release(WinLockReason.Lock);
        Assert.Equal(0, Current);
    }

    [Fact]
    public void Spaeter_gesetzte_Computerrichtlinie_entfernt_den_eigenen_Wert()
    {
        var p = Policy();
        p.Hold(WinLockReason.ReplaceWinL);
        _machine.Values[(Key, Value)] = 1;
        Assert.Equal(WinLockStatus.MachinePolicy, p.Apply());
        Assert.Null(Current);
        Assert.Null(Marker);
    }

    [Theory]
    [InlineData(null, null, FallbackLockMethod.LockWorkstation, null)]
    [InlineData(0, null, FallbackLockMethod.LockWorkstation, null)]
    [InlineData(null, 0, FallbackLockMethod.LockWorkstation, null)]
    [InlineData(1, null, FallbackLockMethod.DisconnectSession, "HKLM")]
    [InlineData(null, 1, FallbackLockMethod.DisconnectSession, "HKCU")]
    [InlineData(0, 1, FallbackLockMethod.DisconnectSession, "HKCU")]
    public void Entscheidung_vor_dem_Rueckfall(int? machine, int? user, FallbackLockMethod method, string? blockedBy)
    {
        var plan = LockWorkstationPolicy.Plan(machine, user, reverted: false);
        Assert.Equal(method, plan.Method);
        Assert.Equal(blockedBy, plan.BlockedBy);
    }

    [Fact]
    public void Protokolltext_nennt_Code_und_Weg()
    {
        var ok = new FallbackLockPlan(FallbackLockMethod.LockWorkstation, true, null);
        Assert.Equal("foreground -> LockWorkStation, own DisableLockWorkstation removed first", ok.AuditDetail("foreground", FallbackLockOutcome.Locked));
        Assert.Contains(ErrorCodes.FallbackLockDisconnected, ok.AuditDetail("watchdog", FallbackLockOutcome.Disconnected, lockError: 5));
        var blocked = new FallbackLockPlan(FallbackLockMethod.DisconnectSession, false, "HKLM");
        Assert.Contains("set by HKLM", blocked.AuditDetail("failed attempts", FallbackLockOutcome.Disconnected));
        Assert.Contains(ErrorCodes.FallbackLockFailed, blocked.AuditDetail("failed attempts", FallbackLockOutcome.Failed, 0, 7));
    }

    private sealed class FakeUser : IUserPolicyStore
    {
        public Dictionary<(string key, string value), int> Values { get; } = new();
        public List<(string key, string value)> Writes { get; } = new();
        public string? FailKey { get; set; }

        public int? Get(string key, string value) => Values.TryGetValue((key, value), out var v) ? v : null;

        public void Set(string key, string value, int data)
        {
            if (key == FailKey) throw new UnauthorizedAccessException();
            Writes.Add((key, value));
            Values[(key, value)] = data;
        }

        public void Delete(string key, string value)
        {
            Writes.Add((key, value));
            Values.Remove((key, value));
        }
    }

    private sealed class FakeMachine : IMachinePolicyReader
    {
        public Dictionary<(string key, string value), int> Values { get; } = new();
        public int? Get(string key, string value) => Values.TryGetValue((key, value), out var v) ? v : null;
    }
}
