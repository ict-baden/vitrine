// SPDX-License-Identifier: MIT
using Vitrine.Core.Lock;

namespace Vitrine.Tests.Lock;

/// <summary>Abdeckungen je Abschnitt der Sperre (UIPI) und Verhalten beim angekündigten Ende der Sitzung.</summary>
public sealed class LockShieldTests
{
    [Fact]
    public void Gesperrt_fangen_die_Abdeckungen_Klicks_ab_und_halten_den_Vordergrund()
    {
        var s = LockShield.For(LockPhase.Locked);
        Assert.False(s.ClickThrough);
        Assert.True(s.OnTop);
        Assert.True(s.HoldForeground);
    }

    [Fact]
    public void Mit_Entsperr_Dialog_bleiben_die_Abdeckungen_dicht_und_der_Vordergrund_bei_Vitrine()
    {
        var s = LockShield.For(LockPhase.Prompt);
        Assert.False(s.ClickThrough);
        Assert.True(s.OnTop);
        Assert.True(s.HoldForeground);
    }

    [Fact]
    public void Waehrend_externer_Anmeldung_dicht_aber_nicht_immer_oben()
    {
        // Prüfung vom 2026-10-21: durchklickbar ließ Fenster mit Adminrechten unter der Hello-Anmeldung bedienbar
        var s = LockShield.For(LockPhase.ExternalAuth);
        Assert.False(s.ClickThrough);
        Assert.False(s.OnTop);
        Assert.False(s.HoldForeground);
        Assert.InRange(LockShield.ExternalAuthTimeout, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData(LockPhase.Locked, false, true)]   // z. B. Task-Manager als Administrator im Vordergrund
    [InlineData(LockPhase.Locked, true, false)]
    [InlineData(LockPhase.Prompt, false, true)]
    [InlineData(LockPhase.Prompt, true, false)]
    [InlineData(LockPhase.ExternalAuth, false, false)]
    public void Vordergrund_nur_wenn_fremd_und_nie_waehrend_externer_Anmeldung_zurueckholen(LockPhase phase, bool own, bool expected) =>
        Assert.Equal(expected, LockShield.MustTakeForeground(phase, own));

    [Theory]
    [InlineData(LockPhase.Locked, 2.0, true)]
    [InlineData(LockPhase.Locked, 1.5, false)]
    [InlineData(LockPhase.Prompt, 10, false)]
    [InlineData(LockPhase.ExternalAuth, 10, false)]
    public void Rueckfall_Windows_sperren_wenn_Fenster_mit_Adminrechten_den_Vordergrund_haelt(LockPhase phase, double seconds, bool expected) =>
        Assert.Equal(expected, LockShield.MustLockWorkstation(phase, TimeSpan.FromSeconds(seconds)));

    [Fact]
    public void Gesperrt_bleibt_die_Sperre_bei_der_Anfrage_zum_Sitzungsende_stehen()
    {
        Assert.Equal(SessionEndAction.KeepLock, SessionEnd.OnQuery(locked: true));
        Assert.Equal(SessionEndAction.CleanUpAndExit, SessionEnd.OnQuery(locked: false));
    }

    [Theory]
    [InlineData(true, true, false, true, true)]
    [InlineData(false, true, false, true, false)]  // abgebrochen: Sperre bleibt
    [InlineData(true, false, false, true, false)]  // ohne vorherige Anfrage (z. B. von einem Programm geschickt)
    [InlineData(true, true, true, true, false)]    // Restart Manager schließt nur Apps (Update), Sitzung läuft weiter
    [InlineData(true, true, false, false, false)]  // Windows fährt gar nicht herunter
    public void Aufgeraeumt_wird_erst_wenn_die_Sitzung_wirklich_endet(bool ending, bool queried, bool closeApp, bool shuttingDown, bool expected) =>
        Assert.Equal(expected, SessionEnd.CleanUpOnEnd(ending, queried, closeApp, shuttingDown));

    [Fact]
    public void Herunterfahren_nach_Fehlversuchen_ist_erzwungen()
    {
        // Ohne /f lehnte die gesperrte Vitrine das Herunterfahren selbst ab
        var args = FailurePolicy.ShutdownArguments("Too many \"failed\" attempts");
        Assert.StartsWith("/s /f /t 0 ", args);
        Assert.EndsWith("/c \"Too many 'failed' attempts\"", args);
    }
}
