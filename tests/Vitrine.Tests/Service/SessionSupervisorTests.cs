// SPDX-License-Identifier: MIT
using Vitrine.Core.Audit;
using Vitrine.Core.Service;

namespace Vitrine.Tests.Service;

public sealed class SessionSupervisorTests
{
    /// <summary>Monotone Zeit (wie QueryUnbiasedInterruptTime im Dienst): Rechner läuft seit einer Stunde.</summary>
    private static readonly TimeSpan T0 = TimeSpan.FromHours(1);
    private readonly SessionSupervisor _s = new();

    private static TimeSpan Sec(double s) => TimeSpan.FromSeconds(s);

    private static SupervisorActionKind[] Kinds(IEnumerable<SupervisorAction> a) => a.Select(x => x.Kind).ToArray();

    /// <summary>Angemeldet, App gestartet und verbunden.</summary>
    private void Running(int session = 2, int pid = 100, bool locked = false)
    {
        _s.SessionStarted(session, T0);
        Assert.True(_s.AgentConnected(session, pid, T0));
        _s.Message(session, pid, locked ? AgentMessage.Locked : AgentMessage.Unlocked, T0);
    }

    /// <summary>Dienst tickt jede Sekunde von <paramref name="from"/> bis <paramref name="to"/>; die App meldet sich alle 2 s, solange <paramref name="beats"/>.</summary>
    private List<SupervisorAction> TickEverySecond(TimeSpan from, TimeSpan to, bool beats = false, int session = 2, int pid = 100)
    {
        var all = new List<SupervisorAction>();
        for (var t = from; t <= to; t += Sec(1))
        {
            if (beats && (int)t.TotalSeconds % 2 == 0) _s.Message(session, pid, AgentMessage.Beat, t);
            all.AddRange(_s.Tick(t));
        }
        return all;
    }

    [Fact]
    public void Anmeldung_startet_die_App_einmal()
    {
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(_s.SessionStarted(2, T0)));
        Assert.Empty(_s.SessionStarted(2, T0 + Sec(1))); // Start läuft schon
        Assert.True(_s.AgentConnected(2, 100, T0 + Sec(2)));
        Assert.Empty(_s.SessionStarted(2, T0 + Sec(3))); // z. B. erneut verbunden (RDP)
    }

    [Fact]
    public void Beendet_waehrend_der_Sperre_trennt_die_Sitzung_und_startet_gesperrt_neu()
    {
        Running(locked: true);
        var a = _s.AgentLost(2, 100, T0 + Sec(10));
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.RevertWinLock, SupervisorActionKind.StartAgent], Kinds(a));
        Assert.Equal(AuditEventType.AgentLost, a[0].Event);
        Assert.True(a[2].Relock);
        Assert.True(_s.IsLocked(2));
        Assert.Equal([2], _s.LockedSessions);
    }

    [Fact]
    public void Verlust_entfernt_den_WinL_Wert_nach_dem_Trennen_und_vor_dem_Neustart()
    {
        // Issue #16: Die verschwundene App kann DisableLockWorkstation nicht mehr selbst entfernen. Sonst täte Win+L (und
        // LockWorkStation) nichts, bis Vitrine wieder läuft – Trennen schützt zuerst, der Neustart setzt den Wert neu.
        Running(locked: true);
        var a = _s.AgentLost(2, 100, T0 + Sec(10));
        Assert.Equal(SupervisorActionKind.RevertWinLock, a[1].Kind);
        Assert.Equal(2, a[1].SessionId);
        Assert.Null(a[1].Event);

        Running(3, 200);
        Assert.Contains(_s.AgentLost(3, 200, T0 + Sec(10)), x => x.Kind == SupervisorActionKind.RevertWinLock && x.SessionId == 3);
    }

    [Fact]
    public void Beendet_ohne_Sperre_startet_neu()
    {
        Running();
        var a = _s.AgentLost(2, 100, T0 + Sec(10));
        Assert.Equal([SupervisorActionKind.Audit, SupervisorActionKind.RevertWinLock, SupervisorActionKind.StartAgent], Kinds(a));
        Assert.False(a[2].Relock);
        Assert.Empty(_s.LockedSessions);
    }

    [Fact]
    public void Bestaetigtes_Beenden_gilt_bis_zur_naechsten_Anmeldung()
    {
        Running();
        _s.Message(2, 100, AgentMessage.Exit, T0 + Sec(5));
        var a = _s.AgentLost(2, 100, T0 + Sec(6));
        Assert.Equal([SupervisorActionKind.Audit, SupervisorActionKind.RevertWinLock], Kinds(a));
        Assert.Equal(AuditEventType.AgentStopped, a[0].Event);
        Assert.Empty(_s.Tick(T0 + TimeSpan.FromMinutes(10)));
        _s.SessionEnded(2);
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(_s.SessionStarted(2, T0 + TimeSpan.FromHours(1))));
    }

    [Fact]
    public void Bestaetigtes_Beenden_gilt_nicht_fuer_eine_von_Hand_neu_gestartete_App()
    {
        Running();
        _s.Message(2, 100, AgentMessage.Exit, T0 + Sec(5));
        _s.AgentLost(2, 100, T0 + Sec(6));
        // Benutzer startet Vitrine wieder aus dem Startmenü; wird diese App beendet, startet der Dienst sie neu
        Assert.True(_s.AgentConnected(2, 101, T0 + Sec(60)));
        Assert.Contains(SupervisorActionKind.StartAgent, Kinds(_s.AgentLost(2, 101, T0 + Sec(70))));
    }

    [Fact]
    public void Beenden_waehrend_der_Sperre_gilt_nie()
    {
        Running(locked: true);
        _s.Message(2, 100, AgentMessage.Exit, T0 + Sec(5));
        Assert.Contains(SupervisorActionKind.DisconnectSession, Kinds(_s.AgentLost(2, 100, T0 + Sec(6))));
    }

    [Fact]
    public void Erlaubtes_Beenden_hilft_nicht_wenn_danach_gesperrt_wurde()
    {
        Running();
        _s.Message(2, 100, AgentMessage.Exit, T0 + Sec(5));
        _s.Message(2, 100, AgentMessage.Locked, T0 + Sec(6));
        Assert.Contains(SupervisorActionKind.DisconnectSession, Kinds(_s.AgentLost(2, 100, T0 + Sec(7))));
    }

    [Fact]
    public void Haengende_App_waehrend_der_Sperre()
    {
        Running(locked: true);
        Assert.Empty(TickEverySecond(T0 + Sec(1), T0 + SessionSupervisor.LockedTimeout));
        var a = _s.Tick(T0 + SessionSupervisor.LockedTimeout + Sec(1));
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.KillAgent], Kinds(a));
        Assert.Empty(_s.Tick(T0 + SessionSupervisor.LockedTimeout + Sec(2))); // nur einmal
        // Nach dem Beenden: gesperrt neu starten
        var lost = _s.AgentLost(2, 100, T0 + SessionSupervisor.LockedTimeout + Sec(3));
        Assert.Contains(lost, x => x.Kind == SupervisorActionKind.StartAgent && x.Relock);
    }

    [Fact]
    public void Haengende_App_ohne_Sperre_wird_neu_gestartet_ohne_Trennen()
    {
        Running();
        var a = TickEverySecond(T0 + Sec(1), T0 + SessionSupervisor.UnlockedTimeout + Sec(1));
        Assert.Equal([SupervisorActionKind.Audit, SupervisorActionKind.KillAgent], Kinds(a));
    }

    [Fact]
    public void Lebenszeichen_halten_die_App_am_Leben()
    {
        Running(locked: true);
        Assert.Empty(TickEverySecond(T0 + Sec(1), T0 + Sec(120), beats: true));
    }

    // ---------------- Energiesparmodus und Ruhezustand ----------------

    [Fact]
    public void Nach_dem_Aufwachen_wird_eine_gesperrte_App_weder_getrennt_noch_beendet()
    {
        Running(locked: true);
        TickEverySecond(T0 + Sec(1), T0 + Sec(10), beats: true);
        _s.Suspending(T0 + Sec(10));
        // Die monotone Uhr steht im Schlaf; nach dem Aufwachen braucht die App ein paar Sekunden für ihr erstes Lebenszeichen
        _s.Resumed(T0 + Sec(11));
        Assert.Empty(TickEverySecond(T0 + Sec(11), T0 + Sec(11) + SessionSupervisor.ResumeGrace - Sec(1)));
        _s.Message(2, 100, AgentMessage.Beat, T0 + Sec(11) + SessionSupervisor.ResumeGrace - Sec(1));
        Assert.Empty(TickEverySecond(T0 + Sec(11) + SessionSupervisor.ResumeGrace, T0 + Sec(200), beats: true));
        Assert.True(_s.IsLocked(2));
    }

    [Fact]
    public void Nach_dem_Aufwachen_wird_eine_entsperrte_App_nicht_beendet()
    {
        Running();
        _s.Suspending(T0 + Sec(5));
        _s.Resumed(T0 + Sec(6));
        Assert.Empty(TickEverySecond(T0 + Sec(6), T0 + Sec(6) + SessionSupervisor.ResumeGrace + Sec(30), beats: true));
    }

    [Fact]
    public void Waehrend_des_Schlafs_gibt_es_keine_Zeitueberschreitung()
    {
        Running(locked: true);
        _s.Suspending(T0 + Sec(1));
        // Der Dienst tickt noch kurz, bevor Windows wirklich schläft
        Assert.Empty(TickEverySecond(T0 + Sec(1), T0 + Sec(30)));
    }

    [Fact]
    public void Haengt_die_App_nach_der_Schonfrist_noch_wird_wie_sonst_gehandelt()
    {
        Running(locked: true);
        _s.Suspending(T0 + Sec(1));
        _s.Resumed(T0 + Sec(2));
        var a = TickEverySecond(T0 + Sec(2), T0 + Sec(2) + SessionSupervisor.ResumeGrace + SessionSupervisor.LockedTimeout);
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.KillAgent], Kinds(a));
    }

    [Fact]
    public void Abgebrochener_Schlaf_beendet_die_Ueberwachung_nicht()
    {
        Running(locked: true);
        _s.Suspending(T0 + Sec(1));
        // Kein Aufwachen gemeldet, die Uhr läuft aber weiter: Der Rechner schläft offenbar nicht
        var a = TickEverySecond(T0 + Sec(1), T0 + Sec(1) + SessionSupervisor.SuspendLimit + SessionSupervisor.ResumeGrace + SessionSupervisor.LockedTimeout + Sec(2));
        Assert.Contains(SupervisorActionKind.DisconnectSession, Kinds(a));
    }

    [Fact]
    public void Luecke_zwischen_zwei_Ticks_gilt_als_Aufwachen()
    {
        // Ohne Meldung von Windows (z. B. angehaltene VM): der Dienst stand selbst, die App auch
        Running(locked: true);
        TickEverySecond(T0 + Sec(1), T0 + Sec(5), beats: true);
        var after = T0 + Sec(5) + TimeSpan.FromMinutes(30);
        Assert.Empty(TickEverySecond(after, after + SessionSupervisor.ResumeGrace - Sec(1)));
    }

    [Fact]
    public void Start_waehrend_des_Schlafs_scheitert_nicht()
    {
        _s.SessionStarted(2, T0);
        _s.Suspending(T0 + Sec(1));
        _s.Resumed(T0 + Sec(2));
        Assert.Empty(TickEverySecond(T0 + Sec(2), T0 + Sec(2) + SessionSupervisor.StartTimeout));
    }

    // ---------------- Abmelden, Herunterfahren ----------------

    [Fact]
    public void Abmeldung_ist_kein_Verlust()
    {
        Running(locked: true);
        _s.Message(2, 100, AgentMessage.Logoff, T0 + Sec(1));
        var a = _s.AgentLost(2, 100, T0 + Sec(2));
        Assert.Equal([SupervisorActionKind.Audit], Kinds(a));
        Assert.Equal(AuditEventType.AgentStopped, a[0].Event);
        Assert.Empty(TickEverySecond(T0 + Sec(2), T0 + Sec(10)));
        _s.SessionEnded(2); // Windows meldet die Abmeldung
        Assert.Empty(TickEverySecond(T0 + Sec(10), T0 + Sec(120)));
    }

    [Fact]
    public void Abgebrochene_oder_gefaelschte_Abmeldung_waehrend_der_Sperre_trennt_und_sperrt_neu()
    {
        // Strg+Alt+Entf → Neu starten, ein Programm hält die Abmeldung auf, jemand klickt Abbrechen – oder ein Prozess der
        // Sitzung schickt der App WM_QUERYENDSESSION. Die App ist weg, Windows meldet aber keine Abmeldung.
        Running(locked: true);
        _s.Message(2, 100, AgentMessage.Logoff, T0 + Sec(1));
        Assert.Equal([SupervisorActionKind.Audit], Kinds(_s.AgentLost(2, 100, T0 + Sec(2))));
        var end = T0 + Sec(1) + SessionSupervisor.LogoffWindow;
        Assert.Empty(TickEverySecond(T0 + Sec(2), end));
        var a = TickEverySecond(end + Sec(1), end + Sec(1));
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.RevertWinLock, SupervisorActionKind.StartAgent], Kinds(a));
        Assert.Equal(AuditEventType.AgentLost, a[0].Event);
        Assert.Equal("locked, sign-out not completed", a[0].Detail);
        Assert.True(a[2].Relock);
        Assert.True(_s.IsLocked(2));
    }

    [Fact]
    public void Abgebrochene_Abmeldung_ohne_Sperre_startet_neu()
    {
        Running();
        _s.Message(2, 100, AgentMessage.Logoff, T0 + Sec(1));
        _s.AgentLost(2, 100, T0 + Sec(2));
        var a = TickEverySecond(T0 + Sec(2), T0 + Sec(2) + SessionSupervisor.LogoffWindow);
        Assert.Equal([SupervisorActionKind.Audit, SupervisorActionKind.RevertWinLock, SupervisorActionKind.StartAgent], Kinds(a));
        Assert.False(a[2].Relock);
    }

    [Fact]
    public void Herunterfahren_nach_angekuendigter_Abmeldung_startet_und_trennt_nichts()
    {
        Running(locked: true);
        _s.Message(2, 100, AgentMessage.Logoff, T0 + Sec(1));
        _s.AgentLost(2, 100, T0 + Sec(2));
        _s.ShuttingDown();
        Assert.Empty(TickEverySecond(T0 + Sec(2), T0 + Sec(120)));
    }

    [Fact]
    public void Nach_angekuendigter_Abmeldung_gilt_die_Zeitueberschreitung_wieder()
    {
        // „logoff“, aber die App bleibt und schweigt: nach dem Zeitfenster wie jede hängende App
        Running(locked: true);
        _s.Message(2, 100, AgentMessage.Logoff, T0 + Sec(1));
        Assert.Empty(TickEverySecond(T0 + Sec(1), T0 + Sec(1) + SessionSupervisor.LogoffWindow));
        var a = TickEverySecond(T0 + Sec(2) + SessionSupervisor.LogoffWindow, T0 + Sec(5) + SessionSupervisor.LockedTimeout + SessionSupervisor.LogoffWindow);
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.KillAgent], Kinds(a));
        // Danach verschwindet sie: Verlust, nicht Abmeldung
        var lost = _s.AgentLost(2, 100, T0 + Sec(60));
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.RevertWinLock, SupervisorActionKind.StartAgent], Kinds(lost));
    }

    [Fact]
    public void Abmeldung_einer_gesperrt_neu_gestarteten_App_wird_beim_Wiederverbinden_nicht_vergessen()
    {
        Running(locked: true);
        _s.Message(2, 100, AgentMessage.Logoff, T0 + Sec(1));
        _s.AgentLost(2, 100, T0 + Sec(2));
        // Jemand verbindet die Sitzung neu, bevor das Zeitfenster abläuft: Start gesperrt, kein zweiter Start danach
        var a = _s.SessionStarted(2, T0 + Sec(5));
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(a));
        Assert.True(a[0].Relock);
        Assert.True(_s.AgentConnected(2, 101, T0 + Sec(6)));
        Assert.Empty(TickEverySecond(T0 + Sec(6), T0 + Sec(40), beats: true, pid: 101));
    }

    [Fact]
    public void Herunterfahren_startet_und_trennt_nichts()
    {
        Running(2, 100, locked: true);
        Running(3, 200);
        _s.ShuttingDown();
        Assert.Empty(_s.AgentLost(2, 100, T0 + Sec(1)));
        Assert.Empty(_s.AgentLost(3, 200, T0 + Sec(1)));
        Assert.Empty(_s.Tick(T0 + TimeSpan.FromMinutes(5)));
        Assert.Empty(_s.SessionStarted(4, T0 + TimeSpan.FromMinutes(5)));
    }

    // ---------------- Wiederverbinden, Neustart des Dienstes ----------------

    [Fact]
    public void Wiederverbinden_waehrend_der_Wartezeit_vor_dem_Neustart_startet_gesperrt()
    {
        // Gesperrt zweimal beendet: der zweite Neustart wartet (Bremse). Wer die Sitzung in dieser Zeit mit dem
        // Windows-Kennwort neu verbindet, bekommt trotzdem eine gesperrte Vitrine.
        Running(locked: true);
        Assert.True(_s.AgentLost(2, 100, T0 + Sec(10))[2].Relock);
        Assert.True(_s.AgentConnected(2, 101, T0 + Sec(11)));
        var second = _s.AgentLost(2, 101, T0 + Sec(12));
        Assert.Equal([SupervisorActionKind.DisconnectSession, SupervisorActionKind.RevertWinLock], Kinds(second)); // Neustart erst nach der Wartezeit
        var a = _s.SessionStarted(2, T0 + Sec(12.5));
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(a));
        Assert.True(a[0].Relock);
        Assert.True(_s.IsLocked(2));
        Assert.Empty(_s.Tick(T0 + TimeSpan.FromMinutes(1))); // geplanter Neustart entfällt, Start läuft schon
    }

    [Fact]
    public void Wiederverbinden_nach_bestaetigtem_Beenden_startet_entsperrt()
    {
        Running(locked: true);
        _s.AgentLost(2, 100, T0 + Sec(10)); // gesperrt neu gestartet
        Assert.True(_s.AgentConnected(2, 101, T0 + Sec(11)));
        _s.Message(2, 101, AgentMessage.Locked, T0 + Sec(12));
        _s.Message(2, 101, AgentMessage.Unlocked, T0 + Sec(20));
        _s.Message(2, 101, AgentMessage.Exit, T0 + Sec(30));
        Assert.Equal(AuditEventType.AgentStopped, _s.AgentLost(2, 101, T0 + Sec(31))[0].Event);
        var a = _s.SessionStarted(2, T0 + Sec(60));
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(a));
        Assert.False(a[0].Relock);
    }

    [Fact]
    public void Nach_Neustart_des_Dienstes_starten_gesperrte_Sitzungen_gesperrt()
    {
        // Der Dienst trennt beim Beenden gesperrte Sitzungen und merkt sie sich; der neue Dienst startet sie gesperrt
        var locked = _s.SessionStarted(2, T0, locked: true);
        var open = _s.SessionStarted(3, T0);
        Assert.True(locked[0].Relock);
        Assert.False(open[0].Relock);
        Assert.Equal([2], _s.LockedSessions);
        // Bevor die neue App gesperrt hat, meldet sie „unlocked“: zählt nicht
        Assert.True(_s.AgentConnected(2, 100, T0 + Sec(1)));
        _s.Message(2, 100, AgentMessage.Unlocked, T0 + Sec(1));
        Assert.True(_s.IsLocked(2));
    }

    [Fact]
    public void Gemerkte_Sperre_ueberschreibt_nicht_den_Zustand_einer_schon_verbundenen_App()
    {
        // Die alte App lief weiter (Dienst nur neu gestartet) und hat sich schon entsperrt gemeldet
        Assert.True(_s.AgentConnected(2, 100, T0));
        _s.Message(2, 100, AgentMessage.Unlocked, T0);
        Assert.Empty(_s.SessionStarted(2, T0 + Sec(1), locked: true));
        Assert.False(_s.IsLocked(2));
    }

    [Fact]
    public void Gemerkte_gesperrte_Sitzungen()
    {
        Assert.Equal("2,5", ServiceState.Format([5, 2, 5]));
        Assert.Equal([2, 5], ServiceState.Parse(" 5, 2,,x,-1,0 ").Order());
        Assert.Empty(ServiceState.Parse(null));
        Assert.Equal("", ServiceState.Format([]));
    }

    // ---------------- Neustart nach Absturz ----------------

    [Fact]
    public void Gesperrt_neu_gestartete_App_gilt_als_gesperrt_bis_sie_es_selbst_meldet()
    {
        Running(locked: true);
        _s.AgentLost(2, 100, T0 + Sec(1));
        Assert.True(_s.AgentConnected(2, 101, T0 + Sec(2)));
        // Erste Meldung kommt vor der Sperre an
        _s.Message(2, 101, AgentMessage.Unlocked, T0 + Sec(2));
        Assert.True(_s.IsLocked(2));
        Assert.Contains(SupervisorActionKind.DisconnectSession, Kinds(_s.AgentLost(2, 101, T0 + Sec(3))));
    }

    [Fact]
    public void Nach_der_Sperre_gilt_das_Entsperren_der_neu_gestarteten_App()
    {
        Running(locked: true);
        _s.AgentLost(2, 100, T0 + Sec(1));
        Assert.True(_s.AgentConnected(2, 101, T0 + Sec(2)));
        _s.Message(2, 101, AgentMessage.Locked, T0 + Sec(2));
        _s.Message(2, 101, AgentMessage.Unlocked, T0 + Sec(30));
        Assert.False(_s.IsLocked(2));
    }

    [Fact]
    public void Fremde_Prozesse_aendern_nichts()
    {
        Running(locked: true);
        Assert.False(_s.AgentConnected(2, 666, T0 + Sec(1))); // zweite App in derselben Sitzung
        _s.Message(2, 666, AgentMessage.Unlocked, T0 + Sec(2));
        _s.Message(2, 666, AgentMessage.Exit, T0 + Sec(2));
        _s.Message(2, 666, AgentMessage.Logoff, T0 + Sec(2));
        Assert.Empty(_s.AgentLost(2, 666, T0 + Sec(3)));
        Assert.True(_s.IsLocked(2));
        Assert.Equal(100, _s.AgentPid(2));
        Assert.Contains(SupervisorActionKind.DisconnectSession, Kinds(_s.AgentLost(2, 100, T0 + Sec(4))));
    }

    [Fact]
    public void Absturzschleife_wird_gebremst()
    {
        Running();
        var now = T0;
        // 1. Neustart sofort
        Assert.Contains(SupervisorActionKind.StartAgent, Kinds(_s.AgentLost(2, 100, now)));
        Assert.True(_s.AgentConnected(2, 101, now));
        // 2. Neustart nach 1 s
        Assert.DoesNotContain(SupervisorActionKind.StartAgent, Kinds(_s.AgentLost(2, 101, now)));
        Assert.Empty(_s.Tick(now + TimeSpan.FromMilliseconds(500)));
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(_s.Tick(now + Sec(1))));
        Assert.True(_s.AgentConnected(2, 102, now + Sec(1)));
        // 3. Neustart nach 5 s
        _s.AgentLost(2, 102, now + Sec(1));
        Assert.Empty(TickEverySecond(now + Sec(2), now + Sec(5)));
        Assert.Equal([SupervisorActionKind.StartAgent], Kinds(_s.Tick(now + Sec(6))));
    }

    [Fact]
    public void Ohne_Verbindung_wird_hoechstens_alle_fuenf_Minuten_gestartet_und_selten_protokolliert()
    {
        // So sah der Fehler mit den Pipe-Rechten aus: Jeder Start scheitert mangels Verbindung
        _s.SessionStarted(2, T0);
        var actions = TickEverySecond(T0 + Sec(1), T0 + TimeSpan.FromHours(24));
        int starts = actions.Count(a => a.Kind == SupervisorActionKind.StartAgent);
        int audited = actions.Count(a => a.Event == AuditEventType.AgentStartFailed);
        Assert.InRange(starts, 1, 24 * 60 / 5 + 10);
        Assert.InRange(audited, SessionSupervisor.AuditedFailuresInARow, 40);
    }

    [Fact]
    public void Stabile_App_setzt_die_Zaehlung_zurueck()
    {
        Running();
        _s.AgentLost(2, 100, T0);
        _s.AgentConnected(2, 101, T0);
        // läuft lange stabil, dann Absturz: wieder sofort
        Assert.Contains(SupervisorActionKind.StartAgent, Kinds(_s.AgentLost(2, 101, T0 + TimeSpan.FromMinutes(10))));
    }

    [Fact]
    public void Start_ohne_Verbindung_wird_wiederholt()
    {
        _s.SessionStarted(2, T0);
        var a = TickEverySecond(T0 + Sec(1), T0 + SessionSupervisor.StartTimeout + Sec(1));
        Assert.Contains(a, x => x.Event == AuditEventType.AgentStartFailed);
        Assert.Contains(a, x => x.Kind == SupervisorActionKind.StartAgent);
    }

    [Fact]
    public void Gescheiterter_gesperrter_Neustart_bleibt_gesperrt()
    {
        Running(locked: true);
        _s.AgentLost(2, 100, T0);
        var a = _s.StartFailed(2, T0 + Sec(1), "error 5");
        Assert.Equal(AuditEventType.AgentStartFailed, a[0].Event);
        var retry = TickEverySecond(T0 + Sec(2), T0 + Sec(5)).Single(x => x.Kind == SupervisorActionKind.StartAgent);
        Assert.True(retry.Relock);
    }

    [Fact]
    public void Abmeldung_vergisst_die_Sitzung()
    {
        Running(locked: true);
        _s.SessionEnded(2);
        Assert.Empty(_s.AgentLost(2, 100, T0 + Sec(1)));
        Assert.Empty(_s.Tick(T0 + TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void Sitzungen_sind_getrennt()
    {
        Running(2, 100, locked: true);
        Running(3, 200);
        var a = _s.AgentLost(3, 200, T0 + Sec(1));
        Assert.DoesNotContain(SupervisorActionKind.DisconnectSession, Kinds(a));
        Assert.All(a, x => Assert.Equal(3, x.SessionId));
        Assert.True(_s.IsLocked(2));
    }

    [Theory]
    [InlineData("hello", AgentMessage.Hello)]
    [InlineData(" locked\r", AgentMessage.Locked)]
    [InlineData("unlocked", AgentMessage.Unlocked)]
    [InlineData("beat", AgentMessage.Beat)]
    [InlineData("exit", AgentMessage.Exit)]
    [InlineData("logoff", AgentMessage.Logoff)]
    public void Nachrichten(string line, AgentMessage expected)
    {
        Assert.Equal(expected, ServiceProtocol.Parse(line));
        Assert.Equal(expected, ServiceProtocol.Parse(ServiceProtocol.Format(expected)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("LOCKED")]
    [InlineData("unlock")]
    public void Unbekannte_Nachrichten(string? line) => Assert.Null(ServiceProtocol.Parse(line));

    [Fact]
    public void VerschwundeneSitzungenWerdenVergessen_GetrennteBleiben()
    {
        // Sitzung 3: abgebrochene Anmeldung ohne Abmeldemeldung; Sitzung 2: getrennt, gibt es aber noch
        _s.SessionStarted(2, T0);
        _s.SessionStarted(3, T0);

        var gone = _s.ForgetVanished(new HashSet<int> { 2, 4 });

        Assert.Equal(new[] { 3 }, gone);
        Assert.Equal(new[] { 2 }, _s.Sessions.Order().ToArray());
        Assert.Empty(_s.ForgetVanished(new HashSet<int> { 2 }));
    }
}
