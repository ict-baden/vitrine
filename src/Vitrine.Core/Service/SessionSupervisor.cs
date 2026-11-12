// SPDX-License-Identifier: MIT
using Vitrine.Core.Audit;

namespace Vitrine.Core.Service;

/// <summary>
/// Nachrichten der Sitzungs-App an den Dienst (eine Textzeile je Nachricht über \\.\pipe\ICT-Baden.Vitrine.Service).
/// Wer spricht, stellt der Dienst selbst fest (Prozess-ID, Sitzung und Exe-Pfad der Gegenstelle), nicht aus dem Text.
/// </summary>
public enum AgentMessage
{
    /// <summary>„hello“: Verbindung steht.</summary>
    Hello,
    /// <summary>„locked“: Sperre aktiv.</summary>
    Locked,
    /// <summary>„unlocked“: entsperrt.</summary>
    Unlocked,
    /// <summary>„beat“: Lebenszeichen der Oberfläche (alle <see cref="SessionSupervisor.BeatInterval"/>).</summary>
    Beat,
    /// <summary>„exit“: Beenden nach Bestätigung durch einen Administrator – nicht neu starten bis zur nächsten Anmeldung.</summary>
    Exit,
    /// <summary>
    /// „logoff“: Windows fragt, ob die Sitzung enden darf (WM_QUERYENDSESSION). Nur eine Ankündigung: Die Abmeldung kann noch
    /// abgebrochen werden, und dieselbe Nachricht kann jeder Prozess der Sitzung an die App schicken. Siehe
    /// <see cref="SessionSupervisor.LogoffWindow"/>.
    /// </summary>
    Logoff,
}

/// <summary>
/// Gesperrte Sitzungen, die sich der Dienst beim Beenden merkt (<see cref="About.AppPaths.ServiceStateKey"/>, Wert
/// <see cref="LockedSessionsValue"/>): „2,5“. Der nächste Dienst startet sie gesperrt (<see cref="SessionSupervisor.SessionStarted"/>).
/// </summary>
public static class ServiceState
{
    public const string LockedSessionsValue = "LockedSessions";

    public static string Format(IEnumerable<int> sessions) =>
        string.Join(",", sessions.Distinct().Order().Select(s => s.ToString(System.Globalization.CultureInfo.InvariantCulture)));

    /// <summary>Unlesbare Teile werden übergangen; Sitzung 0 (Dienste) zählt nie.</summary>
    public static HashSet<int> Parse(string? value) =>
        (value ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => int.TryParse(p, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : 0)
            .Where(n => n > 0)
            .ToHashSet();
}

public static class ServiceProtocol
{
    public const int MaxLineLength = 64;

    public static AgentMessage? Parse(string? line) => line?.Trim() switch
    {
        "hello" => AgentMessage.Hello,
        "locked" => AgentMessage.Locked,
        "unlocked" => AgentMessage.Unlocked,
        "beat" => AgentMessage.Beat,
        "exit" => AgentMessage.Exit,
        "logoff" => AgentMessage.Logoff,
        _ => null,
    };

    public static string Format(AgentMessage m) => m.ToString().ToLowerInvariant();
}

/// <summary>Was der Dienst für eine Sitzung tun soll.</summary>
public enum SupervisorActionKind
{
    /// <summary>Sitzungs-App starten (als angemeldeter Benutzer, in seiner Sitzung). <see cref="SupervisorAction.Relock"/>: gleich sperren.</summary>
    StartAgent,
    /// <summary>Sitzung trennen: Windows zeigt den Anmeldebildschirm, die Sitzung läuft weiter.</summary>
    DisconnectSession,
    /// <summary>Hängende Sitzungs-App beenden (danach startet <see cref="StartAgent"/> eine neue).</summary>
    KillAgent,
    /// <summary>Nur protokollieren.</summary>
    Audit,
    /// <summary>
    /// Vitrines eigenen Wert <c>DisableLockWorkstation</c> im Hive des Sitzungsbenutzers (HKU\&lt;SID&gt;) entfernen
    /// (<see cref="Lock.LockWorkstationPolicy.Revert"/>). Die App ist weg und kann es nicht mehr selbst: Sonst täte Win+L
    /// (und LockWorkStation) in dieser Sitzung nichts, bis Vitrine wieder läuft. Die neu gestartete App setzt ihn wieder.
    /// </summary>
    RevertWinLock,
}

/// <param name="Event">Eintrag fürs Protokoll (mit <paramref name="Detail"/>), null = keiner.</param>
public sealed record SupervisorAction(SupervisorActionKind Kind, int SessionId, bool Relock = false, AuditEventType? Event = null, string? Detail = null);

/// <summary>
/// Entscheidungen des Dienstes „ICT-Baden Vitrine“ für jede Sitzung, ohne Windows-Aufrufe (getestet unter Linux).
/// Grundsatz: Beenden der Sitzungs-App hilft nie. Verschwindet sie gesperrt (beendet, abgestürzt, hängt), wird die
/// Sitzung getrennt und Vitrine startet gesperrt neu; verschwindet sie entsperrt, startet sie neu. Nur ein von einem
/// Administrator bestätigtes Beenden („exit“) gilt bis zur nächsten Anmeldung oder bis die App wieder läuft.
///
/// Abmelden: Die App meldet „logoff“, bevor Windows die Sitzung beendet. Verschwindet sie danach, wartet der Dienst
/// <see cref="LogoffWindow"/> auf die Abmeldung (<see cref="SessionEnded"/>) oder das Herunterfahren. Kommt keins von beiden
/// (Abmeldung abgebrochen, Nachricht gefälscht), gilt das Verschwinden wie jeder andere Verlust – gesperrt also Trennen
/// und gesperrter Neustart.
///
/// Zeit: <c>now</c> ist eine monotone Uhr, die im Energiesparmodus und Ruhezustand stehen bleibt (im Dienst
/// QueryUnbiasedInterruptTime). Eine Uhrumstellung oder ein Schlaf des Rechners zählt so nie als Schweigen der App.
/// Zusätzlich gibt es nach dem Aufwachen (<see cref="Resumed"/>) und nach einer Lücke zwischen zwei <see cref="Tick"/>
/// eine Schonfrist: Auch die App wacht erst auf und meldet sich danach.
/// </summary>
public sealed class SessionSupervisor
{
    /// <summary>So oft meldet sich die Sitzungs-App.</summary>
    public static readonly TimeSpan BeatInterval = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Ohne Lebenszeichen so lange während der Sperre: Sitzung trennen, App neu starten. 30 s (vorher 15 s): Die Sperre selbst
    /// hängt an einem eigenen Thread (Eingabesperre) und an den Abdeckungen, die auch eine kurz hängende Oberfläche zeigt;
    /// ein Trennen wegen einer kurzen Stockung (z. B. Netzlaufwerk) war unnötig.
    /// </summary>
    public static readonly TimeSpan LockedTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Ohne Lebenszeichen so lange, wenn entsperrt (z. B. angehaltener Prozess): App neu starten.</summary>
    public static readonly TimeSpan UnlockedTimeout = TimeSpan.FromSeconds(60);

    /// <summary>So lange darf ein Start bis zum „hello“ dauern, dann gilt er als gescheitert.</summary>
    public static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(60);

    /// <summary>Nach dem Aufwachen (Energiesparmodus, Ruhezustand) so lange keine Zeitüberschreitung.</summary>
    public static readonly TimeSpan ResumeGrace = TimeSpan.FromSeconds(60);

    /// <summary>Liegen zwei <see cref="Tick"/> weiter auseinander, stand der Dienst selbst (z. B. angehaltene VM): wie Aufwachen.</summary>
    public static readonly TimeSpan TickGap = TimeSpan.FromSeconds(10);

    /// <summary>
    /// So lange nach einem angekündigten Abmelden gilt das Verschwinden der App als erwartet. Kommt in dieser Zeit weder die
    /// Abmeldung noch das Herunterfahren, war sie abgebrochen (oder die Ankündigung gefälscht): dann wie ein Verlust.
    /// Kurz, weil die Sperre so lange offen sein kann; eine länger dauernde echte Abmeldung führt höchstens zu einem
    /// überflüssigen Trennen der ohnehin endenden Sitzung.
    /// </summary>
    public static readonly TimeSpan LogoffWindow = TimeSpan.FromSeconds(20);

    /// <summary>Wartezeit vor dem n-ten Neustart in Folge (Absturzschleife bremsen), höchstens 5 Minuten.</summary>
    private static readonly TimeSpan[] Backoff =
    [
        TimeSpan.Zero, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5),
    ];

    /// <summary>So viele gescheiterte Starts in Folge werden einzeln protokolliert, danach nur noch jeder zwölfte (etwa stündlich).</summary>
    public const int AuditedFailuresInARow = 5;

    /// <summary>Läuft die App so lange ohne Absturz, beginnt die Zählung der Neustarts von vorn.</summary>
    private static readonly TimeSpan StableAfter = TimeSpan.FromMinutes(2);

    private sealed class State
    {
        public int? AgentPid;
        public bool Locked;
        public TimeSpan LastBeat;
        public TimeSpan ConnectedAt;
        public bool ExitAuthorized;
        public bool StartPending;
        public TimeSpan StartRequestedAt;
        public TimeSpan? RestartAt;
        public bool RestartRelock;
        public int Restarts;
        public int FailedStarts;
        public bool TimeoutHandled;
        /// <summary>Gesperrt neu gestartet: Bis die App „locked“ meldet, gilt ein „unlocked“ nicht (sie sperrt gleich).</summary>
        public bool RelockPending;
        /// <summary>Abmeldung angekündigt (seit <see cref="EndingAt"/>): Das Verschwinden der App ist erwartet, höchstens <see cref="LogoffWindow"/> lang.</summary>
        public bool Ending;
        public TimeSpan EndingAt;
        /// <summary>App nach angekündigter Abmeldung verschwunden: Kommt bis dahin + <see cref="LogoffWindow"/> keine Abmeldung, gilt es als Verlust.</summary>
        public TimeSpan? LostWhileEnding;
    }

    private readonly Dictionary<int, State> _sessions = new();
    private TimeSpan? _lastTick;
    private TimeSpan _graceUntil;
    private bool _suspended;
    private TimeSpan _suspendedAt;
    private bool _shuttingDown;

    public IReadOnlyCollection<int> Sessions => _sessions.Keys;

    public bool IsLocked(int session) => _sessions.TryGetValue(session, out var s) && s.Locked;

    /// <summary>Sitzungen, die gerade gesperrt sind (oder gesperrt neu starten sollen).</summary>
    public IReadOnlyList<int> LockedSessions => _sessions.Where(p => p.Value.Locked).Select(p => p.Key).Order().ToList();

    public int? AgentPid(int session) => _sessions.TryGetValue(session, out var s) ? s.AgentPid : null;

    /// <summary>
    /// Benutzer hat sich angemeldet, eine Sitzung wurde wieder verbunden, oder sie bestand schon beim Dienststart. Läuft dort
    /// keine App, startet sie im gewünschten Zustand: gesperrt, wenn die Sitzung gesperrt war oder gesperrt neu starten
    /// sollte (auch während der Wartezeit nach einem Absturz) – sonst könnte ein Wiederverbinden die Sperre aufheben.
    /// </summary>
    /// <param name="locked">Sitzung war gesperrt, als der Dienst zuletzt endete (gemerkt über den Neustart des Dienstes).</param>
    public List<SupervisorAction> SessionStarted(int session, TimeSpan now, bool locked = false)
    {
        if (_shuttingDown) return [];
        var s = Get(session);
        s.ExitAuthorized = false;
        s.Ending = false;
        // Hat sich die App schon wieder gemeldet, gilt ihr eigener Zustand
        if (locked && s.AgentPid is null) s.Locked = true;
        if (s.AgentPid is not null || s.StartPending) return [];
        return [Start(session, s, now, relock: s.Locked)];
    }

    /// <summary>Benutzer hat sich abgemeldet: Sitzung vergessen.</summary>
    public void SessionEnded(int session) => _sessions.Remove(session);

    /// <summary>
    /// Abgleich mit den Sitzungen, die Windows noch kennt (jede Minute): Sitzungen ohne Abmeldemeldung verschwinden sonst nie –
    /// z. B. eine abgebrochene Anmeldung –, und der Dienst versuchte stündlich weiter, dort die App zu starten.
    /// Gelöscht werden nur Sitzungen, die es nicht mehr gibt; getrennte Sitzungen bleiben.
    /// </summary>
    /// <returns>Die vergessenen Sitzungen.</returns>
    public IReadOnlyList<int> ForgetVanished(IReadOnlyCollection<int> existingSessions)
    {
        var gone = _sessions.Keys.Where(id => !existingSessions.Contains(id)).Order().ToList();
        foreach (var id in gone) _sessions.Remove(id);
        return gone;
    }

    /// <summary>
    /// Eine Vitrine-App derselben Exe hat sich aus der Sitzung gemeldet. Läuft dort schon eine, wird die zweite abgelehnt
    /// (false): Sie könnte sonst den Zustand der ersten überschreiben.
    /// </summary>
    public bool AgentConnected(int session, int pid, TimeSpan now)
    {
        if (_shuttingDown) return false;
        var s = Get(session);
        if (s.AgentPid is { } existing && existing != pid) return false;
        s.AgentPid = pid;
        s.StartPending = false;
        s.RestartAt = null;
        s.LastBeat = now;
        s.ConnectedAt = now;
        s.TimeoutHandled = false;
        s.FailedStarts = 0;
        // Ein früher bestätigtes Beenden gilt nicht für eine App, die danach (von Hand) wieder gestartet wurde
        s.ExitAuthorized = false;
        s.Ending = false;
        s.LostWhileEnding = null;
        return true;
    }

    public List<SupervisorAction> Message(int session, int pid, AgentMessage message, TimeSpan now)
    {
        if (!_sessions.TryGetValue(session, out var s) || s.AgentPid != pid) return [];
        s.LastBeat = now;
        s.TimeoutHandled = false;
        switch (message)
        {
            case AgentMessage.Locked:
                s.Locked = true;
                s.RelockPending = false;
                break;
            // Eine gesperrt neu gestartete App meldet sich, bevor sie gesperrt hat: dieses „unlocked“ gilt nicht
            case AgentMessage.Unlocked when !s.RelockPending:
                s.Locked = false;
                break;
            case AgentMessage.Exit when !s.Locked:
                s.ExitAuthorized = true;
                break;
            case AgentMessage.Logoff:
                s.Ending = true;
                s.EndingAt = now;
                break;
        }
        return [];
    }

    /// <summary>Die App der Sitzung ist weg (Verbindung zu, Prozess beendet).</summary>
    public List<SupervisorAction> AgentLost(int session, int pid, TimeSpan now)
    {
        if (!_sessions.TryGetValue(session, out var s) || s.AgentPid != pid) return [];
        s.AgentPid = null;
        if (_shuttingDown) return [];
        // Abmeldung angekündigt: Die Sitzung endet wohl gleich. Erst nach LogoffWindow ohne Abmeldung wie ein Verlust (Tick).
        if (s.Ending && now - s.EndingAt <= LogoffWindow)
        {
            s.LostWhileEnding = now;
            return [new(SupervisorActionKind.Audit, session, Event: AuditEventType.AgentStopped, Detail: "sign-out announced")];
        }
        s.Ending = false;
        return Lost(session, s, now, "");
    }

    /// <summary>Verlust der App: gesperrt trennen und gesperrt neu starten, sonst neu starten (außer nach bestätigtem Beenden).</summary>
    private static List<SupervisorAction> Lost(int session, State s, TimeSpan now, string suffix)
    {
        if (now - s.ConnectedAt > StableAfter) s.Restarts = 0;
        // Win+L-Wert der verschwundenen App entfernen – nach dem Trennen (das zuerst schützt), vor dem Neustart (der ihn
        // bei Bedarf wieder setzt)
        var revert = new SupervisorAction(SupervisorActionKind.RevertWinLock, session);

        if (s.Locked)
        {
            // Gesperrt verschwunden: Sitzung sofort trennen, dann gesperrt neu starten
            return Actions(new(SupervisorActionKind.DisconnectSession, session, Event: AuditEventType.AgentLost, Detail: "locked" + suffix),
                revert, Schedule(session, s, now, relock: true));
        }
        if (s.ExitAuthorized) return [new(SupervisorActionKind.Audit, session, Event: AuditEventType.AgentStopped), revert];
        return Actions(new(SupervisorActionKind.Audit, session, Event: AuditEventType.AgentLost, Detail: "unlocked" + suffix), revert,
            Schedule(session, s, now, relock: false));
    }

    /// <summary>Start gescheitert (CreateProcessAsUser) – später noch einmal.</summary>
    public List<SupervisorAction> StartFailed(int session, TimeSpan now, string error)
    {
        if (!_sessions.TryGetValue(session, out var s) || _shuttingDown) return [];
        s.StartPending = false;
        return Actions(Failure(session, s, error), Schedule(session, s, now, s.RestartRelock));
    }

    /// <summary>
    /// Windows geht in den Energiesparmodus oder Ruhezustand: bis zum Aufwachen keine Zeitüberschreitungen. Kommt kein
    /// Aufwachen (Schlaf abgebrochen), gilt nach <see cref="SuspendLimit"/> laufender Zeit wieder die normale Überwachung.
    /// </summary>
    public void Suspending(TimeSpan now)
    {
        _suspended = true;
        _suspendedAt = now;
    }

    /// <summary>Läuft die monotone Uhr nach <see cref="Suspending"/> so lange weiter, schläft der Rechner nicht.</summary>
    public static readonly TimeSpan SuspendLimit = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Windows ist aufgewacht. Alle Fristen beginnen neu, mit Schonfrist: Die App wacht gleichzeitig auf und braucht
    /// einen Moment, bis sie sich wieder meldet. Eine gesperrte App bleibt gesperrt, ihre Sperre wird nicht angefasst.
    /// </summary>
    public void Resumed(TimeSpan now)
    {
        _suspended = false;
        _graceUntil = now + ResumeGrace;
        _lastTick = now;
        foreach (var s in _sessions.Values)
        {
            s.LastBeat = now;
            s.TimeoutHandled = false;
            if (s.StartPending) s.StartRequestedAt = now;
        }
    }

    /// <summary>Windows fährt herunter: Das Verschwinden der Apps ist erwartet, nichts mehr starten oder trennen.</summary>
    public void ShuttingDown() => _shuttingDown = true;

    /// <summary>Jede Sekunde: Zeitüberschreitungen und fällige Neustarts.</summary>
    public List<SupervisorAction> Tick(TimeSpan now)
    {
        var actions = new List<SupervisorAction>();
        if (_shuttingDown) return actions;
        // Stand der Dienst selbst (Energiesparmodus ohne Meldung, angehaltene VM), behandeln wie ein Aufwachen
        if (_lastTick is { } last && now - last > TickGap) Resumed(now);
        _lastTick = now;
        if (_suspended && now - _suspendedAt > SuspendLimit) Resumed(now);
        if (_suspended) return actions;
        bool grace = now < _graceUntil;

        foreach (var (session, s) in _sessions)
        {
            // Angekündigte Abmeldung ohne Abmeldung: nur LogoffWindow lang gilt sie
            if (s.Ending && now - s.EndingAt > LogoffWindow)
            {
                s.Ending = false;
                if (s.LostWhileEnding is not null && s.AgentPid is null)
                {
                    s.LostWhileEnding = null;
                    actions.AddRange(Lost(session, s, now, ", sign-out not completed"));
                    continue;
                }
            }
            if (s.AgentPid is not null)
            {
                var silent = now - s.LastBeat;
                if (!grace && !s.TimeoutHandled && !s.Ending && silent > (s.Locked ? LockedTimeout : UnlockedTimeout))
                {
                    s.TimeoutHandled = true;
                    if (s.Locked) actions.Add(new(SupervisorActionKind.DisconnectSession, session, Event: AuditEventType.AgentLost, Detail: "not responding, locked"));
                    else actions.Add(new(SupervisorActionKind.Audit, session, Event: AuditEventType.AgentLost, Detail: "not responding, unlocked"));
                    // Beenden; AgentLost folgt, sobald der Prozess weg ist, und plant den Neustart
                    actions.Add(new(SupervisorActionKind.KillAgent, session));
                }
                continue;
            }

            if (s.StartPending && !grace && now - s.StartRequestedAt > StartTimeout)
            {
                s.StartPending = false;
                if (Failure(session, s, "no connection") is { } audit) actions.Add(audit);
                if (Schedule(session, s, now, s.RestartRelock) is { } start) actions.Add(start);
            }
            else if (!s.StartPending && s.RestartAt is { } due && now >= due)
            {
                actions.Add(Start(session, s, now, s.RestartRelock));
            }
        }
        return actions;
    }

    private static List<SupervisorAction> Actions(params SupervisorAction?[] actions) => actions.OfType<SupervisorAction>().ToList();

    private State Get(int session)
    {
        if (!_sessions.TryGetValue(session, out var s)) _sessions[session] = s = new State();
        return s;
    }

    /// <summary>Gescheiterten Start protokollieren – die ersten in Folge einzeln, danach nur jeden zwölften (kein Überlaufen des Protokolls).</summary>
    private static SupervisorAction? Failure(int session, State s, string detail)
    {
        s.FailedStarts++;
        bool audit = s.FailedStarts <= AuditedFailuresInARow || (s.FailedStarts - AuditedFailuresInARow) % 12 == 0;
        return audit
            ? new(SupervisorActionKind.Audit, session, Event: AuditEventType.AgentStartFailed,
                Detail: s.FailedStarts > 1 ? $"{detail} ({s.FailedStarts} in a row)" : detail)
            : null;
    }

    private static SupervisorAction Start(int session, State s, TimeSpan now, bool relock)
    {
        s.StartPending = true;
        s.StartRequestedAt = now;
        s.RestartAt = null;
        s.LostWhileEnding = null;
        s.Locked = relock; // bis zur ersten Meldung gilt der gewünschte Zustand
        s.RelockPending = relock;
        s.RestartRelock = relock;
        return new(SupervisorActionKind.StartAgent, session, relock);
    }

    /// <summary>Neustart planen: beim ersten Mal sofort (Start-Aktion), danach mit wachsender Wartezeit (null, Tick startet).</summary>
    private static SupervisorAction? Schedule(int session, State s, TimeSpan now, bool relock)
    {
        var delay = Backoff[Math.Min(s.Restarts, Backoff.Length - 1)];
        s.Restarts++;
        s.RestartRelock = relock;
        s.Locked = relock;
        s.RelockPending = relock;
        if (delay == TimeSpan.Zero) return Start(session, s, now, relock);
        s.RestartAt = now + delay;
        return null;
    }
}
