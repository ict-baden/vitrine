// SPDX-License-Identifier: MIT
using Vitrine.Core.About;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Lock;

/// <summary>DWORD-Werte unter HKLM lesen (in der App die Registry, in Tests eine Attrappe).</summary>
public interface IMachinePolicyReader
{
    /// <summary>Aktueller Wert, null wenn nicht gesetzt oder kein DWORD.</summary>
    int? Get(string key, string value);
}

/// <summary>Warum Vitrine Win+L gerade abschaltet.</summary>
public enum WinLockReason
{
    /// <summary>Während der Vitrine-Sperre (mit <c>Security.RestrictCtrlAltDel</c>).</summary>
    Lock,
    /// <summary><c>Lock.ReplaceWinL</c>: solange Vitrine läuft, sperrt Win+L mit Vitrine.</summary>
    ReplaceWinL,
}

/// <summary>Ergebnis von <see cref="LockWorkstationPolicy.Apply"/>.</summary>
public enum WinLockStatus
{
    /// <summary>Kein Grund, Win+L abzuschalten; nichts gesetzt.</summary>
    Off,
    /// <summary>Vitrine hat <c>DisableLockWorkstation</c> gesetzt (vorheriger Zustand gemerkt).</summary>
    Applied,
    /// <summary>
    /// Unter HKLM gibt es einen Wert (Gruppenrichtlinie für den Computer): Vitrine schreibt nichts. Mit 1 ist Win+L ohnehin
    /// aus, mit 0 hat der Administrator das Sperren ausdrücklich erlaubt.
    /// </summary>
    MachinePolicy,
    /// <summary>Unter HKCU stand schon 1 (Gruppenrichtlinie oder Administrator): Vitrine schreibt und löscht nichts.</summary>
    AlreadyDisabled,
    /// <summary>Schreiben gescheitert (Sicherung oder Wert); Win+L sperrt dann weiter Windows.</summary>
    Failed,
}

/// <summary>Wie ein Rückfall Windows sperrt.</summary>
public enum FallbackLockMethod
{
    /// <summary><c>LockWorkStation()</c>, also der Windows-Sperrbildschirm.</summary>
    LockWorkstation,
    /// <summary>
    /// Sitzung trennen (<c>WTSDisconnectSession</c>): Windows zeigt den Anmeldebildschirm. Funktioniert auch, wenn eine
    /// fremde Richtlinie <c>DisableLockWorkstation</c> gesetzt hat – dann tut <c>LockWorkStation()</c> nichts.
    /// </summary>
    DisconnectSession,
}

/// <param name="Method">Womit gesperrt werden soll.</param>
/// <param name="RevertedOwnValue">Vitrines eigener Wert wurde eben entfernt bzw. zurückgesetzt.</param>
/// <param name="BlockedBy">Warum nicht <c>LockWorkStation</c>: „HKLM“ oder „HKCU“ (fremder Wert), sonst null.</param>
public sealed record FallbackLockPlan(FallbackLockMethod Method, bool RevertedOwnValue, string? BlockedBy)
{
    /// <summary>Protokolltext (Englisch, sprachunabhängig) für den Rückfall und sein Ergebnis.</summary>
    public string AuditDetail(string cause, FallbackLockOutcome outcome, int lockError = 0, int disconnectError = 0)
    {
        var how = Method == FallbackLockMethod.LockWorkstation ? "LockWorkStation" : $"disconnect (DisableLockWorkstation set by {BlockedBy})";
        var own = RevertedOwnValue ? ", own DisableLockWorkstation removed first" : "";
        return outcome switch
        {
            FallbackLockOutcome.Locked => $"{cause} -> {how}{own}",
            FallbackLockOutcome.Disconnected when Method == FallbackLockMethod.LockWorkstation =>
                $"{cause} -> LockWorkStation{own} did not lock (error {lockError}) -> {ErrorCodes.FallbackLockDisconnected} session disconnected",
            FallbackLockOutcome.Disconnected => $"{cause} -> {ErrorCodes.FallbackLockDisconnected} {how}{own}",
            _ => $"{cause} -> {ErrorCodes.FallbackLockFailed} {how}{own} failed (lock error {lockError}, disconnect error {disconnectError})",
        };
    }
}

/// <summary>Was der Rückfall erreicht hat.</summary>
public enum FallbackLockOutcome
{
    /// <summary>Windows ist gesperrt.</summary>
    Locked,
    /// <summary>Sitzung getrennt (Anmeldebildschirm).</summary>
    Disconnected,
    /// <summary>Weder Sperren noch Trennen hat geklappt – die Sitzung ist womöglich offen.</summary>
    Failed,
}

/// <summary>
/// Win+L und „Sperren“ im Strg+Alt+Entf-Menü abschalten: Benutzerrichtlinie
/// <c>HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation = 1</c>. Win+L behandelt
/// Windows selbst; ein Low-Level-Hook kann es nicht abfangen. Ist der Wert gesetzt, tut Win+L nichts mehr, und der
/// Tastendruck kommt bei den Programmen an.
///
/// <para><b>Achtung:</b> Solange der Wert gesetzt ist, sperrt auch <c>LockWorkStation()</c> nicht – genau der Rückfall,
/// den Vitrine an mehreren Stellen nutzt (Wächter, Fehlversuche, Vordergrund eines Administrator-Fensters, zweite
/// Instanz). Vor jedem Rückfall deshalb <see cref="BeforeFallbackLock"/>: entfernt Vitrines eigenen Wert und sagt, ob
/// Windows danach überhaupt sperren kann (sonst Sitzung trennen).</para>
///
/// <para>Vorheriger Zustand: in einem Merkwert unter HKCU (<see cref="AppPaths.UserStateKey"/>), nicht in einer Datei –
/// so kann auch der Dienst (SYSTEM, über HKU\&lt;SID&gt;) nach einem Absturz aufräumen. Gibt es den Merkwert, hat
/// Vitrine den Wert gesetzt. Ein Wert, den eine Richtlinie gesetzt hat (HKLM vorhanden oder HKCU schon 1), wird nie
/// überschrieben und nie gelöscht.</para>
/// </summary>
public sealed class LockWorkstationPolicy
{
    public const string Key = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
    public const string Value = "DisableLockWorkstation";

    /// <summary>Merkwert: vorheriger HKCU-Wert, <see cref="NotSet"/> = gab es nicht.</summary>
    public const string MarkerValue = "DisableLockWorkstationBefore";

    /// <summary>Im Merkwert: vor Vitrine war <c>DisableLockWorkstation</c> nicht gesetzt.</summary>
    public const int NotSet = -1;

    private readonly IUserPolicyStore _user;
    private readonly IMachinePolicyReader _machine;
    private readonly string _markerKey;
    private readonly HashSet<WinLockReason> _reasons = new();
    private readonly object _gate = new();

    /// <param name="markerKey">Schlüssel des Merkwerts relativ zum Benutzer-Hive (Standard: <see cref="AppPaths.UserStateKey"/>).</param>
    public LockWorkstationPolicy(IUserPolicyStore user, IMachinePolicyReader machine, string? markerKey = null)
    {
        _user = user;
        _machine = machine;
        _markerKey = markerKey ?? AppPaths.UserStateKey;
    }

    /// <summary>Gibt es gerade einen Grund (Sperre, ReplaceWinL)?</summary>
    public bool Held { get { lock (_gate) return _reasons.Count > 0; } }

    /// <summary>Hat Vitrine den Wert gesetzt (Merkwert vorhanden)?</summary>
    public bool IsApplied => SafeGet(_user, _markerKey, MarkerValue) is not null;

    /// <summary>Grund dazunehmen und Win+L abschalten.</summary>
    public WinLockStatus Hold(WinLockReason reason)
    {
        lock (_gate)
        {
            _reasons.Add(reason);
            return ApplyLocked();
        }
    }

    /// <summary>Grund wegnehmen; ohne Grund den eigenen Wert entfernen.</summary>
    public void Release(WinLockReason reason)
    {
        lock (_gate)
        {
            _reasons.Remove(reason);
            if (_reasons.Count == 0) Revert();
        }
    }

    /// <summary>Alle Gründe weg (Programmende).</summary>
    public void ReleaseAll()
    {
        lock (_gate)
        {
            _reasons.Clear();
            Revert();
        }
    }

    /// <summary>
    /// Erneut setzen, wenn es einen Grund gibt – nach einem Rückfall, sobald Windows wieder entsperrt bzw. die Sitzung
    /// wieder verbunden ist. Ohne Grund: nichts.
    /// </summary>
    public WinLockStatus Apply()
    {
        lock (_gate) return ApplyLocked();
    }

    private WinLockStatus ApplyLocked()
    {
        if (_reasons.Count == 0) return WinLockStatus.Off;
        // Gruppenrichtlinie für den Computer: nicht anfassen. Ein früher von Vitrine gesetzter Wert wird entfernt.
        if (SafeGet(_machine, Key, Value) is not null)
        {
            Revert();
            return WinLockStatus.MachinePolicy;
        }
        var marker = SafeGet(_user, _markerKey, MarkerValue);
        var current = SafeGet(_user, Key, Value);
        if (marker is null)
        {
            // Stand schon 1 (Gruppenrichtlinie, Administrator, Benutzer): nicht unser Wert – nie überschreiben, nie löschen
            if (current == 1) return WinLockStatus.AlreadyDisabled;
            // Erst merken, dann setzen. Lässt sich der Merkwert nicht schreiben, wird nichts gesetzt: Ohne Merkwert fände
            // niemand den Wert wieder, und Win+L (und LockWorkStation) blieben dauerhaft aus.
            try { _user.Set(_markerKey, MarkerValue, current ?? NotSet); }
            catch { return WinLockStatus.Failed; }
            if (SafeGet(_user, _markerKey, MarkerValue) is null) return WinLockStatus.Failed;
        }
        // Merkwert schon da (zweiter Grund, nach einem Rückfall, nach einem Absturz): er behält den Zustand vor Vitrine
        try { _user.Set(Key, Value, 1); }
        catch
        {
            Revert();
            return WinLockStatus.Failed;
        }
        return WinLockStatus.Applied;
    }

    /// <summary>
    /// Eigenen Wert entfernen bzw. auf den Stand vor Vitrine zurücksetzen. Nur mit Merkwert und nur, wenn noch 1 steht
    /// (hat inzwischen jemand anderes den Wert geändert, bleibt er). Gründe bleiben (für <see cref="Apply"/>).
    /// Auch beim Start nach einem Absturz, im Wächter und im Dienst. true = ein Wert wurde entfernt oder zurückgesetzt.
    /// </summary>
    public bool Revert()
    {
        var marker = SafeGet(_user, _markerKey, MarkerValue);
        if (marker is null) return false;
        bool changed = false;
        try
        {
            if (SafeGet(_user, Key, Value) == 1)
            {
                if (marker == NotSet) _user.Delete(Key, Value);
                else _user.Set(Key, Value, marker.Value);
                changed = true;
            }
        }
        catch
        {
            // Merkwert bleiben lassen: Der nächste Versuch (Start, Wächter, Dienst) räumt dann auf
            return false;
        }
        try { _user.Delete(_markerKey, MarkerValue); } catch { }
        return changed;
    }

    /// <summary>
    /// Vor jedem <c>LockWorkStation()</c>-Rückfall: eigenen Wert entfernen (die Gründe bleiben – nach dem Entsperren von
    /// Windows setzt <see cref="Apply"/> ihn wieder) und entscheiden, ob Windows danach sperren kann. Steht noch ein
    /// fremder Wert (HKLM oder HKCU = 1), sperrt <c>LockWorkStation()</c> nicht: Sitzung trennen.
    /// </summary>
    public FallbackLockPlan BeforeFallbackLock()
    {
        lock (_gate)
        {
            bool reverted = Revert();
            return Plan(SafeGet(_machine, Key, Value), SafeGet(_user, Key, Value), reverted);
        }
    }

    /// <summary>Entscheidung für den Rückfall aus den Werten nach dem Entfernen des eigenen Werts.</summary>
    public static FallbackLockPlan Plan(int? machine, int? user, bool reverted) =>
        machine == 1 ? new(FallbackLockMethod.DisconnectSession, reverted, "HKLM")
        : user == 1 ? new(FallbackLockMethod.DisconnectSession, reverted, "HKCU")
        : new(FallbackLockMethod.LockWorkstation, reverted, null);

    private static int? SafeGet(IUserPolicyStore s, string key, string value)
    {
        try { return s.Get(key, value); }
        catch { return null; }
    }

    private static int? SafeGet(IMachinePolicyReader s, string key, string value)
    {
        try { return s.Get(key, value); }
        catch { return null; }
    }
}
