// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Lock;

/// <summary>Abschnitt einer Sperre, nach dem sich die Abdeckungen richten.</summary>
public enum LockPhase
{
    /// <summary>Gesperrt, kein Dialog offen.</summary>
    Locked,
    /// <summary>Entsperr-Dialog von Vitrine offen (liegt über den Abdeckungen).</summary>
    Prompt,
    /// <summary>Fenster eines Anmelde-Prozesses (Windows Hello, Microsoft-Anmeldung) muss bedienbar sein.</summary>
    ExternalAuth,
}

/// <param name="ClickThrough">Klicks gehen durch die Abdeckung zur Anwendung darunter (WS_EX_TRANSPARENT).</param>
/// <param name="OnTop">Abdeckungen über allen Fenstern halten (auch über „immer oben“).</param>
/// <param name="HoldForeground">Den Vordergrund (Tastatureingabe) bei Vitrine halten: bei der Abdeckung bzw. beim Dialog.</param>
public sealed record ShieldState(bool ClickThrough, bool OnTop, bool HoldForeground);

/// <summary>
/// Die Low-Level-Hooks eines Prozesses ohne Administratorrechte sehen keine Eingaben, die an Fenster mit höherer
/// Integrität gehen (UIPI: als Administrator gestarteter Task-Manager, Konsole, Gerätesoftware). Damit die Sperre dort
/// nicht nur an den Hooks hängt, fangen die Abdeckungen im gesperrten Zustand selbst die Klicks ab (nicht durchklickbar,
/// immer oben), und Vitrine holt den Vordergrund zurück, sobald ein anderes Fenster ihn hat – Tastatureingaben gehen
/// dann an Vitrine, nicht an das Fenster mit höherer Integrität. Während einer externen Anmeldung (Hello, Microsoft)
/// fangen die Abdeckungen Klicks weiter ab, liegen aber nicht mehr „immer oben“, sondern nur über den gewöhnlichen
/// Fenstern: Das danach erscheinende Anmeldefenster liegt darüber und ist bedienbar, Fenster darunter – auch solche mit
/// Administratorrechten – bleiben verdeckt. Die externe Anmeldung ist zeitlich begrenzt (<see cref="ExternalAuthTimeout"/>).
/// </summary>
public static class LockShield
{
    public static ShieldState For(LockPhase phase) => phase switch
    {
        LockPhase.Locked => new(ClickThrough: false, OnTop: true, HoldForeground: true),
        // Der Dialog liegt über den Abdeckungen; den Vordergrund holt Vitrine dann für den Dialog zurück
        LockPhase.Prompt => new(ClickThrough: false, OnTop: true, HoldForeground: true),
        // Nicht durchklickbar; HWND_NOTOPMOST legt die Abdeckung über alle gewöhnlichen Fenster, das Anmeldefenster kommt danach
        LockPhase.ExternalAuth => new(ClickThrough: false, OnTop: false, HoldForeground: false),
        _ => new(ClickThrough: false, OnTop: true, HoldForeground: true),
    };

    /// <summary>Längste Dauer einer externen Anmeldung (Hello, Microsoft); danach wird sie abgebrochen.</summary>
    public static readonly TimeSpan ExternalAuthTimeout = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Wie lange ein Fenster mit höherer Integrität den Vordergrund während der Sperre halten darf, bevor Vitrine als
    /// Rückfall Windows sperrt (LockWorkStation): Vitrine bekommt den Vordergrund von dort nicht zuverlässig zurück.
    /// </summary>
    public static readonly TimeSpan ForeignForegroundLimit = TimeSpan.FromSeconds(2);

    /// <summary>Muss als Rückfall Windows gesperrt werden? Nur gesperrt ohne Dialog, nach <see cref="ForeignForegroundLimit"/>.</summary>
    public static bool MustLockWorkstation(LockPhase phase, TimeSpan foreignForegroundFor) =>
        phase == LockPhase.Locked && foreignForegroundFor >= ForeignForegroundLimit;

    /// <summary>Muss Vitrine den Vordergrund zurückholen?</summary>
    public static bool MustTakeForeground(LockPhase phase, bool foregroundIsOwn) => For(phase).HoldForeground && !foregroundIsOwn;
}

/// <summary>Was beim angekündigten Ende der Windows-Sitzung (WM_QUERYENDSESSION) mit der Sperre geschieht.</summary>
public enum SessionEndAction
{
    /// <summary>Nicht gesperrt: aufräumen und beenden, Windows fährt fort.</summary>
    CleanUpAndExit,
    /// <summary>
    /// Gesperrt: Sperre stehen lassen und das Ende ablehnen. Erst wenn Windows die Sitzung wirklich beendet
    /// (WM_ENDSESSION mit TRUE), wird aufgeräumt.
    /// </summary>
    KeepLock,
}

/// <summary>
/// Neustart oder Abmelden während der Sperre: WM_QUERYENDSESSION ist nur eine Anfrage. Hält ein anderes Programm das
/// Ende auf, kann der Benutzer es abbrechen – hätte Vitrine bei der Anfrage schon aufgeräumt, wäre der Arbeitsplatz
/// danach ohne Sperre (Strg+Alt+Entf → Neu starten → Abbrechen; Befund vom 2026-10-21). Deshalb lehnt Vitrine das Ende
/// gesperrt ab; Windows zeigt dann die Liste der Apps, die das Ende verhindern („Trotzdem neu starten“ oder „Abbrechen“).
/// Erzwungene Neustarts (shutdown /f, Updates nach Frist) beenden Vitrine wie bisher. Zusätzlich blendet die Sperre
/// den Ein/Aus-Schalter im Strg+Alt+Entf-Menü aus (NoClose in <see cref="SasRestrictions"/>).
/// </summary>
public static class SessionEnd
{
    public static SessionEndAction OnQuery(bool locked) => locked ? SessionEndAction.KeepLock : SessionEndAction.CleanUpAndExit;

    /// <summary>
    /// Bei WM_ENDSESSION nur aufräumen, wenn die Sitzung wirklich endet: wParam TRUE (nicht abgebrochen), vorher kam in
    /// diesem Durchgang WM_QUERYENDSESSION, es ist kein Schließen einzelner Apps durch den Restart Manager
    /// (ENDSESSION_CLOSEAPP, z. B. bei einem Update) und Windows fährt die Sitzung tatsächlich herunter (SM_SHUTTINGDOWN).
    /// Eine von einem Programm der Sitzung geschickte Nachricht allein hebt die Sperre so nicht auf.
    /// </summary>
    public static bool CleanUpOnEnd(bool sessionEnding, bool queried, bool closeApp, bool systemShuttingDown) =>
        sessionEnding && queried && !closeApp && systemShuttingDown;
}
