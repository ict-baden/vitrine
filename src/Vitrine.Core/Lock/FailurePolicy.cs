// SPDX-License-Identifier: MIT
using Vitrine.Core.Config;

namespace Vitrine.Core.Lock;

/// <summary>Regeln für Fehlversuche: Wartezeit, verbleibende Versuche, Auslösen der Maßnahme.</summary>
public static class FailurePolicy
{
    /// <summary>Längste Wartezeit zwischen zwei Versuchen.</summary>
    public static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(30);

    /// <summary>Ab dem 3. Fehlversuch 2 s, 4 s, 8 s … höchstens 30 s; ohne <see cref="SecuritySettings.ProgressiveDelay"/> keine.</summary>
    public static TimeSpan Delay(int failed, SecuritySettings s)
    {
        if (!s.ProgressiveDelay || failed < 3) return TimeSpan.Zero;
        var seconds = Math.Min(MaxDelay.TotalSeconds, Math.Pow(2, Math.Min(failed - 2, 30)));
        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>Löst dieser Fehlversuch die Maßnahme aus (Windows sperren, abmelden, herunterfahren)?</summary>
    public static bool TriggersAction(int failed, SecuritySettings s) =>
        s.MaxFailedAttempts > 0 && s.FailureAction != FailureAction.None && failed >= s.MaxFailedAttempts;

    /// <summary>Verbleibende Versuche bis zur Maßnahme, null wenn keine Maßnahme eingestellt ist.</summary>
    public static int? Remaining(int failed, SecuritySettings s) =>
        s.MaxFailedAttempts > 0 && s.FailureAction != FailureAction.None ? Math.Max(0, s.MaxFailedAttempts - failed) : null;

    /// <summary>
    /// Argumente für shutdown.exe bei der Maßnahme „Herunterfahren“: erzwungen (/f). Ohne /f fragte Windows bei Vitrine an,
    /// und Vitrine lehnt das Ende der Sitzung gesperrt ab (SessionEnd) – die Maßnahme liefe ins Leere.
    /// </summary>
    public static string ShutdownArguments(string reason) => $"/s /f /t 0 /c \"{reason.Replace('"', '\'')}\"";

    /// <summary>Hinweis „Noch n Versuche“ nur bei den letzten beiden.</summary>
    public static bool ShouldWarn(int? remaining) => remaining is > 0 and <= 2;
}

/// <summary>
/// Zählt Fehlversuche und hält die Wartezeit über einzelne Dialoge hinweg fest: Schließen und neu Öffnen des Dialogs
/// setzt sie nicht zurück. Zurückgesetzt wird nur nach einem erfolgreichen Entsperren (nicht nach Signatur oder
/// Admin-Bestätigung, damit eine eigene gültige Anmeldung das Zählen nicht aushebelt).
/// </summary>
public sealed class FailureThrottle
{
    private DateTimeOffset _blockedUntil = DateTimeOffset.MinValue;

    public int Failed { get; private set; }

    /// <summary>Wie lange noch gewartet werden muss, null wenn ein Versuch erlaubt ist.</summary>
    public TimeSpan? Remaining(DateTimeOffset now) => now < _blockedUntil ? _blockedUntil - now : null;

    /// <summary>Fehlversuch zählen; liefert die neue Wartezeit.</summary>
    public TimeSpan RecordFailure(DateTimeOffset now, SecuritySettings s)
    {
        Failed++;
        var delay = FailurePolicy.Delay(Failed, s);
        _blockedUntil = now + delay;
        return delay;
    }

    public void Reset()
    {
        Failed = 0;
        _blockedUntil = DateTimeOffset.MinValue;
    }
}
