// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Auth;

/// <summary>Oberstes Fenster beim Aufräumen eines Anmeldedialogs.</summary>
/// <param name="Window">Fenster.</param>
/// <param name="Owner">Besitzer (GW_OWNER), 0 = keiner.</param>
/// <param name="ProcessName">Dateiname der Exe, null = nicht lesbar.</param>
public readonly record struct TopWindow(nint Window, nint Owner, string? ProcessName);

/// <summary>
/// Windows-Dialoge für Anmeldungen (Windows-Anmeldedialog, Windows Hello) nach Zeitlimit oder Abbruch schließen.
/// Unabhängige Prüfung vom 2026-10-27: CredUIPromptForWindowsCredentials ist modal und blockiert; nach dem Zeitlimit von
/// 2 Minuten blieb der Dialog offen, der Entsperr-Dialog gesperrt (deaktiviert), und jeder neue Versuch öffnete einen
/// weiteren. Jetzt schließt Vitrine die Dialoge, die zu diesem Versuch gehören, gibt den Entsperr-Dialog wieder frei und
/// öffnet keinen neuen, solange der alte noch läuft (<see cref="PromptGate"/>).
/// </summary>
public static class OwnedAuthDialogs
{
    /// <summary>Prozesse, in denen Windows diese Dialoge zeigt.</summary>
    public static readonly IReadOnlySet<string> Processes = new HashSet<string>(
        ["CredentialUIBroker.exe", "CredDialogHost.exe"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Zu schließende Fenster: aus einem Dialog-Prozess und entweder dem Dialog von Vitrine (<paramref name="owner"/>)
    /// gehörend oder erst nach Beginn des Versuchs erschienen (nicht in <paramref name="before"/>) – falls Windows den
    /// Besitzer nicht setzt. Fenster anderer Prozesse nie.
    /// </summary>
    public static IReadOnlyList<nint> ToClose(IEnumerable<TopWindow> windows, nint owner, IReadOnlySet<nint> before) =>
        windows.Where(w => w.Window != 0 && w.ProcessName is { } p && Processes.Contains(p)
                           && ((owner != 0 && w.Owner == owner) || !before.Contains(w.Window)))
            .Select(w => w.Window).Distinct().ToList();
}

/// <summary>Höchstens ein Windows-Anmeldedialog gleichzeitig (der blockierende Aufruf kehrt erst nach dem Schließen zurück).</summary>
public sealed class PromptGate
{
    private int _busy;

    /// <summary>Läuft gerade ein Dialog?</summary>
    public bool Busy => Volatile.Read(ref _busy) != 0;

    /// <summary>Belegen; false = es läuft schon einer.</summary>
    public bool TryEnter() => Interlocked.CompareExchange(ref _busy, 1, 0) == 0;

    public void Exit() => Volatile.Write(ref _busy, 0);
}
