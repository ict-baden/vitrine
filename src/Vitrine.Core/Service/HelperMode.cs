// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Vitrine.Core.Service;

public enum HelperKind
{
    /// <summary>Normale Sitzungs-App (Infobereich, Einstellungen, Sperre, Admin-Hilfsmodi).</summary>
    None,
    /// <summary>Windows-Dienst („Vitrine.exe --service“).</summary>
    Service,
    /// <summary>Wächterprozess („Vitrine.exe --watchdog &lt;pid&gt;“).</summary>
    Watchdog,
}

/// <summary>
/// Hilfsprozesse ohne Oberfläche erkennen, bevor WPF startet: Dienst und Wächter laufen die ganze Zeit mit und brauchen
/// weder Konfiguration, Sprache noch die Ressourcen der Oberfläche (seit 2026-10-26; vorher erst in App.OnStartup, nach
/// dem Laden von WPF, App.xaml und der Konfiguration). Die Regeln sind dieselben wie vorher in App.OnStartup: Schalter
/// ohne Rücksicht auf Groß-/Kleinschreibung und Leerzeichen am Rand, „--service“ vor „--watchdog“, der Wächter nur mit
/// gültiger Prozessnummer direkt nach dem Schalter.
/// </summary>
public readonly record struct HelperMode(HelperKind Kind, int WatchdogPid = 0)
{
    public static HelperMode Detect(IReadOnlyList<string> rawArgs)
    {
        var args = rawArgs.Select(a => a.Trim()).ToArray();
        int Index(string name) => Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

        if (Index("--service") >= 0) return new(HelperKind.Service);
        var i = Index("--watchdog");
        if (i >= 0 && i + 1 < args.Length &&
            int.TryParse(args[i + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
            return new(HelperKind.Watchdog, pid);
        return new(HelperKind.None);
    }
}
