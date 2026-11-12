// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Lock;

/// <summary>Was der Eingabeblocker über ein Fenster weiß, das während einer externen Anmeldung Eingaben möchte.</summary>
/// <param name="ClassName">Fensterklasse des obersten Fensters (z. B. „#32770“ für Standarddialoge).</param>
/// <param name="ProcessPath">Vollständiger Pfad der Exe, die den Inhalt zeigt (bei ApplicationFrameHost: die des Inhalts).</param>
/// <param name="IsVitrineProcess">Fenster von Vitrine selbst.</param>
/// <param name="IsOurWebView">Prozess ist der Browser-Prozess des Anmeldefensters von Vitrine oder eines seiner Kinder.</param>
/// <param name="OwnedByAllowed">Besitzer-Kette führt zu einem ausdrücklich freigegebenen Fenster (Dialog, Anmeldefenster).</param>
/// <param name="PreExisting">War schon sichtbar, als die Anmeldung begann.</param>
public sealed record AuthWindowFacts(string? ClassName, string? ProcessPath, bool IsVitrineProcess, bool IsOurWebView,
    bool OwnedByAllowed, bool PreExisting);

/// <summary>Geschützte Orte, aus denen Anmelde-Prozesse stammen dürfen (Benutzer können dort nichts ablegen).</summary>
public sealed record TrustedRoots(string SystemRoot, string? ProgramFiles, string? ProgramFilesX86)
{
    public static TrustedRoots FromEnvironment() => new(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)),
        NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)));

    private static string? NullIfEmpty(string s) => string.IsNullOrWhiteSpace(s) ? null : s;
}

/// <summary>
/// Welche fremden Fenster während einer externen Anmeldung (Microsoft, Hello, Windows-Anmeldedialog) Eingaben bekommen.
/// Unabhängige Prüfung vom 2026-10-27: Über das Anmeldefenster ließ sich eine fremde Seite öffnen, deren Datei- oder
/// Druckdialog (Standarddialog, dem Anmeldefenster gehörend, in msedgewebview2.exe) Eingaben bekam – damit hätte man unter
/// der Sperre Dateien durchsuchen und Programme starten können. Und Prozesse wurden nur am Dateinamen erkannt – eine
/// eigene „CredDialogHost.exe“ in den Downloads hätte gereicht. Jetzt:
/// <list type="number">
/// <item>Standarddialoge (#32770, NUIDialog: Öffnen, Speichern, Drucken …) nie – außer aus den reinen Anmelde-Prozessen von Windows.</item>
/// <item>Besitzer-Regel nur für Fenster von Vitrine selbst und der WebView2-Prozesse des eigenen Anmeldefensters.</item>
/// <item>Prozesse aus <c>Security.AuthUiProcesses</c> nur von geschützten Orten: die reinen Anmelde-Prozesse und alles
/// andere aus %SystemRoot%\System32 bzw. \SystemApps; msedgewebview2.exe aus dem Ordner der WebView2-Laufzeit; weitere vom
/// Administrator eingetragene Programme aus System32, SystemApps oder Program Files.</item>
/// </list>
/// </summary>
public static class ExternalAuthWindows
{
    /// <summary>Prozesse, die es nur für die Anmeldung gibt (dürfen auch mit schon sichtbaren Fenstern).</summary>
    public static readonly IReadOnlySet<string> Dedicated = new HashSet<string>(
        ["CredentialUIBroker.exe", "Microsoft.AAD.BrokerPlugin.exe", "AccountsControlHost.exe", "CredDialogHost.exe"],
        StringComparer.OrdinalIgnoreCase);

    /// <summary>Fensterklassen von Standarddialogen (Datei öffnen/speichern, Drucken, Ordner wählen, Meldungen).</summary>
    public static readonly IReadOnlySet<string> StandardDialogClasses = new HashSet<string>(["#32770", "NUIDialog"], StringComparer.OrdinalIgnoreCase);

    public const string WebViewProcess = "msedgewebview2.exe";

    public static bool Allow(AuthWindowFacts f, IReadOnlySet<string> allowedProcesses, TrustedRoots roots)
    {
        var name = FileName(f.ProcessPath);
        bool dedicated = name is not null && Dedicated.Contains(name) && IsTrustedLocation(name, f.ProcessPath, roots);

        // 1. Standarddialoge nie (Datei- und Druckdialoge öffnen den Arbeitsplatz)
        if (f.ClassName is { } cls && StandardDialogClasses.Contains(cls) && !dedicated) return false;

        // 2. Gehört einem freigegebenen Fenster – nur Vitrine selbst und die WebView2-Prozesse des eigenen Anmeldefensters
        if (f.OwnedByAllowed && (f.IsVitrineProcess || f.IsOurWebView)) return true;

        // 3. Freigegebene Prozesse, nur vom geschützten Ort
        if (name is null || !allowedProcesses.Contains(name) || !IsTrustedLocation(name, f.ProcessPath, roots)) return false;
        return dedicated || !f.PreExisting;
    }

    /// <summary>
    /// Liegt die Exe an einem Ort, an dem nur Administratoren schreiben? Reine Anmelde-Prozesse: System32 oder SystemApps;
    /// msedgewebview2.exe: Microsoft\EdgeWebView\Application unter Program Files (x86) bzw. Program Files; andere:
    /// System32, SystemApps oder Program Files.
    /// </summary>
    public static bool IsTrustedLocation(string processName, string? path, TrustedRoots roots)
    {
        var p = Normalize(path);
        if (p is null || !string.Equals(FileName(p), processName, StringComparison.OrdinalIgnoreCase)) return false;
        bool system = Under(p, Path.Combine(roots.SystemRoot, "System32")) || Under(p, Path.Combine(roots.SystemRoot, "SystemApps"));
        if (Dedicated.Contains(processName)) return system;
        if (string.Equals(processName, WebViewProcess, StringComparison.OrdinalIgnoreCase))
            return new[] { roots.ProgramFilesX86, roots.ProgramFiles }.Any(pf => pf is not null && Under(p, Path.Combine(pf, "Microsoft", "EdgeWebView", "Application")));
        return system || (roots.ProgramFiles is { } pf64 && Under(p, pf64)) || (roots.ProgramFilesX86 is { } pf86 && Under(p, pf86));
    }

    private static string? FileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var i = path.LastIndexOfAny(['\\', '/']);
        return i < 0 ? path : path[(i + 1)..];
    }

    /// <summary>Windows-Pfad vereinheitlichen: „\\?\“ weg, / → \, keine „..“-Teile (dann ungültig).</summary>
    private static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Trim().Replace('/', '\\');
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        if (p.Split('\\').Any(part => part is ".." or ".")) return null;
        return p;
    }

    private static bool Under(string path, string dir)
    {
        var d = dir.Replace('/', '\\').TrimEnd('\\') + "\\";
        return path.StartsWith(d, StringComparison.OrdinalIgnoreCase);
    }
}
