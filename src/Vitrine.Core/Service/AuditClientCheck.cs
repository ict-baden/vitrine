// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Service;

/// <summary>Ergebnis der Prüfung einer Gegenstelle auf den Pipes des Dienstes. <see cref="Reason"/> englisch (Protokoll).</summary>
public sealed record AuditClientVerdict(bool Accepted, string Reason)
{
    public static readonly AuditClientVerdict Ok = new(true, "same executable");
}

/// <summary>
/// Pfade von Programmdateien vergleichbar machen, ohne das Dateisystem (das macht der Aufrufer unter Windows mit
/// GetFinalPathNameByHandle: 8.3-Namen, Verknüpfungen, Schreibweise). Hier nur, was an der Zeichenkette hängt:
/// Präfixe <c>\\?\</c>, <c>\??\</c>, <c>\\?\UNC\</c>, Schrägstriche, doppelte Trenner, Anführungszeichen, Leerraum.
/// </summary>
public static class ExecutablePath
{
    public static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Trim().Trim('"').Trim().Replace('/', '\\');
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p[8..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal) ||
                 p.StartsWith(@"\\.\", StringComparison.Ordinal)) p = p[4..];
        bool unc = p.StartsWith(@"\\", StringComparison.Ordinal);
        var body = unc ? p[2..] : p;
        while (body.Contains(@"\\", StringComparison.Ordinal)) body = body.Replace(@"\\", @"\", StringComparison.Ordinal);
        p = (unc ? @"\\" : "") + body.TrimEnd('\\');
        return p.Length == 0 ? null : p;
    }

    /// <summary>Gleiche Datei laut Pfad? Windows-Pfade: Groß- und Kleinschreibung zählt nicht.</summary>
    public static bool Same(string? a, string? b) =>
        Normalize(a) is { } x && Normalize(b) is { } y && string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Darf eine Gegenstelle auf der Protokoll- bzw. Dienst-Pipe mit dem Dienst sprechen? Nur Vitrine.exe aus dem Ordner des
/// Dienstes. Eine andere Datei mit gleichem Inhalt (Kopie, harte Verknüpfung in einem Benutzerordner) zählt nicht: Aus
/// ihrem Ordner würden Plugins und DLLs geladen, die der Benutzer ändern kann.
/// </summary>
public static class AuditClientCheck
{
    /// <param name="clientImage">Pfad der Exe der Gegenstelle (QueryFullProcessImageName), null = nicht lesbar.</param>
    /// <param name="clientFinal">Derselbe Pfad nach GetFinalPathNameByHandle, null = Datei nicht zu öffnen.</param>
    /// <param name="serviceExe">Pfad der Exe des Dienstes (Environment.ProcessPath).</param>
    /// <param name="serviceFinal">Derselbe nach GetFinalPathNameByHandle.</param>
    public static AuditClientVerdict Evaluate(string? clientImage, string? clientFinal, string serviceExe, string? serviceFinal)
    {
        if (ExecutablePath.Normalize(clientImage) is null)
            return new(false, "the path of the client's executable could not be read (process ended or access denied)");
        // Beide Seiten möglichst in der Form von GetFinalPathNameByHandle vergleichen; fehlt eine, die Rohpfade
        if (clientFinal is not null && serviceFinal is not null)
            return ExecutablePath.Same(clientFinal, serviceFinal) ? AuditClientVerdict.Ok
                : new(false, "the client is not the service's Vitrine.exe (different file)");
        return ExecutablePath.Same(clientImage, serviceExe) ? AuditClientVerdict.Ok
            : new(false, "the client is not the service's Vitrine.exe (different path)");
    }
}

/// <summary>Was die App über den Dienst weiß (Registry, Dienstverwaltung) – im Test eine Attrappe.</summary>
public interface IAuditServiceState
{
    /// <summary>Rohwert von HKLM\SOFTWARE\ICT-Baden\Vitrine\Audit, Wert „Service“ (null = fehlt oder nicht lesbar).</summary>
    object? ServiceValue { get; }

    /// <summary>Ist der Dienst installiert (bei der Dienstverwaltung bekannt)?</summary>
    bool ServiceInstalled { get; }
}

/// <summary>Schreibt der Dienst das Protokoll, so dass die App weiterleiten muss (#15)?</summary>
public static class AuditServiceDecision
{
    /// <summary>
    /// Wert „Service“: 1 = der Dienst schreibt. Der Dienst setzt ihn als DWORD; QWORD und Zeichenkette „1“ gelten auch
    /// (von Hand oder per Skript gesetzt) – sonst schriebe die App still selbst in einen Ordner, den sie nicht beschreiben darf.
    /// </summary>
    public static bool ServiceWrites(object? value) => value switch
    {
        int i => i == 1,
        long l => l == 1,
        string s => s.Trim() == "1",
        _ => false,
    };

    /// <summary>
    /// Weiterleiten, wenn der Wert gesetzt und der Dienst installiert ist. Ob er gerade läuft, zählt nicht: Läuft er nicht,
    /// warten die Einträge im Speicher (der Ordner ist für Benutzer nur lesbar).
    /// </summary>
    public static bool Expected(IAuditServiceState state) => ServiceWrites(state.ServiceValue) && state.ServiceInstalled;
}

/// <summary>
/// Gleiche Meldung (Schlüssel) höchstens einmal je Zeitraum – für Ablehnungen auf den Pipes des Dienstes: Die App
/// verbindet sich alle paar Sekunden neu, ein fremder Prozess beliebig oft; das Protokoll soll es zeigen, nicht volllaufen.
/// </summary>
public sealed class ReportLimiter(TimeSpan interval, Func<DateTimeOffset>? clock = null)
{
    public const int MaxKeys = 200;
    private readonly Dictionary<string, DateTimeOffset> _last = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<DateTimeOffset> _clock = clock ?? (() => DateTimeOffset.UtcNow);

    /// <summary>true = jetzt melden.</summary>
    public bool ShouldReport(string key)
    {
        lock (_last)
        {
            var now = _clock();
            if (_last.TryGetValue(key, out var last) && now - last < interval) return false;
            if (_last.Count >= MaxKeys) _last.Clear();
            _last[key] = now;
            return true;
        }
    }
}
