// SPDX-License-Identifier: MIT
using System.Reflection;

namespace Vitrine.Core.About;

/// <summary>
/// Angaben über das Programm für Info-Fenster und Protokoll (richtlinien/07). Firma und Copyright kommen aus den
/// Assembly-Angaben (Directory.Build.props), damit ein Wechsel der Firmierung eine einzige Änderung ist.
/// </summary>
public static class AppInfo
{
    public const string Name = "Vitrine";
    public const string RepositoryUrl = "https://github.com/ict-baden/vitrine";
    public const string SupportUrl = RepositoryUrl + "/blob/main/SUPPORT.md";
    /// <summary>Datenschutzhinweise zu Vitrine auf der Webseite (seit 2026-10-21; vorher docs/data-and-privacy.md auf GitHub).</summary>
    public const string PrivacyUrl = "https://ict-baden.de/datenschutz/vitrine/";
    public const string LicenseUrl = RepositoryUrl + "/blob/main/LICENSE";
    public const string NoticesUrl = RepositoryUrl + "/blob/main/THIRD-PARTY-NOTICES.txt";
    public const string HelpUrl = RepositoryUrl + "/blob/main/docs/usage.md";

    /// <summary>
    /// Impressum – es gibt nur eines, auf der Webseite (richtlinien/07). Seit 2026-10-21 die Adresse der neuen Webseite.
    /// Gleiche Adresse in README und SUPPORT.
    /// </summary>
    public const string ImpressumUrl = "https://ict-baden.de/impressum/";

    /// <summary>
    /// Webseite (richtlinien/07: Info-Fenster verlinkt Webseite und Impressum): seit 2026-10-21 die Produktseite.
    /// </summary>
    public const string WebsiteUrl = "https://ict-baden.de/produkte/vitrine/";

    private const string FallbackPublisher = "ICT-Baden";

    private static readonly Assembly Self = typeof(AppInfo).Assembly;

    private static readonly string Informational =
        Self.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";

    /// <summary>Version ohne Build-Anhang, z. B. „0.1.0“ oder „0.1.0-ci.12“.</summary>
    public static string Version { get; } = ParseVersion(Informational);

    /// <summary>Commit-Kürzel (7 Zeichen) aus dem Build-Anhang „+&lt;commit&gt;“, null ohne.</summary>
    public static string? Commit { get; } = ParseCommit(Informational);

    /// <summary>Herausgeber (AssemblyCompany aus Directory.Build.props).</summary>
    public static string Publisher { get; } =
        Self.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company is { Length: > 0 } company && company != Name ? company : FallbackPublisher;

    /// <summary>„© 2026 ICT-Baden“ (AssemblyCopyright).</summary>
    public static string Copyright { get; } =
        Self.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright is { Length: > 0 } copyright ? copyright : $"© 2026 {Publisher}";

    internal static string ParseVersion(string informational)
    {
        var version = informational.Split('+')[0].Trim();
        return version.Length > 0 ? version : "unknown";
    }

    internal static string? ParseCommit(string informational)
    {
        int plus = informational.IndexOf('+');
        if (plus < 0) return null;
        var commit = informational[(plus + 1)..].Trim();
        if (commit.Length == 0) return null;
        return commit.Length > 7 ? commit[..7] : commit;
    }

    internal static string? ReadEmbedded(string name)
    {
        using var stream = Self.GetManifestResourceStream(name);
        if (stream is null) return null;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

/// <summary>
/// Lizenztexte für das Info-Fenster: die eigene MIT-Lizenz (LICENSE) und die der mitgelieferten Bestandteile
/// (THIRD-PARTY-NOTICES.txt). Beide sind eingebettet – die einzelne Exe hat keine Dateien daneben.
/// </summary>
public static class LicenseTexts
{
    public const string LicenseFile = "LICENSE";
    public const string NoticesFile = "THIRD-PARTY-NOTICES.txt";

    public static string? License() => Read(LicenseFile);

    public static string? ThirdPartyNotices() => Read(NoticesFile);

    /// <summary>Eingebettete Fassung, sonst die Datei neben der Exe.</summary>
    internal static string? Read(string name)
    {
        var embedded = AppInfo.ReadEmbedded(name);
        if (embedded is not null) return embedded;
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, name);
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
