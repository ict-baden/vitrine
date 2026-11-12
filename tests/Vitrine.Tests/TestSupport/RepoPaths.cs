// SPDX-License-Identifier: MIT
namespace Vitrine.Tests.TestSupport;

/// <summary>Pfade im Repo, gefunden über Vitrine.sln oberhalb des Testordners.</summary>
internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    public static string Src => Path.Combine(Root, "src");

    /// <summary>Quelltexte ohne bin/obj.</summary>
    public static IEnumerable<string> Files(string folder, string pattern) =>
        Directory.EnumerateFiles(Path.Combine(Root, folder), pattern, SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                     && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                     && !f.Contains($"{Path.DirectorySeparatorChar}node_modules{Path.DirectorySeparatorChar}"));

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Vitrine.sln"))) return dir.FullName;
        throw new InvalidOperationException("Vitrine.sln nicht gefunden");
    }
}

/// <summary>Eigener Temp-Ordner pro Test, wird danach gelöscht.</summary>
internal sealed class TempDir : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("vitrine-test-").FullName;

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch { }
    }
}

/// <summary>Setzt die Sprache der Oberfläche für einen Test und danach zurück.</summary>
internal sealed class UiCulture : IDisposable
{
    private readonly System.Globalization.CultureInfo _ui = System.Globalization.CultureInfo.CurrentUICulture;
    private readonly System.Globalization.CultureInfo _fmt = System.Globalization.CultureInfo.CurrentCulture;

    public UiCulture(string name)
    {
        System.Globalization.CultureInfo.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo(name);
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(name);
    }

    public void Dispose()
    {
        System.Globalization.CultureInfo.CurrentUICulture = _ui;
        System.Globalization.CultureInfo.CurrentCulture = _fmt;
    }
}
