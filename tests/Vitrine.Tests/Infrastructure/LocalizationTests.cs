// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Vitrine.Core.Localization;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Infrastructure;

/// <summary>
/// Sprachdateien (richtlinien/13): jede .resx in fünf Sprachen mit denselben Schlüsseln und Platzhaltern, ohne leere
/// Texte; Vorübersetzungen gekennzeichnet; jeder im Code benutzte Schlüssel vorhanden; Fehlercodes mit Text; Sprachwahl.
/// </summary>
public sealed partial class LocalizationTests
{
    public static TheoryData<string, string> Owners => new()
    {
        { "src/Vitrine.Core/Resources", "CoreStrings" },
        { "src/Vitrine/Resources", "UiStrings" },
    };

    private static readonly string[] PreTranslated = ["es", "fr", "zh-Hans"];

    [Theory]
    [MemberData(nameof(Owners))]
    public void Jede_Sprachdatei_gibt_es_in_fuenf_Sprachen_mit_denselben_Schluesseln_und_Platzhaltern(string folder, string name)
    {
        var english = Load(Path.Combine(RepoPaths.Root, folder, name + ".resx"));
        Assert.NotEmpty(english);
        foreach (var code in UiLanguage.Supported.Where(c => c != UiLanguage.Fallback))
        {
            var other = Load(Path.Combine(RepoPaths.Root, folder, $"{name}.{code}.resx"));
            Assert.Equal(english.Keys.Order(StringComparer.Ordinal), other.Keys.Order(StringComparer.Ordinal));
            foreach (var (key, text) in other)
                Assert.True(Placeholders(english[key]).SetEquals(Placeholders(text)), $"{name}.{code}: {key} – „{english[key]}“ vs. „{text}“");
        }
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public void Keine_leeren_Texte(string folder, string name)
    {
        foreach (var code in UiLanguage.Supported)
        {
            var file = Path.Combine(RepoPaths.Root, folder, code == UiLanguage.Fallback ? name + ".resx" : $"{name}.{code}.resx");
            foreach (var (key, text) in Load(file))
                Assert.False(string.IsNullOrWhiteSpace(text), $"{Path.GetFileName(file)}: {key} ist leer");
        }
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public void Vorübersetzte_Sprachen_sind_gekennzeichnet_geprüfte_nicht(string folder, string name)
    {
        foreach (var code in UiLanguage.Supported.Where(c => c != UiLanguage.Fallback))
        {
            var text = File.ReadAllText(Path.Combine(RepoPaths.Root, folder, $"{name}.{code}.resx"));
            bool marked = text.Contains("Maschinell vorübersetzt – TODO-übersetzen", StringComparison.Ordinal);
            Assert.Equal(PreTranslated.Contains(code), marked);
            Assert.Equal(!UiLanguage.Reviewed.Contains(code), marked);
        }
    }

    [Fact]
    public void Jede_resx_im_Repo_gehoert_zu_einem_bekannten_Besitzer()
    {
        var known = Owners.Select(o => Path.GetFullPath(Path.Combine(RepoPaths.Root, (string)o[0], (string)o[1] + ".resx"))).ToHashSet();
        foreach (var file in RepoPaths.Files("src", "*.resx").Where(f => Path.GetFileName(f).Count(c => c == '.') == 1))
            Assert.Contains(Path.GetFullPath(file), known);
    }

    [Fact]
    public void Jeder_benutzte_Schluessel_existiert()
    {
        var core = Load(Path.Combine(RepoPaths.Root, "src/Vitrine.Core/Resources/CoreStrings.resx"));
        var ui = Load(Path.Combine(RepoPaths.Root, "src/Vitrine/Resources/UiStrings.resx"));
        var missing = new List<string>();

        foreach (var file in RepoPaths.Files("src", "*.cs"))
        {
            var text = File.ReadAllText(file);
            foreach (Match m in CoreUse().Matches(text))
                if (!core.ContainsKey(m.Groups[1].Value)) missing.Add($"{Path.GetFileName(file)}: CoreStrings {m.Groups[1].Value}");
            foreach (Match m in UiUse().Matches(text))
                if (!ui.ContainsKey(m.Groups[1].Value)) missing.Add($"{Path.GetFileName(file)}: UiStrings {m.Groups[1].Value}");
        }
        foreach (var file in RepoPaths.Files("src", "*.xaml"))
            foreach (Match m in XamlUse().Matches(File.ReadAllText(file)))
                if (!ui.ContainsKey(m.Groups[1].Value)) missing.Add($"{Path.GetFileName(file)}: UiStrings {m.Groups[1].Value}");

        Assert.True(missing.Count == 0, string.Join("\n", missing));
    }

    [Fact]
    public void Kein_fester_Text_in_XAML()
    {
        // Erlaubt: Produktname, Symbole (Segoe Fluent Icons), JSON-Beispiele der Schnittstelle
        var problems = new List<string>();
        foreach (var file in RepoPaths.Files("src", "*.xaml"))
            foreach (Match m in XamlLiteral().Matches(File.ReadAllText(file)))
            {
                var value = m.Groups[2].Value;
                if (value is "Vitrine" or "Windows Hello" or "Microsoft Entra ID" || value.StartsWith("&#x", StringComparison.Ordinal)) continue;
                if (value.Any(char.IsLetter)) problems.Add($"{Path.GetFileName(file)}: {m.Groups[1].Value}=\"{value}\"");
            }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void Jeder_Fehlercode_hat_einen_Text_ausser_der_Schnittstelle()
    {
        var core = Load(Path.Combine(RepoPaths.Root, "src/Vitrine.Core/Resources/CoreStrings.resx"));
        var ui = Load(Path.Combine(RepoPaths.Root, "src/Vitrine/Resources/UiStrings.resx"));
        Assert.Equal(ErrorCodes.All.Count, ErrorCodes.All.Distinct().Count());
        foreach (var code in ErrorCodes.All.Where(c => string.CompareOrdinal(c, "VIT-0200") < 0))
        {
            var key = ErrorCodes.Key(code);
            Assert.True(core.ContainsKey(key) || ui.ContainsKey(key), $"{code}: kein Text {key}");
            Assert.False(core.ContainsKey(key) && ui.ContainsKey(key), $"{code}: Text doppelt");
        }
        Assert.All(ErrorCodes.All, c => Assert.Matches(@"^VIT-\d{4}$", c));
    }

    [Fact]
    public void Fehlercodes_stehen_in_der_Doku()
    {
        var doc = File.ReadAllText(Path.Combine(RepoPaths.Root, "docs/error-codes.md"));
        Assert.All(ErrorCodes.All, c => Assert.Contains(c, doc));
    }

    [Theory]
    [InlineData("de-DE", "de")]
    [InlineData("de-AT", "de")]
    [InlineData("en-US", "en")]
    [InlineData("fr-CA", "fr")]
    [InlineData("es-MX", "es")]
    [InlineData("zh-CN", "zh-Hans")]
    [InlineData("zh-SG", "zh-Hans")]
    [InlineData("it-IT", "en")]
    public void Sprache_folgt_dem_System_wenn_nichts_gewaehlt_ist(string system, string expected) =>
        Assert.Equal(expected, UiLanguage.Resolve(CultureInfo.GetCultureInfo(system)));

    [Fact]
    public void Erste_gueltige_Wahl_gewinnt()
    {
        var system = CultureInfo.GetCultureInfo("fr-FR");
        Assert.Equal("es", UiLanguage.Resolve(system, "es", "de", "en"));
        Assert.Equal("de", UiLanguage.Resolve(system, null, "de", "en"));
        Assert.Equal("en", UiLanguage.Resolve(system, "", " ", "EN"));
        Assert.Equal("fr", UiLanguage.Resolve(system, "klingonisch", null, null));
        Assert.Equal("zh-Hans", UiLanguage.Normalize("zh"));
    }

    [Fact]
    public void Texte_in_der_Sprache_sonst_Englisch_mit_Code()
    {
        using (new UiCulture("de")) Assert.Equal("Benutzername oder Kennwort ist falsch. (VIT-0101)", CoreText.Error(ErrorCodes.WrongCredentials));
        using (new UiCulture("en")) Assert.Equal("The user name or password is incorrect. (VIT-0101)", CoreText.Error(ErrorCodes.WrongCredentials));
        using (new UiCulture("it")) Assert.Equal("The user name or password is incorrect. (VIT-0101)", CoreText.Error(ErrorCodes.WrongCredentials));
        using (new UiCulture("zh-Hans")) Assert.Contains("VIT-0101", CoreText.Error(ErrorCodes.WrongCredentials));
    }

    [Fact]
    public void Code_wird_nicht_doppelt_angehaengt()
    {
        using var _ = new UiCulture("en");
        Assert.Equal("x (VIT-0101)", ErrorCodes.WithCode("x (VIT-0101)", "VIT-0101"));
        Assert.Equal("x", ErrorCodes.WithCode("x", null));
    }

    internal static Dictionary<string, string> Load(string file)
    {
        Assert.True(File.Exists(file), $"{file} fehlt");
        return XDocument.Load(file).Root!.Elements("data")
            .ToDictionary(d => (string)d.Attribute("name")!, d => (string?)d.Element("value") ?? "");
    }

    [GeneratedRegex(@"\{(\d+)(?:[,:][^}]*)?\}")]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"CoreText\.(?:T|F)\(""([A-Za-z0-9_]+)""")]
    private static partial Regex CoreUse();

    [GeneratedRegex(@"\bLoc\.(?:T|F)\(""([A-Za-z0-9_]+)""")]
    private static partial Regex UiUse();

    [GeneratedRegex(@"\{ui:T ([A-Za-z0-9_]+)\}")]
    private static partial Regex XamlUse();

    [GeneratedRegex(@"\b(Title|Header|Description|Text|Content|ToolTip)=""([^""{][^""]*)""")]
    private static partial Regex XamlLiteral();

    private static SortedSet<int> Placeholders(string text) =>
        new(Placeholder().Matches(text.Replace("{{", "").Replace("}}", "")).Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)));

    [Fact]
    public void Maschinell_uebersetzte_Sprachen_sind_in_der_Auswahl_gekennzeichnet()
    {
        using var _ = new UiCulture("en");
        Assert.Equal("Deutsch", UiLanguage.ChoiceName("de", "{0} (machine translation)"));
        Assert.Equal("English", UiLanguage.ChoiceName("en", "{0} (machine translation)"));
        Assert.Equal("Español (machine translation)", UiLanguage.ChoiceName("es", "{0} (machine translation)"));
        Assert.True(UiLanguage.IsMachineTranslated("fr"));
        Assert.True(UiLanguage.IsMachineTranslated("zh-Hans"));
        Assert.False(UiLanguage.IsMachineTranslated("DE"));
    }
}
