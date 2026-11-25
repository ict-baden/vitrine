// SPDX-License-Identifier: MIT
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Vitrine.Core.About;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Infrastructure;

/// <summary>Pflichten aus den Richtlinien, die sich am Repo prüfen lassen (03, 06, 12).</summary>
public sealed class RepositoryTests
{
    [Fact]
    public void Jede_Quelldatei_beginnt_mit_SPDX()
    {
        var files = RepoPaths.Files("src", "*.cs").Concat(RepoPaths.Files("tests", "*.cs")).Concat(RepoPaths.Files("samples", "*.cs"));
        var missing = files.Where(f => !File.ReadLines(f).First().StartsWith("// SPDX-License-Identifier: MIT", StringComparison.Ordinal)).ToList();
        Assert.True(missing.Count == 0, string.Join("\n", missing));
    }

    [Fact]
    public void Firmierung_steht_an_einer_Stelle_und_LICENSE_stimmt_ueberein()
    {
        var props = XDocument.Load(Path.Combine(RepoPaths.Root, "Directory.Build.props"));
        var company = props.Descendants("Company").Single().Value;
        Assert.Equal("ICT Baden GmbH", company);
        Assert.Equal(company, AppInfo.Publisher);
        var license = File.ReadAllText(Path.Combine(RepoPaths.Root, "LICENSE"));
        Assert.StartsWith("MIT License", license);
        Assert.Contains($"Copyright (c) 2026 {company}\n", license.Replace("\r\n", "\n"));
        // MSI und App lesen die Firmierung aus Directory.Build.props
        Assert.Contains("Manufacturer=\"$(Manufacturer)\"", File.ReadAllText(Path.Combine(RepoPaths.Root, "installer/Package.wxs")));
        Assert.Contains("Manufacturer=$(Company)", File.ReadAllText(Path.Combine(RepoPaths.Root, "installer/Vitrine.Installer.wixproj")));
        Assert.DoesNotContain("<Company>", File.ReadAllText(Path.Combine(RepoPaths.Root, "src/Vitrine/Vitrine.csproj")));
    }

    [Theory]
    [InlineData("ICT Baden GmbH", true)]
    [InlineData("ICT-Baden", true)] // Versionsinfo der Builds bis 0.5.1
    [InlineData("ICT Baden", false)]
    [InlineData("Contoso", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Herausgeber_erkennt_auch_Builds_mit_der_frueheren_Angabe(string? company, bool expected) =>
        Assert.Equal(expected, AppInfo.IsOwnPublisher(company));

    [Fact]
    public void Bilder_aus_README_und_Doku_gibt_es()
    {
        // Prüfung vom 2026-10-20: usage.md zeigte auf Screenshots, die nie eingecheckt waren
        var missing = new List<string>();
        var pages = new[] { Path.Combine(RepoPaths.Root, "README.md") }.Concat(RepoPaths.Files("docs", "*.md"));
        foreach (var page in pages)
            foreach (Match m in Regex.Matches(File.ReadAllText(page), @"(?:\]\(|src=""|srcset="")(?<p>[^)""\s]*assets/[^)""\s]+\.(?:png|svg|jpg|gif))"))
            {
                var file = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(page)!, m.Groups["p"].Value));
                if (!File.Exists(file)) missing.Add($"{Path.GetRelativePath(RepoPaths.Root, page)}: {m.Groups["p"].Value}");
            }
        Assert.True(missing.Count == 0, string.Join("\n", missing));
    }

    [Fact]
    public void Keine_Verweise_mehr_auf_das_alte_Repo()
    {
        var hits = new List<string>();
        foreach (var file in RepoPaths.Files(".", "*").Where(f => Path.GetExtension(f) is ".md" or ".cs" or ".xaml" or ".wxs" or ".yml" or ".ps1" or ".json" or ".admx" or ".adml" or ".html" or ".txt")
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}") && !f.EndsWith("RepositoryTests.cs", StringComparison.Ordinal)))
            if (File.ReadAllText(file).Contains("gear1900/vitrine", StringComparison.OrdinalIgnoreCase)) hits.Add(file);
        Assert.True(hits.Count == 0, string.Join("\n", hits));
    }

    [Fact]
    public void Version_ist_0_x_solange_nicht_in_echter_Umgebung_getestet()
    {
        var csproj = XDocument.Load(Path.Combine(RepoPaths.Root, "src/Vitrine/Vitrine.csproj"));
        var version = csproj.Descendants("Version").Single().Value;
        Assert.StartsWith("0.", version);
    }

    [Fact]
    public void Jede_ausgelieferte_Abhaengigkeit_steht_in_den_Hinweisen()
    {
        var notices = File.ReadAllText(Path.Combine(RepoPaths.Root, "THIRD-PARTY-NOTICES.txt"));
        var csproj = XDocument.Load(Path.Combine(RepoPaths.Root, "src/Vitrine/Vitrine.csproj"));
        foreach (var p in csproj.Descendants("PackageReference"))
        {
            var id = p.Attribute("Include")!.Value;
            var version = p.Attribute("Version")!.Value.Trim('[', ']'); // [4.84.1] = genau diese Version
            Assert.Contains($"\"{id}\"", notices);
            Assert.Contains(version, notices);
        }
        // Mitgelieferte Teile mit eigener Lizenz (Ausnahmen nach richtlinien/02 und 06)
        Assert.Contains("Microsoft.Windows.SDK.NET.dll", notices);
        Assert.Contains("MICROSOFT SOFTWARE LICENSE TERMS", notices);
        Assert.Contains("Microsoft Reciprocal License", notices);
    }

    [Fact]
    public void WebView2_Lader_mit_geprueften_Lizenz_und_Pruefsummen()
    {
        // Anmeldefenster (seit 2026-10): WebView2Loader.dll wird weitergegeben. Version, Lizenztext (LICENSE.txt des Pakets)
        // und Prüfsumme stehen in check-broker-licence.ps1; die CI scheitert, wenn eins davon abweicht.
        var csproj = XDocument.Load(Path.Combine(RepoPaths.Root, "src/Vitrine/Vitrine.csproj"));
        var version = csproj.Descendants("PackageReference").Single(p => p.Attribute("Include")!.Value == "Microsoft.Web.WebView2").Attribute("Version")!.Value;
        var script = File.ReadAllText(Path.Combine(RepoPaths.Root, ".github/scripts/check-broker-licence.ps1"));
        Assert.Contains($"$WebView2Version = '{version}'", script);
        Assert.Contains("$LoaderHash = '", script);
        Assert.Contains("LoaderHash", File.ReadAllText(Path.Combine(RepoPaths.Root, ".github/scripts/msi-test.ps1")));
        var notices = File.ReadAllText(Path.Combine(RepoPaths.Root, "THIRD-PARTY-NOTICES.txt"));
        Assert.Contains($"Microsoft Edge WebView2 SDK {version}", notices);
        Assert.Contains("WebView2Loader.dll", notices);
        Assert.Contains("D. Microsoft Edge WebView2 SDK licence", notices);
    }

    [Fact]
    public void Windows_Kontobroker_nur_in_der_letzten_MIT_Version()
    {
        // msalruntime.dll (Microsoft.Identity.Client.NativeInterop) steht bis 0.20.4 unter MIT, ab 0.20.6 unter
        // Lizenzbedingungen, die die Weitergabe verbieten (Abschnitt 3 e). Microsoft.Identity.Client.Broker ab 4.84.2 zieht
        // 0.20.6 nach. Deshalb: alles genau festgelegt, Broker im Standard-Build, -p:WamBroker=false baut ohne.
        var text = File.ReadAllText(Path.Combine(RepoPaths.Root, "src/Vitrine/Vitrine.csproj"));
        var csproj = XDocument.Parse(text);
        string Version(string id) => csproj.Descendants("PackageReference").Single(p => p.Attribute("Include")!.Value == id).Attribute("Version")!.Value;
        Assert.Equal("[4.84.1]", Version("Microsoft.Identity.Client"));
        Assert.Equal("[4.84.1]", Version("Microsoft.Identity.Client.Broker"));
        Assert.Equal("[0.20.4]", Version("Microsoft.Identity.Client.NativeInterop"));
        foreach (var id in new[] { "Microsoft.Identity.Client.Broker", "Microsoft.Identity.Client.NativeInterop" })
        {
            var p = csproj.Descendants("PackageReference").Single(p => p.Attribute("Include")!.Value == id);
            Assert.Contains("'$(WamBroker)' == 'true'", (string?)p.Parent!.Attribute("Condition") ?? "");
        }
        Assert.Contains("<WamBroker Condition=\"'$(WamBroker)' == ''\">true</WamBroker>", text);

        var notices = File.ReadAllText(Path.Combine(RepoPaths.Root, "THIRD-PARTY-NOTICES.txt"));
        Assert.Contains("\"Microsoft.Identity.Client.NativeInterop\" 0.20.4", notices);
        Assert.Contains("msalruntime.dll", notices);
        // Die CI prüft Version, Lizenz und Prüfsumme in den fertigen Paketen, Dependabot schlägt keine neueren Stände vor
        Assert.Contains("check-broker-licence.ps1", File.ReadAllText(Path.Combine(RepoPaths.Root, ".github/workflows/build.yml")));
        Assert.Contains("$NativeInteropVersion = '0.20.4'", File.ReadAllText(Path.Combine(RepoPaths.Root, ".github/scripts/check-broker-licence.ps1")));
        var dependabot = File.ReadAllText(Path.Combine(RepoPaths.Root, ".github/dependabot.yml"));
        Assert.Contains("dependency-name: \"Microsoft.Identity.Client.NativeInterop\"", dependabot);
        Assert.Contains("versions: [\">= 0.20.5\"]", dependabot);
    }

    [Fact]
    public void Doku_nennt_Zahl_und_Revision_der_Richtlinien_wie_die_ADMX()
    {
        // Prüfung vom 2026-10-20: Doku sagte 46 Richtlinien und Revision 2.0, die ADMX hatte 52 und 2.1
        var admx = XDocument.Load(Path.Combine(RepoPaths.Root, "policy/Vitrine.admx"));
        XNamespace ns = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
        var count = admx.Descendants(ns + "policy").Count();
        var revision = admx.Root!.Attribute("revision")!.Value;
        var install = File.ReadAllText(Path.Combine(RepoPaths.Root, "docs/installation.md"));
        Assert.Contains($"{count} policies", File.ReadAllText(Path.Combine(RepoPaths.Root, "README.md")));
        Assert.Contains($"{count} policies", install);
        Assert.DoesNotMatch(@"revision (?!" + Regex.Escape(revision) + @"\b)\d+\.\d+", install);
        foreach (var lang in new[] { "en-US", "de-DE" })
            Assert.Equal(revision, XDocument.Load(Path.Combine(RepoPaths.Root, $"policy/{lang}/Vitrine.adml")).Root!.Attribute("revision")!.Value);
    }

    [Theory]
    [InlineData("en-US")]
    [InlineData("de-DE")]
    public void Jede_Richtlinie_hat_einen_Erklaertext(string lang)
    {
        // Prüfung vom 2026-10-20: 45 englische (33 deutsche) Erklärtexte wiederholten nur den Titel
        var adml = XDocument.Load(Path.Combine(RepoPaths.Root, $"policy/{lang}/Vitrine.adml"));
        var strings = adml.Descendants().Where(e => e.Name.LocalName == "string")
            .ToDictionary(e => (string)e.Attribute("id")!, e => e.Value.Trim());
        var missing = strings.Where(p => p.Key.EndsWith("_Help", StringComparison.Ordinal) &&
                                         (p.Value.Length == 0 || p.Value == strings.GetValueOrDefault(p.Key[..^5])))
            .Select(p => p.Key).ToList();
        Assert.True(missing.Count == 0, string.Join(", ", missing));
    }

    [Fact]
    public void XML_Dateien_sind_wohlgeformt()
    {
        // Ein „--“ in einem XML-Kommentar der Package.wxs fiel erst beim MSI-Build in der CI auf (WIX0104)
        var files = new[] { "*.wxs", "*.wixproj", "*.csproj", "*.props", "*.admx", "*.adml", "*.resx", "*.xaml" }
            .SelectMany(pattern => new[] { "installer", "policy", "src", "tests", "samples" }.SelectMany(dir => RepoPaths.Files(dir, pattern)))
            .Append(Path.Combine(RepoPaths.Root, "Directory.Build.props"));
        var broken = new List<string>();
        foreach (var file in files)
            try { XDocument.Load(file); }
            catch (System.Xml.XmlException ex) { broken.Add($"{file}: {ex.Message}"); }
        Assert.True(broken.Count == 0, string.Join("\n", broken));
    }

    [Fact]
    public void Keine_Personennamen_aus_dem_alten_Stand()
    {
        var hits = new List<string>();
        foreach (var file in RepoPaths.Files("src", "*.*").Concat(RepoPaths.Files("docs", "*.md")).Where(f => !f.EndsWith(".png", StringComparison.Ordinal) && !f.EndsWith(".ico", StringComparison.Ordinal) && !f.EndsWith(".gif", StringComparison.Ordinal)))
            if (Regex.IsMatch(File.ReadAllText(file), "Max Mustermann|m\\.muster|mmuster")) hits.Add(file);
        Assert.True(hits.Count == 0, string.Join("\n", hits));
    }

    [Theory]
    [InlineData("0.1.0-ci.12+abcdef0123456789", "0.1.0-ci.12", "abcdef0")]
    [InlineData("0.1.0", "0.1.0", null)]
    [InlineData("", "unknown", null)]
    [InlineData("1.0.0+", "1.0.0", null)]
    public void Version_und_Commit_aus_der_Assembly(string informational, string version, string? commit)
    {
        Assert.Equal(version, AppInfo.ParseVersion(informational));
        Assert.Equal(commit, AppInfo.ParseCommit(informational));
    }

    [Fact]
    public void Lizenztexte_sind_eingebettet()
    {
        Assert.StartsWith("MIT License", LicenseTexts.License());
        Assert.StartsWith("THIRD-PARTY NOTICES", LicenseTexts.ThirdPartyNotices());
        Assert.Equal("ICT-Baden", AppPaths.Vendor);
    }

    [Fact]
    public void Impressum_Datenschutz_und_Produktseite_auf_der_Webseite()
    {
        Assert.Equal("https://ict-baden.de/impressum/", AppInfo.ImpressumUrl);
        Assert.Equal("https://ict-baden.de/datenschutz/vitrine/", AppInfo.PrivacyUrl);
        Assert.Equal("https://ict-baden.de/produkte/vitrine/", AppInfo.WebsiteUrl);
        foreach (var file in new[] { "README.md", "SUPPORT.md" })
            Assert.Contains(AppInfo.ImpressumUrl, File.ReadAllText(Path.Combine(RepoPaths.Root, file)));
    }

    [Fact]
    public void Beispieladressen_nur_mit_example_com_oder_contoso_com()
    {
        // Prüfung vom 2026-10-21: name@firma.de, company.com usw. sind echte Domänen
        string[] forbidden = ["firma.de", "company.com", "empresa.com", "entreprise.com", "beispiel.de", "example.de"];
        var files = RepoPaths.Files("src", "*.*").Concat(RepoPaths.Files("docs", "*.md")).Concat(RepoPaths.Files("policy", "*.*"))
            .Concat(RepoPaths.Files("samples", "*.*")).Append(Path.Combine(RepoPaths.Root, "README.md"))
            .Where(f => Path.GetExtension(f) is ".cs" or ".resx" or ".md" or ".xaml" or ".adml" or ".ps1" or ".json");
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            foreach (var domain in forbidden)
                Assert.False(text.Contains("@" + domain, StringComparison.OrdinalIgnoreCase) || text.Contains("." + domain, StringComparison.OrdinalIgnoreCase),
                    $"{Path.GetRelativePath(RepoPaths.Root, file)}: {domain}");
        }
    }
}
