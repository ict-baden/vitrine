// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Vitrine.Core.Localization;

/// <summary>
/// Sprache der Oberfläche (richtlinien/13, Muster aus Riegel). Reihenfolge: VITRINE_LANGUAGE → Richtlinie (GPO/Intune,
/// nicht übersteuerbar) → Wahl des Benutzers → Gerätekonfiguration → Betriebssystem → Englisch. Fehlt ein Text in einer
/// Sprache, zeigt .NET den englischen aus der neutralen .resx.
/// </summary>
public static class UiLanguage
{
    /// <summary>Umgebungsvariable, die alles übersteuert (Skripte, Tests, Screenshots).</summary>
    public const string EnvironmentVariable = "VITRINE_LANGUAGE";

    /// <summary>Rückfallsprache, steht in den neutralen *Strings.resx.</summary>
    public const string Fallback = "en";

    /// <summary>Sprachen mit eigener Sprachdatei, in der Reihenfolge der Auswahlliste.</summary>
    public static IReadOnlyList<string> Supported { get; } = ["en", "de", "es", "fr", "zh-Hans"];

    /// <summary>Von Muttersprachlern geprüfte Sprachen; die anderen sind maschinell vorübersetzt (TODO-übersetzen).</summary>
    public static IReadOnlyList<string> Reviewed { get; } = ["en", "de"];

    /// <summary>Sprache des Systems beim Start, bevor Vitrine sie überschreibt.</summary>
    public static CultureInfo System { get; } = CultureInfo.CurrentUICulture;

    /// <summary>"" (keine Wahl) oder ein Code aus <see cref="Supported"/> in dessen Schreibweise.</summary>
    public static string Normalize(string? setting)
    {
        var code = setting?.Trim() ?? "";
        if (code.Length == 0) return "";
        var exact = Supported.FirstOrDefault(s => s.Equals(code, StringComparison.OrdinalIgnoreCase));
        if (exact is not null) return exact;
        // „zh“, „zh-CN“, „de-AT“ … auf eine unterstützte Sprache abbilden
        try { return FromCulture(CultureInfo.GetCultureInfo(code)) ?? ""; }
        catch (CultureNotFoundException) { return ""; }
    }

    /// <summary>Die Sprache, die gilt: die erste gültige Wahl in Reihenfolge, dann das System, sonst Englisch.</summary>
    public static string Resolve(CultureInfo system, params string?[] choices)
    {
        foreach (var choice in choices)
        {
            var chosen = Normalize(choice);
            if (chosen.Length > 0) return chosen;
        }
        return FromCulture(system) ?? Fallback;
    }

    /// <summary>
    /// Stellt die Sprache für alle Threads ein. <paramref name="choices"/> in absteigendem Vorrang (nach der
    /// Umgebungsvariablen), z. B. Richtlinie, Benutzer, Gerät.
    /// </summary>
    public static CultureInfo Apply(params string?[] choices)
    {
        var all = new string?[choices.Length + 1];
        all[0] = Environment.GetEnvironmentVariable(EnvironmentVariable);
        Array.Copy(choices, 0, all, 1, choices.Length);
        var culture = CultureInfo.GetCultureInfo(Resolve(System, all));
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentUICulture = culture;
        // Datum, Uhrzeit und Zahlen in der Sprache der Oberfläche (richtlinien/13 Punkt 5)
        var formats = FormatCulture(culture);
        CultureInfo.DefaultThreadCurrentCulture = formats;
        CultureInfo.CurrentCulture = formats;
        return culture;
    }

    /// <summary>Name einer Sprache in ihr selbst („Deutsch“, „English“, „中文(简体)“), für die Auswahlliste.</summary>
    public static string NativeName(string code)
    {
        var culture = CultureInfo.GetCultureInfo(code);
        var name = culture.NativeName;
        return name.Length == 0 ? code : char.ToUpper(name[0], culture) + name[1..];
    }

    /// <summary>Maschinell übersetzt und noch nicht von Muttersprachlern geprüft?</summary>
    public static bool IsMachineTranslated(string code) => !Reviewed.Contains(code, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Eintrag der Auswahlliste: Name der Sprache, maschinell übersetzte gekennzeichnet („Español (maschinell übersetzt)“).
    /// </summary>
    /// <param name="machineFormat">Muster mit {0} in der Sprache der Oberfläche (Language_MachineTranslated).</param>
    public static string ChoiceName(string code, string machineFormat) =>
        IsMachineTranslated(code) ? string.Format(CultureInfo.CurrentCulture, machineFormat, NativeName(code)) : NativeName(code);

    /// <summary>
    /// Kultur für Datum und Zahlen: die des Systems, wenn sie zur Sprache passt (de-AT bleibt de-AT), sonst eine
    /// spezifische Kultur der Sprache (neutrale Kulturen wie „de“ formatieren nicht überall gleich gut).
    /// </summary>
    private static CultureInfo FormatCulture(CultureInfo ui)
    {
        if (FromCulture(System) == ui.Name && !System.IsNeutralCulture) return System;
        try { return CultureInfo.CreateSpecificCulture(ui.Name); }
        catch (CultureNotFoundException) { return ui; }
    }

    private static string? FromCulture(CultureInfo culture)
    {
        for (var c = culture; !c.Equals(CultureInfo.InvariantCulture); c = c.Parent)
        {
            var match = Supported.FirstOrDefault(s => s.Equals(c.Name, StringComparison.OrdinalIgnoreCase));
            if (match is not null) return match;
            // zh-CN → zh-Hans (Parent), zh → zh-Hans (vereinfacht ist unsere chinesische Sprache)
            if (c.Name.Equals("zh", StringComparison.OrdinalIgnoreCase)) return "zh-Hans";
        }
        return null;
    }
}
