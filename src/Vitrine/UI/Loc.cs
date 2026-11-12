// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows.Markup;
using Vitrine.Core.Localization;

namespace Vitrine.UI;

/// <summary>
/// Text aus UiStrings in XAML: <c>{ui:T Key}</c> (richtlinien/13: kein Text fest im Code). Die Sprache steht beim Öffnen
/// eines Fensters fest; ein Sprachwechsel öffnet die Fenster neu. Ein fehlender Schlüssel erscheint als „[Key]“ und fällt
/// im Test <c>TextKeyTests</c> auf.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class TExtension : MarkupExtension
{
    public TExtension() { }

    public TExtension(string key) => Key = key;

    [ConstructorArgument("key")]
    public string Key { get; set; } = "";

    public override object ProvideValue(IServiceProvider serviceProvider) => Loc.T(Key);
}

/// <summary>Texte der Oberfläche (Resources/UiStrings*.resx).</summary>
public static class Loc
{
    /// <summary>
    /// Eigener ResourceManager statt einer erzeugten Klasse: Der zweite XAML-Übersetzungslauf (wpftmp) kennt erzeugte
    /// Klassen nicht (wie in Riegel).
    /// </summary>
    public static readonly System.Resources.ResourceManager Strings = new("Vitrine.Resources.UiStrings", typeof(Loc).Assembly);

    public static string T(string key) => Strings.GetString(key, CultureInfo.CurrentUICulture) ?? $"[{key}]";

    public static string F(string key, params object?[] args) => string.Format(CultureInfo.CurrentCulture, T(key), args);

    /// <summary>Meldung mit Fehlercode, Text aus <c>Error_VIT&lt;nnnn&gt;</c> in UiStrings.</summary>
    public static string Error(string code, params object?[] args) => ErrorCodes.Format(Strings, code, args);

    /// <summary>Kurzname eines Wochentags für die Zeitplan-Zeile („Mo“, „Mon“, „lun“ …).</summary>
    public static string Day(DayOfWeek d) => T("Day_" + d);
}
