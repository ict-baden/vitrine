// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Vitrine.UI;

/// <summary>Eine Einstellungszeile im Windows-11-Stil: Symbol, Titel, Beschreibung, Steuerelement rechts.</summary>
public class SettingCard : ContentControl
{
    public static readonly DependencyProperty HeaderProperty =
        DependencyProperty.Register(nameof(Header), typeof(string), typeof(SettingCard), new PropertyMetadata(""));
    public static readonly DependencyProperty DescriptionProperty =
        DependencyProperty.Register(nameof(Description), typeof(string), typeof(SettingCard), new PropertyMetadata(null));
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(nameof(Glyph), typeof(string), typeof(SettingCard), new PropertyMetadata(null));
    public static readonly DependencyProperty IsManagedProperty =
        DependencyProperty.Register(nameof(IsManaged), typeof(bool), typeof(SettingCard), new PropertyMetadata(false));

    public string Header { get => (string)GetValue(HeaderProperty); set => SetValue(HeaderProperty, value); }
    public string? Description { get => (string?)GetValue(DescriptionProperty); set => SetValue(DescriptionProperty, value); }
    public string? Glyph { get => (string?)GetValue(GlyphProperty); set => SetValue(GlyphProperty, value); }

    /// <summary>Wert kommt aus einer Richtlinie (GPO/Intune) und kann hier nicht geändert werden.</summary>
    public bool IsManaged { get => (bool)GetValue(IsManagedProperty); set => SetValue(IsManagedProperty, value); }

    /// <summary>Pfad wie "Lock.IdleMinutes" – damit markiert das Fenster per Richtlinie verwaltete Werte.</summary>
    public string? PolicyPath { get; set; }
}

/// <summary>List&lt;string&gt; ↔ mehrzeiliger Text (eine Zeile pro Eintrag).</summary>
public sealed class LinesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is IEnumerable<string> list ? string.Join(Environment.NewLine, list) : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => (value as string ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
}

/// <summary>List&lt;MaskRegion&gt; ↔ Zeilen „Monitor:X,Y,Breite,Höhe“ (wie in der Richtlinie); ungültige Zeilen entfallen.</summary>
public sealed class MaskLinesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is IEnumerable<Vitrine.Core.Lock.MaskRegion> list ? string.Join(Environment.NewLine, list.Select(m => m.Format())) : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => (value as string ?? "").Split('\n').Select(l => Vitrine.Core.Lock.MaskRegion.Parse(l.Trim())).OfType<Vitrine.Core.Lock.MaskRegion>().ToList();
}

/// <summary>int (0–100) ↔ double für Slider.</summary>
public sealed class IntDoubleConverter : IValueConverter
{
    // ConverterParameter "pct" → 0–100 wird zu 0.0–1.0 (für Opacity)
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is int i ? (parameter as string == "pct" ? i / 100d : i) : 0d;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is double d ? (int)Math.Round(parameter as string == "pct" ? d * 100 : d) : 0;
}

/// <summary>Enum ↔ bool für RadioButtons: ConverterParameter = Enum-Name.</summary>
public sealed class EnumBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value?.ToString() == parameter?.ToString();

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? Enum.Parse(targetType, parameter!.ToString()!) : Binding.DoNothing;
}

public sealed record Choice(object Value, string Label);
