// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;
using Vitrine.Services.Interop;

namespace Vitrine.UI.Theme;

public static class ThemeManager
{
    // Fluent-Theme aus WPF (.NET 9+), eingebunden als Wörterbuch statt über Application.ThemeMode, damit Vitrine
    // selbst entscheidet, wann hell oder dunkel gilt. Achtung: WPF leitet ThemeMode trotzdem aus dem eingefügten
    // Wörterbuch ab (Fluent.Light.xaml → Light) und tauscht dabei die Instanz aus; deshalb sucht ApplyTheme die
    // Wörterbücher über ihre Quelle. Durchsichtige Fenster (Overlays, Entsperr-Dialog, Flyout) bekommen von WPF kein
    // Mica (AllowsTransparency); das Mica der übrigen Fenster setzt ApplyWindowChrome passend zu IsDark.
    private const string FluentUri = "pack://application:,,,/PresentationFramework.Fluent;component/Themes/Fluent.{0}.xaml";
    private const string VitrineUri = "pack://application:,,,/Vitrine;component/UI/Theme/{0}.xaml";

    // Akzent-Pinsel, die bei einer eigenen Akzentfarbe überschrieben werden
    private static readonly string[] AccentKeys =
        { "AccentFillColorDefaultBrush", "AccentFillColorSecondaryBrush", "AccentFillColorTertiaryBrush", "TextOnAccentFillColorPrimaryBrush" };

    private static ResourceDictionary? _fluent;
    private static ResourceDictionary? _vitrine;
    private static string _accent = "";

    public static bool IsDark { get; private set; } = true;

    /// <summary>Kein Mica (für Screenshots: RenderTargetBitmap sieht den durchsichtigen Hintergrund sonst nicht).</summary>
    public static bool NoMica { get; set; }

    /// <summary>Hell oder dunkel erzwingen (Screenshots).</summary>
    public static void SetDark(bool dark)
    {
        IsDark = dark;
        ApplyTheme();
    }

    /// <param name="forceDark">Nur für Screenshots: Schema vorgeben statt Windows zu folgen.</param>
    public static void Initialize(string? accentHex, bool? forceDark = null)
    {
        IsDark = forceDark ?? !SystemUsesLightTheme();
        _accent = accentHex ?? "";
        ApplyTheme();
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            // General: Hell/Dunkel; Color: Windows-Akzentfarbe geändert
            if (forceDark is not null) return;
            if (e.Category is not (UserPreferenceCategory.General or UserPreferenceCategory.Color)) return;
            IsDark = !SystemUsesLightTheme();
            Application.Current.Dispatcher.BeginInvoke(ApplyTheme);
        };
    }

    private static void ApplyTheme()
    {
        var merged = Application.Current.Resources.MergedDictionaries;
        // Alle Theme-Wörterbücher nach Quelle entfernen, nicht nach Instanz: WPF (.NET 9+) erkennt ein eingefügtes
        // Fluent-Wörterbuch, setzt daraufhin Application.ThemeMode und ersetzt es dabei durch eine eigene Instanz
        // (System.Windows.ThemeManager.AddOrUpdateThemeResources). Ein Remove(_fluent) fand die alte Instanz deshalb
        // nicht mehr – nach einem Wechsel dunkel → hell blieb Fluent.Dark hinter Fluent.Light stehen und gewann:
        // helle Schrift auf hellem Mica (#20).
        for (int i = merged.Count - 1; i >= 0; i--)
            if (IsThemeDictionary(merged[i].Source)) merged.RemoveAt(i);

        var variant = SystemParameters.HighContrast ? "HC" : IsDark ? "Dark" : "Light";
        merged.Insert(0, new ResourceDictionary { Source = new Uri(string.Format(FluentUri, variant)) });
        merged.Insert(1, new ResourceDictionary { Source = new Uri(string.Format(VitrineUri, IsDark ? "Dark" : "Light")) });
        // Die tatsächlich eingefügten Instanzen merken (WPF hat das Fluent-Wörterbuch eventuell schon ausgetauscht)
        _fluent = merged.First(d => IsFluentDictionary(d.Source));
        _vitrine = merged.First(d => IsVitrineThemeDictionary(d.Source));

        BuildDerivedStyles();
        SetAccent(_accent);

        foreach (Window w in Application.Current.Windows)
            if (w is IThemedWindow) ApplyWindowChrome(w);
    }

    private static bool IsFluentDictionary(Uri? source) =>
        source?.OriginalString.StartsWith("pack://application:,,,/PresentationFramework.Fluent;component/Themes/", StringComparison.OrdinalIgnoreCase) == true;

    private static bool IsVitrineThemeDictionary(Uri? source) =>
        source?.OriginalString is { } s
        && (s.Equals(string.Format(VitrineUri, "Dark"), StringComparison.OrdinalIgnoreCase)
            || s.Equals(string.Format(VitrineUri, "Light"), StringComparison.OrdinalIgnoreCase));

    private static bool IsThemeDictionary(Uri? source) => IsFluentDictionary(source) || IsVitrineThemeDictionary(source);

    /// <summary>
    /// Stile, die auf Fluent aufbauen. Im Code statt in XAML, weil BasedOn per StaticResource
    /// über Geschwister-Wörterbücher hinweg nicht zuverlässig auflöst.
    /// </summary>
    private static void BuildDerivedStyles() => BuildDerivedStyles(Application.Current.Resources, _fluent!);

    private static void BuildDerivedStyles(ResourceDictionary r, ResourceDictionary fluent)
    {
        var button = fluent[typeof(Button)] as Style;
        var accent = fluent["AccentButtonStyle"] as Style ?? button;
        var textBox = fluent[typeof(TextBox)] as Style;

        r["AccentButton"] = new Style(typeof(Button), accent);

        var ghost = new Style(typeof(Button), button);
        ghost.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
        ghost.Setters.Add(new Setter(Control.BorderBrushProperty, Brushes.Transparent));
        ghost.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(8, 6, 8, 6)));
        r["GhostButton"] = ghost;

        var multi = new Style(typeof(TextBox), textBox);
        multi.Setters.Add(new Setter(TextBoxBase.AcceptsReturnProperty, true));
        multi.Setters.Add(new Setter(TextBox.TextWrappingProperty, TextWrapping.NoWrap));
        multi.Setters.Add(new Setter(FrameworkElement.MinHeightProperty, 76.0));
        multi.Setters.Add(new Setter(Control.VerticalContentAlignmentProperty, VerticalAlignment.Top));
        multi.Setters.Add(new Setter(Control.FontFamilyProperty, new FontFamily("Cascadia Mono, Consolas")));
        multi.Setters.Add(new Setter(Control.FontSizeProperty, 13.0));
        multi.Setters.Add(new Setter(ScrollViewer.VerticalScrollBarVisibilityProperty, ScrollBarVisibility.Auto));
        r["MultiLineBox"] = multi;
    }

    /// <summary>Leer = Windows-Akzentfarbe (Standard). Sonst #RRGGBB als Firmenfarbe.</summary>
    public static void SetAccent(string? hex)
    {
        _accent = hex ?? "";
        ApplyAccent(Application.Current.Resources, _fluent, _accent);
    }

    private static void ApplyAccent(ResourceDictionary r, ResourceDictionary? fluent, string accent)
    {
        foreach (var k in AccentKeys) r.Remove(k);

        Color c;
        if (TryParse(accent, out var custom))
        {
            c = custom;
            r["AccentFillColorDefaultBrush"] = Freeze(new SolidColorBrush(c));
            r["AccentFillColorSecondaryBrush"] = Freeze(new SolidColorBrush(Color.FromArgb(0xE6, c.R, c.G, c.B)));
            r["AccentFillColorTertiaryBrush"] = Freeze(new SolidColorBrush(Color.FromArgb(0xCC, c.R, c.G, c.B)));
            var lum = (0.299 * c.R + 0.587 * c.G + 0.114 * c.B) / 255;
            r["TextOnAccentFillColorPrimaryBrush"] = Freeze(new SolidColorBrush(lum > 0.68 ? Colors.Black : Colors.White));
        }
        else
        {
            c = (fluent?["AccentFillColorDefaultBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(0x00, 0x67, 0xC0);
        }
        r["AccentSubtle"] = Freeze(new SolidColorBrush(Color.FromArgb(0x33, c.R, c.G, c.B)));
    }

    /// <summary>
    /// Eigener Satz der Theme-Ressourcen für Fenster auf einem anderen UI-Thread (Entsperr-Dialog auf dem Sperr-Desktop,
    /// <c>Lock.Mode = Desktop</c>). Auf dem aufrufenden Thread geladen: Pinsel und Stile aus Application.Resources gehören
    /// dem UI-Thread der App und dürfen dort nicht benutzt werden. Das Fenster bekommt das Wörterbuch vor
    /// InitializeComponent in seine Resources; so findet jede Suche es vor den Ressourcen der App.
    /// </summary>
    public static ResourceDictionary CreateThreadResources()
    {
        var variant = SystemParameters.HighContrast ? "HC" : IsDark ? "Dark" : "Light";
        var fluent = new ResourceDictionary { Source = new Uri(string.Format(FluentUri, variant)) };
        var d = new ResourceDictionary();
        d.MergedDictionaries.Add(fluent);
        d.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri(string.Format(VitrineUri, IsDark ? "Dark" : "Light")) });
        d.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri(string.Format(VitrineUri, "Controls")) });
        BuildDerivedStyles(d, fluent);
        ApplyAccent(d, fluent, _accent);
        return d;
    }

    /// <summary>Die Akzentfarbe von Windows, unabhängig von einer eigenen Firmenfarbe.</summary>
    public static Color AccentColorOfWindows =>
        (_fluent?["AccentFillColorDefaultBrush"] as SolidColorBrush)?.Color ?? Color.FromRgb(0x00, 0x67, 0xC0);

    /// <summary>Aktuelle Akzentfarbe – Windows oder eigene.</summary>
    public static Color AccentColor =>
        (Application.Current.TryFindResource("AccentFillColorDefaultBrush") as SolidColorBrush)?.Color ?? Color.FromRgb(0x00, 0x67, 0xC0);

    private static bool TryParse(string hex, out Color c)
    {
        c = default;
        if (string.IsNullOrWhiteSpace(hex)) return false;
        try { c = (Color)ColorConverter.ConvertFromString(hex); return true; }
        catch { return false; }
    }

    private static T Freeze<T>(T f) where T : Freezable { f.Freeze(); return f; }

    private static bool SystemUsesLightTheme()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int i && i == 1;
        }
        catch { return false; }
    }

    public static bool IsWindows11 => Environment.OSVersion.Version.Build >= 22000;

    /// <summary>Dunkle Titelleiste, runde Ecken und – unter Windows 11 – Mica-Hintergrund.</summary>
    public static void ApplyWindowChrome(Window w, bool mica = true)
    {
        var hwnd = new WindowInteropHelper(w).Handle;
        if (hwnd == 0) return;

        int dark = IsDark ? 1 : 0;
        Native.DwmSetWindowAttribute(hwnd, Native.DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));

        if (mica && IsWindows11 && !NoMica)
        {
            int backdrop = 2; // DWMSBT_MAINWINDOW (Mica)
            if (Native.DwmSetWindowAttribute(hwnd, Native.DWMWA_SYSTEMBACKDROP_TYPE, ref backdrop, sizeof(int)) == 0)
            {
                w.Background = Brushes.Transparent;
                if (HwndSource.FromHwnd(hwnd) is { CompositionTarget: { } ct })
                    ct.BackgroundColor = Colors.Transparent;
                var m = new Native.MARGINS { Left = -1, Right = -1, Top = -1, Bottom = -1 };
                Native.DwmExtendFrameIntoClientArea(hwnd, ref m);
                return;
            }
        }
        w.SetResourceReference(Control.BackgroundProperty, "ApplicationBackgroundBrush");
    }
}

/// <summary>Markiert Fenster, deren Rahmen bei Theme-Wechsel neu gesetzt werden.</summary>
public interface IThemedWindow { }
