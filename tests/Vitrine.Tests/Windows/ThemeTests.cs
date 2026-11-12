// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Vitrine.UI.Theme;

namespace Vitrine.Tests.Windows;

/// <summary>
/// Hell- und Dunkelmodus (#20): Nach jedem Wechsel gelten nur die Farben des gewählten Schemas, und Schrift ist auf
/// den Hintergründen lesbar. Nur Ressourcen-Wörterbücher, kein Fenster, keine Registry-Schreibzugriffe.
/// </summary>
[Collection(WpfCollection.Name)]
public sealed class ThemeTests
{
    private const string FluentPrefix = "pack://application:,,,/PresentationFramework.Fluent;component/Themes/";

    // Mica ist durchscheinend; ungefähre Grundfarbe des Materials (Windows 11, ohne Desktop-Tönung)
    private static readonly Color MicaLight = Color.FromRgb(0xF3, 0xF3, 0xF3);
    private static readonly Color MicaDark = Color.FromRgb(0x20, 0x20, 0x20);

    [Fact]
    public void Wechsel_dunkel_hell_laesst_kein_altes_Fluent_Woerterbuch_zurueck()
    {
        WpfHost.Run(() =>
        {
            if (SystemParameters.HighContrast) return; // dann gilt Fluent.HC, unabhängig von hell/dunkel
            foreach (var dark in new[] { true, false, true, false, false, true, false })
            {
                ThemeManager.SetDark(dark);
                var fluent = Application.Current.Resources.MergedDictionaries
                    .Where(d => d.Source?.OriginalString.StartsWith(FluentPrefix, StringComparison.OrdinalIgnoreCase) == true)
                    .ToList();
                Assert.Single(fluent);
                Assert.EndsWith(dark ? "Fluent.Dark.xaml" : "Fluent.Light.xaml", fluent[0].Source!.OriginalString);
                Assert.Single(Application.Current.Resources.MergedDictionaries,
                    d => d.Source?.OriginalString.Contains("/UI/Theme/", StringComparison.Ordinal) == true);

                var text = Brush("TextFillColorPrimaryBrush");
                Assert.True(dark ? Luminance(text) > 0.5 : Luminance(text) < 0.1,
                    $"{(dark ? "dunkel" : "hell")}: TextFillColorPrimaryBrush = {text}");
            }
        });
    }

    [Fact]
    public void Hell_und_dunkel_haben_dieselben_Schluessel()
    {
        WpfHost.Run(() =>
        {
            var dark = Keys(Load("Dark"));
            var light = Keys(Load("Light"));
            Assert.Equal(dark, light);
        });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Schrift_ist_auf_allen_Hintergruenden_lesbar(bool dark)
    {
        WpfHost.Run(() =>
        {
            if (SystemParameters.HighContrast) return;
            ThemeManager.SetDark(dark);
            var mica = dark ? MicaDark : MicaLight;
            var app = Over(Brush("ApplicationBackgroundBrush"), mica);
            var backgrounds = new Dictionary<string, Color>
            {
                ["Mica"] = mica,
                ["ApplicationBackgroundBrush"] = app,
                ["Card auf Mica"] = Over(Brush("CardBackgroundFillColorDefaultBrush"), mica),
                ["Card auf ApplicationBackground"] = Over(Brush("CardBackgroundFillColorDefaultBrush"), app),
                // Entsperr-Dialog und Flyout liegen über beliebigem Inhalt: schlechtester Fall heller bzw. dunkler Desktop
                ["CardBg"] = Over(Brush("CardBg"), dark ? Colors.White : Colors.Black),
                ["FlyoutBg"] = Over(Brush("FlyoutBg"), dark ? Colors.White : Colors.Black),
            };
            foreach (var (name, bg) in backgrounds)
            {
                foreach (var key in new[] { "TextFillColorPrimaryBrush", "TextFillColorSecondaryBrush" })
                {
                    var ratio = Contrast(Over(Brush(key), bg), bg);
                    Assert.True(ratio >= 4.5, $"{(dark ? "dunkel" : "hell")}: {key} auf {name}: {ratio:0.00} < 4.5");
                }
                // Kippschalter (keine Schrift): Rand und Knopf mindestens 3:1 (WCAG 1.4.11)
                foreach (var key in new[] { "ControlOffStroke", "Knob" })
                {
                    var ratio = Contrast(Over(Brush(key), Over(Brush("ControlOff"), bg)), bg);
                    Assert.True(ratio >= 3, $"{(dark ? "dunkel" : "hell")}: {key} auf {name}: {ratio:0.00} < 3");
                }
            }
        });
    }

    private static ResourceDictionary Load(string variant) =>
        new() { Source = new Uri($"pack://application:,,,/Vitrine;component/UI/Theme/{variant}.xaml") };

    private static SortedSet<string> Keys(ResourceDictionary d) =>
        new(d.Keys.Cast<object>().Select(k => k.ToString()!), StringComparer.Ordinal);

    private static Color Brush(string key) =>
        Application.Current.TryFindResource(key) is SolidColorBrush b ? b.Color : throw new InvalidOperationException($"{key} fehlt");

    /// <summary>Farbe mit Alpha über einen deckenden Hintergrund legen.</summary>
    private static Color Over(Color fg, Color bg)
    {
        double a = fg.A / 255.0;
        byte Mix(byte f, byte b) => (byte)Math.Round(f * a + b * (1 - a));
        return Color.FromRgb(Mix(fg.R, bg.R), Mix(fg.G, bg.G), Mix(fg.B, bg.B));
    }

    /// <summary>Relative Leuchtdichte nach WCAG 2.x.</summary>
    private static double Luminance(Color c)
    {
        static double Ch(byte v)
        {
            double s = v / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * Ch(c.R) + 0.7152 * Ch(c.G) + 0.0722 * Ch(c.B);
    }

    private static double Contrast(Color a, Color b)
    {
        double la = Luminance(a), lb = Luminance(b);
        return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WpfCollection
{
    public const string Name = "WPF";
}

/// <summary>Eine WPF-Application pro Testprozess, auf einem eigenen STA-Thread.</summary>
internal static class WpfHost
{
    private static readonly Lazy<Dispatcher> Ui = new(() =>
    {
        Dispatcher? dispatcher = null;
        using var ready = new ManualResetEventSlim();
        var t = new Thread(() =>
        {
            _ = Application.Current ?? new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            dispatcher = Dispatcher.CurrentDispatcher;
            ready.Set();
            Dispatcher.Run();
        });
        t.SetApartmentState(ApartmentState.STA);
        t.IsBackground = true;
        t.Start();
        ready.Wait();
        return dispatcher!;
    });

    public static void Run(Action action) => Ui.Value.Invoke(action);
}
