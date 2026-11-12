// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Vitrine.Core.Config;
using Vitrine.Core.Lock;
using Vitrine.Services.Interop;

namespace Vitrine.UI;

/// <summary>
/// Ein immer oben liegendes Fenster pro Monitor. Es dunkelt ab, verdeckt bei Bedarf (ganz, einzelne Bereiche oder alles
/// außer freigegebenen Programmen) und zeigt den Hinweis. Eingaben blockiert vor allem der InputBlocker; gesperrt fängt
/// die Abdeckung zusätzlich selbst alle Klicks ab, denn die Hooks sehen keine Eingaben an Fenster mit höherer Integrität
/// (<see cref="LockShield"/>). Durchklickbar ist sie nur während einer externen Anmeldung.
/// </summary>
public partial class OverlayWindow : Window
{
    private readonly Native.MonitorInfo _monitor;
    private readonly DispatcherTimer _clock;
    private readonly List<PixelRect> _masks;
    private readonly Func<PixelRect, List<PixelRect>>? _revealed;
    private readonly DispatcherTimer? _revealTimer;
    private List<PixelRect> _holes = [];

    /// <param name="monitorNumber">Nummer des Monitors wie in den Einstellungen (für <see cref="AppearanceSettings.Masks"/>).</param>
    /// <param name="revealed">
    /// Bei <see cref="LockVisual.Windows"/>: sichtbare Teile der freigegebenen Fenster auf dem Monitor (Pixel, relativ zu
    /// ihm). Wird regelmäßig neu abgefragt, damit verschobene Fenster sichtbar bleiben.
    /// </param>
    public OverlayWindow(Native.MonitorInfo monitor, int monitorNumber, AppearanceSettings look, string title, string hint,
        Func<PixelRect, List<PixelRect>>? revealed = null)
    {
        InitializeComponent();
        _monitor = monitor;
        var bounds = Bounds;

        bool blank = look.Visual == LockVisual.Blank;
        bool windows = look.Visual == LockVisual.Windows;
        Blank.Visibility = blank || windows ? Visibility.Visible : Visibility.Collapsed;
        Dim.Opacity = blank || windows ? 0 : Math.Clamp(look.DimPercent, 0, 100) / 100.0;
        // Bei „ganz verdeckt“ sind Bereiche überflüssig
        _masks = blank ? [] : ScreenMasks.MaskRects(look.Masks, monitorNumber, bounds);
        if (windows)
        {
            _revealed = revealed;
            _holes = revealed?.Invoke(bounds) ?? [];
            _revealTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _revealTimer.Tick += (_, _) => RefreshRevealed();
            _revealTimer.Start();
        }
        SizeChanged += (_, _) => DrawMasks();
        Clock.Visibility = Date.Visibility = blank && look.ShowClock ? Visibility.Visible : Visibility.Collapsed;
        Pill.Visibility = look.ShowStatusPill ? Visibility.Visible : Visibility.Collapsed;
        SetText(title, hint);

        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += (_, _) => UpdateClock();
        UpdateClock();
        if (blank) _clock.Start();

        // Grobe Position vorab, exakte Pixel nach dem Erzeugen des Handles
        Left = monitor.Bounds.Left; Top = monitor.Bounds.Top;
        Width = Math.Max(1, monitor.Bounds.Right - monitor.Bounds.Left);
        Height = Math.Max(1, monitor.Bounds.Bottom - monitor.Bounds.Top);

        SourceInitialized += (_, _) => { ApplyShield(); Place(); };
        // Bei unterschiedlicher Skalierung je Monitor rechnet WPF die Größe um – danach exakt neu setzen, ohne die
        // Z-Reihenfolge zu ändern (sonst läge die Abdeckung über einem offenen Dialog)
        DpiChanged += (_, _) => Dispatcher.BeginInvoke(() => Place(keepZOrder: true));
        Loaded += (_, _) => AnimateIn();
        Closed += (_, _) => { _clock.Stop(); _revealTimer?.Stop(); };
    }

    /// <summary>Abdeckung des Hauptbildschirms (übernimmt den Vordergrund).</summary>
    public bool IsPrimary => _monitor.IsPrimary;

    private PixelRect Bounds => new(_monitor.Bounds.Left, _monitor.Bounds.Top, _monitor.Bounds.Right, _monitor.Bounds.Bottom);

    private void RefreshRevealed()
    {
        List<PixelRect> holes;
        try { holes = _revealed?.Invoke(Bounds) ?? []; }
        catch { holes = []; } // im Zweifel alles verdeckt
        if (holes.SequenceEqual(_holes)) return;
        _holes = holes;
        DrawMasks();
    }

    /// <summary>Pixel des Monitors in Einheiten dieses Fensters (WPF rechnet in DIP, je Monitor andere Skalierung).</summary>
    private Rect ToDip(PixelRect r)
    {
        double sx = ActualWidth / Math.Max(1, Bounds.Width), sy = ActualHeight / Math.Max(1, Bounds.Height);
        return new Rect(r.Left * sx, r.Top * sy, r.Width * sx, r.Height * sy);
    }

    private void DrawMasks()
    {
        if (ActualWidth <= 0) return;

        // Freigegebene Fenster: Löcher in die Abdeckung schneiden
        if (_revealTimer is not null)
        {
            var clip = new GeometryGroup { FillRule = FillRule.EvenOdd };
            clip.Children.Add(new RectangleGeometry(new Rect(0, 0, ActualWidth, ActualHeight)));
            foreach (var h in _holes) clip.Children.Add(new RectangleGeometry(ToDip(h)));
            Blank.Clip = clip;
        }

        MaskLayer.Children.Clear();
        foreach (var m in _masks)
        {
            var r = ToDip(m);
            var box = new Border
            {
                Width = r.Width, Height = r.Height,
                Background = new SolidColorBrush(Color.FromRgb(0x0B, 0x0D, 0x12)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(0x26, 0xFF, 0xFF, 0xFF)),
                BorderThickness = new Thickness(1),
                Child = r.Width >= 48 && r.Height >= 48
                    ? new TextBlock
                    {
                        Text = "\uE72E", FontFamily = (FontFamily)FindResource("IconFont"), FontSize = 20,
                        Foreground = new SolidColorBrush(Color.FromArgb(0x66, 0xFF, 0xFF, 0xFF)),
                        HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                    }
                    : null,
            };
            Canvas.SetLeft(box, r.X);
            Canvas.SetTop(box, r.Y);
            MaskLayer.Children.Add(box);
        }
    }

    public void SetText(string title, string hint)
    {
        PillTitle.Text = title;
        PillHint.Text = hint;
        PillHint.Visibility = string.IsNullOrEmpty(hint) ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>Hebt die Leiste kurz hervor – z. B. wenn jemand während der Sperre tippt.</summary>
    public void Nudge()
    {
        var sb = new Storyboard();
        var a = new DoubleAnimationUsingKeyFrames();
        a.KeyFrames.Add(new EasingDoubleKeyFrame(-6, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(80))));
        a.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(260)),
            new ElasticEase { Oscillations = 2, Springiness = 6 }));
        Storyboard.SetTarget(a, Pill);
        Storyboard.SetTargetProperty(a, new PropertyPath("RenderTransform.Y"));
        sb.Children.Add(a);
        sb.Begin();
    }

    private ShieldState _shield = LockShield.For(LockPhase.Locked);

    /// <summary>Verhalten je Abschnitt der Sperre: durchklickbar und unten nur während einer externen Anmeldung.</summary>
    public void SetShield(ShieldState shield)
    {
        _shield = shield;
        ApplyShield();
        SetOnTop(shield.OnTop);
    }

    /// <summary>Über allen Fenstern halten (auch über „immer oben“ gestarteten) – oder während einer externen Anmeldung darunter.</summary>
    public void SetOnTop(bool onTop)
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == 0) return;
        Native.SetWindowPos(hwnd, onTop ? Native.HWND_TOPMOST : Native.HWND_NOTOPMOST, 0, 0, 0, 0,
            Native.SWP_NOMOVE | Native.SWP_NOSIZE | Native.SWP_NOACTIVATE);
    }

    /// <summary>Direkt unter ein anderes Fenster legen (den Entsperr-Dialog), ohne zu aktivieren.</summary>
    public void PlaceBelow(nint above)
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == 0 || above == 0) return;
        Native.SetWindowPos(hwnd, above, 0, 0, 0, 0, Native.SWP_NOMOVE | Native.SWP_NOSIZE | Native.SWP_NOACTIVATE);
    }

    /// <summary>Vordergrund (und damit die Tastatur) zurückholen, z. B. von einem als Administrator gestarteten Fenster.</summary>
    public void TakeForeground() => Native.ForceForeground(new WindowInteropHelper(this).Handle);

    private void ApplyShield()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == 0) return;
        var ex = (long)Native.GetWindowLongPtr(hwnd, Native.GWL_EXSTYLE);
        ex |= Native.WS_EX_TOOLWINDOW | Native.WS_EX_LAYERED;
        // Durchklickbar und nie aktiv nur während der externen Anmeldung. Sonst nimmt die Abdeckung Klicks selbst an
        // (Root hat dafür einen fast unsichtbaren Hintergrund – völlig transparente Pixel liefen sonst durch) und darf
        // den Vordergrund übernehmen.
        if (_shield.ClickThrough) ex |= Native.WS_EX_TRANSPARENT | Native.WS_EX_NOACTIVATE;
        else ex &= ~(long)(Native.WS_EX_TRANSPARENT | Native.WS_EX_NOACTIVATE);
        Native.SetWindowLongPtr(hwnd, Native.GWL_EXSTYLE, (nint)ex);
    }

    private void Place(bool keepZOrder = false)
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == 0) return;
        var b = _monitor.Bounds;
        Native.SetWindowPos(hwnd, _shield.OnTop ? Native.HWND_TOPMOST : Native.HWND_NOTOPMOST, b.Left, b.Top, b.Right - b.Left, b.Bottom - b.Top,
            Native.SWP_NOACTIVATE | Native.SWP_SHOWWINDOW | (keepZOrder ? Native.SWP_NOZORDER : 0));
    }

    private void AnimateIn()
    {
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        Pill.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260)) { EasingFunction = ease });
        PillShift.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty,
            new DoubleAnimation(16, 0, TimeSpan.FromMilliseconds(320)) { EasingFunction = ease });
    }

    private void UpdateClock()
    {
        var now = DateTime.Now;
        // Uhrzeit und Datum in der Sprache der Oberfläche (richtlinien/13 Punkt 5), Muster aus der Sprachdatei
        Clock.Text = now.ToString("t", CultureInfo.CurrentCulture);
        Date.Text = now.ToString(Loc.T("Overlay_DateFormat"), CultureInfo.CurrentCulture);
    }
}
