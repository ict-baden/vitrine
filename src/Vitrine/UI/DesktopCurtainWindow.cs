// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Vitrine.Services.Interop;
using Vitrine.Services.Lock;

namespace Vitrine.UI;

/// <summary>
/// Vollbild-Fenster je Monitor auf Vitrines Sperr-Desktop (<c>Lock.Mode = Desktop</c>): dunkler Hintergrund, auf Wunsch die
/// Vorschau des Windows-Desktops (nur Bild, keine Bedienung) und der Hinweis wie bei den Abdeckungen. Läuft auf dem
/// UI-Thread des Sperr-Desktops (<see cref="LockDesktopHost"/>) und benutzt deshalb keine Ressourcen der App. Eingaben
/// meldet es als <see cref="Activity"/>; auf dem Sperr-Desktop gibt es keine anderen Fenster, die sie bekommen könnten.
/// </summary>
internal sealed class DesktopCurtainWindow : Window
{
    private static readonly FontFamily Font = new("Segoe UI Variable Text, Segoe UI, Microsoft YaHei UI");

    private readonly Native.MonitorInfo _monitor;
    private readonly Hotkey _hotkey;
    private readonly Image _image = new() { Stretch = Stretch.Fill };
    private readonly TextBlock _stamp;
    private readonly Border _pill;
    private readonly TranslateTransform _pillShift = new();
    private bool _allowClose;

    public event Action<ActivityKind>? Activity;

    /// <param name="resources">Theme-Ressourcen dieses Threads: Auch Stile ohne Schlüssel (für Window, TextBlock …) dürfen nicht aus den Ressourcen der App kommen.</param>
    public DesktopCurtainWindow(Native.MonitorInfo monitor, string title, string hint, int dimPercent, Hotkey hotkey, bool previewExpected,
        ResourceDictionary resources)
    {
        Resources.MergedDictionaries.Add(resources);
        _monitor = monitor;
        _hotkey = hotkey;
        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Topmost = true;
        Background = new SolidColorBrush(Color.FromRgb(0x0B, 0x0D, 0x12));
        FontFamily = Font;
        Cursor = Cursors.Arrow;
        Left = monitor.Bounds.Left; Top = monitor.Bounds.Top;
        Width = Math.Max(1, monitor.Bounds.Right - monitor.Bounds.Left);
        Height = Math.Max(1, monitor.Bounds.Bottom - monitor.Bounds.Top);

        var dim = new Rectangle { Fill = Brushes.Black, Opacity = Math.Clamp(dimPercent, 0, 100) / 100.0, IsHitTestVisible = false };
        var titleText = new TextBlock
        {
            Text = title, Foreground = Brushes.White, FontSize = 15, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap,
        };
        var hintText = new TextBlock
        {
            Text = hint, Foreground = new SolidColorBrush(Color.FromArgb(0xC8, 0xFF, 0xFF, 0xFF)), FontSize = 13,
            Margin = new Thickness(0, 2, 0, 0), TextWrapping = TextWrapping.Wrap,
            Visibility = string.IsNullOrEmpty(hint) ? Visibility.Collapsed : Visibility.Visible,
        };
        var lockGlyph = new TextBlock
        {
            Text = "", FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"), FontSize = 20, Foreground = Brushes.White,
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 14, 0),
        };
        var pillContent = new DockPanel();
        DockPanel.SetDock(lockGlyph, Dock.Left);
        pillContent.Children.Add(lockGlyph);
        pillContent.Children.Add(new StackPanel { Children = { titleText, hintText } });
        _pill = new Border
        {
            Child = pillContent, CornerRadius = new CornerRadius(14), Padding = new Thickness(20, 12, 22, 12),
            Background = new SolidColorBrush(Color.FromArgb(0xE0, 0x20, 0x22, 0x28)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(0x30, 0xFF, 0xFF, 0xFF)), BorderThickness = new Thickness(1),
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Bottom,
            Margin = new Thickness(24, 0, 24, 48), MaxWidth = 720, RenderTransform = _pillShift,
        };
        _stamp = new TextBlock
        {
            Foreground = new SolidColorBrush(Color.FromArgb(0xB0, 0xFF, 0xFF, 0xFF)), FontSize = 12,
            HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 16, 20, 0),
            Text = previewExpected ? "" : Loc.T("Desktop_NoPreview"),
        };
        var root = new Grid { Background = Brushes.Transparent };
        root.Children.Add(_image);
        root.Children.Add(dim);
        root.Children.Add(_stamp);
        root.Children.Add(_pill);
        Content = root;

        SourceInitialized += (_, _) =>
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            var ex = (long)Native.GetWindowLongPtr(hwnd, Native.GWL_EXSTYLE) | Native.WS_EX_TOOLWINDOW;
            Native.SetWindowLongPtr(hwnd, Native.GWL_EXSTYLE, (nint)ex);
            var b = _monitor.Bounds;
            Native.SetWindowPos(hwnd, Native.HWND_TOPMOST, b.Left, b.Top, b.Right - b.Left, b.Bottom - b.Top, Native.SWP_SHOWWINDOW);
        };
        PreviewKeyDown += OnKey;
        PreviewMouseDown += (_, e) => { e.Handled = true; Activity?.Invoke(ActivityKind.Mouse); };
        // Alt+F4 und Ähnliches: Die Abdeckung schließt nur Vitrine selbst
        Closing += (_, e) => { if (!_allowClose) e.Cancel = true; };
    }

    public bool IsPrimary => _monitor.IsPrimary;

    public string Device => _monitor.Device;

    private void OnKey(object sender, KeyEventArgs e)
    {
        e.Handled = true;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var vk = (uint)KeyInterop.VirtualKeyFromKey(key);
        // ModifierKeys hat dieselben Bits wie MOD_ALT/CONTROL/SHIFT/WIN
        var mods = (uint)Keyboard.Modifiers & 0xF;
        Activity?.Invoke(!_hotkey.IsEmpty && vk == _hotkey.VirtualKey && mods == (_hotkey.Modifiers & 0xF) ? ActivityKind.Hotkey : ActivityKind.Key);
    }

    /// <summary>Vorschau setzen (eingefrorenes Bild, null = keins) und den Zeitpunkt anzeigen.</summary>
    public void SetPreview(BitmapSource? frame, string? stamp)
    {
        _image.Source = frame;
        if (stamp is not null) _stamp.Text = stamp;
    }

    public void Nudge()
    {
        var a = new DoubleAnimationUsingKeyFrames();
        a.KeyFrames.Add(new EasingDoubleKeyFrame(-6, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(80))));
        a.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(260)), new ElasticEase { Oscillations = 2, Springiness = 6 }));
        _pillShift.BeginAnimation(TranslateTransform.YProperty, a);
    }

    public void TakeForeground() => Native.ForceForeground(new WindowInteropHelper(this).Handle);

    public void CloseForGood()
    {
        _allowClose = true;
        Close();
    }
}
