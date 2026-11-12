// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Vitrine.Services.Interop;

namespace Vitrine.UI;

public partial class TrayFlyout : Window
{
    public event Action? LockRequested;
    public event Action? LockBlankRequested;
    public event Action? SettingsRequested;
    public event Action? LogRequested;
    public event Action? AboutRequested;
    public event Action? ExitRequested;

    /// <param name="responsible">„Verantwortlich: … seit …“ (GxP), null = nicht anzeigen.</param>
    public TrayFlyout(string footer, string statusTitle, string statusText, bool ok, string? responsible = null)
    {
        InitializeComponent();
        Footer.Text = footer;
        StatusTitle.Text = statusTitle;
        StatusText.Text = statusText;
        ResponsibleText.Text = responsible ?? "";
        ResponsibleText.Visibility = string.IsNullOrEmpty(responsible) ? Visibility.Collapsed : Visibility.Visible;
        StatusDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, ok ? "SystemFillColorSuccessBrush" : "SystemFillColorCautionBrush");

        // Schließen deaktiviert das Fenster; ohne diese Marke riefe Deactivated ein zweites Close() während des Schließens
        // auf – eine Ausnahme mitten in der Fensternachricht, die den Prozess beenden kann (gefunden bei den Screenshots).
        Closing += (_, _) => _closing = true;
        Deactivated += (_, _) => CloseOnce();
        PreviewKeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Escape) CloseOnce(); };
        Loaded += (_, _) =>
        {
            PlaceNearTray();
            Activate();
            var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
            Slide.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(24, 0, TimeSpan.FromMilliseconds(220)) { EasingFunction = ease });
            Card.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
        };
    }

    private void PlaceNearTray()
    {
        var mon = Native.GetMonitorAtCursor();
        if (mon is null) return;
        var hwnd = new WindowInteropHelper(this).Handle;
        var dpi = VisualTreeHelper.GetDpi(this);
        int w = (int)(ActualWidth * dpi.DpiScaleX), h = (int)(ActualHeight * dpi.DpiScaleY);
        var wa = mon.Work;
        Native.SetWindowPos(hwnd, Native.HWND_TOPMOST, wa.Right - w, wa.Bottom - h, 0, 0, Native.SWP_NOSIZE);
    }

    private bool _closing;

    private void CloseOnce()
    {
        if (_closing) return;
        _closing = true;
        Close();
    }

    private void Fire(Action? a) { CloseOnce(); a?.Invoke(); }

    private void Lock_Click(object s, RoutedEventArgs e) => Fire(LockRequested);
    private void Blank_Click(object s, RoutedEventArgs e) => Fire(LockBlankRequested);
    private void Settings_Click(object s, RoutedEventArgs e) => Fire(SettingsRequested);
    private void Log_Click(object s, RoutedEventArgs e) => Fire(LogRequested);
    private void About_Click(object s, RoutedEventArgs e) => Fire(AboutRequested);
    private void Exit_Click(object s, RoutedEventArgs e) => Fire(ExitRequested);
}
