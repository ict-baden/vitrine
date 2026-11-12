// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Vitrine.Core.Lock;
using Vitrine.Services.Interop;

namespace Vitrine.UI;

/// <summary>
/// Bereiche zum Verdecken direkt auf dem Bildschirm aufziehen: ein halbdurchsichtiges Fenster je Monitor, darunter der
/// echte Desktop. Ziehen legt einen Bereich an, Rechtsklick entfernt einen, Eingabe übernimmt, Esc verwirft.
/// Bereiche für „jeden Monitor“ (*) bleiben erhalten und werden mit angezeigt.
/// </summary>
internal static class MaskEditor
{
    /// <summary>Neue Liste, oder null wenn abgebrochen.</summary>
    public static Task<List<MaskRegion>?> EditAsync(IReadOnlyList<MaskRegion> current)
    {
        var done = new TaskCompletionSource<List<MaskRegion>?>();
        var masks = current.Select(m => m.Normalized()).ToList();
        var monitors = Native.GetMonitors();
        var numbers = ScreenMasks.NumberMonitors(monitors.Select(m => (new PixelRect(m.Bounds.Left, m.Bounds.Top, m.Bounds.Right, m.Bounds.Bottom), m.IsPrimary)).ToList());
        var windows = new List<Surface>();

        void Finish(bool apply)
        {
            if (done.Task.IsCompleted) return;
            foreach (var w in windows) w.Close();
            done.SetResult(apply ? masks : null);
        }
        void Redraw() { foreach (var w in windows) w.Draw(); }

        for (int i = 0; i < monitors.Count; i++)
        {
            var w = new Surface(monitors[i], numbers[i], masks, Redraw, Finish);
            windows.Add(w);
            w.Show();
        }
        windows.FirstOrDefault(w => w.IsPrimary)?.Activate();
        return done.Task;
    }

    private sealed class Surface : Window
    {
        private readonly Native.MonitorInfo _monitor;
        private readonly int _number;
        private readonly List<MaskRegion> _masks;
        private readonly Action _redrawAll;
        private readonly Action<bool> _finish;
        private readonly Canvas _canvas = new() { Background = Brushes.Transparent };
        private readonly Border _draft = new()
        {
            BorderBrush = Brushes.White, BorderThickness = new Thickness(2), Background = new SolidColorBrush(Color.FromArgb(0x66, 0x0B, 0x0D, 0x12)),
            Visibility = Visibility.Collapsed, IsHitTestVisible = false,
        };
        private Point? _start;

        public bool IsPrimary => _monitor.IsPrimary;

        public Surface(Native.MonitorInfo monitor, int number, List<MaskRegion> masks, Action redrawAll, Action<bool> finish)
        {
            _monitor = monitor;
            _number = number;
            _masks = masks;
            _redrawAll = redrawAll;
            _finish = finish;

            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = new SolidColorBrush(Color.FromArgb(0x55, 0, 0, 0));
            ResizeMode = ResizeMode.NoResize;
            ShowInTaskbar = false;
            Topmost = true;
            Cursor = Cursors.Cross;
            Title = Loc.T("MaskEditor_Title");
            FontFamily = (FontFamily)Application.Current.FindResource("UiFont");
            Left = monitor.Bounds.Left; Top = monitor.Bounds.Top;
            Width = Math.Max(1, monitor.Bounds.Right - monitor.Bounds.Left);
            Height = Math.Max(1, monitor.Bounds.Bottom - monitor.Bounds.Top);

            var root = new Grid();
            root.Children.Add(_canvas);
            root.Children.Add(new TextBlock
            {
                Text = Loc.F("MaskEditor_Monitor", number), Foreground = Brushes.White, FontSize = 28, FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(24), HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top,
                IsHitTestVisible = false,
            });
            root.Children.Add(Toolbar());
            Content = root;

            SourceInitialized += (_, _) => Place();
            // Wie OverlayWindow: Bei unterschiedlicher Skalierung je Monitor rechnet WPF die Größe beim Wechsel auf diesen
            // Monitor um – danach wieder genau auf die Pixel des Monitors setzen. Sonst wären die Prozentwerte der Bereiche
            // auf ein zu großes oder zu kleines Fenster bezogen und lägen später an anderer Stelle (Prüfung vom 2026-10-20).
            DpiChanged += (_, _) => Dispatcher.BeginInvoke(Place);
            SizeChanged += (_, _) => Draw();
            KeyDown += (_, e) =>
            {
                if (e.Key == Key.Escape) _finish(false);
                else if (e.Key == Key.Enter) _finish(true);
            };
            MouseLeftButtonDown += (_, e) =>
            {
                _start = e.GetPosition(_canvas);
                CaptureMouse();
                UpdateDraft(_start.Value);
                _draft.Visibility = Visibility.Visible;
            };
            MouseMove += (_, e) => { if (_start is not null) UpdateDraft(e.GetPosition(_canvas)); };
            MouseLeftButtonUp += (_, e) =>
            {
                if (_start is not { } s) return;
                _start = null;
                ReleaseMouseCapture();
                _draft.Visibility = Visibility.Collapsed;
                var r = new Rect(s, e.GetPosition(_canvas));
                if (r.Width < 8 || r.Height < 8) return; // versehentlicher Klick
                _masks.Add(new MaskRegion
                {
                    Monitor = _number,
                    X = r.X / ActualWidth * 100, Y = r.Y / ActualHeight * 100,
                    Width = r.Width / ActualWidth * 100, Height = r.Height / ActualHeight * 100,
                }.Normalized());
                _redrawAll();
            };
        }

        /// <summary>Fenster genau auf den Monitor legen (Pixel, unabhängig von der Skalierung).</summary>
        private void Place()
        {
            var b = _monitor.Bounds;
            Native.SetWindowPos(new WindowInteropHelper(this).Handle, Native.HWND_TOPMOST, b.Left, b.Top, b.Right - b.Left, b.Bottom - b.Top,
                Native.SWP_SHOWWINDOW);
        }

        private FrameworkElement Toolbar()
        {
            var done = new Button { Content = Loc.T("MaskEditor_Done"), Margin = new Thickness(12, 0, 0, 0), IsDefault = true, Cursor = Cursors.Arrow };
            done.SetResourceReference(StyleProperty, "AccentButton");
            done.Click += (_, _) => _finish(true);
            var cancel = new Button { Content = Loc.T("Common_Cancel"), Margin = new Thickness(8, 0, 0, 0), IsCancel = true, Cursor = Cursors.Arrow };
            cancel.Click += (_, _) => _finish(false);
            var panel = new StackPanel { Orientation = Orientation.Horizontal };
            panel.Children.Add(new TextBlock { Text = Loc.T("MaskEditor_Hint"), Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center });
            panel.Children.Add(done);
            panel.Children.Add(cancel);
            return new Border
            {
                Child = panel, Background = new SolidColorBrush(Color.FromArgb(0xE6, 0x16, 0x1A, 0x22)), CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16, 10, 10, 10), Margin = new Thickness(0, 24, 0, 0), Cursor = Cursors.Arrow,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Top,
            };
        }

        private void UpdateDraft(Point p)
        {
            var r = new Rect(_start!.Value, p);
            Canvas.SetLeft(_draft, r.X);
            Canvas.SetTop(_draft, r.Y);
            _draft.Width = r.Width;
            _draft.Height = r.Height;
        }

        public void Draw()
        {
            if (ActualWidth <= 0) return;
            _canvas.Children.Clear();
            int px = Math.Max(1, _monitor.Bounds.Right - _monitor.Bounds.Left), py = Math.Max(1, _monitor.Bounds.Bottom - _monitor.Bounds.Top);
            foreach (var m in _masks.Where(m => m.Monitor == 0 || m.Monitor == _number))
            {
                var mask = m;
                var r = ScreenMasks.MaskRects([mask], _number, new PixelRect(0, 0, px, py)).FirstOrDefault();
                if (r.IsEmpty) continue;
                var box = new Border
                {
                    Width = r.Width * ActualWidth / px, Height = r.Height * ActualHeight / py,
                    Background = new SolidColorBrush(Color.FromArgb(0xD9, 0x0B, 0x0D, 0x12)),
                    BorderBrush = new SolidColorBrush(mask.Monitor == 0 ? Color.FromRgb(0x8B, 0x5C, 0xF6) : Colors.White),
                    BorderThickness = new Thickness(2),
                    ToolTip = Loc.T("MaskEditor_Remove"),
                    Cursor = Cursors.Hand,
                };
                box.MouseRightButtonUp += (_, e) => { _masks.Remove(mask); e.Handled = true; _redrawAll(); };
                // Ziehen innerhalb eines Bereichs legt trotzdem einen neuen an (überlappend erlaubt)
                Canvas.SetLeft(box, r.Left * ActualWidth / px);
                Canvas.SetTop(box, r.Top * ActualHeight / py);
                _canvas.Children.Add(box);
            }
            _canvas.Children.Add(_draft);
        }
    }
}
