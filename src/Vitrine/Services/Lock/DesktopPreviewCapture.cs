// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using Vitrine.Core.Config;
using Vitrine.Core.Lock;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

/// <summary>
/// Vorschau des Windows-Desktops für den Sperr-Desktop (<c>Lock.DesktopShowPreview</c>). Ein Desktop, der nicht
/// Eingabe-Desktop ist, wird nicht gezeichnet – BitBlt vom Bildschirm liefert dort kein Bild. Deshalb setzt ein eigener
/// Hintergrund-Thread (er hängt wie jeder neue Thread am Windows-Desktop des Prozesses) das Bild aus den einzelnen
/// Fenstern zusammen: PrintWindow mit PW_RENDERFULLCONTENT (über die Umleitungsfläche des DWM), von unten nach oben,
/// beschnitten auf den sichtbaren Rahmen; verdeckte Bereiche schwarz, verkleinert auf höchstens 1600 Pixel Breite.
/// Was die Fenster nicht selbst zeichnen (manche GPU-Inhalte, Fenster mit höherer Integrität), bleibt schwarz. Eigene
/// Fenster (die Abdeckungen) zählen nicht. Was gezeigt wird, entscheidet <see cref="DesktopPreview"/>.
/// </summary>
public sealed class DesktopPreviewCapture : IDisposable
{
    private const int MaxWidth = 1600;

    private readonly PreviewContent _content;
    private readonly AppearanceSettings _look;
    private readonly TimeSpan? _interval;
    private readonly Action<IReadOnlyDictionary<string, BitmapSource>, DateTime> _deliver;
    private readonly Action<string> _failed;
    private readonly ManualResetEventSlim _stop = new();
    private Thread? _thread;

    /// <param name="deliver">Neue Bilder je Monitor (Gerätename), eingefroren; auf dem Thread der Vorschau.</param>
    /// <param name="failed">Kein Bild möglich (englischer Grund); auf dem Thread der Vorschau, höchstens einmal.</param>
    public DesktopPreviewCapture(PreviewContent content, AppearanceSettings look, TimeSpan? interval,
        Action<IReadOnlyDictionary<string, BitmapSource>, DateTime> deliver, Action<string> failed)
    {
        _content = content;
        _look = look;
        _interval = interval;
        _deliver = deliver;
        _failed = failed;
    }

    public void Start()
    {
        if (_content == PreviewContent.None || _thread is not null) return;
        _thread = new Thread(Run) { IsBackground = true, Name = "Vitrine.DesktopPreview", Priority = ThreadPriority.BelowNormal };
        _thread.Start();
    }

    private void Run()
    {
        bool reported = false;
        do
        {
            try
            {
                var frames = CaptureAll();
                if (frames.Count > 0) _deliver(frames, DateTime.Now);
                else if (!reported) { reported = true; _failed("no monitor could be captured"); }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                if (!reported) { reported = true; _failed(ex.Message); }
            }
        }
        while (_interval is { } wait && !_stop.Wait(wait));
    }

    private sealed record Win(nint Hwnd, PixelRect Full, PixelRect Visible, bool Reveal);

    private Dictionary<string, BitmapSource> CaptureAll()
    {
        var own = (uint)Environment.ProcessId;
        var names = new Dictionary<uint, bool>();
        var windows = new List<Win>();
        Native.EnumWindows((h, _) =>
        {
            if (!Native.IsWindowVisible(h) || Native.IsIconic(h)) return true;
            if (Native.DwmGetWindowAttribute(h, Native.DWMWA_CLOAKED, out int cloaked, sizeof(int)) == 0 && cloaked != 0) return true;
            Native.GetWindowThreadProcessId(h, out var pid);
            if (pid == own || Native.IsHungAppWindow(h)) return true;
            if (!Native.GetWindowRect(h, out var full)) return true;
            if (Native.DwmGetWindowAttribute(h, Native.DWMWA_EXTENDED_FRAME_BOUNDS, out Native.RECT vis, Marshal.SizeOf<Native.RECT>()) != 0) vis = full;
            if (!names.TryGetValue(pid, out var reveal))
                names[pid] = reveal = _content == PreviewContent.RevealedWindows
                    && ScreenMasks.IsRevealed(Native.GetProcessImageName(pid), _look.RevealProcesses);
            windows.Add(new Win(h, ToPixel(full), ToPixel(vis), reveal));
            return true;
        }, 0);

        var monitors = Native.GetMonitors();
        var numbers = ScreenMasks.NumberMonitors(monitors.Select(m => (ToPixel(m.Bounds), m.IsPrimary)).ToList());
        var plan = windows.Select(w => (w.Visible, w.Reveal)).ToList();
        var result = new Dictionary<string, BitmapSource>();
        for (int i = 0; i < monitors.Count; i++)
        {
            var bounds = ToPixel(monitors[i].Bounds);
            var order = DesktopPreview.WindowsToDraw(plan, bounds, _content);
            var masks = ScreenMasks.MaskRects(_look.Masks, numbers[i], bounds);
            if (Compose(bounds, order.Select(n => windows[n]).ToList(), masks) is { } frame) result[monitors[i].Device] = frame;
        }
        return result;
    }

    private static BitmapSource? Compose(PixelRect monitor, List<Win> bottomToTop, List<PixelRect> masks)
    {
        int w = monitor.Width, h = monitor.Height;
        if (w <= 0 || h <= 0) return null;
        var screen = Native.GetDC(0);
        if (screen == 0) return null;
        nint mem = 0, bmp = 0, old = 0;
        try
        {
            mem = Native.CreateCompatibleDC(screen);
            bmp = Native.CreateCompatibleBitmap(screen, w, h);
            if (mem == 0 || bmp == 0) return null;
            old = Native.SelectObject(mem, bmp);
            Native.PatBlt(mem, 0, 0, w, h, Native.BLACKNESS);

            foreach (var win in bottomToTop) DrawWindow(screen, mem, monitor, win);
            // Verdeckte Bereiche (Appearance.Masks) wie im Abdeckungs-Modus: bleiben verdeckt
            foreach (var m in masks) Native.PatBlt(mem, m.Left, m.Top, m.Width, m.Height, Native.BLACKNESS);

            return Scale(screen, mem, w, h);
        }
        finally
        {
            if (old != 0) Native.SelectObject(mem, old);
            if (bmp != 0) Native.DeleteObject(bmp);
            if (mem != 0) Native.DeleteDC(mem);
            Native.ReleaseDC(0, screen);
        }
    }

    private static void DrawWindow(nint screen, nint target, PixelRect monitor, Win win)
    {
        int ww = win.Full.Width, wh = win.Full.Height;
        if (ww < 2 || wh < 2 || ww > 16384 || wh > 16384) return;
        var dc = Native.CreateCompatibleDC(screen);
        var bmp = Native.CreateCompatibleBitmap(screen, ww, wh);
        if (dc == 0 || bmp == 0)
        {
            if (bmp != 0) Native.DeleteObject(bmp);
            if (dc != 0) Native.DeleteDC(dc);
            return;
        }
        var old = Native.SelectObject(dc, bmp);
        try
        {
            if (!Native.PrintWindow(win.Hwnd, dc, Native.PW_RENDERFULLCONTENT)) return;
            // Nur der sichtbare Rahmen (ohne den unsichtbaren Rand für die Größenänderung, der sonst schwarz erschiene)
            var vis = win.Visible.Intersect(win.Full);
            Native.BitBlt(target, vis.Left - monitor.Left, vis.Top - monitor.Top, vis.Width, vis.Height,
                dc, vis.Left - win.Full.Left, vis.Top - win.Full.Top, Native.SRCCOPY);
        }
        finally
        {
            Native.SelectObject(dc, old);
            Native.DeleteObject(bmp);
            Native.DeleteDC(dc);
        }
    }

    /// <summary>Verkleinert (höchstens <see cref="MaxWidth"/> breit) als eingefrorenes WPF-Bild.</summary>
    private static BitmapSource? Scale(nint screen, nint source, int w, int h)
    {
        double f = Math.Min(1.0, (double)MaxWidth / w);
        int sw = Math.Max(1, (int)(w * f)), sh = Math.Max(1, (int)(h * f));
        var dc = Native.CreateCompatibleDC(screen);
        var bmp = Native.CreateCompatibleBitmap(screen, sw, sh);
        try
        {
            if (dc == 0 || bmp == 0) return null;
            var old = Native.SelectObject(dc, bmp);
            Native.SetStretchBltMode(dc, Native.HALFTONE);
            Native.StretchBlt(dc, 0, 0, sw, sh, source, 0, 0, w, h, Native.SRCCOPY);
            Native.SelectObject(dc, old);
            var frame = Imaging.CreateBitmapSourceFromHBitmap(bmp, 0, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            frame.Freeze();
            return frame;
        }
        finally
        {
            if (bmp != 0) Native.DeleteObject(bmp);
            if (dc != 0) Native.DeleteDC(dc);
        }
    }

    private static PixelRect ToPixel(Native.RECT r) => new(r.Left, r.Top, r.Right, r.Bottom);

    public void Dispose()
    {
        // Nicht warten: Ein hängendes PrintWindow hielte sonst den UI-Thread auf. Der Hintergrund-Thread endet nach dem
        // laufenden Bild; ein spätes Bild landet bei Abdeckungen, die es nicht mehr gibt
        _stop.Set();
    }
}
