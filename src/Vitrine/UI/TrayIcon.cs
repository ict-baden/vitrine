// SPDX-License-Identifier: MIT
using System.Windows;
using Microsoft.Win32;
using Vitrine.Services.Interop;
using Forms = System.Windows.Forms;

namespace Vitrine.UI;

/// <summary>Symbol im Infobereich. Linksklick: modernes Flyout, Rechtsklick: kompaktes Menü.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Func<TrayFlyout> _flyoutFactory;
    private TrayFlyout? _open;
    private Func<Forms.ContextMenuStrip>? _buildMenu;
    private int _iconSize;

    public TrayIcon(Func<TrayFlyout> flyoutFactory, Action onLock, Action onSettings, Action onAbout, Action onExit)
    {
        _flyoutFactory = flyoutFactory;
        _iconSize = IconPixels();
        _icon = new Forms.NotifyIcon
        {
            Icon = LoadIcon(_iconSize),
            Text = Trim(Loc.T("Tray_Tooltip")),
            Visible = true,
        };

        // Das Kontextmenü (WinForms-ToolStrip) kostet beim ersten Anlegen rund 300 ms. Es entsteht deshalb erst, wenn die
        // App sonst nichts zu tun hat – oder spätestens beim ersten Rechtsklick (seit 2026-10-26, Issue #18).
        _buildMenu = () =>
        {
            var menu = new Forms.ContextMenuStrip { ShowImageMargin = false };
            menu.Items.Add(Loc.T("Tray_MenuLock"), null, (_, _) => onLock());
            menu.Items.Add(Loc.T("Tray_MenuSettings"), null, (_, _) => onSettings());
            menu.Items.Add(Loc.T("Tray_MenuAbout"), null, (_, _) => onAbout());
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add(Loc.T("Tray_MenuExit"), null, (_, _) => onExit());
            return menu;
        };
        // NotifyIcon zeigt das Menü beim Loslassen der rechten Taste – beim Drücken angelegt, ist es rechtzeitig da
        _icon.MouseDown += (_, e) => { if (e.Button == Forms.MouseButtons.Right) EnsureMenu(); };
        Application.Current.Dispatcher.BeginInvoke(EnsureMenu, System.Windows.Threading.DispatcherPriority.ApplicationIdle);

        SystemEvents.DisplaySettingsChanged += OnDisplayChanged;
        SystemEvents.UserPreferenceChanged += OnDisplayChanged;

        _icon.MouseClick += (_, e) =>
        {
            if (e.Button != Forms.MouseButtons.Left) return;
            Application.Current.Dispatcher.BeginInvoke(ToggleFlyout);
        };
    }

    private void EnsureMenu()
    {
        if (_disposed || _buildMenu is null) return;
        var build = _buildMenu;
        _buildMenu = null;
        _icon.ContextMenuStrip = build();
    }

    /// <summary>
    /// Kantenlänge des Infobereich-Symbols in Pixeln für das DPI der Taskleiste (#17). SystemInformation.SmallIconSize
    /// bleibt bei PerMonitorV2 auf dem DPI beim Anmelden stehen; nach einem Wechsel der Skalierung wäre das Symbol unscharf.
    /// </summary>
    private static int IconPixels()
    {
        var taskbar = Native.FindWindowEx(0, 0, "Shell_TrayWnd", null);
        uint dpi = taskbar != 0 ? Native.GetDpiForWindow(taskbar) : 0;
        int px = dpi != 0 ? Native.GetSystemMetricsForDpi(Native.SM_CXSMICON, dpi) : 0;
        return px > 0 ? px : Forms.SystemInformation.SmallIconSize.Width;
    }

    private static System.Drawing.Icon LoadIcon(int size)
    {
        var stream = Application.GetResourceStream(AppIcon.IconUri)?.Stream;
        if (stream is null) return System.Drawing.SystemIcons.Shield;
        using (stream) return new System.Drawing.Icon(stream, size, size);
    }

    // Skalierung oder Bildschirme geändert: Symbol in neuer Größe laden
    private void OnDisplayChanged(object? sender, EventArgs e) =>
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            var size = IconPixels();
            if (size == _iconSize || _disposed) return;
            _iconSize = size;
            var old = _icon.Icon;
            _icon.Icon = LoadIcon(size);
            if (!ReferenceEquals(old, System.Drawing.SystemIcons.Shield)) old?.Dispose();
        });

    private void ToggleFlyout()
    {
        if (_open is not null) { _open.Close(); return; }
        _open = _flyoutFactory();
        _open.Closed += (_, _) => _open = null;
        _open.Show();
    }

    public void SetTooltip(string text) => _icon.Text = Trim(text);

    // NotifyIcon erlaubt höchstens 63 Zeichen
    private static string Trim(string text) => text.Length > 63 ? text[..63] : text;

    public void ShowBalloon(string title, string text) => _icon.ShowBalloonTip(4000, title, text, Forms.ToolTipIcon.Info);

    private bool _disposed;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        SystemEvents.DisplaySettingsChanged -= OnDisplayChanged;
        SystemEvents.UserPreferenceChanged -= OnDisplayChanged;
        _icon.Visible = false;
        // NotifyIcon gibt weder Menü noch Symbol frei – sonst bliebe bei jedem Sprachwechsel beides liegen (GDI/USER-Objekte)
        var menu = _icon.ContextMenuStrip;
        var icon = _icon.Icon;
        _icon.Dispose();
        menu?.Dispose();
        if (!ReferenceEquals(icon, System.Drawing.SystemIcons.Shield)) icon?.Dispose();
    }
}
