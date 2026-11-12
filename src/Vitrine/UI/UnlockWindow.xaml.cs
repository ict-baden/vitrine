// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Vitrine.Abstractions;
using Vitrine.Services.Interop;

namespace Vitrine.UI;

public enum PromptKind { Unlock, Signature, Admin }

/// <summary>Weitere Eingaben des Dialogs: Begründung und ob die Notfall-Anmeldung gewählt ist.</summary>
public sealed record PromptInput(string? Reason, bool Emergency)
{
    public static readonly PromptInput None = new(null, false);
}

/// <summary>Was der Dialog anzeigen soll und wie er prüft.</summary>
public sealed class PromptRequest
{
    public PromptKind Kind { get; init; } = PromptKind.Unlock;
    public required string Heading { get; init; }
    public string? SubHeading { get; init; }

    /// <summary>Warum angemeldet wird (Text für Windows Hello und Plugins), in der Sprache der Oberfläche.</summary>
    public required string Reason { get; init; }
    public string Initials { get; init; } = "?";
    public string? SignReason { get; init; }
    public string? SignMeaning { get; init; }
    public required IReadOnlyList<IAuthProvider> Methods { get; init; }
    public string? PreferredMethod { get; init; }
    public string? DefaultUser { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public string? LogoPath { get; init; }

    /// <summary>
    /// Prüft die Anmeldung (Authentifizierung + Richtlinie + Protokoll). Liefert null bei Erfolg,
    /// sonst die Fehlermeldung, sowie ggf. eine Wartezeit vor dem nächsten Versuch.
    /// </summary>
    public required Func<IAuthProvider, AuthRequest, PromptInput, Task<(AuthOutcome? ok, string? error, TimeSpan delay)>> Verify { get; init; }

    /// <summary>Bestätigung: Begründung verlangen (Security.ReasonRequiredForAdminActions).</summary>
    public bool ReasonRequired { get; init; }

    /// <summary>Mindestlänge der Begründung.</summary>
    public int ReasonMinLength { get; init; } = 1;

    /// <summary>Entsperren: Verfahren der Notfall-Anmeldung (Windows-Kennwort); null = keine Notfall-Anmeldung.</summary>
    public IAuthProvider? EmergencyMethod { get; init; }

    /// <summary>Mindestlänge der Begründung einer Notfall-Anmeldung.</summary>
    public int EmergencyReasonMinLength { get; init; } = 10;

    /// <summary>
    /// Wird true, solange ein externes Anmeldefenster (Entra/Hello) offen ist. Erster Parameter: der Dialog, der es meldet –
    /// Meldungen eines schon geschlossenen Dialogs werden so erkannt und ignoriert.
    /// </summary>
    public Action<UnlockWindow, bool>? ExternalFlowChanged { get; init; }
}

public partial class UnlockWindow : Window
{
    private readonly PromptRequest _req;
    private readonly TaskCompletionSource<AuthOutcome?> _tcs = new();
    private readonly DispatcherTimer _timeout;
    private readonly CancellationTokenSource _cts = new();
    private IAuthProvider _method;
    private DateTime _deadline;
    private bool _busy;
    private DateTime _lockedUntil = DateTime.MinValue;
    private bool _emergency;

    public Task<AuthOutcome?> Result => _tcs.Task;

    public PromptKind Kind => _req.Kind;

    /// <param name="resources">
    /// Theme-Ressourcen des eigenen UI-Threads (Dialog auf dem Sperr-Desktop, <see cref="Theme.ThemeManager.CreateThreadResources"/>);
    /// null = die der App.
    /// </param>
    public UnlockWindow(PromptRequest req, ResourceDictionary? resources = null)
    {
        if (resources is not null) Resources.MergedDictionaries.Add(resources);
        InitializeComponent();
        _req = req;
        _method = req.Methods.FirstOrDefault(m => m.Id == req.PreferredMethod) ?? req.Methods[0];

        Heading.Text = req.Heading;
        SubHeading.Text = req.SubHeading ?? "";
        SubHeading.Visibility = string.IsNullOrEmpty(req.SubHeading) ? Visibility.Collapsed : Visibility.Visible;
        Initials.Text = req.Initials;
        UserBox.Text = req.DefaultUser ?? "";

        ApplyAccentToAvatar();
        LoadLogo(req.LogoPath);

        switch (req.Kind)
        {
            case PromptKind.Signature:
                Title = Loc.T("Prompt_TitleSignature");
                KindGlyph.Text = "\uEE56"; // Signature
                SignatureBox.Visibility = Visibility.Visible;
                SignReason.Text = req.SignReason ?? "";
                SignMeaning.Text = string.IsNullOrEmpty(req.SignMeaning) ? "" : Loc.F("Prompt_SignMeaning", req.SignMeaning);
                SignMeaning.Visibility = string.IsNullOrEmpty(req.SignMeaning) ? Visibility.Collapsed : Visibility.Visible;
                OkText.Text = Loc.T("Prompt_Sign");
                Footer.Text = Loc.T("Prompt_SignFooter");
                break;
            case PromptKind.Admin:
                Title = Loc.T("Prompt_TitleAdmin");
                KindGlyph.Text = "\uE7EF"; // Admin
                OkText.Text = Loc.T("Prompt_Confirm");
                break;
        }

        BuildMethodBar();
        SelectMethod(_method);
        if (req.Kind == PromptKind.Unlock && req.EmergencyMethod is not null) EmergencyRow.Visibility = Visibility.Visible;
        UpdateReasonPanel();

        _timeout = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(100) };
        _timeout.Tick += OnTimeoutTick;
        ResetTimeout();

        PreviewKeyDown += (_, e) =>
        {
            ResetTimeout();
            if (e.Key == Key.Escape && !_busy) { Finish(null); e.Handled = true; }
        };
        PreviewMouseMove += (_, _) => ResetTimeout();
        PreviewMouseDown += (_, _) => ResetTimeout();

        SourceInitialized += (_, _) =>
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            var ex = (long)Native.GetWindowLongPtr(hwnd, Native.GWL_EXSTYLE) | Native.WS_EX_TOOLWINDOW;
            Native.SetWindowLongPtr(hwnd, Native.GWL_EXSTYLE, (nint)ex);
        };
        Loaded += (_, _) =>
        {
            PlaceOnActiveMonitor();
            AnimateIn();
            ForceForeground();
            FocusFirstField();
            _timeout.Start();
        };
        Closed += (_, _) =>
        {
            _timeout.Stop();
            _cts.Cancel();
            _tcs.TrySetResult(null);
        };
    }

    // ---------- Aufbau ----------

    private void BuildMethodBar()
    {
        if (_req.Methods.Count <= 1)
        {
            MethodBar.Visibility = Visibility.Collapsed;
            return;
        }
        foreach (var m in _req.Methods)
        {
            var rb = new RadioButton
            {
                Content = ShortName(m),
                Tag = m.Glyph,
                GroupName = "method",
                // Symbol über kurzem Text: Nebeneinander (Symbol links) passten drei Verfahren nicht mehr in den Dialog
                // („Windows sign-in“ abgeschnitten); zu lange Texte verkleinert der Stil, statt sie abzuschneiden
                Style = (Style)FindResource("MethodTab"),
                IsChecked = m == _method,
                ToolTip = m.DisplayName,
            };
            AutomationProperties.SetName(rb, m.DisplayName);
            rb.Checked += (_, _) => SelectMethod(m);
            Methods.Children.Add(rb);
        }
    }

    private static string ShortName(IAuthProvider m) => m.Id switch
    {
        "entra" => "Microsoft",
        "windows" => Loc.T("Method_WindowsShort"),
        "hello" => "Hello",
        "windowslogon" => Loc.T("Method_WindowsLogonShort"),
        "fido" => Loc.T("Method_FidoShort"),
        "pin" => Loc.T("Method_PinShort"),
        _ => m.DisplayName,
    };

    private void SelectMethod(IAuthProvider m)
    {
        _method = m;
        HideError();
        switch (m.Input)
        {
            case AuthInputKind.UsernamePassword:
                CredentialPanel.Visibility = Visibility.Visible;
                UserRow.Visibility = Visibility.Visible;
                SecretLabel.Text = Loc.T("Prompt_Password");
                SecretLabel.Margin = new Thickness(2, 12, 0, 6);
                ExternalPanel.Visibility = Visibility.Collapsed;
                break;
            case AuthInputKind.Secret:
                CredentialPanel.Visibility = Visibility.Visible;
                UserRow.Visibility = Visibility.Collapsed;
                SecretLabel.Text = m.DisplayName;
                SecretLabel.Margin = new Thickness(2, 0, 0, 6);
                ExternalPanel.Visibility = Visibility.Collapsed;
                break;
            default:
                CredentialPanel.Visibility = Visibility.Collapsed;
                ExternalPanel.Visibility = Visibility.Visible;
                ExternalGlyph.Text = m.Glyph;
                ExternalText.Text = m.Id switch
                {
                    "entra" => Loc.T("Prompt_ExternalEntra"),
                    "hello" => Loc.T("Prompt_ExternalHello"),
                    "windowslogon" => Loc.T("Prompt_ExternalWindowsLogon"),
                    "fido" => Loc.T("Prompt_ExternalFido"),
                    _ => Loc.F("Prompt_ExternalOther", m.DisplayName),
                };
                break;
        }
        if (_req.Kind == PromptKind.Unlock)
            OkText.Text = m.Input == AuthInputKind.External ? Loc.F("Prompt_ContinueWith", ShortName(m)) : Loc.T("Prompt_Unlock");
        if (IsLoaded) FocusFirstField();
    }

    /// <summary>Notfall-Anmeldung ein- bzw. ausschalten: nur Windows-Kennwort, Begründung verlangt, Hinweis sichtbar.</summary>
    private void Emergency_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _req.EmergencyMethod is not { } windows) return;
        _emergency = !_emergency;
        MethodBar.Visibility = _emergency || _req.Methods.Count <= 1 ? Visibility.Collapsed : Visibility.Visible;
        EmergencyNote.Visibility = _emergency ? Visibility.Visible : Visibility.Collapsed;
        EmergencyLinkText.Text = Loc.T(_emergency ? "Prompt_EmergencyBack" : "Prompt_Emergency");
        if (_emergency)
        {
            // Wer im Notfall entsperrt, ist meist nicht der Benutzer der Sitzung
            UserBox.Text = "";
            SelectMethod(windows);
        }
        else SelectMethod(_req.Methods.FirstOrDefault(m => m.Id == _req.PreferredMethod) ?? _req.Methods[0]);
        if (_req.Kind == PromptKind.Unlock && _emergency) OkText.Text = Loc.T("Prompt_EmergencyUnlock");
        UpdateReasonPanel();
        if (IsLoaded) FocusFirstField();
    }

    private bool ReasonNeeded => _emergency || (_req.Kind == PromptKind.Admin && _req.ReasonRequired);

    private int ReasonMin => _emergency ? _req.EmergencyReasonMinLength : _req.ReasonMinLength;

    private void UpdateReasonPanel()
    {
        ReasonPanel.Visibility = ReasonNeeded ? Visibility.Visible : Visibility.Collapsed;
        ReasonLabel.Text = Loc.F("Prompt_ReasonLabel", Core.Governance.Reasons.EffectiveMinLength(ReasonMin));
    }

    private void FocusFirstField()
    {
        if (_method.Input == AuthInputKind.External) { OkButton.Focus(); return; }
        if (_emergency && string.IsNullOrWhiteSpace(ReasonBox.Text)) ReasonBox.Focus();
        else if (_method.Input == AuthInputKind.UsernamePassword && string.IsNullOrWhiteSpace(UserBox.Text)) UserBox.Focus();
        else SecretBox.Focus();
        Keyboard.Focus(Keyboard.FocusedElement);
    }

    private void ApplyAccentToAvatar()
    {
        if (TryFindResource("AccentFillColorDefaultBrush") is SolidColorBrush b)
        {
            AvatarA.Color = b.Color;
            var c = b.Color;
            AvatarB.Color = Color.FromRgb((byte)Math.Min(255, c.R + 48), (byte)(c.G * 0.65), (byte)Math.Min(255, c.B + 8));
        }
    }

    private void LoadLogo(string? path)
    {
        // Nur lokale Dateien (oder Freigaben) – kein http: oder andere Schemata
        if (string.IsNullOrWhiteSpace(path) || !Uri.TryCreate(path, UriKind.Absolute, out var uri) || !uri.IsFile || !File.Exists(path)) return;
        try
        {
            var img = new BitmapImage();
            img.BeginInit();
            img.CacheOption = BitmapCacheOption.OnLoad;
            img.UriSource = new Uri(path, UriKind.Absolute);
            img.EndInit();
            Logo.Source = img;
            Logo.Visibility = Visibility.Visible;
        }
        catch { }
    }

    // ---------- Ablauf ----------

    private async void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (DateTime.Now < _lockedUntil)
        {
            ShowError(Core.Localization.CoreText.Error(Core.Localization.ErrorCodes.PleaseWait, Math.Ceiling((_lockedUntil - DateTime.Now).TotalSeconds)));
            return;
        }

        if (ReasonNeeded && !Core.Governance.Reasons.IsSufficient(ReasonBox.Text, ReasonMin))
        {
            ShowError(Core.Localization.CoreText.Error(Core.Localization.ErrorCodes.ReasonTooShort, Core.Governance.Reasons.EffectiveMinLength(ReasonMin)));
            ReasonBox.Focus();
            return;
        }

        SetBusy(true);
        HideError();
        bool external = _method.Input == AuthInputKind.External;
        try
        {
            if (external)
            {
                _timeout.Stop();
                _req.ExternalFlowChanged?.Invoke(this, true);
            }

            var request = new AuthRequest
            {
                UserName = _method.Input == AuthInputKind.UsernamePassword ? UserBox.Text.Trim() : _req.DefaultUser,
                Secret = SecretBox.Password,
                OwnerWindow = new WindowInteropHelper(this).Handle,
                Reason = _req.Reason,
            };

            var input = new PromptInput(ReasonNeeded ? Core.Governance.Reasons.Normalize(ReasonBox.Text) : null, _emergency);
            var (ok, error, delay) = await _req.Verify(_method, request, input);

            if (ok is not null)
            {
                await AnimateOutAsync();
                Finish(ok);
                return;
            }

            SecretBox.Clear();
            if (delay > TimeSpan.Zero) _lockedUntil = DateTime.Now + delay;
            ShowError(error ?? Core.Localization.CoreText.Error(Core.Localization.ErrorCodes.SignInFailed));
            Shake();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
        finally
        {
            if (external) _req.ExternalFlowChanged?.Invoke(this, false);
        }

        if (!_tcs.Task.IsCompleted)
        {
            if (external) ForceForeground();
            SetBusy(false);
            ResetTimeout();
            _timeout.Start();
            if (IsVisible) FocusFirstField();
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy) Finish(null);
    }

    private void Finish(AuthOutcome? result)
    {
        _tcs.TrySetResult(result);
        Close();
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        OkText.Visibility = busy ? Visibility.Hidden : Visibility.Visible;
        Spinner.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        UserBox.IsEnabled = SecretBox.IsEnabled = Methods.IsEnabled = ReasonBox.IsEnabled = EmergencyRow.IsEnabled = !busy;
        CancelButton.IsEnabled = !busy;
        if (busy)
            SpinnerRotate.BeginAnimation(RotateTransform.AngleProperty,
                new DoubleAnimation(0, 360, TimeSpan.FromSeconds(0.9)) { RepeatBehavior = RepeatBehavior.Forever });
        else
            SpinnerRotate.BeginAnimation(RotateTransform.AngleProperty, null);
    }

    private void ShowError(string text)
    {
        ErrorText.Text = text;
        ErrorBar.Visibility = Visibility.Visible;
    }

    private void HideError() => ErrorBar.Visibility = Visibility.Collapsed;

    /// <summary>Nur für die Screenshots: Fehlermeldung zeigen, ohne anzumelden.</summary>
    internal void ShowErrorForScreenshot(string text) => ShowError(text);

    // ---------- Zeitlimit ----------

    private void ResetTimeout() => _deadline = DateTime.Now.AddSeconds(Math.Max(5, _req.TimeoutSeconds));

    private void OnTimeoutTick(object? sender, EventArgs e)
    {
        if (_busy) return;
        var total = Math.Max(5, _req.TimeoutSeconds);
        var left = (_deadline - DateTime.Now).TotalSeconds;
        TimeoutScale.ScaleX = Math.Clamp(left / total, 0, 1);
        if (left <= 0) Finish(null);
    }

    // ---------- Fenster ----------

    /// <summary>Fensterhandle (0, solange das Fenster noch nicht erzeugt ist).</summary>
    public nint Handle => new WindowInteropHelper(this).Handle;

    /// <summary>Holt den Dialog zuverlässig nach vorn, obwohl die Eingabe gerade woanders „gehört“.</summary>
    public void ForceForeground()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == 0) return;
        var fg = Native.GetForegroundWindow();
        if (fg != 0 && Native.IsHungAppWindow(fg)) fg = 0; // nicht an ein hängendes Fenster anhängen
        uint fgThread = fg == 0 ? 0 : Native.GetWindowThreadProcessId(fg, out _);
        uint myThread = Native.GetCurrentThreadId();
        bool attached = fg != 0 && fgThread != myThread && Native.AttachThreadInput(fgThread, myThread, true);
        try
        {
            Native.SetWindowPos(hwnd, Native.HWND_TOPMOST, 0, 0, 0, 0, Native.SWP_NOMOVE | Native.SWP_NOSIZE | Native.SWP_SHOWWINDOW);
            Native.BringWindowToTop(hwnd);
            Native.SetForegroundWindow(hwnd);
            Activate();
        }
        finally
        {
            if (attached) Native.AttachThreadInput(fgThread, myThread, false);
        }
    }

    private void PlaceOnActiveMonitor()
    {
        var mon = Native.GetMonitorAtCursor();
        if (mon is null) return;
        var hwnd = new WindowInteropHelper(this).Handle;
        var dpi = VisualTreeHelper.GetDpi(this);
        int w = (int)(ActualWidth * dpi.DpiScaleX), h = (int)(ActualHeight * dpi.DpiScaleY);
        var b = mon.Work;
        int x = b.Left + (b.Right - b.Left - w) / 2;
        int y = b.Top + (int)((b.Bottom - b.Top - h) * 0.42);
        Native.SetWindowPos(hwnd, Native.HWND_TOPMOST, x, y, 0, 0, Native.SWP_NOSIZE | Native.SWP_NOACTIVATE);
    }

    private void AnimateIn()
    {
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        var d = TimeSpan.FromMilliseconds(220);
        Card.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, d) { EasingFunction = ease });
        CardScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(0.96, 1, d) { EasingFunction = ease });
        CardScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(0.96, 1, d) { EasingFunction = ease });
    }

    private Task AnimateOutAsync()
    {
        var tcs = new TaskCompletionSource();
        var a = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(140));
        a.Completed += (_, _) => tcs.TrySetResult();
        Card.BeginAnimation(OpacityProperty, a);
        CardScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(1, 0.98, TimeSpan.FromMilliseconds(140)));
        CardScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(1, 0.98, TimeSpan.FromMilliseconds(140)));
        return tcs.Task;
    }

    private void Shake()
    {
        var a = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromMilliseconds(420) };
        double[] xs = { -10, 9, -7, 5, -3, 0 };
        for (int i = 0; i < xs.Length; i++)
            a.KeyFrames.Add(new LinearDoubleKeyFrame(xs[i], KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(70 * (i + 1)))));
        CardShake.BeginAnimation(TranslateTransform.XProperty, a);
    }
}
