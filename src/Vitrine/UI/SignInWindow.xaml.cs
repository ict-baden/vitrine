// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;
using Vitrine.Core.Auth;
using Vitrine.UI.Theme;

namespace Vitrine.UI;

/// <summary>Das Anmeldefenster ließ sich nicht öffnen oder der Browser-Prozess ist abgestürzt (VIT-0192).</summary>
public sealed class SignInWindowException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Die Anmeldeseite wollte eine Adresse öffnen, die nicht erlaubt ist (VIT-0193); <see cref="Host"/> für die Meldung.</summary>
public sealed class SignInHostBlockedException(string host) : Exception(host)
{
    public string Host { get; } = host;
}

/// <summary>
/// Eigenes Anmeldefenster für Microsoft Entra ID (MSAL <c>ICustomWebUi</c>, <see cref="Services.Auth.EmbeddedWebUi"/>):
/// WebView2 mit einem Profilordner nur für diesen Versuch, im privaten Modus (Cookies nur im Speicher), ohne Anmeldung
/// über das Windows-Konto (AllowSingleSignOnUsingOSPrimaryAccount = false). Nach dem Schließen werden die
/// Browser-Prozesse beendet und der Ordner gelöscht – es bleibt nichts, womit der nächste Versuch ein Konto kennt.
/// Sicherheitsschlüssel und Passkeys gehen über die WebAuthn-API von Windows (Windows-Sicherheitsdialog).
/// Kein Browser: keine Adressleiste, keine neuen Fenster, keine Downloads, nur HTTPS, keine Entwicklertools, kein
/// Kontextmenü, keine Berechtigungen (Kamera, Standort …). Während der Sperre gibt <see cref="InteractiveChanged"/> das
/// Fenster für Eingaben frei (LockController → InputBlocker); seine WebView2-Inhalte sind Kindfenster und zählen mit.
/// </summary>
public partial class SignInWindow : Window, IThemedWindow
{
    private readonly Uri _start;
    private readonly Uri _redirect;
    private readonly string _profile;
    private readonly IReadOnlyList<string> _extraHosts;
    private readonly TaskCompletionSource<Uri> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CoreWebView2Environment? _env;
    private nint _hwnd;
    private bool _closed;
    private Task _starting = Task.CompletedTask;

    /// <summary>Fenster offen (true) bzw. geschlossen (false), auf dem UI-Thread. Die Sperre gibt es dafür frei.</summary>
    public static event Action<nint, bool>? InteractiveChanged;

    /// <summary>
    /// Browser-Prozess (msedgewebview2.exe) des Fensters gestartet (PID) bzw. Fenster zu (0), auf dem UI-Thread. Nur seine
    /// Fenster und die seiner Kindprozesse fallen unter die Besitzer-Regel des Eingabeblockers.
    /// </summary>
    public static event Action<uint>? BrowserProcessChanged;

    /// <summary>
    /// Läuft in jedem Dokument (auch Frames) vor dessen Skripten: kein Drucken, keine Dateiauswahl. Zweite Verteidigung –
    /// fremde Seiten öffnet das Fenster ohnehin nicht (EmbeddedSignIn.Decide); auf den Anmeldeseiten braucht es beides nie.
    /// </summary>
    internal const string HardeningScript = """
        (() => {
          const none = () => undefined;
          const lock = (o, k, v) => { try { Object.defineProperty(o, k, { value: v, writable: false, configurable: false }); } catch (e) { } };
          lock(window, 'print', none);
          for (const k of ['showOpenFilePicker', 'showSaveFilePicker', 'showDirectoryPicker']) lock(window, k, undefined);
          const isFile = el => el instanceof HTMLInputElement && (el.type || '').toLowerCase() === 'file';
          const click = HTMLInputElement.prototype.click;
          lock(HTMLInputElement.prototype, 'click', function () { if (!isFile(this)) return click.call(this); });
          const picker = HTMLInputElement.prototype.showPicker;
          if (picker) lock(HTMLInputElement.prototype, 'showPicker', function () { if (!isFile(this)) return picker.call(this); });
          const stop = e => {
            const t = e.target instanceof Element ? e.target : null;
            if (!t) return;
            const input = t.closest('input');
            const label = t.closest('label');
            if (isFile(input) || (label && isFile(label.control))) { e.preventDefault(); e.stopImmediatePropagation(); }
          };
          for (const type of ['click', 'keydown', 'keyup', 'drop']) window.addEventListener(type, stop, true);
        })();
        """;

    /// <summary>Umleitung mit Code (bzw. Fehler) für MSAL; Abbruch: <see cref="OperationCanceledException"/>.</summary>
    public Task<Uri> Result => _tcs.Task;

    /// <summary>Ordner und Prozesse sind aufgeräumt (true = Ordner gelöscht).</summary>
    public Task<bool> CleanedUp => _cleanup.Task;
    private readonly TaskCompletionSource<bool> _cleanup = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public SignInWindow(Uri start, Uri redirect, string profileFolder, nint owner, IEnumerable<string>? allowedHosts = null)
    {
        InitializeComponent();
        _start = start;
        _redirect = redirect;
        _profile = profileFolder;
        _extraHosts = allowedHosts?.ToList() ?? [];
        // Über dem Dialog (Besitzer): So liegt das Fenster auch während der Sperre über dem Entsperr-Dialog
        if (owner != 0) new WindowInteropHelper(this).Owner = owner;
        SourceInitialized += (_, _) =>
        {
            ThemeManager.ApplyWindowChrome(this, mica: false);
            _hwnd = new WindowInteropHelper(this).Handle;
            InteractiveChanged?.Invoke(_hwnd, true);
        };
        Loaded += (_, _) => _starting = StartAsync();
        Closed += async (_, _) =>
        {
            _closed = true;
            _tcs.TrySetException(new OperationCanceledException());
            if (_hwnd != 0) InteractiveChanged?.Invoke(_hwnd, false);
            BrowserProcessChanged?.Invoke(0);
            await CleanUpAsync();
        };
    }

    private async Task StartAsync()
    {
        try
        {
            Directory.CreateDirectory(_profile);
            var options = new CoreWebView2EnvironmentOptions
            {
                // Nie still mit dem Konto der Windows-Sitzung anmelden (Primary Refresh Token)
                AllowSingleSignOnUsingOSPrimaryAccount = false,
                Language = CultureInfo.CurrentUICulture.Name,
                ExclusiveUserDataFolderAccess = true,
            };
            _env = await CoreWebView2Environment.CreateAsync(null, _profile, options);
            if (_closed) return; // inzwischen abgebrochen: keinen Browser mehr starten
            var controller = _env.CreateCoreWebView2ControllerOptions();
            controller.IsInPrivateModeEnabled = true;
            await Web.EnsureCoreWebView2Async(_env, controller);
            if (_closed || _tcs.Task.IsCompleted) return; // inzwischen abgebrochen

            var core = Web.CoreWebView2;
            var s = core.Settings;
            s.AreDevToolsEnabled = false;
            s.AreDefaultContextMenusEnabled = false;
            s.AreBrowserAcceleratorKeysEnabled = false; // kein Drucken, Suchen, Neu laden mit Tasten
            s.IsStatusBarEnabled = false;
            s.IsPasswordAutosaveEnabled = false;
            s.IsGeneralAutofillEnabled = false;
            s.IsSwipeNavigationEnabled = false;
            s.AreHostObjectsAllowed = false;
            s.IsWebMessageEnabled = false;
            s.AreDefaultScriptDialogsEnabled = false; // alert/confirm ohne eigenes Fenster (ScriptDialogOpening: verworfen)
            await core.AddScriptToExecuteOnDocumentCreatedAsync(HardeningScript);
            if (_closed) return;
            BrowserProcessChanged?.Invoke(core.BrowserProcessId);

            core.NavigationStarting += (_, e) => OnNavigation(e.Uri, () => e.Cancel = true, topLevel: true);
            core.FrameNavigationStarting += (_, e) => OnNavigation(e.Uri, () => e.Cancel = true, topLevel: false);
            // Links wie „Nutzungsbedingungen“ öffneten sonst ein neues Browserfenster
            core.NewWindowRequested += (_, e) => e.Handled = true;
            // Was die Anmeldung braucht (WebAuthn), ist keine Berechtigung; alles andere abgelehnt
            core.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
            core.DownloadStarting += (_, e) => e.Cancel = true;
            core.BasicAuthenticationRequested += (_, e) => e.Cancel = true;
            // Keine anderen Programme (ms-settings:, mailto: …), kein „Speichern unter“, keine Bildschirmaufnahme
            core.LaunchingExternalUriScheme += (_, e) => e.Cancel = true;
            core.SaveAsUIShowing += (_, e) => e.Cancel = true;
            core.ScreenCaptureStarting += (_, e) => e.Cancel = true;
            core.ProcessFailed += (_, e) =>
            {
                if (e.ProcessFailedKind is CoreWebView2ProcessFailedKind.BrowserProcessExited or CoreWebView2ProcessFailedKind.RenderProcessExited
                    or CoreWebView2ProcessFailedKind.RenderProcessUnresponsive)
                    Fail(new SignInWindowException(e.ProcessFailedKind.ToString()));
            };
            core.NavigationCompleted += (_, _) =>
            {
                LoadingText.Visibility = Visibility.Collapsed;
                Web.Visibility = Visibility.Visible;
            };
            core.Navigate(_start.AbsoluteUri);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Fail(new SignInWindowException(ex.Message, ex));
        }
    }

    private void OnNavigation(string uri, Action cancel, bool topLevel)
    {
        switch (EmbeddedSignIn.Decide(uri, _redirect, _extraHosts))
        {
            case SignInNavigation.Allow:
                return;
            case SignInNavigation.Complete:
                // Nicht laden (auf http://localhost lauscht niemand), sondern an MSAL geben. In einem Frame nur abbrechen.
                cancel();
                if (topLevel && Uri.TryCreate(uri, UriKind.Absolute, out var result) && _tcs.TrySetResult(result)) CloseLater();
                return;
            default:
                cancel();
                // Hauptseite auf eine fremde Adresse: Anmeldung abbrechen und den Host nennen (VIT-0193). Frames still verwerfen.
                if (topLevel) Fail(new SignInHostBlockedException(EmbeddedSignIn.BlockedTarget(uri)));
                return;
        }
    }

    private void Fail(Exception ex)
    {
        if (_tcs.TrySetException(ex)) CloseLater();
    }

    /// <summary>Nicht aus einem Ereignis von WebView2 heraus schließen (das Steuerelement wird beim Schließen entsorgt).</summary>
    private void CloseLater() => Dispatcher.BeginInvoke(() => { if (!_closed) Close(); });

    /// <summary>Abbrechen von außen (Zeitlimit, Sperre beendet): Fenster zu, Ergebnis abgebrochen.</summary>
    public void Cancel()
    {
        _tcs.TrySetException(new OperationCanceledException());
        if (!_closed) Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Cancel();

    /// <summary>
    /// WebView2 schließen, auf das Ende der Browser-Prozesse warten (höchstens 5 s) und den Profilordner löschen
    /// (mehrere Versuche). Was übrig bleibt, räumt der nächste Start bzw. Versuch auf (EphemeralProfiles.CleanUp).
    /// </summary>
    private async Task CleanUpAsync()
    {
        try
        {
            // Erst den Start abwarten: sonst legte ein noch laufendes CreateAsync den Ordner nach dem Löschen neu an
            try { await _starting; } catch (Exception ex) when (ex is not OutOfMemoryException) { }
            var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (_env is { } env) env.BrowserProcessExited += (_, _) => exited.TrySetResult();
            else exited.TrySetResult();
            try { Web.Dispose(); } catch (Exception ex) when (ex is not OutOfMemoryException) { }
            await Task.WhenAny(exited.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            _cleanup.TrySetResult(await EphemeralProfiles.DeleteWithRetryAsync(_profile, attempts: 10, TimeSpan.FromMilliseconds(500)));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _cleanup.TrySetResult(false);
        }
    }
}
