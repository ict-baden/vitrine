// SPDX-License-Identifier: MIT
using System.Diagnostics;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Services.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Governance;
using Vitrine.Core.About;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;
using Vitrine.Core.Fido;
using System.Globalization;
using Vitrine.Services.Lock;
using Vitrine.UI.Theme;

namespace Vitrine.UI;

/// <summary>Was die Person in den Einstellungen darf (Rollen, Roles.*).</summary>
public enum SettingsAccess
{
    /// <summary>Alles ansehen und ändern (Einstellungs-Administrator).</summary>
    Full,
    /// <summary>Nur Protokoll und Berechtigungsbericht, nichts ändern (Prüfer).</summary>
    AuditOnly,
}

public partial class SettingsWindow : Window, IThemedWindow
{
    private static readonly string[] Accents = { "", "#5B8CFF", "#8B5CF6", "#0EA5E9", "#14B8A6", "#22C55E", "#F59E0B", "#EF4444", "#EC4899" };

    private readonly ConfigStore _store;
    private readonly SessionInfo _session;
    private readonly LockController _lock;
    private readonly AuthRegistry _auth;
    private readonly AuditLog _audit;
    private readonly TriggerService _triggers;
    private readonly DispatcherTimer _dirtyTimer;
    private readonly Action _openAbout;
    private readonly Action _afterReload;
    private VitrineConfig _edit = new();
    private string _savedJson = "";
    private readonly SettingsAccess _access;
    private readonly AuthOutcome? _operator;
    private readonly FidoAdministration _fido;

    /// <summary>
    /// Pfade für die Anzeige. Der Screenshot-Modus setzt hier die Standardorte statt seiner Temp-Ordner ein, damit auf den
    /// Bildern keine Pfade des Build-Rechners stehen.
    /// </summary>
    internal static Func<string, string> DisplayPath { get; set; } = p => p;

    public SettingsWindow(ConfigStore store, SessionInfo session, LockController lockController, AuthRegistry auth,
        AuditLog audit, TriggerService triggers, Action openAbout, Action afterReload,
        SettingsAccess access = SettingsAccess.Full, AuthOutcome? operatorWho = null)
    {
        InitializeComponent();
        _access = access;
        // Wer die Einstellungen geöffnet hat (Bestätigung oder Benutzer der Sitzung) – steht als Person im Protokoll
        _operator = operatorWho;
        _store = store;
        _session = session;
        _lock = lockController;
        _auth = auth;
        _audit = audit;
        _triggers = triggers;
        _openAbout = openAbout;
        _afterReload = afterReload;
        _fido = new FidoAdministration(lockController);

        NavInitials.Text = session.Initials;
        NavUser.Text = session.DisplayName;
        NavMachine.Text = $"{session.MachineName} · {session.UserName}";
        VersionText.Text = Loc.F("Info_Version", AppInfo.Version);
        InfoConfigPath.Description = DisplayPath(_store.MachineFile);
        PipeNameText.Text = $@"\\.\pipe\{AppPaths.PipeName(session.SessionId)}";
        // Beispiel mit Bereich („Mo-Fr“); einzelne Tage mit Komma gehen ebenso
        ScheduleCard.Description = Loc.F("Lock_Schedule_Desc",
            $"{Schedule.DayName(DayOfWeek.Monday, CultureInfo.CurrentCulture)}-{Schedule.DayName(DayOfWeek.Friday, CultureInfo.CurrentCulture)}");

        TriggerCombo.ItemsSource = new[]
        {
            new Choice(UnlockTrigger.AnyInput, Loc.T("Unlock_TriggerAny")),
            new Choice(UnlockTrigger.KeyOnly, Loc.T("Unlock_TriggerKey")),
            new Choice(UnlockTrigger.HotkeyOnly, Loc.T("Unlock_TriggerHotkey")),
        };
        KeysStoreCombo.ItemsSource = new[]
        {
            new Choice(FidoStoreKind.Local, Loc.T("Keys_StoreLocalOption")),
            new Choice(FidoStoreKind.ActiveDirectory, Loc.T("Keys_StoreDirectoryOption")),
        };
        LockModeCombo.ItemsSource = new[]
        {
            new Choice(LockMode.Overlay, Loc.T("Lock_ModeOverlay")),
            new Choice(LockMode.Desktop, Loc.T("Lock_ModeDesktop")),
        };
        FailureCombo.ItemsSource = new[]
        {
            new Choice(FailureAction.None, Loc.T("Sec_ActionNone")),
            new Choice(FailureAction.LockWorkstation, Loc.T("Sec_ActionLock")),
            new Choice(FailureAction.LogOff, Loc.T("Sec_ActionLogOff")),
            new Choice(FailureAction.Shutdown, Loc.T("Sec_ActionShutdown")),
        };
        LanguageCombo.ItemsSource = new[] { new Choice("", Loc.T("Look_LanguageSystem")) }
            .Concat(UiLanguage.Supported.Select(c => new Choice(c, UiLanguage.ChoiceName(c, Loc.T("Language_MachineTranslated")))))
            .ToArray();

        BuildAccentSwatches();
        LoadFromStore();

        _dirtyTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(600) };
        _dirtyTimer.Tick += (_, _) => UpdateFooter();
        _dirtyTimer.Start();

        SourceInitialized += (_, _) => ThemeManager.ApplyWindowChrome(this);
        Loaded += (_, _) => { MarkManaged(); RefreshLog(); ApplyAccess(); };
        Closed += (_, _) => _dirtyTimer.Stop();
        _lock.StatusChanged += OnLockStatus;
        Closed += (_, _) => _lock.StatusChanged -= OnLockStatus;
        _lock.ResponsibilityChanged += OnResponsibility;
        Closed += (_, _) => _lock.ResponsibilityChanged -= OnResponsibility;
    }

    /// <summary>Seiten für ShowPage und die Screenshots.</summary>
    public static readonly string[] Pages = ["home", "lock", "unlock", "look", "security", "roles", "keys", "entra", "audit", "integration", "info"];

    public void ShowPage(string name)
    {
        var nav = name switch
        {
            "lock" => NavLock,
            "unlock" => NavUnlock,
            "look" => NavLook,
            "security" => NavSecurity,
            "roles" => NavRoles,
            "keys" => NavKeys,
            "entra" => NavEntra,
            "audit" => NavAudit,
            "integration" => NavIntegration,
            "info" => NavInfo,
            _ => NavHome,
        };
        nav.IsChecked = true;
    }

    // ================= Laden / Speichern =================

    private void LoadFromStore()
    {
        _edit = Clone(_store.Editable);
        DataContext = _edit;
        HotkeyBox.Text = Hotkey.Display(_edit.Lock.Hotkey);
        ScheduleBox.Text = ScheduleText(_edit.Lock.Schedule);
        AutostartToggle.IsChecked = Autostart.IsEnabled;
        // Unter dem Dienst startet er Vitrine in jeder Sitzung; ein zweiter Start pro Benutzer würde nur stören
        if (Services.Supervisor.ServiceLink.Connected)
        {
            AutostartToggle.IsEnabled = false;
            AutostartCard.Description = Loc.T("Lock_Autostart_Service");
        }
        RedirectBox.Text = RedirectUri(_edit.Entra.ClientId);
        // Build ohne Windows-Kontobroker (-p:WamBroker=false, docs/entra-id.md): Schalter ohne Wirkung
        if (!EntraIdProvider.BrokerIncluded)
        {
            BrokerToggle.IsEnabled = false;
            BrokerCard.Description = Loc.T("Entra_Broker_NotIncluded");
        }
        UpdateBrokerWarning();
        HighlightAccent();
        _savedJson = Serialize(_edit);
        RefreshOverview();
    }

    /// <summary>
    /// Prüfer: nur die Seite Protokoll, nichts änderbar (Schalter der Seite gesperrt, Speichern ausgeblendet).
    /// </summary>
    private void ApplyAccess()
    {
        if (_access != SettingsAccess.AuditOnly) return;
        foreach (var nav in new[] { NavHome, NavLock, NavUnlock, NavLook, NavSecurity, NavRoles, NavEntra, NavIntegration })
            nav.Visibility = Visibility.Collapsed;
        foreach (var card in FindChildren<SettingCard>(PageAudit)) card.IsEnabled = false;
        SaveButton.Visibility = DiscardButton.Visibility = Visibility.Collapsed;
        _dirtyTimer.Stop();
        ShowPage("audit");
        ShowFooter("\uE72E", Loc.T("Settings_AuditOnly"));
    }

    private void OnResponsibility() => Dispatcher.BeginInvoke(RefreshOverview);

    /// <summary>Person für den Protokolleintrag: wer die Einstellungen geöffnet hat, sonst der Benutzer der Sitzung.</summary>
    private string OperatorName => _operator?.UserName ?? _session.UserName;

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (_access != SettingsAccess.Full) return;
        if (!ApplyUiOnlyFields()) return;
        // Unterschied zum gespeicherten Stand (Geheimnisse maskiert) und ggf. Begründung – beides kommt ins Protokoll
        var changes = ConfigDiff.Compute(System.Text.Json.Nodes.JsonNode.Parse(_savedJson)!.AsObject(),
            JsonSerializer.SerializeToNode(_edit, ConfigStore.Json)!.AsObject());
        string? reason = null;
        if (_store.Current.Security.ReasonRequiredForConfigChanges || _edit.Security.ReasonRequiredForConfigChanges)
        {
            reason = ReasonDialog.Ask(this, Reasons.EffectiveMinLength(_store.Current.Security.ReasonMinLength), changes);
            if (reason is null) return;
        }
        try
        {
            _store.Save(_edit);
            AfterSave(changes, reason);
        }
        // Kein Schreibrecht – oder Besitzer/Rechte lassen sich ohne Adminrechte nicht setzen (Ordner, die ein Benutzer
        // angelegt hatte): dann mit Adminrechten übernehmen
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException
                                       or System.Security.Principal.IdentityNotMappedException)
        {
            // Normale Benutzer dürfen %ProgramData%\ICT-Baden\Vitrine nicht beschreiben → mit Adminrechten übernehmen
            var tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"vitrine-{Guid.NewGuid():N}.json");
            var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(_edit, ConfigStore.Json));
            File.WriteAllBytes(tmp, bytes);
            // Prüfsumme bindet den Prozess mit Adminrechten an genau diesen Inhalt (Austausch der Temp-Datei nach UAC)
            var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
            try
            {
                var p = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"--apply-config \"{tmp}\" --sha256 {sha}")
                { UseShellExecute = true, Verb = "runas" });
                p?.WaitForExit();
                _store.Load();
                // Der Prozess mit Adminrechten meldet Fehler selbst (Meldungsfenster); hier nicht „Gespeichert“ anzeigen
                if (p is null || p.ExitCode != 0) ShowFooter("\uE7BA", Loc.Error(ErrorCodes.SaveFailed, $"exit {p?.ExitCode}"), warn: true);
                else AfterSave(changes, reason);
            }
            catch (System.ComponentModel.Win32Exception)
            {
                ShowFooter("\uE7BA", Loc.Error(ErrorCodes.SaveNeedsAdmin), warn: true);
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
        catch (Exception ex)
        {
            ShowFooter("\uE7BA", Loc.Error(ErrorCodes.SaveFailed, ex.Message), warn: true);
        }
    }

    private void AfterSave(IReadOnlyList<ConfigChange> changes, string? reason)
    {
        _lock.Log(AuditEventType.ConfigChanged, OperatorName, _operator?.Details.GetValueOrDefault("method"), ConfigDiff.Summary(changes),
            ConfigDiff.ToAuditData(changes, reason));
        ThemeManager.SetAccent(_store.Current.Appearance.Accent);
        LoadFromStore();
        MarkManaged();
        ShowFooter("\uE73E", Loc.T("Footer_Saved"));
        _afterReload();
    }

    private void Discard_Click(object sender, RoutedEventArgs e) => LoadFromStore();

    /// <returns>false, wenn eine Zeile des Zeitplans nicht lesbar ist – dann wird nicht gespeichert (vorher fiel sie still weg).</returns>
    private bool ApplyUiOnlyFields()
    {
        var lines = ScheduleBox.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var bad = lines.Where(l => Schedule.Parse(l, CultureInfo.CurrentCulture) is null).ToList();
        if (bad.Count > 0)
        {
            ShowFooter("\uE7BA", CoreText.Error(ErrorCodes.ConfigEntryInvalid, Loc.T("Lock_Schedule"), string.Join("; ", bad)), warn: true);
            NavLock.IsChecked = true;
            return false;
        }
        _edit.Lock.Schedule = lines.Select(l => Schedule.Parse(l, CultureInfo.CurrentCulture)!).ToList();
        return true;
    }

    private void UpdateFooter()
    {
        if (!IsLoaded) return;
        var dirty = Serialize(_edit) != _savedJson || ScheduleBox.Text.Trim() != ScheduleText(_edit.Lock.Schedule).Trim();
        if (dirty) ShowFooter("\uE7C3", Loc.T("Footer_Unsaved"));
        else if (FooterText.Text == Loc.T("Footer_Unsaved")) ShowFooter("\uE73E", Loc.T("Footer_AllSaved"));
        SaveButton.IsEnabled = dirty;
    }

    private void ShowFooter(string glyph, string text, bool warn = false)
    {
        FooterIcon.Text = glyph;
        FooterText.Text = text;
        FooterIcon.SetResourceReference(TextBlock.ForegroundProperty, warn ? "SystemFillColorCriticalBrush" : "TextFillColorSecondaryBrush");
    }

    private static VitrineConfig Clone(VitrineConfig c) =>
        JsonSerializer.Deserialize<VitrineConfig>(JsonSerializer.Serialize(c, ConfigStore.Json), ConfigStore.Json)!;

    private static string Serialize(VitrineConfig c) => JsonSerializer.Serialize(c, ConfigStore.Json);

    private static string ScheduleText(IEnumerable<ScheduleEntry> entries) =>
        string.Join(Environment.NewLine, entries.Select(e => Schedule.Format(e, CultureInfo.CurrentCulture)));

    /// <summary>Per Richtlinie festgelegte Werte sperren und kennzeichnen.</summary>
    private void MarkManaged()
    {
        foreach (var card in FindChildren<SettingCard>(this))
            card.IsManaged = card.PolicyPath is { } p && _store.IsManaged(p);
    }

    private static IEnumerable<T> FindChildren<T>(DependencyObject root) where T : DependencyObject
    {
        foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
        {
            if (child is T t) yield return t;
            foreach (var x in FindChildren<T>(child)) yield return x;
        }
    }

    // ================= Navigation =================

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsInitialized || sender is not RadioButton rb) return;
        var pages = new (RadioButton nav, StackPanel page)[]
        {
            (NavHome, PageHome), (NavLock, PageLock), (NavUnlock, PageUnlock), (NavLook, PageLook),
            (NavSecurity, PageSecurity), (NavRoles, PageRoles), (NavKeys, PageKeys), (NavEntra, PageEntra), (NavAudit, PageAudit), (NavIntegration, PageIntegration),
            (NavInfo, PageInfo),
        };
        foreach (var (nav, page) in pages)
            page.Visibility = nav == rb ? Visibility.Visible : Visibility.Collapsed;
        PageTitle.Text = rb.Content?.ToString();
        Scroller.ScrollToTop();
        if (rb == NavHome) RefreshOverview();
        if (rb == NavAudit) RefreshLog();
        if (rb == NavKeys) _ = RefreshKeysAsync();
    }

    // ================= Übersicht =================

    private void OnLockStatus(LockStatus s) => Dispatcher.BeginInvoke(RefreshOverview);

    private void RefreshOverview()
    {
        bool locked = _lock.Status == LockStatus.Locked;
        HomeStatus.Text = locked ? Loc.T("Status_Locked") : Loc.T("Home_StatusReady");
        HomeDot.SetResourceReference(Shape.FillProperty, locked ? "SystemFillColorCautionBrush" : "SystemFillColorSuccessBrush");
        HomeHint.Text = _lock.LastUnlockedBy is { } who && !locked
            ? Loc.F("Home_LastUnlocked", who)
            : Loc.T("Home_Hint");
        var responsible = (Application.Current as App)?.ResponsibleText();
        HomeResponsible.Text = responsible ?? "";
        HomeResponsible.Visibility = responsible is null ? Visibility.Collapsed : Visibility.Visible;

        var cfg = _store.Current;
        FactHotkey.Text = Hotkey.Display(cfg.Lock.Hotkey);
        FactIdle.Text = cfg.Lock.IdleMinutes > 0 ? Loc.F("Home_AfterMinutes", cfg.Lock.IdleMinutes) : Loc.T("Common_Off");
        FactMethods.Text = string.Join(", ", cfg.Unlock.Methods.Select(m => m switch
        {
            "entra" => "Microsoft",
            "windows" => Loc.T("Method_WindowsShort"),
            "hello" => "Windows Hello",
            "windowslogon" => Loc.T("Method_WindowsLogon"),
            "fido" => Loc.T("Method_Fido"),
            _ => _auth.Get(m)?.DisplayName ?? m,
        }));

        Notices.Children.Clear();
        if (string.IsNullOrWhiteSpace(cfg.Entra.ClientId) && cfg.Unlock.Methods.Contains("entra"))
            AddNotice("\uE77B", Loc.T("Notice_EntraTitle"), Loc.T("Notice_EntraText"), () => NavEntra.IsChecked = true);
        if (_triggers.HotkeyError is { } hk)
            AddNotice("\uE765", Loc.T("Notice_HotkeyTitle"), hk, () => NavLock.IsChecked = true);
        if (_store.ManagedPaths.Count > 0)
            AddNotice("\uE7EF", Loc.T("Notice_ManagedTitle"), Loc.F("Notice_ManagedText", _store.ManagedPaths.Count), null);
        if (_store.UsesLegacyPolicy)
            AddNotice("\uE7EF", Loc.T("Notice_LegacyPolicyTitle"), Loc.T("Notice_LegacyPolicyText"), null);
        if (_store.UsesLegacyMachineFile)
            AddNotice("\uE8B7", Loc.T("Notice_LegacyConfigTitle"), Loc.F("Notice_LegacyConfigText", AppPaths.LegacyMachineConfigFile, _store.MachineFile), null);
        foreach (var err in _store.LoadErrors) AddNotice("\uE7BA", Loc.T("Notice_ConfigErrorTitle"), err, null);
        // Nur Microsoft, aber am Sperrbildschirm nicht möglich; Regeln ohne passende Windows-Anmeldung (VIT-0016, VIT-0017)
        foreach (var w in Core.Auth.LockScreenMethods.Warnings(cfg.Unlock, EntraIdProvider.OnLockScreen(cfg.Entra)))
            AddNotice("\uE7BA", Loc.T("Notice_ConfigErrorTitle"), w.Message, () => NavUnlock.IsChecked = true);
        // Microsoft: WebView2-Laufzeit fehlt (VIT-0190), Broker eingeschaltet (VIT-0191)
        // Sicherheitsschlüssel: Windows-Sicherheitsdialog bekäme während der Sperre keine Eingaben (VIT-0423)
        foreach (var w in Core.Fido.FidoWarnings.For(cfg))
            AddNotice("\uE88E", Loc.T("Notice_ConfigErrorTitle"), w.Message, () => NavSecurity.IsChecked = true);
        foreach (var w in EntraIdProvider.Warnings(cfg.Entra))
            AddNotice("\uE77B", Loc.T("Notice_ConfigErrorTitle"), w.Message, () => NavEntra.IsChecked = true);
        // Niemand darf die Einstellungen ändern (VIT-0430)
        foreach (var code in RoleCheck.Warnings(cfg))
            AddNotice("\uE7EF", Loc.T("Notice_ConfigErrorTitle"), CoreText.Error(code), () => NavRoles.IsChecked = true);
        foreach (var err in _auth.PluginErrors) AddNotice("\uE74C", Loc.T("Notice_PluginTitle"), err, () => NavIntegration.IsChecked = true);
        if (cfg.Unlock.Methods.Contains("pin"))
            AddNotice("\uE8AC", Loc.T("Notice_PinTitle"), Loc.T("Notice_PinText"), () => NavUnlock.IsChecked = true);
        NoticeHeader.Visibility = Notices.Children.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        var plugins = _auth.All.Where(p => p.Id is not ("entra" or "windows" or "hello" or "windowslogon" or "fido" or "pin")).ToList();
        PluginText.Text = plugins.Count == 0
            ? Loc.F("Int_NoPlugins", DisplayPath(System.IO.Path.Combine(AppContext.BaseDirectory, "Plugins")))
            : string.Join(Environment.NewLine, plugins.Select(p => $"• {p.DisplayName}  (ID: {p.Id})"));
    }

    private void AddNotice(string glyph, string title, string text, Action? onClick)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var icon = new TextBlock { Text = glyph, Style = (Style)FindResource("Icon"), Margin = new Thickness(0, 0, 16, 0) };
        icon.SetResourceReference(TextBlock.ForegroundProperty, "AccentFillColorDefaultBrush");
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock { Text = title, Style = (Style)FindResource("BodyStrong") });
        stack.Children.Add(new TextBlock { Text = text, Style = (Style)FindResource("Caption") });
        Grid.SetColumn(stack, 1);
        grid.Children.Add(icon);
        grid.Children.Add(stack);
        if (onClick is not null)
        {
            var b = new Button { Content = Loc.T("Common_Open"), Margin = new Thickness(16, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            b.Click += (_, _) => onClick();
            Grid.SetColumn(b, 2);
            grid.Children.Add(b);
        }
        Notices.Children.Add(new Border { Style = (Style)FindResource("Card"), Child = grid });
    }

    private void LockNow_Click(object sender, RoutedEventArgs e) => _lock.Lock(LockTriggers.Settings);

    /// <summary>Nur für Screenshots: Protokollordner wie bei einer Standardinstallation leer zeigen (der Lauf schreibt in einen Temp-Ordner).</summary>
    internal void ShowDefaultAuditFolder()
    {
        _edit.Audit.Directory = null;
        _savedJson = Serialize(_edit);
        DataContext = null;
        DataContext = _edit;
    }

    // ================= Sperren =================

    private void HotkeyBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        e.Handled = true;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        if (key is Key.Delete or Key.Back) { _edit.Lock.Hotkey = ""; HotkeyBox.Text = "–"; return; }
        if (key is Key.LeftCtrl or Key.RightCtrl or Key.LeftAlt or Key.RightAlt or Key.LeftShift or Key.RightShift
            or Key.LWin or Key.RWin or Key.Tab or Key.Escape) return;
        var mods = Keyboard.Modifiers;
        if (Keyboard.IsKeyDown(Key.LWin) || Keyboard.IsKeyDown(Key.RWin)) mods |= ModifierKeys.Windows;
        if (mods == ModifierKeys.None || mods == ModifierKeys.Shift) { HotkeyBox.Text = Loc.T("Lock_HotkeyNeedsModifier"); return; }
        _edit.Lock.Hotkey = Hotkey.Format(mods, key);
        HotkeyBox.Text = Hotkey.Display(_edit.Lock.Hotkey);
    }

    private void Autostart_Click(object sender, RoutedEventArgs e) => Autostart.Set(AutostartToggle.IsChecked == true);

    // ================= Entsperren =================

    private void SetPin_Click(object sender, RoutedEventArgs e)
    {
        var pin = PinDialog.Ask(this);
        if (pin is null) return;
        _edit.Unlock.PinHash = pin.Length == 0 ? null : PinProvider.Hash(pin);
        if (pin.Length > 0) _edit.Unlock.MethodPin = true;
        DataContext = null;
        DataContext = _edit;
    }

    // ================= Sicherheitsschlüssel =================

    /// <summary>Zeile der Schlüsselliste.</summary>
    private sealed record KeyRow(FidoKeyInfo Key, string Title, string Text, double Opacity, string RevokeText, Visibility RevokeVisibility);

    private void RefreshKeys_Click(object sender, RoutedEventArgs e) => _ = RefreshKeysAsync();

    /// <summary>Stand und Liste vom Dienst (er allein liest und schreibt die Ablage).</summary>
    private async Task RefreshKeysAsync()
    {
        var status = await _fido.StatusAsync();
        var lines = new List<string>();
        if (status is not { } s)
        {
            lines.Add(CoreText.Error(ErrorCodes.FidoServiceRequired));
            KeysRegisterButton.IsEnabled = false;
        }
        else
        {
            KeysRegisterButton.IsEnabled = Services.Auth.WebAuthnApi.Available && s.StoreError is null;
            lines.Add(Loc.F("Keys_Status", s.Active, s.RpId));
            lines.Add(s.IsDirectory
                ? Loc.F("Keys_StoreDirectory", s.Location ?? "?", s.LastSync?.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) ?? Loc.T("Keys_NeverUsed"))
                : Loc.T("Keys_StoreLocal"));
            if (s.SyncError is { } syncError) lines.Add(syncError);
            if (s.StoreError is { } err) lines.Add(err);
            if (s.OtherRpId > 0) lines.Add(CoreText.Error(ErrorCodes.FidoRpIdChanged, s.OtherRpId, s.RpId));
        }
        if (!Services.Auth.WebAuthnApi.Available) lines.Add(CoreText.Error(ErrorCodes.FidoUnavailable));
        if (!_store.Current.Unlock.Methods.Contains("fido")) lines.Add(Loc.T("Keys_MethodOff"));
        KeysStatusText.Text = string.Join(Environment.NewLine, lines);

        var (keys, error) = await _fido.ListAsync();
        if (error is not null) ShowKeysResult(error, warn: true);
        var culture = CultureInfo.CurrentCulture;
        KeysList.ItemsSource = (keys ?? []).OrderBy(k => k.IsActive ? 0 : 1).ThenBy(k => k.Person, StringComparer.CurrentCultureIgnoreCase).Select(k => new KeyRow(k,
            $"{k.Label} · {k.Person}",
            k.IsActive
                ? Loc.F("Keys_RowActive", k.RegisteredAt?.ToLocalTime().ToString("g", culture) ?? "?", k.RegisteredBy,
                    k.LastUsedAt?.ToLocalTime().ToString("g", culture) ?? Loc.T("Keys_NeverUsed"), k.Aaguid)
                : Loc.F("Keys_RowRevoked", k.RevokedAt?.ToLocalTime().ToString("g", culture) ?? "?", k.RevokedBy ?? "?", k.RevokeReason ?? ""),
            k.IsActive ? 1.0 : 0.55, Loc.T("Keys_Revoke"), k.IsActive ? Visibility.Visible : Visibility.Collapsed)).ToList();
    }

    private void ShowKeysResult(string text, bool warn)
    {
        KeysResultText.Text = text;
        KeysResult.SetResourceReference(Border.BackgroundProperty, warn ? "SystemFillColorCriticalBackgroundBrush" : "SystemFillColorSuccessBackgroundBrush");
        KeysResult.Visibility = Visibility.Visible;
    }

    private async void RegisterKey_Click(object sender, RoutedEventArgs e)
    {
        if (FidoDialogs.AskRegistration(this) is not { } input) return;
        KeysRegisterButton.IsEnabled = false;
        try
        {
            var error = await _fido.RegisterAsync(new WindowInteropHelper(this).Handle, input.Account, input.Label, input.Reason,
                user => FidoDialogs.AskDirectoryLogin(this, user));
            ShowKeysResult(error ?? Loc.F("Keys_Registered_Ok", input.Label, input.Account), warn: error is not null);
        }
        finally { await RefreshKeysAsync(); }
    }

    private async void RevokeKey_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not FidoKeyInfo key) return;
        if (FidoDialogs.AskRevocation(this, key) is not { } reason) return;
        var error = await _fido.RevokeAsync(key, reason, user => FidoDialogs.AskDirectoryLogin(this, user));
        ShowKeysResult(error ?? Loc.F("Keys_Revoked_Ok", key.Label, key.Person), warn: error is not null);
        await RefreshKeysAsync();
    }

    // ================= Darstellung =================

    private void BuildAccentSwatches()
    {
        foreach (var hex in Accents)
        {
            bool system = hex.Length == 0;
            var b = new Button
            {
                Width = 28, Height = 28, Padding = new Thickness(0), Margin = new Thickness(3, 0, 3, 0), Tag = hex,
                BorderThickness = new Thickness(2), BorderBrush = Brushes.Transparent,
                ToolTip = system ? Loc.T("Look_AccentWindows") : hex,
            };
            if (system)
                b.Background = new SolidColorBrush(ThemeManager.AccentColorOfWindows);
            else
                b.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Template = SwatchTemplate();
            b.Click += (_, _) =>
            {
                _edit.Appearance.Accent = hex;
                HighlightAccent();
                ThemeManager.SetAccent(hex);
            };
            AccentSwatches.Children.Add(b);
        }
    }

    private static ControlTemplate SwatchTemplate()
    {
        var t = new ControlTemplate(typeof(Button));
        var outer = new FrameworkElementFactory(typeof(Border));
        outer.SetValue(Border.CornerRadiusProperty, new CornerRadius(14));
        outer.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
        outer.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
        outer.SetValue(Border.PaddingProperty, new Thickness(2));
        var inner = new FrameworkElementFactory(typeof(Border));
        inner.SetValue(Border.CornerRadiusProperty, new CornerRadius(10));
        inner.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
        outer.AppendChild(inner);
        t.VisualTree = outer;
        return t;
    }

    private void HighlightAccent()
    {
        foreach (var b in AccentSwatches.Children.OfType<Button>())
        {
            if (string.Equals(b.Tag as string, _edit.Appearance.Accent ?? "", StringComparison.OrdinalIgnoreCase))
                b.SetResourceReference(Control.BorderBrushProperty, "TextFillColorPrimaryBrush");
            else
                b.BorderBrush = Brushes.Transparent;
        }
    }

    private void Dim_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        // Vorschau sofort aktualisieren (die Bindung an die POCO-Konfiguration meldet keine Änderungen)
        if (PreviewDim is not null) PreviewDim.Opacity = e.NewValue / 100;
    }

    /// <summary>Bereiche auf dem Bildschirm aufziehen (UI/MaskEditor). Die Einstellungen treten solange zurück.</summary>
    private async void DrawMasks_Click(object sender, RoutedEventArgs e)
    {
        MasksBox.GetBindingExpression(TextBox.TextProperty)?.UpdateSource(); // getippte Zeilen zuerst übernehmen
        var state = WindowState;
        WindowState = WindowState.Minimized;
        try
        {
            if (await MaskEditor.EditAsync(_edit.Appearance.Masks) is { } masks)
            {
                _edit.Appearance.Masks = masks;
                DataContext = null;
                DataContext = _edit;
            }
        }
        finally
        {
            WindowState = state;
            Activate();
        }
    }

    private void ClearMasks_Click(object sender, RoutedEventArgs e)
    {
        _edit.Appearance.Masks = [];
        DataContext = null;
        DataContext = _edit;
    }

    private void BrowseLogo_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = Loc.T("Look_LogoFilter") };
        if (dlg.ShowDialog(this) == true)
        {
            _edit.Appearance.LogoPath = dlg.FileName;
            DataContext = null;
            DataContext = _edit;
        }
    }

    // ================= Entra =================

    private string RedirectUri(string? clientId) =>
        EntraIdProvider.UsesBroker(_edit.Entra)
            ? EntraIdProvider.RedirectUri(_edit.Entra, string.IsNullOrWhiteSpace(clientId) ? Loc.T("Entra_RedirectPlaceholder") : clientId)
            : EntraIdProvider.RedirectUri(_edit.Entra, clientId);

    private void Broker_Click(object sender, RoutedEventArgs e)
    {
        RedirectBox.Text = RedirectUri(_edit.Entra.ClientId);
        UpdateBrokerWarning();
    }

    /// <summary>Warnung unter dem Schalter, solange der Broker eingeschaltet ist (in diesem Build vorhanden).</summary>
    private void UpdateBrokerWarning()
    {
        bool on = EntraIdProvider.UsesBroker(_edit.Entra);
        BrokerWarning.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        BrokerWarningText.Text = on ? Core.Localization.CoreText.Error(Core.Localization.ErrorCodes.EntraBrokerRemembersAccounts) : "";
    }

    private void ClientId_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (RedirectBox is not null && sender is TextBox tb) RedirectBox.Text = RedirectUri(tb.Text);
    }

    private void CopyRedirect_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(RedirectBox.Text); ShowFooter("\uE8C8", Loc.T("Footer_RedirectCopied")); } catch { }
    }

    private async void TestEntra_Click(object sender, RoutedEventArgs e)
    {
        EntraResult.Visibility = Visibility.Visible;
        EntraResultText.Text = Loc.T("Entra_TestRunning");
        var provider = new EntraIdProvider(_session, () => _edit.Entra);
        var r = await provider.AuthenticateAsync(new AuthRequest
        {
            OwnerWindow = new WindowInteropHelper(this).Handle,
            Reason = Loc.T("Entra_TestButton"),
            SessionUser = _session.UserName,
            SessionUpn = _session.Upn,
        }, CancellationToken.None);

        if (!r.Success) { EntraResultText.Text = $"✗ {ErrorCodes.WithCode(r.Error ?? "", r.ErrorCode)}"; return; }
        // Wie beim Entsperren: lokale Gruppen und Administratoren über die Entra-SIDs (S-1-12-1-…)
        r = EntraLocalGroups.Expand(r, _edit.Unlock.AllowedGroups, WindowsAccounts.ToSid, new LocalGroupDirectory());
        var policy = UnlockPolicy.Evaluate(r, _edit.Unlock, resolveSid: WindowsAccounts.ToSid);
        string YesNo(bool b) => b ? Loc.T("Common_Yes") : Loc.T("Common_No");
        var rows = new (string label, string value)[]
        {
            (Loc.T("Entra_TestSignedIn"), $"{r.DisplayName} <{r.UserName}>"),
            (Loc.T("Entra_TestObjectId"), r.UserId ?? "–"),
            (Loc.T("Entra_TestTenant"), r.TenantId ?? "–"),
            (Loc.T("Entra_TestSessionUser"), YesNo(r.IsSessionUser)),
            (Loc.T("Entra_TestAdmin"), r.IsAdministrator ? Loc.T("Entra_TestAdminYes") : Loc.T("Common_No")),
            (Loc.T("Entra_TestGroups"), r.Groups.Count == 0 ? Loc.T("Entra_TestNoGroups") : string.Join(", ", r.Groups.Take(8))),
            (Loc.T("Entra_TestMayUnlock"), policy.Allowed ? Loc.T("Common_Yes") : $"{Loc.T("Common_No")} – {policy.Reason}"),
        };
        EntraResultText.Text = "✓ " + string.Join("\n  ", rows.Select(x => $"{x.label}: {x.value}"));
    }

    // ================= Protokoll =================

    private sealed record LogRow(string Glyph, Brush Brush, string Title, string Text, string Time);

    private void RefreshLog_Click(object sender, RoutedEventArgs e) => RefreshLog();

    /// <summary>Wer das Protokoll schreibt (#15): Dienst mit Schlüssel, Dienst gerade nicht erreichbar, oder die App selbst.</summary>
    private void ShowAuditMode()
    {
        string glyph, title, text, brush;
        if (_audit.Forwarding && _lock.AuditLink is { } link)
        {
            if (link.Problem is { } problem)
            {
                // Zustellproblem (VIT-0330): wartende Einträge und Grund statt „verbunden“
                (glyph, title, text, brush) = ("", Loc.T("Audit_ModeOfflineTitle"), problem.UserText(), "SystemFillColorCautionBackgroundBrush");
            }
            else if (link.Connected)
            {
                var key = Platform.AuditState.PublicKeys().LastOrDefault();
                (glyph, title, text, brush) = ("", Loc.T("Audit_ModeServiceTitle"), Loc.F("Audit_ModeServiceText", key?.Fingerprint ?? "–"),
                    "SystemFillColorSuccessBackgroundBrush");
            }
            else
                (glyph, title, text, brush) = ("", Loc.T("Audit_ModeOfflineTitle"), Loc.F("Audit_ModeOfflineText", link.Pending),
                    "SystemFillColorCautionBackgroundBrush");
        }
        else
            (glyph, title, text, brush) = ("", Loc.T("Audit_ModeLocalTitle"), Loc.T("Audit_ModeLocalText"), "SystemFillColorCriticalBackgroundBrush");
        AuditModeGlyph.Text = glyph;
        AuditModeTitle.Text = title;
        AuditModeText.Text = text;
        AuditModeBox.SetResourceReference(Border.BackgroundProperty, brush);
    }

    private void RefreshLog()
    {
        ShowAuditMode();
        var file = CurrentLogFile();
        var rows = new List<LogRow>();
        if (file is not null)
        {
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var lines = new List<string>();
                while (sr.ReadLine() is { } l) if (l.Length > 0) lines.Add(l);
                foreach (var line in lines.TakeLast(80).Reverse())
                {
                    if (AuditLog.Parse(line) is not { } e) continue;
                    rows.Add(ToRow(e));
                }
            }
            catch { }
        }
        LogList.ItemsSource = rows;
    }

    private LogRow ToRow(AuditEntry e)
    {
        Brush B(string key) => (Brush)FindResource(key);
        var (glyph, brush) = e.Event switch
        {
            AuditEventType.Locked => ("\uE72E", B("AccentFillColorDefaultBrush")),
            AuditEventType.Unlocked => ("\uE785", B("SystemFillColorSuccessBrush")),
            AuditEventType.UnlockFailed => ("\uE7BA", B("SystemFillColorCriticalBrush")),
            AuditEventType.UnlockDenied => ("\uE8F8", B("SystemFillColorCriticalBrush")),
            AuditEventType.SignatureGranted => ("\uEE56", B("SystemFillColorSuccessBrush")),
            AuditEventType.SignatureFailed => ("\uEE56", B("SystemFillColorCriticalBrush")),
            AuditEventType.FailureActionTriggered => ("\uE7E8", B("SystemFillColorCautionBrush")),
            AuditEventType.ConfigChanged => ("\uE713", B("TextFillColorSecondaryBrush")),
            AuditEventType.PromptShown => ("\uE8BD", B("TextFillColorTertiaryBrush")),
            AuditEventType.AppStarted => ("\uE768", B("TextFillColorTertiaryBrush")),
            AuditEventType.AppStopped => ("\uE71A", B("TextFillColorTertiaryBrush")),
            _ => ("\uE946", B("TextFillColorTertiaryBrush")),
        };
        var title = Loc.Strings.GetString("Event_" + e.Event, CultureInfo.CurrentUICulture) ?? e.Event.ToString();
        // Bekannte englische Details übersetzt zeigen (im Protokoll bleiben sie sprachunabhängig)
        var detail = AuditDetails.TryLockedFor(e.Detail, out var duration) ? Loc.F("Audit_LockedFor", duration) : e.Detail;
        var text = string.Join(" · ", new[] { e.Actor, e.Method, detail }.Where(s => !string.IsNullOrEmpty(s)));
        return new LogRow(glyph, brush, title, text, e.Time.ToLocalTime().ToString("g", CultureInfo.CurrentCulture));
    }

    private string? CurrentLogFile() => _audit.CurrentFile();

    private void VerifyLog_Click(object sender, RoutedEventArgs e)
    {
        var file = CurrentLogFile();
        VerifyResult.Visibility = Visibility.Visible;
        if (file is null)
        {
            VerifyText.Text = Loc.T("Audit_NoLog");
            VerifyResult.SetResourceReference(Border.BackgroundProperty, "CardBackgroundFillColorDefaultBrush");
            return;
        }
        // Mit den Ankern des Dienstes und den Schlüsseln dieses Rechners (#15)
        var result = Platform.AuditTools.Verify(file);
        var (ok, msg) = (result.Ok, result.Message);
        VerifyText.Text = $"{(ok ? "✓" : "✗")} {System.IO.Path.GetFileName(file)}: {msg}";
        VerifyResult.SetResourceReference(Border.BackgroundProperty, ok ? "SystemFillColorAttentionBackgroundBrush" : "SystemFillColorCriticalBackgroundBrush");
    }

    /// <summary>Berechtigungsbericht (HTML und CSV daneben) für Prüfer und Einstellungs-Administratoren.</summary>
    private async void Report_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = Loc.T("Audit_ReportFilter"),
            FileName = $"vitrine-authorizations-{_session.MachineName}-{DateTime.Now:yyyy-MM-dd}.html",
        };
        if (dlg.ShowDialog(this) != true) return;
        VerifyResult.Visibility = Visibility.Visible;
        // Ablage der Sicherheitsschlüssel mit letztem Abgleich (vom Dienst, falls erreichbar)
        var fido = await _fido.StatusAsync();
        Core.Fido.FidoStoreInfo? fidoStore = fido is null ? null
            : new(Enum.TryParse<FidoStoreKind>(fido.Store, out var kind) ? kind : FidoStoreKind.Local, fido.LastSync, fido.SyncError, fido.Location);
        try
        {
            var written = Platform.AuthorizationReports.Write(dlg.FileName, _store, OperatorName, fidoStore);
            VerifyText.Text = "✓ " + Loc.F("Report_Written", string.Join(", ", written.Select(System.IO.Path.GetFileName)));
            VerifyResult.SetResourceReference(Border.BackgroundProperty, "SystemFillColorAttentionBackgroundBrush");
            try { Process.Start(new ProcessStartInfo(written[0]) { UseShellExecute = true }); } catch { }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            VerifyText.Text = "✗ " + Loc.Error(ErrorCodes.ReportFailed, ex.Message);
            VerifyResult.SetResourceReference(Border.BackgroundProperty, "SystemFillColorCriticalBackgroundBrush");
        }
    }

    private void OpenLogFolder_Click(object sender, RoutedEventArgs e)
    {
        var file = CurrentLogFile();
        var dir = file is null ? _audit.LogDirectory : System.IO.Path.GetDirectoryName(file)!;
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true }); } catch { }
    }

    // ================= Info =================

    private void OpenAbout_Click(object sender, RoutedEventArgs e) => _openAbout();

    private void OpenConfig_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var file = File.Exists(_store.MachineFile) ? _store.MachineFile
                     : File.Exists(AppPaths.LegacyMachineConfigFile) ? AppPaths.LegacyMachineConfigFile : null;
            if (file is null) { ShowFooter("\uE946", Loc.T("Footer_NotSavedYet")); return; }
            Process.Start(new ProcessStartInfo(System.IO.Path.Combine(Environment.SystemDirectory, "notepad.exe"), $"\"{file}\"") { UseShellExecute = false });
        }
        catch { }
    }

    private void ReloadPolicy_Click(object sender, RoutedEventArgs e)
    {
        _store.Load();
        LoadFromStore();
        MarkManaged();
        ShowFooter("\uE72C", Loc.F("Footer_Reloaded", _store.ManagedPaths.Count));
        _afterReload();
    }
}

/// <summary>Eingaben zum Registrieren und Widerrufen von Sicherheitsschlüsseln.</summary>
internal static class FidoDialogs
{
    public sealed record Registration(string Account, string Label, string Reason);

    public static Registration? AskRegistration(Window owner)
    {
        var account = new TextBox();
        var label = new TextBox();
        var reason = new TextBox { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 60 };
        Registration? result = null;
        Show(owner, Loc.T("Keys_RegisterTitle"), Loc.T("Keys_Register"),
            [(Loc.T("Keys_Account"), account), (Loc.T("Keys_Label"), label), (Loc.F("Keys_Reason", FidoProtocol.MinReasonLength), reason)],
            Loc.T("Keys_RegisterHint"),
            () =>
            {
                if (account.Text.Trim().Length == 0) return CoreText.Error(ErrorCodes.FidoAccountNotFound);
                if (label.Text.Trim().Length == 0 || label.Text.Trim().Length > FidoProtocol.MaxLabelLength || !FidoProtocol.ReasonValid(reason.Text))
                    return CoreText.Error(ErrorCodes.FidoReasonTooShort, FidoProtocol.MinReasonLength);
                result = new Registration(account.Text.Trim(), label.Text.Trim(), reason.Text.Trim());
                return null;
            });
        return result;
    }

    public static string? AskRevocation(Window owner, FidoKeyInfo key)
    {
        var reason = new TextBox { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 60 };
        string? result = null;
        Show(owner, Loc.T("Keys_RevokeTitle"), Loc.T("Keys_Revoke"), [(Loc.F("Keys_Reason", FidoProtocol.MinReasonLength), reason)],
            Loc.F("Keys_RevokeHint", key.Label, key.Person),
            () =>
            {
                if (!FidoProtocol.ReasonValid(reason.Text)) return CoreText.Error(ErrorCodes.FidoReasonTooShort, FidoProtocol.MinReasonLength);
                result = reason.Text.Trim();
                return null;
            });
        return result;
    }

    /// <summary>
    /// Ablage im AD: Konto (vorbelegt mit der registrierenden Person) und Windows-Kennwort für das Schreiben. Nur für diesen
    /// Vorgang an den Dienst, nie gespeichert. null = abgebrochen.
    /// </summary>
    public static FidoDirectoryLogin? AskDirectoryLogin(Window owner, string user)
    {
        var account = new TextBox { Text = user };
        var password = new PasswordBox();
        FidoDirectoryLogin? result = null;
        Show(owner, Loc.T("Keys_DirectoryLoginTitle"), Loc.T("Keys_DirectoryLoginOk"),
            [(Loc.T("Keys_DirectoryUser"), account), (Loc.T("Keys_DirectoryPassword"), password)],
            Loc.T("Keys_DirectoryLoginHint"),
            () =>
            {
                if (account.Text.Trim().Length == 0 || password.Password.Length == 0) return CoreText.Error(ErrorCodes.FidoDirectoryCredentialRequired);
                result = new FidoDirectoryLogin(account.Text.Trim(), password.Password);
                return null;
            }, focus: user.Length > 0 ? 1 : 0);
        return result;
    }

    /// <summary>Einfacher Dialog wie beim Entsperr-Kennwort: Felder, Hinweis, OK prüft (Fehlertext oder null = fertig).</summary>
    private static void Show(Window owner, string title, string okText, (string Label, Control Box)[] fields, string hint, Func<string?> ok, int focus = 0)
    {
        var w = new Window
        {
            Owner = owner, Title = title, Width = 480, SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false,
            FontFamily = (FontFamily)owner.FindResource("UiFont"),
        };
        w.SetResourceReference(Window.BackgroundProperty, "ApplicationBackgroundBrush");
        var stack = new StackPanel { Margin = new Thickness(24) };
        var hintText = new TextBlock { Text = hint, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(2, 0, 0, 12), Style = (Style)owner.FindResource("Caption") };
        stack.Children.Add(hintText);
        foreach (var (label, box) in fields)
        {
            stack.Children.Add(new TextBlock { Text = label, Style = (Style)owner.FindResource("Caption"), Margin = new Thickness(2, 8, 0, 6) });
            stack.Children.Add(box);
        }
        var err = new TextBlock { Margin = new Thickness(0, 10, 0, 0), Visibility = Visibility.Collapsed, TextWrapping = TextWrapping.Wrap };
        err.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
        stack.Children.Add(err);
        var okButton = new Button { Content = okText, Style = (Style)owner.FindResource("AccentButton"), MinWidth = 110, IsDefault = true };
        var cancel = new Button { Content = Loc.T("Common_Cancel"), MinWidth = 100, Margin = new Thickness(0, 0, 8, 0), IsCancel = true };
        okButton.Click += (_, _) =>
        {
            if (ok() is { } problem) { err.Text = problem; err.Visibility = Visibility.Visible; return; }
            w.Close();
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        buttons.Children.Add(cancel);
        buttons.Children.Add(okButton);
        stack.Children.Add(buttons);
        w.Content = stack;
        w.SourceInitialized += (_, _) => ThemeManager.ApplyWindowChrome(w, mica: false);
        w.Loaded += (_, _) => fields[focus].Box.Focus();
        w.ShowDialog();
    }
}

/// <summary>Kleiner Dialog zum Festlegen des Entsperr-Kennworts.</summary>
internal static class PinDialog
{
    public static string? Ask(Window owner)
    {
        var w = new Window
        {
            Owner = owner, Title = Loc.T("Pin_Title"), Width = 440, SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false,
            FontFamily = (FontFamily)owner.FindResource("UiFont"),
        };
        w.SetResourceReference(Window.BackgroundProperty, "ApplicationBackgroundBrush");
        var p1 = new PasswordBox();
        var p2 = new PasswordBox { Margin = new Thickness(0, 6, 0, 0) };
        var err = new TextBlock { Margin = new Thickness(0, 10, 0, 0), Visibility = Visibility.Collapsed, TextWrapping = TextWrapping.Wrap };
        err.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
        var ok = new Button { Content = Loc.T("Pin_Apply"), Style = (Style)owner.FindResource("AccentButton"), MinWidth = 110, IsDefault = true };
        var clear = new Button { Content = Loc.T("Pin_Remove"), MinWidth = 100, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = Loc.T("Common_Cancel"), MinWidth = 100, Margin = new Thickness(0, 0, 8, 0), IsCancel = true };

        string? result = null;
        ok.Click += (_, _) =>
        {
            if (p1.Password.Length < PinProvider.MinLength) { err.Text = CoreText.Error(ErrorCodes.PinTooShort, PinProvider.MinLength); err.Visibility = Visibility.Visible; return; }
            if (p1.Password != p2.Password) { err.Text = CoreText.Error(ErrorCodes.PinMismatch); err.Visibility = Visibility.Visible; return; }
            result = p1.Password; w.Close();
        };
        clear.Click += (_, _) => { result = ""; w.Close(); };

        var label = new TextBlock { Text = Loc.T("Pin_Label"), Style = (Style)owner.FindResource("Caption"), Margin = new Thickness(2, 0, 0, 6) };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        buttons.Children.Add(clear); buttons.Children.Add(cancel); buttons.Children.Add(ok);
        var stack = new StackPanel { Margin = new Thickness(24) };
        stack.Children.Add(label); stack.Children.Add(p1); stack.Children.Add(p2); stack.Children.Add(err); stack.Children.Add(buttons);
        w.Content = stack;
        w.SourceInitialized += (_, _) => ThemeManager.ApplyWindowChrome(w, mica: false);
        w.Loaded += (_, _) => p1.Focus();
        w.ShowDialog();
        return result;
    }
}

/// <summary>Begründung für eine Änderung der Einstellungen (Security.ReasonRequiredForConfigChanges), mit Liste der Änderungen.</summary>
internal static class ReasonDialog
{
    public static string? Ask(Window owner, int minLength, IReadOnlyList<ConfigChange> changes)
    {
        var w = new Window
        {
            Owner = owner, Title = Loc.T("Reason_Title"), Width = 520, SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false,
            FontFamily = (FontFamily)owner.FindResource("UiFont"),
        };
        w.SetResourceReference(Window.BackgroundProperty, "ApplicationBackgroundBrush");
        var intro = new TextBlock { Text = Loc.F("Reason_Intro", changes.Count), Style = (Style)owner.FindResource("Caption"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(2, 0, 0, 6) };
        var list = new TextBox
        {
            Text = string.Join(Environment.NewLine, changes.Select(c => $"{c.Path}: {c.Old ?? ConfigDiff.NotSet} → {c.New ?? ConfigDiff.NotSet}")),
            IsReadOnly = true, TextWrapping = TextWrapping.NoWrap, MaxHeight = 160, MinHeight = 60,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
        var label = new TextBlock { Text = Loc.F("Prompt_ReasonLabel", minLength), Style = (Style)owner.FindResource("Caption"), Margin = new Thickness(2, 12, 0, 6) };
        var box = new TextBox { MaxLength = Reasons.MaxLength, MinHeight = 54, TextWrapping = TextWrapping.Wrap, VerticalContentAlignment = VerticalAlignment.Top };
        System.Windows.Automation.AutomationProperties.SetLabeledBy(box, label);
        var err = new TextBlock { Margin = new Thickness(0, 10, 0, 0), Visibility = Visibility.Collapsed, TextWrapping = TextWrapping.Wrap };
        err.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
        var ok = new Button { Content = Loc.T("Reason_Save"), Style = (Style)owner.FindResource("AccentButton"), MinWidth = 110, IsDefault = true };
        var cancel = new Button { Content = Loc.T("Common_Cancel"), MinWidth = 100, Margin = new Thickness(0, 0, 8, 0), IsCancel = true };

        string? result = null;
        ok.Click += (_, _) =>
        {
            if (!Reasons.IsSufficient(box.Text, minLength)) { err.Text = CoreText.Error(ErrorCodes.ReasonTooShort, minLength); err.Visibility = Visibility.Visible; return; }
            result = Reasons.Normalize(box.Text);
            w.Close();
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        buttons.Children.Add(cancel); buttons.Children.Add(ok);
        var stack = new StackPanel { Margin = new Thickness(24) };
        stack.Children.Add(intro); stack.Children.Add(list); stack.Children.Add(label); stack.Children.Add(box); stack.Children.Add(err); stack.Children.Add(buttons);
        w.Content = stack;
        w.SourceInitialized += (_, _) => ThemeManager.ApplyWindowChrome(w, mica: false);
        w.Loaded += (_, _) => box.Focus();
        w.ShowDialog();
        return result;
    }
}

/// <summary>Autostart pro Benutzer über HKCU\...\Run.</summary>
internal static class Autostart
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public static bool IsEnabled
    {
        get
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(Key);
                return k?.GetValue("Vitrine") is string;
            }
            catch { return false; }
        }
    }

    public static void Set(bool on)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(Key, true);
            // --autostart: Läuft Vitrine schon (z. B. vom Dienst gestartet), beendet sich die zweite Instanz still
            if (on && Environment.ProcessPath is { } p) k.SetValue("Vitrine", $"\"{p}\" --autostart");
            else k.DeleteValue("Vitrine", false);
        }
        catch { }
    }
}
