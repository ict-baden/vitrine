// SPDX-License-Identifier: MIT
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Vitrine.Core.About;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.UI.Theme;

namespace Vitrine.UI;

/// <summary>
/// Info-Fenster (richtlinien/07): Version und Build, Copyright und Lizenz, Drittanbieter-Lizenzen, „Diese Software sendet
/// keine Daten an ICT-Baden.“, Links zu Webseite, Impressum, Datenschutz, Quellcode, Hilfe &amp; Support. Für jeden
/// Benutzer ohne Adminrechte erreichbar (Infobereich); hier wählt jeder auch seine Sprache (richtlinien/13 Punkt 8).
/// </summary>
public partial class AboutWindow : Window, IThemedWindow
{
    private readonly App _app;
    private readonly ConfigStore _store;
    private bool _loading = true;

    public AboutWindow(App app, ConfigStore store)
    {
        InitializeComponent();
        _app = app;
        _store = store;

        VersionText.Text = Loc.F("About_Version", AppInfo.Version, AppInfo.Commit ?? "–", Environment.Version.ToString(3));
        PublisherText.Text = Loc.F("About_Publisher", AppInfo.Publisher);
        LicenceCard.Description = Loc.F("About_LicenceText", AppInfo.Copyright);

        var device = UiLanguage.Normalize(store.Editable.Appearance.Language);
        var deviceName = device.Length == 0 ? Loc.T("Look_LanguageSystem") : UiLanguage.NativeName(device);
        LanguageCombo.ItemsSource = new[] { new Choice("", Loc.F("About_LanguageDefault", deviceName)) }
            .Concat(UiLanguage.Supported.Select(c => new Choice(c, UiLanguage.ChoiceName(c, Loc.T("Language_MachineTranslated")))))
            .ToArray();
        LanguageCombo.SelectedValue = UiLanguage.Normalize(UserPreferences.Load().Language);
        if (app.LanguageIsManaged)
        {
            LanguageCombo.IsEnabled = false;
            LanguageCombo.SelectedValue = UiLanguage.Normalize(store.Current.Appearance.Language);
            LanguageCard.Description = Loc.T("About_LanguageManaged");
        }
        else LanguageCard.Description = Loc.T("About_Language_Desc");
        _loading = false;

        SourceInitialized += (_, _) => ThemeManager.ApplyWindowChrome(this);
    }

    private void Language_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || LanguageCombo.SelectedValue is not string code) return;
        try { _app.ChangeLanguage(code); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ErrorText.Text = Loc.Error(ErrorCodes.PreferencesNotSaved, ex.Message);
            ErrorText.Visibility = Visibility.Visible;
        }
    }

    private void Licence_Click(object sender, RoutedEventArgs e) =>
        ShowText(Loc.T("About_Licence"), LicenseTexts.License(), AppInfo.LicenseUrl);

    private void Notices_Click(object sender, RoutedEventArgs e) =>
        ShowText(Loc.T("About_Notices"), LicenseTexts.ThirdPartyNotices(), AppInfo.NoticesUrl);

    private void Link_Click(object sender, RoutedEventArgs e)
    {
        var url = ((sender as FrameworkElement)?.Tag as string) switch
        {
            "support" => AppInfo.SupportUrl,
            "source" => AppInfo.RepositoryUrl,
            "website" => AppInfo.WebsiteUrl,
            "impressum" => AppInfo.ImpressumUrl,
            "privacy" => AppInfo.PrivacyUrl,
            _ => null,
        };
        if (url is not null) OpenLink(url);
    }

    /// <summary>Öffnet nur feste https-Adressen im Standardbrowser (richtlinien/09).</summary>
    internal static void OpenLink(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return;
        try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); } catch { }
    }

    private void ShowText(string title, string? text, string url)
    {
        var box = new TextBox
        {
            Text = text ?? Loc.F("About_TextMissing", url),
            IsReadOnly = true,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            FontFamily = new FontFamily("Cascadia Mono, Consolas"),
            FontSize = 12,
            BorderThickness = new Thickness(0),
        };
        var w = new Window
        {
            Owner = this, Title = title, Width = 820, Height = 640, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = box, ShowInTaskbar = false,
        };
        w.SetResourceReference(BackgroundProperty, "ApplicationBackgroundBrush");
        w.SourceInitialized += (_, _) => ThemeManager.ApplyWindowChrome(w, mica: false);
        w.ShowDialog();
    }
}
