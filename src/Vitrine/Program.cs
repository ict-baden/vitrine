// SPDX-License-Identifier: MIT
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;
using Vitrine.Platform;
using Vitrine.Services.Lock;
using Vitrine.Services.Supervisor;

namespace Vitrine;

/// <summary>
/// Einstieg (StartupObject in Vitrine.csproj statt des von WPF erzeugten Main). Dienst und Wächter laufen ohne WPF:
/// Sie sind die ganze Zeit da und brauchen weder Fenster noch Ressourcen der Oberfläche oder die Konfiguration
/// (Issue #18: zwei volle WPF-Prozesse je Sitzung für nichts). Alles andere startet wie bisher über <see cref="App"/>.
/// </summary>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var helper = HelperMode.Detect(args);
        switch (helper.Kind)
        {
            case HelperKind.Service:
                // Wie vorher in App.OnStartup: Sprache aus Richtlinie und Gerätekonfiguration (Fehlertexte, die der Dienst
                // über die Pipe an die App zurückgibt)
                ApplyServiceLanguage();
                VitrineService.RunService();
                return 0;
            case HelperKind.Watchdog:
                // Ergebnis des Rückfalls (#16) über den Protokolldienst bzw. pro Benutzer (#15); Konfiguration erst dann laden
                Watchdog.Run(helper.WatchdogPid, d => FallbackAudit.WriteWithCurrentConfig(AuditEventType.Error, d));
                return 0;
        }

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }

    private static void ApplyServiceLanguage()
    {
        try
        {
            var store = new ConfigStore(ConfigFiles.Default, RegistryPolicySource.All(), new AdminOnlyFiles());
            store.Load();
            var policy = store.IsManaged("Appearance.Language") ? store.Current.Appearance.Language : null;
            UiLanguage.Apply(policy, UserPreferences.Load().Language, store.Editable.Appearance.Language);
        }
        catch { /* Sprache ist Beiwerk – der Dienst startet trotzdem */ }
    }
}
