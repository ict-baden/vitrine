// SPDX-License-Identifier: MIT
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Platform;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Einzelner Eintrag ins Protokoll von einem Prozess ohne eigenes, geöffnetes Protokoll (zweite Instanz, Wächter).
/// Schreibt der Dienst das Protokoll (#15), geht der Eintrag über die Protokoll-Pipe an ihn – der Ordner ist für Benutzer
/// nur lesbar, ein eigener Schreibversuch landete still im Ordner pro Benutzer. Ist der Dienst nicht erreichbar: in den
/// Ordner pro Benutzer (vermerkt als nicht zugestellt) und ins Ereignisprotokoll. Ohne WPF nutzbar (Wächter, Issue #18).
/// </summary>
public static class FallbackAudit
{
    public static void Write(AuditSettings settings, string userName, AuditEventType type, string detail)
    {
        try
        {
            var log = new AuditLog(settings, userName, new EventLogSink());
            if (!AuditLink.ServiceExpected())
            {
                log.Write(type, detail: detail);
                return;
            }
            using var link = new AuditLink();
            log.UseForwarder(link);
            link.Start();
            var draft = log.Write(type, detail: detail);
            var until = DateTime.UtcNow + TimeSpan.FromSeconds(2);
            while (!link.Connected && DateTime.UtcNow < until) Thread.Sleep(50);
            if (link.Flush(TimeSpan.FromSeconds(2))) return;
            log.WriteUnsent(link.TakeUnsent());
            try { new EventLogSink().Write(draft); } catch { }
        }
        catch { }
    }

    /// <summary>
    /// Für den Wächter: Konfiguration (Protokoll-Einstellungen aus Gerät, Benutzer und Richtlinie) erst laden, wenn wirklich
    /// etwas zu schreiben ist – der Wächter wartet sonst nur und braucht sie nie.
    /// </summary>
    public static void WriteWithCurrentConfig(AuditEventType type, string detail)
    {
        try
        {
            var store = new ConfigStore(ConfigFiles.Default, RegistryPolicySource.All(), new AdminOnlyFiles());
            store.Load();
            Write(store.Current.Audit, new Vitrine.Services.Auth.SessionInfo().UserName, type, detail);
        }
        catch { }
    }
}
