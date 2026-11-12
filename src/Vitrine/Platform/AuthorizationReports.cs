// SPDX-License-Identifier: MIT
using Vitrine.Core.About;
using Vitrine.Core.Config;
using Vitrine.Core.Governance;
using Vitrine.Services.Auth;

namespace Vitrine.Platform;

/// <summary>Berechtigungsbericht schreiben (--authorization-report, Einstellungen › Protokoll).</summary>
public static class AuthorizationReports
{
    /// <summary>
    /// Endet <paramref name="file"/> auf .csv, nur CSV; sonst HTML in die Datei und CSV daneben (gleicher Name, .csv).
    /// Liefert die geschriebenen Dateien.
    /// </summary>
    /// <param name="fidoStore">Stand der Schlüssel-Ablage vom Dienst, soweit erreichbar (letzter Abgleich mit dem AD).</param>
    public static IReadOnlyList<string> Write(string file, ConfigStore store, string generatedBy, Core.Fido.FidoStoreInfo? fidoStore = null)
    {
        var report = AuthorizationReport.Build(store.Current, store.IsManaged, new WindowsGroupResolver(), Environment.MachineName,
            generatedBy, DateTimeOffset.UtcNow, AppInfo.Version, fidoStore);
        var full = Path.GetFullPath(file);
        var utf8 = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true); // mit BOM, damit Excel UTF-8 erkennt
        if (string.Equals(Path.GetExtension(full), ".csv", StringComparison.OrdinalIgnoreCase))
        {
            File.WriteAllText(full, report.ToCsv(), utf8);
            return [full];
        }
        var csv = Path.ChangeExtension(full, ".csv");
        File.WriteAllText(full, report.ToHtml(), new System.Text.UTF8Encoding(false));
        File.WriteAllText(csv, report.ToCsv(), utf8);
        return [full, csv];
    }
}
