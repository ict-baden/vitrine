// SPDX-License-Identifier: MIT
using Vitrine.Core.Audit;
using Vitrine.Core.Localization;

namespace Vitrine.Platform;

/// <summary>Prüfen und Schlüssel exportieren mit den Ankern und Schlüsseln dieses Rechners (--verify-log, Einstellungen, #15).</summary>
public static class AuditTools
{
    /// <summary>
    /// Prüft eine Datei oder einen Ordner. Schlüssel: <paramref name="keysFile"/> (dann auch dessen Anker), sonst
    /// für Dateien dieses Rechners die öffentlichen Schlüssel aus der Registry, sonst die passende Schlüsseldatei daneben. Anker: aus der Registry,
    /// für Dateien dieses Rechners.
    /// </summary>
    public static AuditVerifyResult Verify(string path, string? keysFile = null)
    {
        AuditVerifyOptions o;
        if (keysFile is not null)
        {
            string json;
            try { json = File.ReadAllText(keysFile); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                return new AuditVerifyResult(false, CoreText.Error(ErrorCodes.LogNoPublicKey, keysFile), ErrorCodes.LogNoPublicKey);
            }
            if (AuditKeyFile.Parse(json) is not { } parsed)
                return new AuditVerifyResult(false, CoreText.Error(ErrorCodes.LogNoPublicKey, keysFile), ErrorCodes.LogNoPublicKey);
            bool local = string.Equals(parsed.Machine, Environment.MachineName, StringComparison.OrdinalIgnoreCase);
            IAuditAnchorStore? anchors = parsed.Anchors.Count > 0 ? new MemoryAnchorStore(parsed.Anchors) : local ? new RegistryAnchorStore() : null;
            o = new AuditVerifyOptions { TrustedKeys = parsed.Keys, Anchors = anchors, AnchorMachine = parsed.Machine };
        }
        else
        {
            // Dateien dieses Rechners mit den Schlüsseln aus der Registry (nur SYSTEM schreibt dort) – nicht mit einer
            // Schlüsseldatei, die neben der Datei liegt; Dateien anderer Rechner mit ihrer eigenen Schlüsseldatei
            o = new AuditVerifyOptions
            {
                KeysNextToFile = true,
                PreferredKeys = AuditState.PublicKeys(),
                PreferredKeysMachine = Environment.MachineName,
                Anchors = new RegistryAnchorStore(),
                AnchorMachine = Environment.MachineName,
            };
        }
        return Directory.Exists(path) ? AuditVerifier.VerifyFolder(path, o) : AuditVerifier.VerifyFile(path, o);
    }

    /// <summary>Öffentliche Schlüssel und Anker dieses Rechners als JSON (für Prüfer). null, wenn der Dienst noch keinen Schlüssel hat.</summary>
    public static string? ExportKeys()
    {
        var keys = AuditState.PublicKeys();
        return keys.Count == 0 ? null : AuditKeyFile.Serialize(Environment.MachineName, keys, new RegistryAnchorStore().All());
    }
}
