// SPDX-License-Identifier: MIT
using System.Text.Json;
using Vitrine.Core.About;

namespace Vitrine.Core.Config;

/// <summary>
/// Persönliche Einstellungen, die keine Adminrechte brauchen: bisher nur die Sprache der Oberfläche
/// (%LocalAppData%\Vitrine\preferences.json). Sicherheitsrelevantes gehört nie hierher.
/// </summary>
public sealed class UserPreferences
{
    /// <summary>"" = Vorgabe des Geräts bzw. Sprache von Windows.</summary>
    public string Language { get; set; } = "";

    public static UserPreferences Load(string? file = null)
    {
        file ??= AppPaths.PreferencesFile;
        try
        {
            if (!File.Exists(file) || new FileInfo(file).Length > 64 * 1024) return new();
            return JsonSerializer.Deserialize<UserPreferences>(File.ReadAllText(file), ConfigStore.Json) ?? new();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return new(); }
    }

    /// <summary>Speichert; wirft bei Schreibfehlern (der Aufrufer meldet sie).</summary>
    public void Save(string? file = null)
    {
        file ??= AppPaths.PreferencesFile;
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var tmp = file + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, ConfigStore.Json));
        File.Move(tmp, file, overwrite: true);
    }
}
