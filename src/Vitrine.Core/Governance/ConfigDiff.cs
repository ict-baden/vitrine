// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Text.Json.Nodes;
using Vitrine.Core.Config;

namespace Vitrine.Core.Governance;

/// <summary>Geänderter Wert: Pfad wie „Lock.IdleMinutes“, alter und neuer Wert als Text (null = nicht gesetzt).</summary>
/// <param name="Masked">Geheimnis (Hash, Kennwort): Werte sind durch <see cref="ConfigDiff.Hidden"/> ersetzt.</param>
public sealed record ConfigChange(string Path, string? Old, string? New, bool Masked);

/// <summary>
/// Unterschied zweier Konfigurationen auf JSON-Ebene (für ConfigChanged im Protokoll). Objekte werden bis zu den Werten
/// verglichen, Listen als Ganzes. Geheimnisse (<see cref="IsSecret"/>) erscheinen nie im Klartext.
/// </summary>
public static class ConfigDiff
{
    /// <summary>Platzhalter für einen gesetzten geheimen Wert.</summary>
    public const string Hidden = "(hidden)";

    /// <summary>Platzhalter für „nicht gesetzt“.</summary>
    public const string NotSet = "(not set)";

    private static readonly JsonSerializerOptions Compact = new() { WriteIndented = false };

    public static IReadOnlyList<ConfigChange> Compute(VitrineConfig before, VitrineConfig after) =>
        Compute(JsonSerializer.SerializeToNode(before, ConfigStore.Json)!.AsObject(), JsonSerializer.SerializeToNode(after, ConfigStore.Json)!.AsObject());

    public static IReadOnlyList<ConfigChange> Compute(JsonObject before, JsonObject after)
    {
        var a = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var b = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Flatten(before, "", a);
        Flatten(after, "", b);
        var changes = new List<ConfigChange>();
        foreach (var path in a.Keys.Union(b.Keys, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
        {
            var old = a.GetValueOrDefault(path);
            var neu = b.GetValueOrDefault(path);
            if (string.Equals(old, neu, StringComparison.Ordinal)) continue;
            changes.Add(IsSecret(path)
                ? new ConfigChange(path, Mask(old), Mask(neu), true)
                : new ConfigChange(path, old, neu, false));
        }
        return changes;
    }

    /// <summary>Geheime Werte: Name endet auf Hash, Password oder Secret (z. B. Unlock.PinHash).</summary>
    public static bool IsSecret(string path)
    {
        var name = path[(path.LastIndexOf('.') + 1)..];
        return name.EndsWith("Hash", StringComparison.OrdinalIgnoreCase) || name.EndsWith("Password", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("Secret", StringComparison.OrdinalIgnoreCase);
    }

    private static string? Mask(string? v) => string.IsNullOrEmpty(v) ? null : Hidden;

    private static void Flatten(JsonNode? node, string prefix, Dictionary<string, string?> into)
    {
        if (node is JsonObject o)
        {
            foreach (var (key, value) in o)
                Flatten(value, prefix.Length == 0 ? key : $"{prefix}.{key}", into);
            return;
        }
        if (prefix.Length == 0) return;
        into[prefix] = node switch
        {
            null => null,
            JsonValue v when v.TryGetValue<string>(out var s) => s,
            _ => node.ToJsonString(Compact),
        };
    }

    /// <summary>Kurzfassung für das Detail des Eintrags (sprachunabhängig).</summary>
    public static string Summary(IReadOnlyList<ConfigChange> changes) =>
        changes.Count == 0 ? "Settings saved (no changes)" : $"Settings saved: {changes.Count} change(s)";

    /// <summary>
    /// Data des Eintrags ConfigChanged: „reason“, „changes“ (Anzahl) und je Änderung Pfad → „alt -> neu“. Der Dienst nimmt
    /// höchstens 32 Einträge mit je 500 Zeichen an; was nicht passt, steht als Liste der Pfade unter „more“.
    /// </summary>
    public static Dictionary<string, string> ToAuditData(IReadOnlyList<ConfigChange> changes, string? reason, int maxEntries = 32, int maxValue = 200)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal) { ["changes"] = changes.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        if (Reasons.Normalize(reason) is { } r) d["reason"] = r;
        // Platz für „more“ freihalten
        int room = Math.Max(0, maxEntries - d.Count - 1);
        var shown = changes.Take(changes.Count <= room + 1 ? room + 1 : room).ToList();
        foreach (var c in shown)
            d[Key(c.Path)] = Cut($"{c.Old ?? NotSet} -> {c.New ?? NotSet}", maxValue);
        if (shown.Count < changes.Count)
            d["more"] = Cut(string.Join(", ", changes.Skip(shown.Count).Select(c => c.Path)), 500);
        return d;
    }

    private static string Key(string path) => path.Length <= 64 ? path : path[..64];

    private static string Cut(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}
