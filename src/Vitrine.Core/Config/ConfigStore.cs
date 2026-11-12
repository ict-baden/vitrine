// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Vitrine.Core.About;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;

namespace Vitrine.Core.Config;

/// <summary>
/// Liest Richtlinienwerte eines Registry-Schlüssels (z. B. HKLM\SOFTWARE\Policies\ICT-Baden\Vitrine). In der App
/// steht dahinter die Windows-Registry, in Tests eine Attrappe.
/// </summary>
public interface IPolicySource
{
    /// <summary>Für Meldungen, z. B. „HKLM\SOFTWARE\Policies\ICT-Baden\Vitrine“.</summary>
    string Name { get; }

    /// <summary>
    /// Werte des Unterschlüssels <paramref name="section"/> (Wertname → Inhalt: int für DWORD, string für REG_SZ,
    /// string[] für REG_MULTI_SZ), null wenn es ihn nicht gibt.
    /// </summary>
    IReadOnlyDictionary<string, object>? ReadSection(string section);
}

/// <summary>
/// Schützt die Gerätekonfiguration: Nur Dateien, die normale Benutzer weder ändern noch ersetzen können, gelten als
/// Gerätekonfiguration (sonst könnte jeder Benutzer z. B. %ProgramData%\Vitrine\config.json anlegen und damit Regeln,
/// Skripte und das Entsperr-Kennwort für alle setzen). In der App prüft die Windows-Implementierung Besitzer, Zugriffsliste
/// und Verknüpfungen von Datei und Ordnern.
/// </summary>
public interface IConfigFileGuard
{
    /// <summary>Dürfen nur Administratoren (bzw. SYSTEM) die Datei ändern oder ersetzen?</summary>
    bool IsProtected(string file);

    /// <summary>
    /// Liest die Datei über denselben Handle, an dem auch Besitzer und Rechte geprüft werden (kein Austausch zwischen
    /// Prüfen und Lesen). null, wenn es die Datei nicht gibt; <see cref="UnauthorizedAccessException"/>, wenn sie nicht
    /// geschützt ist.
    /// </summary>
    string? ReadProtected(string file, long maxBytes);

    /// <summary>
    /// Vor dem Schreiben: Ordner anlegen und mit dem übergeordneten Ordner auf Administratoren sichern; Verknüpfungen
    /// (Junctions) ablehnen, damit ein Schreibvorgang mit Adminrechten nicht umgeleitet werden kann.
    /// </summary>
    void PrepareDirectory(string directory);

    /// <summary>Nach dem Speichern: Besitzer der Datei auf Administratoren setzen (wirft, wenn das nicht geht).</summary>
    void Protect(string file);
}

/// <summary>Wo die Konfigurationsdateien liegen (neue und alte Orte, richtlinien/12).</summary>
public sealed record ConfigFiles(string Machine, string LegacyMachine, string User, string LegacyUser)
{
    public static ConfigFiles Default => new(AppPaths.MachineConfigFile, AppPaths.LegacyMachineConfigFile,
        AppPaths.UserConfigFile, AppPaths.LegacyUserConfigFile);
}

public sealed class ConfigStore
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Konfigurationsdateien sind klein; größere werden nicht gelesen (Schutz vor Speicherfressern).</summary>
    public const long MaxFileBytes = 1024 * 1024;

    private readonly ConfigFiles _files;
    private readonly IReadOnlyList<IPolicySource> _policies;
    private readonly IConfigFileGuard? _guard;

    /// <summary>Abschnitte, die eine Benutzer-Konfiguration (Security.AllowUserConfig) setzen darf – nie Sicherheit,
    /// Entsperren, Entra, Protokoll, Skripte oder Schnittstelle.</summary>
    public static readonly IReadOnlySet<string> UserSections =
        new HashSet<string>(["Appearance", "Lock"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Werte dieser Abschnitte, die auch eine erlaubte Benutzer-Konfiguration nie setzt: Sie schützen vertrauliche Inhalte
    /// (verdeckte Bereiche, sichtbare Programme), ein Benutzer könnte sie sonst für sich leeren bzw. erweitern.
    /// </summary>
    public static readonly IReadOnlySet<string> UserExcluded =
        new HashSet<string>(["Appearance.Masks", "Appearance.RevealProcesses"], StringComparer.OrdinalIgnoreCase);

    /// <param name="files">Orte der Konfigurationsdateien.</param>
    /// <param name="policies">Richtlinienquellen in aufsteigendem Vorrang (die letzte gewinnt), z. B. HKCU alt, HKCU,
    /// HKLM alt, HKLM.</param>
    /// <param name="guard">Prüft, ob Gerätedateien vor Benutzern geschützt sind; null nur in Tests.</param>
    public ConfigStore(ConfigFiles files, IReadOnlyList<IPolicySource> policies, IConfigFileGuard? guard = null)
    {
        _files = files;
        _policies = policies;
        _guard = guard;
    }

    /// <summary>Datei der Gerätekonfiguration, in die gespeichert wird.</summary>
    public string MachineFile => _files.Machine;

    /// <summary>Gelesene Gerätekonfiguration lag noch am alten Ort; beim nächsten Speichern zieht sie um.</summary>
    public bool UsesLegacyMachineFile { get; private set; }

    /// <summary>Pfade wie "Lock.IdleMinutes", die per Richtlinie festgelegt sind.</summary>
    public IReadOnlySet<string> ManagedPaths => _managed;
    private readonly HashSet<string> _managed = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Richtlinienwerte kamen (auch) aus dem alten Schlüssel ohne Herstellerpräfix.</summary>
    public bool UsesLegacyPolicy { get; private set; }

    public VitrineConfig Current { get; private set; } = new();

    /// <summary>Konfiguration ohne Richtlinien-Werte (das, was die Einstellungen speichern).</summary>
    public VitrineConfig Editable { get; private set; } = new();

    public event Action<VitrineConfig>? Changed;

    /// <summary>Probleme beim Laden, schon mit Fehlercode (Text aus CoreStrings).</summary>
    public List<string> LoadErrors { get; } = new();

    public void Load()
    {
        LoadErrors.Clear();
        _managed.Clear();
        UsesLegacyPolicy = false;

        var root = JsonSerializer.SerializeToNode(new VitrineConfig(), Json)!.AsObject();

        // Gerät: neuer Ort, sonst alter Ort (Übergang) – beide nur, wenn normale Benutzer sie nicht ändern können
        UsesLegacyMachineFile = !File.Exists(_files.Machine) && File.Exists(_files.LegacyMachine);
        var machine = UsesLegacyMachineFile ? _files.LegacyMachine : _files.Machine;
        MergeFile(root, machine, () => ReadMachine(machine));

        // Das speichern die Einstellungen: nur Standard + Gerät, nie die Benutzerschicht
        Editable = Deserialize(root);

        // Ob Benutzer-Konfiguration erlaubt ist, entscheiden Gerät UND Richtlinie (die Richtlinie kann sie abschalten)
        var probe = (JsonObject)root.DeepClone();
        foreach (var source in _policies) ApplyPolicy(probe, source, mark: false);
        if (ReadBool(probe, "Security", "AllowUserConfig"))
        {
            var user = File.Exists(_files.User) || !File.Exists(_files.LegacyUser) ? _files.User : _files.LegacyUser;
            MergeFile(root, user, () => ReadPlain(user), UserSections);
        }

        foreach (var source in _policies) ApplyPolicy(root, source, mark: true);

        Current = Deserialize(root);
        foreach (var invalid in Auth.EntraClaims.InvalidAuthContexts(Current.Entra))
            LoadErrors.Add(CoreText.Error(ErrorCodes.AuthContextInvalid, invalid));
        foreach (var entry in Current.Lock.Schedule.Where(e => Schedule.NormalizeTime(e.Time) is null))
            LoadErrors.Add(CoreText.Error(ErrorCodes.ConfigEntryInvalid, "Lock.Schedule", entry.Time));
        Changed?.Invoke(Current);
    }

    /// <summary>Speichert in die Geräte-Konfiguration (braucht Schreibrecht auf %ProgramData%\ICT-Baden\Vitrine).</summary>
    public void Save(VitrineConfig config) => WriteMachineFile(JsonSerializer.Serialize(config, Json));

    /// <summary>
    /// Schreibt die Gerätedatei neu (neue Datei statt Überschreiben, damit Besitzer und Rechte vom Schreibenden kommen) und
    /// schützt sie (Windows: Besitzer Administratoren). Auch für --apply-config.
    /// </summary>
    public void WriteMachineFile(string json)
    {
        var dir = Path.GetDirectoryName(_files.Machine)!;
        if (_guard is not null) _guard.PrepareDirectory(dir);
        else Directory.CreateDirectory(dir);
        // Neue Datei mit zufälligem Namen (CreateNew): Eine vorab angelegte oder verlinkte Temp-Datei eines Benutzers
        // wird so nie mitbenutzt; Besitzer und Rechte kommen vom Schreibenden bzw. vom Ordner.
        var tmp = Path.Combine(dir, $".config-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var w = new StreamWriter(fs, new System.Text.UTF8Encoding(false)))
                w.Write(json);
            File.Move(tmp, _files.Machine, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
        _guard?.Protect(_files.Machine);
        Load();
    }



    public bool IsManaged(string path) => _managed.Contains(path);

    /// <summary>Prüft eine Konfigurationsdatei, bevor sie übernommen wird (--apply-config). Wirft bei Fehlern.</summary>
    public static VitrineConfig Validate(string json)
    {
        var node = JsonNode.Parse(json, documentOptions: DocumentOptions) as JsonObject
                   ?? throw new InvalidDataException(CoreText.T("Config_NotAnObject"));
        var root = JsonSerializer.SerializeToNode(new VitrineConfig(), Json)!.AsObject();
        DeepMerge(root, node);
        return root.Deserialize<VitrineConfig>(Json) ?? throw new InvalidDataException(CoreText.T("Config_NotAnObject"));
    }

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private VitrineConfig Deserialize(JsonObject root)
    {
        try { return root.Deserialize<VitrineConfig>(Json) ?? new VitrineConfig(); }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or NotSupportedException)
        {
            // Ein falscher Typ in der Datei (z. B. "IdleMinutes": "fünf") darf nicht alle Einstellungen auf Standard setzen
            // und schon gar nicht den Start verhindern – Fehler melden, Standardwerte nehmen.
            LoadErrors.Add(CoreText.Error(ErrorCodes.ConfigUnreadable, "config.json", ex.Message));
            return new VitrineConfig();
        }
    }

    /// <summary>Gerätedatei: nur, wenn sie geschützt ist (sonst VIT-0012).</summary>
    private string? ReadMachine(string file)
    {
        if (_guard is null) return ReadPlain(file);
        try { return _guard.ReadProtected(file, MaxFileBytes); }
        catch (UnauthorizedAccessException)
        {
            LoadErrors.Add(CoreText.Error(ErrorCodes.ConfigNotProtected, file));
            return null;
        }
    }

    private static string? ReadPlain(string file)
    {
        if (!File.Exists(file)) return null;
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (fs.Length > MaxFileBytes) throw new InvalidDataException(CoreText.F("Config_TooLarge", MaxFileBytes / 1024));
        using var reader = new StreamReader(fs);
        return reader.ReadToEnd();
    }

    private void MergeFile(JsonObject target, string file, Func<string?> read, IReadOnlySet<string>? onlySections = null)
    {
        try
        {
            var text = read();
            if (text is null) return;
            var node = JsonNode.Parse(text, documentOptions: DocumentOptions);
            if (node is not JsonObject obj) throw new InvalidDataException(CoreText.T("Config_NotAnObject"));
            if (onlySections is not null)
            {
                foreach (var key in obj.Select(p => p.Key).Where(k => !onlySections.Contains(k)).ToList()) obj.Remove(key);
                foreach (var (section, value) in obj.ToList())
                    if (value is JsonObject so)
                        foreach (var key in so.Select(p => p.Key).Where(k => UserExcluded.Contains($"{section}.{k}")).ToList()) so.Remove(key);
            }
            // Erst auf einer Kopie prüfen: Ein falscher Typ (z. B. "IdleMinutes": "fünf") darf weder die übrigen Schichten
            // noch die Richtlinien verwerfen – dann gilt die ganze Datei nicht, und der Fehler wird gemeldet.
            var trial = (JsonObject)target.DeepClone();
            DeepMerge(trial, obj);
            trial.Deserialize<VitrineConfig>(Json);
            DeepMerge(target, obj);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException
                                       or InvalidOperationException or NotSupportedException)
        {
            LoadErrors.Add(CoreText.Error(ErrorCodes.ConfigUnreadable, file, ex.Message));
        }
    }

    internal static void DeepMerge(JsonObject target, JsonObject source)
    {
        foreach (var (key, value) in source)
        {
            var existingKey = target.Select(p => p.Key).FirstOrDefault(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) ?? key;
            if (value is JsonObject so && target[existingKey] is JsonObject to)
                DeepMerge(to, so);
            else
                target[existingKey] = value?.DeepClone();
        }
    }

    private static bool ReadBool(JsonObject root, string section, string prop)
    {
        try { return root[section]?[prop]?.GetValue<bool>() ?? false; }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException) { return false; }
    }

    /// <summary>
    /// Übernimmt die Werte einer Richtlinienquelle: Unterschlüssel = Abschnitt, Wertname = Eigenschaft.
    /// DWORD → Zahl/bool/Enum, REG_SZ → Text/Enum-Name, REG_MULTI_SZ → Liste.
    /// </summary>
    private void ApplyPolicy(JsonObject root, IPolicySource source, bool mark)
    {
        try
        {
            foreach (var section in typeof(VitrineConfig).GetProperties())
            {
                var values = source.ReadSection(section.Name);
                if (values is null || values.Count == 0) continue;
                if (root[section.Name] is not JsonObject sectionNode) continue;

                foreach (var prop in section.PropertyType.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (prop.GetCustomAttribute<JsonIgnoreAttribute>() is not null) continue;
                    var raw = values.FirstOrDefault(v => string.Equals(v.Key, prop.Name, StringComparison.OrdinalIgnoreCase)).Value;
                    if (raw is null) continue;
                    var rejected = new List<string>();
                    var node = ConvertPolicyValue(raw, prop.PropertyType, rejected);
                    // Unlesbare Einträge einer Liste (Zeitplan, Bereiche) nicht still übergehen
                    if (mark && rejected.Count > 0)
                        LoadErrors.Add(CoreText.Error(ErrorCodes.ConfigEntryInvalid, $"{section.Name}.{prop.Name}", string.Join("; ", rejected)));
                    if (node is null) continue;
                    sectionNode[prop.Name] = node;
                    if (!mark) continue;
                    _managed.Add($"{section.Name}.{prop.Name}");
                    if (source is ILegacyPolicySource) UsesLegacyPolicy = true;
                }
            }
        }
        catch (Exception ex)
        {
            // Registry-Fehler (Zugriff, kaputte Werte) dürfen den Start nie verhindern
            if (mark) LoadErrors.Add(CoreText.Error(ErrorCodes.PolicyUnreadable, source.Name, ex.Message));
        }
    }

    /// <param name="rejected">Nimmt Listeneinträge auf, die nicht lesbar waren und deshalb fehlen.</param>
    internal static JsonNode? ConvertPolicyValue(object raw, Type t, List<string>? rejected = null)
    {
        var u = Nullable.GetUnderlyingType(t) ?? t;
        try
        {
            if (u == typeof(bool)) return JsonValue.Create(Convert.ToInt64(raw, System.Globalization.CultureInfo.InvariantCulture) != 0);
            if (u == typeof(int)) return JsonValue.Create(Convert.ToInt32(raw, System.Globalization.CultureInfo.InvariantCulture));
            if (u == typeof(string)) return JsonValue.Create(raw is string[] a ? string.Join(";", a) : raw.ToString());
            if (u.IsEnum)
            {
                if (raw is int i) return JsonValue.Create(Enum.ToObject(u, i).ToString());
                var text = raw.ToString() ?? "";
                // Unbekannte Namen nicht übernehmen, sonst scheitert das ganze Laden
                return Enum.TryParse(u, text, ignoreCase: true, out var parsed) ? JsonValue.Create(parsed!.ToString()) : null;
            }
            if (u == typeof(List<string>))
            {
                var items = SplitList(raw);
                return new JsonArray(items.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
            }
            if (u == typeof(List<MaskRegion>))
            {
                // Format: "1:0,0,30,100" (Monitor:X,Y,Breite,Höhe in Prozent), "*" = jeder Monitor
                var items = SplitList(raw);
                rejected?.AddRange(items.Where(m => MaskRegion.Parse(m) is null));
                var masks = items.Select(MaskRegion.Parse).Where(m => m is not null).ToList();
                return JsonSerializer.SerializeToNode(masks, Json);
            }
            if (u == typeof(List<ScheduleEntry>))
            {
                // Format: "18:00", "18:00@Mon,Tue,Wed" oder "18:00@Mon-Fri"
                var items = SplitList(raw);
                rejected?.AddRange(items.Where(e => Schedule.Parse(e) is null));
                var entries = items.Select(Schedule.Parse).Where(e => e is not null).ToList();
                return JsonSerializer.SerializeToNode(entries, Json);
            }
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
        return null;
    }

    private static string[] SplitList(object raw) => raw is string[] arr
        ? arr.Select(s => s.Trim()).Where(s => s.Length > 0).ToArray()
        : (raw.ToString() ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>Kennzeichnet die Quelle des alten Richtlinienpfads (für den Hinweis in den Einstellungen).</summary>
public interface ILegacyPolicySource : IPolicySource;
