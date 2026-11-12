// SPDX-License-Identifier: MIT
using System.Text.Json;
using Vitrine.Core.About;

namespace Vitrine.Core.Lock;

/// <summary>DWORD-Werte unter HKCU (in der App die Registry, in Tests eine Attrappe).</summary>
public interface IUserPolicyStore
{
    /// <summary>Aktueller Wert, null wenn nicht gesetzt oder kein DWORD.</summary>
    int? Get(string key, string value);

    void Set(string key, string value, int data);

    void Delete(string key, string value);
}

/// <summary>
/// Strg+Alt+Entf (Secure Attention Sequence) kann keine Anwendung abfangen. Stattdessen setzt Vitrine während der Sperre
/// die Benutzer-Richtlinien, die im Strg+Alt+Entf-Menü Task-Manager, Abmelden, Kennwort ändern und den Ein/Aus-Schalter
/// (Neu starten, Herunterfahren) ausblenden. „Sperren“
/// bleibt – das führt nur zum Windows-Sperrbildschirm. Vorherige Werte werden in einer Datei gesichert und nach dem
/// Entsperren (oder nach einem Absturz beim nächsten Start bzw. durch den Wächter) zurückgeschrieben.
/// </summary>
public sealed class SasRestrictions
{
    internal static readonly (string key, string value)[] Values =
    {
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableChangePassword"),
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoLogoff"),
        // Ein/Aus-Schalter (Neu starten, Herunterfahren) im Strg+Alt+Entf-Menü und im Startmenü ausblenden: Ein über
        // „Neu starten“ angefangenes und dann abgebrochenes Ende der Sitzung soll gar nicht erst möglich sein (seit 2026-10-21)
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoClose"),
    };

    private readonly IUserPolicyStore _store;
    private readonly string _backupFile;

    public SasRestrictions(IUserPolicyStore store, string? backupFile = null)
    {
        _store = store;
        _backupFile = backupFile ?? Path.Combine(AppPaths.UserDir, "sas-backup.json");
    }

    /// <summary>Sind die Einschränkungen gerade gesetzt (Sicherung vorhanden)?</summary>
    public bool IsApplied => File.Exists(_backupFile);

    public void Apply()
    {
        // Gibt es die Sicherung schon (Absturz, oder vom Benutzer selbst angelegt), bleibt sie – die Werte werden trotzdem
        // gesetzt, sonst ließe eine angelegte Datei die Einschränkungen einfach ausfallen.
        // Fehlen in einer vorhandenen Sicherung Werte (ältere Version ohne NoClose, von Hand angelegt), kommen sie mit ihrem
        // jetzigen Stand dazu – sonst bliebe ein neu gesetzter Wert nach dem Entsperren stehen.
        // Unlesbare Sicherung bleibt, wie sie ist: Restore setzt dann alle Werte auf „nicht gesetzt“.
        var backup = IsApplied ? ReadBackup() : new Dictionary<string, int?>();
        bool changed = !IsApplied;
        foreach (var (key, value) in Values)
        {
            if (backup is null || backup.ContainsKey($"{key}|{value}")) continue;
            backup[$"{key}|{value}"] = SafeGet(key, value);
            changed = true;
        }
        // Sicherung auch im Speicher: Lässt sich die Datei nicht schreiben, stellt diese Instanz trotzdem richtig wieder her
        if (backup is not null) _memoryBackup = new Dictionary<string, int?>(backup);
        if (changed && backup is not null)
        {
            // Erst die Sicherung, dann ändern: Stürzt Vitrine dazwischen ab, lässt sich alles zurücksetzen. Scheitert die
            // Sicherung (volle Platte, Datei gesperrt, „.tmp“ als Ordner angelegt), werden die Werte trotzdem gesetzt –
            // die Sperre geht vor; Restore nimmt dann die Sicherung im Speicher (oder setzt alles auf „nicht gesetzt“).
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_backupFile)!);
                var tmp = _backupFile + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(backup));
                File.Move(tmp, _backupFile, overwrite: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Ohne Sicherungsdatei fände Restore nichts zum Zurücksetzen: eine leere, unlesbare Markierung anlegen
                try { if (!File.Exists(_backupFile)) File.WriteAllText(_backupFile, ""); } catch { }
            }
        }

        foreach (var (key, value) in Values)
        {
            try { _store.Set(key, value, 1); }
            catch { /* kein Schreibrecht (z. B. per GPO gesperrt) – dann eben nicht */ }
        }
    }

    public void Restore()
    {
        if (!IsApplied && _memoryBackup is null) return;
        // Datei, sonst die Sicherung im Speicher; beschädigt bzw. keine (null): unten auf „nicht gesetzt“ zurückfallen
        var backup = (IsApplied ? ReadBackup() : null) ?? _memoryBackup;
        _memoryBackup = null;

        foreach (var (key, value) in Values)
        {
            // Nur die bekannten Werte anfassen – nie, was sonst in der Sicherungsdatei steht.
            int? old = null;
            bool known = backup is not null && backup.TryGetValue($"{key}|{value}", out old);
            try
            {
                if (known && old is not null) _store.Set(key, value, old.Value);
                else if (known || backup is null) _store.Delete(key, value);
            }
            catch { }
        }
        try { File.Delete(_backupFile); } catch { }
    }

    private Dictionary<string, int?>? _memoryBackup;

    private Dictionary<string, int?>? ReadBackup()
    {
        try { return JsonSerializer.Deserialize<Dictionary<string, int?>>(File.ReadAllText(_backupFile)); }
        catch { return null; }
    }

    private int? SafeGet(string key, string value)
    {
        try { return _store.Get(key, value); }
        catch { return null; }
    }
}

/// <summary>Merkt sich auf der Platte, ob gerade gesperrt ist – für den Wächterprozess.</summary>
public static class LockState
{
    private static string FilePath => Path.Combine(AppPaths.UserDir, "locked");

    public static void Set(bool locked)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            if (locked) File.WriteAllText(FilePath, DateTimeOffset.UtcNow.ToString("O"));
            else File.Delete(FilePath);
        }
        catch { }
    }

    public static bool WasLocked => File.Exists(FilePath);
}
