// SPDX-License-Identifier: MIT
using System.Diagnostics;
using Microsoft.Win32;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Lock;

namespace Vitrine.Platform;

/// <summary>Richtlinienwerte aus der Registry (HKLM oder HKCU, neuer oder alter Schlüssel).</summary>
public class RegistryPolicySource : IPolicySource
{
    private readonly RegistryKey _hive;
    private readonly string _key;

    public RegistryPolicySource(RegistryKey hive, string key)
    {
        _hive = hive;
        _key = key;
    }

    public string Name => $"{(_hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\\{_key}";

    public IReadOnlyDictionary<string, object>? ReadSection(string section)
    {
        using var key = _hive.OpenSubKey($"{_key}\\{section}");
        if (key is null) return null;
        var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in key.GetValueNames())
            if (key.GetValue(name) is { } v) values[name] = v;
        return values;
    }

    /// <summary>Quellen in aufsteigendem Vorrang: Benutzer vor Gerät, alter Schlüssel vor neuem.</summary>
    public static IReadOnlyList<IPolicySource> All() =>
    [
        new LegacyRegistryPolicySource(Registry.CurrentUser),
        new RegistryPolicySource(Registry.CurrentUser, AppPaths.PolicyKey),
        new LegacyRegistryPolicySource(Registry.LocalMachine),
        new RegistryPolicySource(Registry.LocalMachine, AppPaths.PolicyKey),
    ];
}

/// <summary>Alter Richtlinienschlüssel SOFTWARE\Policies\Vitrine (Übergang, docs/installation.md).</summary>
public sealed class LegacyRegistryPolicySource(RegistryKey hive) : RegistryPolicySource(hive, AppPaths.LegacyPolicyKey), ILegacyPolicySource;

/// <summary>
/// DWORD-Werte im Hive des Benutzers: Strg+Alt+Entf-Einschränkungen, DisableLockWorkstation und sein Merkwert. Ohne
/// Angaben HKCU; der Dienst (SYSTEM) übergibt <c>HKU</c> und die SID des Sitzungsbenutzers.
/// </summary>
public sealed class RegistryUserPolicyStore : IUserPolicyStore
{
    private readonly RegistryKey _root;
    private readonly string _prefix;

    public RegistryUserPolicyStore() : this(Registry.CurrentUser, null) { }

    /// <param name="root">z. B. <see cref="Registry.Users"/></param>
    /// <param name="subKey">z. B. die SID des Benutzers unter HKU</param>
    public RegistryUserPolicyStore(RegistryKey root, string? subKey)
    {
        _root = root;
        _prefix = string.IsNullOrEmpty(subKey) ? "" : subKey + "\\";
    }

    public int? Get(string key, string value)
    {
        using var k = _root.OpenSubKey(_prefix + key);
        return k?.GetValue(value) is int i ? i : null;
    }

    public void Set(string key, string value, int data)
    {
        using var k = _root.CreateSubKey(_prefix + key, writable: true);
        k.SetValue(value, data, RegistryValueKind.DWord);
    }

    public void Delete(string key, string value)
    {
        using var k = _root.OpenSubKey(_prefix + key, writable: true);
        k?.DeleteValue(value, throwOnMissingValue: false);
    }
}

/// <summary>DWORD-Werte unter HKLM (Computerrichtlinie, z. B. DisableLockWorkstation).</summary>
public sealed class RegistryMachinePolicyReader : IMachinePolicyReader
{
    public int? Get(string key, string value)
    {
        using var k = Registry.LocalMachine.OpenSubKey(key);
        return k?.GetValue(value) is int i ? i : null;
    }
}

/// <summary>Einträge zusätzlich ins Ereignisprotokoll „Anwendung“ (Quelle „ICT-Baden Vitrine“, sonst die alte „Vitrine“).</summary>
public sealed class EventLogSink : IAuditSink
{
    private EventLog? _log;
    private bool _checked;

    private readonly object _gate = new();

    // Mehrere Aufrufer möglich (Dienst: Protokoll und Fehlerspur); die EventLog-Instanz nur unter der Sperre benutzen
    public void Write(AuditEntry e)
    {
        lock (_gate) WriteLocked(e);
    }

    private void WriteLocked(AuditEntry e)
    {
        if (!_checked)
        {
            _checked = true;
            var source = SourceExists(AppPaths.EventSource) ? AppPaths.EventSource
                    : SourceExists(AppPaths.LegacyEventSource) ? AppPaths.LegacyEventSource : null;
            // Eine Instanz für alle Einträge: Das statische EventLog.WriteEntry prüft bei jedem Aufruf erneut, ob die Quelle
            // existiert (durchsucht alle Ereignisprotokolle in der Registry), die Instanz nur beim ersten Mal (Issue #18).
            if (source is not null) _log = new EventLog { Source = source };
        }
        if (_log is null) return;
        var type = e.Event switch
        {
            AuditEventType.UnlockFailed or AuditEventType.UnlockDenied or AuditEventType.SignatureFailed or
                AuditEventType.FidoKeyRejected => EventLogEntryType.FailureAudit,
            AuditEventType.FailureActionTriggered or AuditEventType.Error or AuditEventType.SessionEndRefused or
                AuditEventType.AuditLocalMode or AuditEventType.UnlockBypass or AuditEventType.DesktopSwitchDetected or
                AuditEventType.WindowsLockDetected or AuditEventType.FidoCloneSuspected => EventLogEntryType.Warning,
            AuditEventType.Unlocked or AuditEventType.SignatureGranted => EventLogEntryType.SuccessAudit,
            _ => EventLogEntryType.Information,
        };
        // Sprachunabhängig wie das Protokoll selbst (richtlinien/13 Punkt 5)
        var text = $"{e.Event}\r\nSession: {e.SessionUser}\r\nPerson: {e.Actor}\r\nMethod: {e.Method}\r\n{e.Detail}\r\nSequence: {e.Seq}\r\nHash: {e.Hash}";
        // Format 3 (Dienst, #15): Stufe und Schlüssel – zweite Spur zum Abgleich mit der Datei
        if (e.Assurance is not null) text += $"\r\nAssurance: {e.Assurance}\r\nKey: {e.Key}";
        _log.WriteEntry(text, type, 1000 + (int)e.Event);
    }

    private static bool SourceExists(string source)
    {
        try { return EventLog.SourceExists(source); }
        catch { return false; } // ohne Adminrechte nicht alle Protokolle lesbar
    }

    /// <summary>Registriert die Ereignisquelle (braucht Administratorrechte).</summary>
    public static void Register()
    {
        if (!EventLog.SourceExists(AppPaths.EventSource))
            EventLog.CreateEventSource(AppPaths.EventSource, "Application");
    }
}
