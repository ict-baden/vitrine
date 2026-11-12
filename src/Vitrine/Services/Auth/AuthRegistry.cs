// SPDX-License-Identifier: MIT
using System.Reflection;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Services.Auth;

/// <summary>Alle bekannten Anmeldeverfahren – eingebaute und Plugins.</summary>
public sealed class AuthRegistry
{
    private readonly Dictionary<string, IAuthProvider> _all = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Plugins, die nicht geladen wurden – Meldung mit Fehlercode.</summary>
    public List<string> PluginErrors { get; } = new();

    /// <param name="auditLink">Verbindung zum Dienst (Sicherheitsschlüssel prüft er); null = ohne Dienst, Verfahren „fido“ nicht verfügbar.</param>
    public AuthRegistry(SessionInfo session, ConfigStore store, Supervisor.AuditLink? auditLink = null)
    {
        Add(new EntraIdProvider(session, () => store.Current.Entra));
        Add(new WindowsPasswordProvider(session));
        Add(new WindowsHelloProvider(session));
        Add(new WindowsLogonProvider(session));
        Add(new FidoProvider(() => auditLink));
        Add(new PinProvider(() => store.Current.Unlock));

        // Plugins nur laden, wenn ein eingestelltes Verfahren eines braucht – Laden heißt fremden Code ausführen
        if (store.Current.Integration.LoadPlugins && store.Current.Unlock.Methods.Any(m => !_all.ContainsKey(m))) LoadPlugins();
    }

    public IEnumerable<IAuthProvider> All => _all.Values;

    public IAuthProvider? Get(string id) => _all.TryGetValue(id, out var p) ? p : null;

    /// <summary>Aktivierte Verfahren in konfigurierter Reihenfolge, die gerade verfügbar sind.</summary>
    public async Task<List<IAuthProvider>> GetActiveAsync(IEnumerable<string> ids, CancellationToken ct = default)
    {
        var list = new List<IAuthProvider>();
        foreach (var id in ids)
        {
            if (Get(id) is not { } p) continue;
            try { if (await p.IsAvailableAsync(ct)) list.Add(p); } catch { }
        }
        // Rückfall: Windows-Kennwort geht immer
        if (list.Count == 0 && Get("windows") is { } w) list.Add(w);
        return list;
    }

    private void Add(IAuthProvider p) => _all[p.Id] = p;

    /// <summary>
    /// Lädt IAuthProvider-Implementierungen aus „Plugins\*.dll“ neben der EXE.
    /// Der Ordner muss vor Schreibzugriff normaler Benutzer geschützt sein (Programme-Verzeichnis).
    /// </summary>
    private void LoadPlugins()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Plugins");
        if (!Directory.Exists(dir)) return;
        var guard = new Platform.AdminOnlyFiles();
        foreach (var dll in Directory.EnumerateFiles(dir, "*.dll"))
        {
            try
            {
                // Plugins sind voll vertrauenswürdig (sie entscheiden, wer Administrator ist). Deshalb nur aus einem Ordner,
                // den normale Benutzer nicht beschreiben können – nicht neben einer Vitrine.exe im Download-Ordner.
                if (!guard.IsProtected(dll))
                {
                    PluginErrors.Add(UI.Loc.Error(ErrorCodes.PluginsNotProtected, Path.GetFileName(dll)));
                    continue;
                }
                var asm = Assembly.LoadFrom(dll);
                foreach (var t in asm.GetExportedTypes())
                {
                    if (t.IsAbstract || !typeof(IAuthProvider).IsAssignableFrom(t)) continue;
                    if (t.GetConstructor(Type.EmptyTypes) is null) continue;
                    var p = (IAuthProvider)Activator.CreateInstance(t)!;
                    if (_all.ContainsKey(p.Id)) { PluginErrors.Add(UI.Loc.Error(ErrorCodes.PluginIdTaken, Path.GetFileName(dll), p.Id)); continue; }
                    Add(p);
                }
            }
            catch (Exception ex)
            {
                PluginErrors.Add(UI.Loc.Error(ErrorCodes.PluginNotLoaded, Path.GetFileName(dll), ex.Message));
            }
        }
    }
}
