// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>Rollen in Vitrine (Roles.* in der Konfiguration).</summary>
public enum VitrineRole
{
    /// <summary>Einstellungen öffnen und ändern, Vitrine beenden (Roles.ConfigAdmins).</summary>
    ConfigAdmin,
    /// <summary>Sicherheitsschlüssel registrieren und widerrufen (Roles.Registrars).</summary>
    Registrar,
    /// <summary>Protokoll und Berechtigungsbericht ansehen und exportieren, nichts ändern (Roles.Auditors).</summary>
    Auditor,
}

/// <summary>
/// Prüft die Rollen einer angemeldeten Person. Schnittstelle, damit andere Teile (z. B. das Verfahren für
/// Sicherheitsschlüssel) die Prüfung übergeben bekommen und mit einer Attrappe getestet werden können.
/// </summary>
public interface IRoleCheck
{
    /// <summary>Darf Einstellungen öffnen und ändern und Vitrine beenden.</summary>
    bool IsConfigAdmin(AuthOutcome o);

    /// <summary>Darf Sicherheitsschlüssel registrieren und widerrufen.</summary>
    bool IsRegistrar(AuthOutcome o);

    /// <summary>Darf das Protokoll und den Berechtigungsbericht ansehen (Einstellungs-Administratoren immer).</summary>
    bool IsAuditor(AuthOutcome o);
}

/// <summary>
/// Rollenprüfung nach Roles.*, Security.LocalAdministratorsArePrivileged und Unlock.AllowedDomains.
/// Regeln: Nur eine erfolgreiche, persönliche Anmeldung (nie das gemeinsame Entsperr-Kennwort) aus einer erlaubten Domäne
/// hat Rollen. Mitglieder der lokalen Administratoren haben alle Rollen, solange LocalAdministratorsArePrivileged an ist
/// (Standard, wie vor 0.5.0) – leere Rollengruppen ändern also nichts. Dazu kommen die Mitglieder der jeweiligen Gruppe.
/// Prüfer (Auditor) ist auch, wer Einstellungs-Administrator ist.
/// Microsoft-Anmeldungen werden mit <see cref="EntraLocalGroups"/> um lokale Gruppen ergänzt, wenn ein Verzeichnis übergeben ist.
/// </summary>
public sealed class RoleCheck : IRoleCheck
{
    private readonly Func<VitrineConfig> _config;
    private readonly Func<string, string?>? _resolveSid;
    private readonly Func<ILocalGroupDirectory>? _directory;

    /// <param name="config">Aktuelle Konfiguration (wird bei jeder Prüfung neu gelesen).</param>
    /// <param name="resolveSid">„DOMÄNE\Gruppe“ → SID (Windows); null = nur wörtlicher Vergleich.</param>
    /// <param name="directory">Lokale Gruppen für Microsoft-Anmeldungen; je Prüfung ein neues Objekt (kein Zwischenspeicher).</param>
    public RoleCheck(Func<VitrineConfig> config, Func<string, string?>? resolveSid = null, Func<ILocalGroupDirectory>? directory = null)
    {
        _config = config;
        _resolveSid = resolveSid;
        _directory = directory;
    }

    public bool IsConfigAdmin(AuthOutcome o) => RolesOf(o).Contains(VitrineRole.ConfigAdmin);

    public bool IsRegistrar(AuthOutcome o) => RolesOf(o).Contains(VitrineRole.Registrar);

    public bool IsAuditor(AuthOutcome o) => RolesOf(o).Contains(VitrineRole.Auditor);

    public bool Has(AuthOutcome o, VitrineRole role) => RolesOf(o).Contains(role);

    /// <summary>Alle Rollen der Person (leer bei Fehlschlag, gemeinsamem Kennwort oder nicht erlaubter Domäne).</summary>
    public IReadOnlySet<VitrineRole> RolesOf(AuthOutcome o)
    {
        var cfg = _config();
        var roles = new HashSet<VitrineRole>();
        if (!o.Success || UnlockPolicy.IsShared(o) || !UnlockPolicy.DomainAllowed(o, cfg.Unlock)) return roles;

        if (_directory is not null)
        {
            try { o = EntraLocalGroups.Expand(o, AllGroups(cfg), _resolveSid, _directory()); }
            catch { /* Verzeichnis nicht lesbar: nur die Gruppen der Anmeldung zählen */ }
        }

        bool admin = cfg.Security.LocalAdministratorsArePrivileged && o.IsAdministrator;
        if (admin || UnlockPolicy.InGroups(o, cfg.Roles.ConfigAdmins, _resolveSid)) roles.Add(VitrineRole.ConfigAdmin);
        if (admin || UnlockPolicy.InGroups(o, cfg.Roles.Registrars, _resolveSid)) roles.Add(VitrineRole.Registrar);
        if (roles.Contains(VitrineRole.ConfigAdmin) || UnlockPolicy.InGroups(o, cfg.Roles.Auditors, _resolveSid)) roles.Add(VitrineRole.Auditor);
        return roles;
    }

    /// <summary>Hat die Person eine der verlangten Rollen? Sonst Ablehnung mit Code (für Dialog und Protokoll).</summary>
    public PolicyDecision Decide(AuthOutcome o, IReadOnlyCollection<VitrineRole> accepted)
    {
        if (!o.Success)
            return new(false, o.Error ?? CoreText.Error(ErrorCodes.SignInFailed), o.ErrorCode ?? ErrorCodes.SignInFailed);
        if (UnlockPolicy.IsShared(o)) return PolicyDecision.Deny(ErrorCodes.PersonalAdminRequired);
        var cfg = _config();
        if (!UnlockPolicy.DomainAllowed(o, cfg.Unlock)) return PolicyDecision.Deny(ErrorCodes.DomainNotAllowed);
        if (RolesOf(o).Overlaps(accepted)) return PolicyDecision.Allow;
        // Ohne Rollengruppen und mit privilegierten Administratoren bleibt es bei der bisherigen Meldung
        if (cfg.Security.LocalAdministratorsArePrivileged && accepted.All(r => GroupsOf(cfg, r).Count == 0))
            return PolicyDecision.Deny(ErrorCodes.AdminRequired);
        return PolicyDecision.Deny(ErrorCodes.RoleRequired, string.Join(", ", accepted.Select(Name)));
    }

    /// <summary>Gruppen einer Rolle aus der Konfiguration.</summary>
    public static IReadOnlyList<string> GroupsOf(VitrineConfig cfg, VitrineRole role) => role switch
    {
        VitrineRole.ConfigAdmin => cfg.Roles.ConfigAdmins,
        VitrineRole.Registrar => cfg.Roles.Registrars,
        _ => cfg.Roles.Auditors,
    };

    /// <summary>Alle Gruppen aus Entsperr-Regeln, Notfall-Anmeldung und Rollen (für <see cref="EntraLocalGroups.Expand"/>).</summary>
    public static IEnumerable<string> AllGroups(VitrineConfig cfg) =>
        cfg.Unlock.AllowedGroups.Concat(cfg.Unlock.BypassGroups).Concat(cfg.Roles.ConfigAdmins)
            .Concat(cfg.Roles.Registrars).Concat(cfg.Roles.Auditors)
            .Where(g => !string.IsNullOrWhiteSpace(g)).Select(g => g.Trim()).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>Name der Rolle in der Sprache der Oberfläche.</summary>
    public static string Name(VitrineRole role) => role switch
    {
        VitrineRole.ConfigAdmin => CoreText.T("Role_ConfigAdmin"),
        VitrineRole.Registrar => CoreText.T("Role_Registrar"),
        _ => CoreText.T("Role_Auditor"),
    };

    /// <summary>
    /// Warnungen zur Einstellung (Übersicht, Protokoll): Ohne privilegierte Administratoren und ohne Gruppe in
    /// Roles.ConfigAdmins kann niemand die Einstellungen in Vitrine ändern (nur noch über Richtlinie oder Datei, VIT-0430).
    /// </summary>
    public static IEnumerable<string> Warnings(VitrineConfig cfg)
    {
        if (!cfg.Security.LocalAdministratorsArePrivileged && cfg.Security.SettingsAdminOnly
            && cfg.Roles.ConfigAdmins.All(string.IsNullOrWhiteSpace))
            yield return ErrorCodes.NoConfigAdmin;
    }
}
