// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Governance;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>
/// Notfall-Anmeldung („Bypass“): Eine Person aus Unlock.BypassGroups darf mit dem Windows-Kennwort entsperren, auch wenn
/// die Entsperr-Regeln (Unlock.Allowed) sie nicht zulassen – nur mit Begründung (Unlock.BypassReasonMinLength). Mitglieder
/// der lokalen Administratoren dürfen es auch, solange Security.LocalAdministratorsArePrivileged an ist. Ohne Notfall-Gruppen
/// gibt es keine Notfall-Anmeldung. Unlock.AllowedDomains gilt weiter; das gemeinsame Entsperr-Kennwort nie.
/// </summary>
public static class EmergencyAccess
{
    /// <summary>Einziges Verfahren der Notfall-Anmeldung (Windows-Kennwort, persönlich und vom Dienst prüfbar).</summary>
    public const string Method = "windows";

    /// <summary>Markierung in <see cref="AuthOutcome.Details"/>: Entsperrt über die Notfall-Anmeldung.</summary>
    public const string Detail = "emergency";

    /// <summary>Begründung in <see cref="AuthOutcome.Details"/> und im Protokoll.</summary>
    public const string ReasonDetail = "reason";

    public static bool Enabled(UnlockSettings s) => s.BypassGroups.Any(g => !string.IsNullOrWhiteSpace(g));

    public static bool IsEmergency(AuthOutcome o) => o.Details.TryGetValue(Detail, out var v) && v == "true";

    /// <summary>Begründung vor der Anmeldung prüfen (kein Fehlversuch, wenn nur sie fehlt).</summary>
    public static PolicyDecision CheckReason(string? reason, UnlockSettings s) =>
        Reasons.IsSufficient(reason, s.BypassReasonMinLength)
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(ErrorCodes.ReasonTooShort, Reasons.EffectiveMinLength(s.BypassReasonMinLength));

    /// <summary>Darf diese (erfolgreich angemeldete) Person über die Notfall-Anmeldung entsperren?</summary>
    /// <param name="method">Verfahren der Anmeldung; nur <see cref="Method"/> ist zulässig.</param>
    public static PolicyDecision Evaluate(AuthOutcome o, string method, VitrineConfig cfg, string? reason, Func<string, string?>? resolveSid = null)
    {
        if (!o.Success)
            return new(false, o.Error ?? CoreText.Error(ErrorCodes.SignInFailed), o.ErrorCode ?? ErrorCodes.SignInFailed);
        if (!string.Equals(method, Method, StringComparison.Ordinal) || UnlockPolicy.IsShared(o))
            return PolicyDecision.Deny(ErrorCodes.EmergencyNeedsWindowsPassword);
        if (!Enabled(cfg.Unlock)) return PolicyDecision.Deny(ErrorCodes.EmergencyNotAllowed, o.DisplayName ?? o.UserName);
        if (CheckReason(reason, cfg.Unlock) is { Allowed: false } r) return r;
        if (!UnlockPolicy.DomainAllowed(o, cfg.Unlock)) return PolicyDecision.Deny(ErrorCodes.DomainNotAllowed);
        bool admin = cfg.Security.LocalAdministratorsArePrivileged && o.IsAdministrator;
        return admin || UnlockPolicy.InGroups(o, cfg.Unlock.BypassGroups, resolveSid)
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(ErrorCodes.EmergencyNotAllowed, o.DisplayName ?? o.UserName);
    }

    /// <summary>Ergebnis nach erlaubter Notfall-Anmeldung: Verfahren, Markierung und Begründung fürs Protokoll.</summary>
    public static AuthOutcome Mark(AuthOutcome o, string? reason) =>
        AuthResults.Verified(o, Method).WithDetails(new Dictionary<string, string>(AuthResults.Verified(o, Method).Details)
        {
            [Detail] = "true",
            [ReasonDetail] = Reasons.Normalize(reason) ?? "",
        });
}
