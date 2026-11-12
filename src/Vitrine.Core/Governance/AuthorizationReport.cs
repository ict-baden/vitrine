// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Net;
using System.Text;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Governance;

/// <summary>Art eines Gruppeneintrags im Bericht.</summary>
public enum GroupKind
{
    /// <summary>Lokale Gruppe dieses Rechners (auch vordefinierte wie Administratoren).</summary>
    Local,
    /// <summary>Gruppe einer Active-Directory-Domäne.</summary>
    Domain,
    /// <summary>Entra-ID-Gruppe oder App-Rolle (Objekt-ID); Mitglieder verwaltet Entra ID.</summary>
    Entra,
    /// <summary>Auf diesem Rechner nicht auflösbar (z. B. Name einer Entra-App-Rolle oder unbekannte Gruppe).</summary>
    Unknown,
}

/// <summary>Aufgelöster Gruppeneintrag.</summary>
/// <param name="Entry">Eintrag wie in der Konfiguration.</param>
/// <param name="Name">Name der Gruppe („RECHNER\Gruppe“), soweit bekannt.</param>
/// <param name="Members">Direkte Mitglieder (Namen, sonst SIDs); null = nicht auflösbar.</param>
public sealed record GroupResolution(string Entry, GroupKind Kind, string? Sid, string? Name, IReadOnlyList<string>? Members);

/// <summary>Löst Gruppeneinträge auf (Windows: lokale Gruppen, Domäne); im Test eine Attrappe.</summary>
public interface IGroupResolver
{
    GroupResolution Resolve(string entry);
}

/// <summary>Einordnung von Gruppeneinträgen (plattformneutral).</summary>
public static class GroupEntries
{
    /// <param name="entry">Eintrag aus der Konfiguration.</param>
    /// <param name="sid">Aufgelöste SID (oder der Eintrag selbst, wenn er eine SID ist), null = nicht auflösbar.</param>
    /// <param name="machineSid">SID der Kontendomäne des Rechners.</param>
    public static GroupKind Classify(string entry, string? sid, string? machineSid)
    {
        entry = entry.Trim();
        if (Guid.TryParse(entry, out _)) return GroupKind.Entra;
        sid ??= entry.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) ? entry : null;
        if (sid is null) return GroupKind.Unknown;
        if (sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)) return GroupKind.Entra;
        if (EntraLocalGroups.IsLocalGroupSid(sid, machineSid)) return GroupKind.Local;
        return sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) ? GroupKind.Domain : GroupKind.Unknown;
    }

    /// <summary>Objekt-ID eines Entra-Kontos oder einer Entra-Gruppe aus der SID S-1-12-1-… (Umkehrung von EntraClaims.SidFromObjectId).</summary>
    public static string? ObjectIdFromSid(string? sid)
    {
        if (sid is null || !sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)) return null;
        var parts = sid["S-1-12-1-".Length..].Split('-');
        if (parts.Length != 4) return null;
        var bytes = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            if (!uint.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var v)) return null;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * 4, 4), v);
        }
        return new Guid(bytes).ToString();
    }
}

/// <summary>Zeile des Berichts.</summary>
/// <param name="Setting">Konfigurationspfad (z. B. „Roles.Auditors“), leer bei abgeleiteten Zeilen.</param>
/// <param name="Source">Herkunft: Richtlinie oder Konfiguration.</param>
public sealed record ReportRow(string Setting, string Label, string Value, string Source, IReadOnlyList<GroupResolution> Groups);

public sealed record ReportSection(string Title, IReadOnlyList<ReportRow> Rows);

/// <summary>
/// Berechtigungsbericht: Wer darf entsperren, wer darf die Notfall-Anmeldung nutzen, wer hat welche Rolle, mit welchen
/// Verfahren, und woher kommt die Einstellung (Richtlinie oder Konfiguration). Gruppen werden soweit möglich mit ihren
/// aktuellen Mitgliedern aufgelöst. Texte in der Sprache der Oberfläche; als HTML (zum Lesen, Drucken, Unterschreiben)
/// und CSV.
/// </summary>
public sealed class AuthorizationReport
{
    public required string Machine { get; init; }
    public required string GeneratedBy { get; init; }
    public required DateTimeOffset GeneratedAt { get; init; }
    public required string Version { get; init; }
    public required IReadOnlyList<ReportSection> Sections { get; init; }

    /// <summary>Lokale Administratoren (immer aufgelöst: Sie haben Rollen, solange LocalAdministratorsArePrivileged an ist).</summary>
    public const string AdministratorsSid = EntraLocalGroups.AdministratorsSid;

    /// <param name="isManaged">Ist der Pfad per Richtlinie festgelegt?</param>
    /// <param name="fidoStore">Stand der Schlüssel-Ablage vom Dienst (letzter Abgleich mit dem AD); null = nicht bekannt.</param>
    public static AuthorizationReport Build(VitrineConfig cfg, Func<string, bool> isManaged, IGroupResolver resolver,
        string machine, string generatedBy, DateTimeOffset at, string version, FidoStoreInfo? fidoStore = null)
    {
        var cache = new Dictionary<string, GroupResolution>(StringComparer.OrdinalIgnoreCase);
        GroupResolution Resolve(string e)
        {
            if (cache.TryGetValue(e, out var r)) return r;
            try { r = resolver.Resolve(e); }
            catch { r = new GroupResolution(e, GroupEntries.Classify(e, null, null), null, null, null); }
            return cache[e] = r;
        }
        List<GroupResolution> Groups(IEnumerable<string> entries) =>
            entries.Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => Resolve(e.Trim())).ToList();
        string Src(string path) => isManaged(path) ? CoreText.T("Report_SourcePolicy") : CoreText.T("Report_SourceConfig");
        ReportRow Row(string path, string label, string value, IReadOnlyList<GroupResolution>? groups = null) =>
            new(path, label, value, Src(path), groups ?? []);
        string YesNo(bool b) => CoreText.T(b ? "Report_Yes" : "Report_No");
        string List(IEnumerable<string> items) => items.Any(i => !string.IsNullOrWhiteSpace(i)) ? string.Join(", ", items.Where(i => !string.IsNullOrWhiteSpace(i))) : CoreText.T("Report_None");

        var u = cfg.Unlock;
        var allowed = Enum.GetValues<UnlockAllowed>().Where(f => f != UnlockAllowed.None && u.Allowed.HasFlag(f))
            .Select(f => f switch
            {
                UnlockAllowed.SessionUser => CoreText.T("Report_Allowed_SessionUser"),
                UnlockAllowed.Administrators => CoreText.T("Report_Allowed_Administrators"),
                UnlockAllowed.Groups => CoreText.T("Report_Allowed_Groups"),
                UnlockAllowed.Users => CoreText.T("Report_Allowed_Users"),
                _ => CoreText.T("Report_Allowed_AnyAuthenticated"),
            }).ToList();
        var unlock = new List<ReportRow>
        {
            Row("Unlock.Allowed", CoreText.T("Report_UnlockAllowed"), allowed.Count == 0 ? CoreText.T("Report_None") : string.Join(", ", allowed)),
            Row("Unlock.AllowedGroups", CoreText.T("Report_UnlockGroups"),
                u.Allowed.HasFlag(UnlockAllowed.Groups) ? List(u.AllowedGroups) : CoreText.T("Report_NotUsed"),
                u.Allowed.HasFlag(UnlockAllowed.Groups) ? Groups(u.AllowedGroups) : []),
            Row("Unlock.AllowedUsers", CoreText.T("Report_UnlockUsers"),
                u.Allowed.HasFlag(UnlockAllowed.Users) ? List(u.AllowedUsers) : CoreText.T("Report_NotUsed")),
            Row("Unlock.AllowedDomains", CoreText.T("Report_UnlockDomains"), u.AllowedDomains.Count == 0 ? CoreText.T("Report_AllDomains") : List(u.AllowedDomains)),
            Row("Unlock.Methods", CoreText.T("Report_Methods"), List(u.Methods)),
            Row("Fido.Store", CoreText.T("Report_FidoStore"), FidoStoreText(cfg.Fido, fidoStore)),
        };

        var emergency = new List<ReportRow>
        {
            Row("Unlock.BypassGroups", CoreText.T("Report_BypassGroups"),
                EmergencyAccess.Enabled(u) ? List(u.BypassGroups) : CoreText.T("Report_BypassOff"), Groups(u.BypassGroups)),
            Row("Unlock.BypassReasonMinLength", CoreText.T("Report_BypassMinLength"),
                Reasons.EffectiveMinLength(u.BypassReasonMinLength).ToString(CultureInfo.CurrentCulture)),
        };

        var sec = cfg.Security;
        string RoleValue(IReadOnlyList<string> groups)
        {
            var listed = groups.Where(g => !string.IsNullOrWhiteSpace(g)).ToList();
            var admins = sec.LocalAdministratorsArePrivileged ? CoreText.T("Report_LocalAdmins") : null;
            if (listed.Count == 0) return admins ?? CoreText.T("Report_Nobody");
            return admins is null ? string.Join(", ", listed) : $"{string.Join(", ", listed)}; {admins}";
        }
        var roles = new List<ReportRow>
        {
            Row("Security.LocalAdministratorsArePrivileged", CoreText.T("Report_AdminsPrivileged"), YesNo(sec.LocalAdministratorsArePrivileged)),
            Row("Roles.ConfigAdmins", RoleCheck.Name(VitrineRole.ConfigAdmin), RoleValue(cfg.Roles.ConfigAdmins), Groups(cfg.Roles.ConfigAdmins)),
            Row("Roles.Registrars", RoleCheck.Name(VitrineRole.Registrar), RoleValue(cfg.Roles.Registrars), Groups(cfg.Roles.Registrars)),
            Row("Roles.Auditors", RoleCheck.Name(VitrineRole.Auditor), RoleValue(cfg.Roles.Auditors) + "; " + CoreText.T("Report_AuditorsIncludeAdmins"),
                Groups(cfg.Roles.Auditors)),
        };
        if (sec.LocalAdministratorsArePrivileged || u.Allowed.HasFlag(UnlockAllowed.Administrators))
            roles.Add(new ReportRow("", CoreText.T("Report_LocalAdmins"), CoreText.T("Report_LocalAdminsNote"), "", [Resolve(AdministratorsSid)]));

        var governance = new List<ReportRow>
        {
            Row("Security.SettingsAdminOnly", CoreText.T("Report_SettingsAdminOnly"), YesNo(sec.SettingsAdminOnly)),
            Row("Security.ExitRequiresAdmin", CoreText.T("Report_ExitRequiresAdmin"), YesNo(sec.ExitRequiresAdmin)),
            Row("Security.ReasonRequiredForAdminActions", CoreText.T("Report_ReasonAdmin"), YesNo(sec.ReasonRequiredForAdminActions)),
            Row("Security.ReasonRequiredForConfigChanges", CoreText.T("Report_ReasonConfig"), YesNo(sec.ReasonRequiredForConfigChanges)),
            Row("Security.ReasonMinLength", CoreText.T("Report_ReasonMinLength"), Reasons.EffectiveMinLength(sec.ReasonMinLength).ToString(CultureInfo.CurrentCulture)),
        };

        return new AuthorizationReport
        {
            Machine = machine, GeneratedBy = generatedBy, GeneratedAt = at, Version = version,
            Sections =
            [
                new(CoreText.T("Report_SectionUnlock"), unlock),
                new(CoreText.T("Report_SectionEmergency"), emergency),
                new(CoreText.T("Report_SectionRoles"), roles),
                new(CoreText.T("Report_SectionGovernance"), governance),
            ],
        };
    }

    /// <summary>Ablage der Sicherheitsschlüssel: lokal oder Active Directory mit Container und letztem Abgleich.</summary>
    public static string FidoStoreText(FidoSettings fido, FidoStoreInfo? info)
    {
        if (fido.Store != FidoStoreKind.ActiveDirectory) return CoreText.T("Report_FidoStoreLocal");
        var location = info?.Location ?? (string.IsNullOrWhiteSpace(fido.DirectoryContainer) ? "CN=Vitrine,CN=Program Data" : fido.DirectoryContainer.Trim());
        var sync = info is null ? CoreText.T("Report_FidoSyncUnknown")
            : info.LastSync is { } t ? t.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
            : CoreText.T("Report_FidoSyncNever");
        return CoreText.F("Report_FidoStoreDirectory", location, sync);
    }

    /// <summary>Text einer Gruppe: Name, Art, Mitglieder bzw. warum keine.</summary>
    public static string Describe(GroupResolution g)
    {
        var name = g.Name is null || string.Equals(g.Name, g.Entry, StringComparison.OrdinalIgnoreCase) ? g.Entry : $"{g.Entry} ({g.Name})";
        var kind = g.Kind switch
        {
            GroupKind.Local => CoreText.T("Report_Kind_Local"),
            GroupKind.Domain => CoreText.T("Report_Kind_Domain"),
            GroupKind.Entra => CoreText.T("Report_Kind_Entra"),
            _ => CoreText.T("Report_Kind_Unknown"),
        };
        string members = g.Members switch
        {
            null when g.Kind == GroupKind.Entra => CoreText.T("Report_MembersEntra"),
            null => CoreText.T("Report_MembersUnresolved"),
            { Count: 0 } => CoreText.T("Report_MembersNone"),
            var m => string.Join(", ", m),
        };
        return $"{name} [{kind}]: {members}";
    }

    private string Time => GeneratedAt.ToLocalTime().ToString("f", CultureInfo.CurrentCulture) + " (" +
                           GeneratedAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC)";

    public string ToHtml()
    {
        static string H(string s) => WebUtility.HtmlEncode(s);
        var sb = new StringBuilder();
        var lang = CultureInfo.CurrentUICulture.Name;
        sb.Append("<!DOCTYPE html>\n<html lang=\"").Append(H(lang.Length == 0 ? "en" : lang)).Append("\">\n<head>\n<meta charset=\"utf-8\">\n<title>")
          .Append(H(CoreText.F("Report_Title", Machine))).Append("</title>\n<style>\n")
          .Append("body{font-family:'Segoe UI',Arial,sans-serif;font-size:10.5pt;color:#1b1b1b;margin:2em;max-width:60em}")
          .Append("h1{font-size:16pt;margin-bottom:.2em}h2{font-size:12.5pt;margin-top:1.6em;border-bottom:1px solid #999}")
          .Append("table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}")
          .Append("th{background:#eee}td.src{white-space:nowrap;color:#555}ul{margin:.2em 0 0 1.2em;padding:0}code{font-size:9.5pt}")
          .Append(".meta td{border:none;padding:1px 12px 1px 0}.sign td{height:3em;vertical-align:bottom}")
          .Append("@media print{body{margin:0}}\n</style>\n</head>\n<body>\n");
        sb.Append("<h1>").Append(H(CoreText.F("Report_Title", Machine))).Append("</h1>\n<table class=\"meta\">\n");
        void Meta(string k, string v) => sb.Append("<tr><td>").Append(H(k)).Append("</td><td>").Append(H(v)).Append("</td></tr>\n");
        Meta(CoreText.T("Report_Machine"), Machine);
        Meta(CoreText.T("Report_GeneratedAt"), Time);
        Meta(CoreText.T("Report_GeneratedBy"), GeneratedBy);
        Meta(CoreText.T("Report_Version"), Version);
        sb.Append("</table>\n<p>").Append(H(CoreText.T("Report_Intro"))).Append("</p>\n");

        foreach (var section in Sections)
        {
            sb.Append("<h2>").Append(H(section.Title)).Append("</h2>\n<table>\n<tr><th>").Append(H(CoreText.T("Report_ColSetting")))
              .Append("</th><th>").Append(H(CoreText.T("Report_ColValue"))).Append("</th><th>").Append(H(CoreText.T("Report_ColSource"))).Append("</th></tr>\n");
            foreach (var r in section.Rows)
            {
                sb.Append("<tr><td>").Append(H(r.Label));
                if (r.Setting.Length > 0) sb.Append("<br><code>").Append(H(r.Setting)).Append("</code>");
                sb.Append("</td><td>").Append(H(r.Value));
                if (r.Groups.Count > 0)
                {
                    sb.Append("<ul>");
                    foreach (var g in r.Groups) sb.Append("<li>").Append(H(Describe(g))).Append("</li>");
                    sb.Append("</ul>");
                }
                sb.Append("</td><td class=\"src\">").Append(H(r.Source)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");
        }

        sb.Append("<h2>").Append(H(CoreText.T("Report_Approval"))).Append("</h2>\n<p>").Append(H(CoreText.T("Report_ApprovalText")))
          .Append("</p>\n<table class=\"sign\">\n<tr><th>").Append(H(CoreText.T("Report_Role"))).Append("</th><th>")
          .Append(H(CoreText.T("Report_SignName"))).Append("</th><th>").Append(H(CoreText.T("Report_SignDate"))).Append("</th><th>")
          .Append(H(CoreText.T("Report_Signature"))).Append("</th></tr>\n");
        foreach (var role in new[] { "Report_SignPreparedBy", "Report_SignReviewedBy", "Report_SignApprovedBy" })
            sb.Append("<tr><td>").Append(H(CoreText.T(role))).Append("</td><td></td><td></td><td></td></tr>\n");
        sb.Append("</table>\n</body>\n</html>\n");
        return sb.ToString();
    }

    /// <summary>CSV nach RFC 4180 (Komma, Anführungszeichen); eine Zeile je Einstellung bzw. je Gruppe.</summary>
    public string ToCsv()
    {
        var sb = new StringBuilder();
        void Line(params string[] cells) => sb.Append(string.Join(",", cells.Select(Cell))).Append("\r\n");
        Line(CoreText.T("Report_ColSection"), CoreText.T("Report_ColSetting"), CoreText.T("Report_ColLabel"), CoreText.T("Report_ColValue"),
            CoreText.T("Report_ColSource"), CoreText.T("Report_ColGroup"), CoreText.T("Report_ColMembers"));
        Line(CoreText.T("Report_Machine"), "", "", Machine, "", "", "");
        Line(CoreText.T("Report_GeneratedAt"), "", "", GeneratedAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC", "", "", "");
        Line(CoreText.T("Report_GeneratedBy"), "", "", GeneratedBy, "", "", "");
        foreach (var s in Sections)
            foreach (var r in s.Rows)
            {
                if (r.Groups.Count == 0) { Line(s.Title, r.Setting, r.Label, r.Value, r.Source, "", ""); continue; }
                foreach (var g in r.Groups)
                    Line(s.Title, r.Setting, r.Label, r.Value, r.Source, g.Name ?? g.Entry,
                        g.Members is null ? (g.Kind == GroupKind.Entra ? CoreText.T("Report_MembersEntra") : CoreText.T("Report_MembersUnresolved"))
                        : string.Join("; ", g.Members));
            }
        return sb.ToString();
    }

    /// <summary>Zelle nach RFC 4180; führende =, +, -, @ entschärft (keine Formeln beim Öffnen in Tabellenprogrammen).</summary>
    internal static string Cell(string s)
    {
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@' or '\t' or '\r') s = "'" + s;
        return s.IndexOfAny([',', '"', '\r', '\n', ';']) >= 0 ? "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : s;
    }
}
