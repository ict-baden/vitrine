// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Auth;

/// <summary>Wie das Gerät angebunden ist (Windows: NetGetAadJoinInformation und NetGetJoinInformation).</summary>
public enum DeviceJoinState
{
    /// <summary>Nicht ermittelbar (API fehlt oder Fehler) – dann entscheidet das Sitzungskonto.</summary>
    Unknown,
    /// <summary>Arbeitsgruppe, weder Active Directory noch Entra.</summary>
    Workgroup,
    /// <summary>Nur Active Directory.</summary>
    DomainJoined,
    /// <summary>Active Directory und Entra (Hybrid Join).</summary>
    HybridJoined,
    /// <summary>Nur Microsoft Entra ID (Entra-joined).</summary>
    EntraJoined,
}

/// <summary>Was über die Sitzung und das Gerät bekannt ist, für <see cref="LogonTarget.Resolve"/>.</summary>
/// <param name="UserName">Sitzungsbenutzer als „DOMÄNE\name“ (bei Entra-Konten „AzureAD\name“).</param>
/// <param name="Upn">UPN der Sitzung, falls Windows einen kennt (lokale Konten: keiner).</param>
/// <param name="Domain">Domäne der Sitzung (bei lokalen Konten der Rechnername).</param>
/// <param name="IsEntraAccount">Sitzungskonto ist ein Entra-Konto („AzureAD\…“).</param>
/// <param name="DeviceJoin">Anbindung des Geräts.</param>
/// <param name="MachineName">Rechnername (für „.\name“).</param>
public sealed record LogonContext(string UserName, string? Upn, string Domain, bool IsEntraAccount, DeviceJoinState DeviceJoin,
    string MachineName);

/// <summary>
/// Benutzer und Domäne für genau einen LogonUser-Aufruf; <see cref="User"/> null = nicht anmeldbar, Meldung VIT-0108.
/// Nie zwei Versuche (erst ohne, dann mit „AzureAD“): jeder Versuch zählt gegen die Kontosperrschwelle.
/// </summary>
public readonly record struct LogonTarget(string? User, string? Domain)
{
    /// <summary>Domäne, über die Windows Entra-Konten anmeldet (wie <c>runas /user:AzureAD\name@contoso.com</c>).</summary>
    public const string EntraDomain = "AzureAD";

    public static LogonTarget Refused => new(null, null);

    public bool IsRefused => User is null;

    /// <summary>UPN, mit dem angemeldet wird, sonst null (fürs Protokoll neben „DOMÄNE\name“).</summary>
    public string? Upn => User is not null && User.Contains('@') ? User : null;

    /// <summary>Auf diesem Gerät gelten UPNs als Entra-Konten?</summary>
    private static bool EntraDevice(LogonContext s) =>
        s.DeviceJoin == DeviceJoinState.EntraJoined || (s.DeviceJoin == DeviceJoinState.Unknown && s.IsEntraAccount);

    private static bool IsEntraDomain(string domain) => domain.Equals(EntraDomain, StringComparison.OrdinalIgnoreCase);

    /// <summary>Eingabe im Feld „Benutzername“ + Sitzung → (Benutzer, Domäne) für LogonUser (Tabelle in docs/sign-in.md).</summary>
    public static LogonTarget Resolve(string? input, LogonContext s)
    {
        input = input?.Trim();
        if (string.IsNullOrEmpty(input))
        {
            // Leer = Sitzungsbenutzer. Entra-Konten nur über „AzureAD“ + UPN; AD-Konten per UPN ohne Domäne.
            if (s.IsEntraAccount)
                return string.IsNullOrEmpty(s.Upn) ? Refused : new(s.Upn, EntraDomain);
            if (!string.IsNullOrEmpty(s.Upn)) return new(s.Upn, null);
            input = s.UserName.Trim();
            if (input.Length == 0) return Refused;
        }

        // „DOMÄNE\name“ vor der @-Prüfung: „AzureAD\name@contoso.com“ enthält auch ein @
        int bs = input.IndexOf('\\');
        if (bs >= 0)
        {
            var domain = input[..bs].Trim();
            var name = input[(bs + 1)..].Trim();
            if (domain.Length == 0 || name.Length == 0 || name.Contains('\\')) return Refused;

            if (IsEntraDomain(domain))
            {
                if (name.Contains('@')) return new(name, EntraDomain);
                // „AzureAD\MaxMuster“ ist kein anmeldbarer Name – nur beim Sitzungsbenutzer über dessen UPN auflösbar
                return s.IsEntraAccount && !string.IsNullOrEmpty(s.Upn) && SameAccount(domain, name, s.UserName)
                    ? new(s.Upn, EntraDomain)
                    : Refused;
            }
            return new(name, domain == "." ? s.MachineName : domain);
        }

        if (input.Contains('@'))
        {
            // Entra-joined: Windows meldet UPNs nur mit „AzureAD“ an (sonst 1326). AD/Hybrid: der Domänencontroller löst den UPN auf.
            // Unbekannter Join-Status: Ist die eigene Sitzung ein Entra-Konto, ist das Gerät Entra-joined.
            // Der UPN der eigenen Entra-Sitzung geht immer über „AzureAD“, auch wenn der Join-Status anderes meldet.
            if (EntraDevice(s) || (s.IsEntraAccount && string.Equals(input, s.Upn, StringComparison.OrdinalIgnoreCase)))
                return new(input, EntraDomain);
            return new(input, null);
        }

        // Name ohne Domäne: in Entra-Sitzungen nicht eindeutig (lokal oder Entra?) – UPN verlangen
        if (s.IsEntraAccount) return Refused;
        return new(input, s.Domain);
    }

    private static bool SameAccount(string domain, string name, string sessionUser)
    {
        int bs = sessionUser.IndexOf('\\');
        if (bs < 0) return false;
        return sessionUser[..bs].Equals(domain, StringComparison.OrdinalIgnoreCase)
            && sessionUser[(bs + 1)..].Equals(name, StringComparison.OrdinalIgnoreCase);
    }
}
