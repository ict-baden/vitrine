// SPDX-License-Identifier: MIT
using System.Security.Principal;
using Vitrine.Abstractions;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Auth;

/// <summary>Wer ist an dieser Windows-Sitzung angemeldet?</summary>
public sealed class SessionInfo
{
    public string UserName { get; }
    public string Sid { get; }
    public string? Upn { get; }
    public string DisplayName { get; }
    public string Domain { get; }
    public bool IsEntraJoinedAccount { get; }
    public bool IsAdministrator { get; }

    /// <summary>Gruppen-SIDs des Sitzungstokens (mit dem verknüpften Vollzugriffs-Token), für die Rollenprüfung ohne Dialog.</summary>
    public IReadOnlyCollection<string> Groups { get; } = [];
    public int SessionId { get; }

    /// <summary>Rechnername für die Anzeige (in den Screenshots ein Beispielname).</summary>
    public string MachineName { get; } = Environment.MachineName;

    /// <summary>Beispielsitzung für die Screenshots (richtlinien/08: keine echten Namen).</summary>
    private SessionInfo(string userName, string displayName, string machineName)
    {
        UserName = userName;
        Sid = "S-1-5-21-0-0-0-1001";
        Domain = userName[..userName.IndexOf('\\')];
        Upn = "operator@contoso.com";
        DisplayName = displayName;
        MachineName = machineName;
        SessionId = 1;
    }

    public static SessionInfo Demo(string displayName) => new(@"LAB\operator", displayName, "LAB-PC-07");

    public SessionInfo()
    {
        using var id = WindowsIdentity.GetCurrent();
        UserName = id.Name;
        Sid = id.User?.Value ?? "";
        Domain = UserName.Contains('\\') ? UserName[..UserName.IndexOf('\\')] : Environment.UserDomainName;
        IsEntraJoinedAccount = Domain.Equals("AzureAD", StringComparison.OrdinalIgnoreCase);
        Upn = Native.GetCurrentUserName(Native.EXTENDED_NAME_FORMAT.NameUserPrincipal);
        DisplayName = Native.GetCurrentUserName(Native.EXTENDED_NAME_FORMAT.NameDisplay) is { Length: > 0 } dn
            ? dn
            : (UserName.Contains('\\') ? UserName[(UserName.IndexOf('\\') + 1)..] : UserName);
        Groups = WindowsAccounts.GetGroupSids(id);
        IsAdministrator = Groups.Contains(WindowsAccounts.AdministratorsSid);
        SessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
    }

    /// <summary>Der Benutzer der Sitzung als Anmeldeergebnis (Windows-Anmeldung), z. B. für die Rollenprüfung ohne Dialog.</summary>
    public AuthOutcome AsOutcome() => new()
    {
        Success = true, UserName = UserName, DisplayName = DisplayName, UserId = Sid, Groups = Groups,
        IsAdministrator = IsAdministrator, IsSessionUser = true,
    };

    public string Initials
    {
        get
        {
            var parts = DisplayName.Split(new[] { ' ', '.', '_', '-', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return "?";
            if (DisplayName.Contains(',') && parts.Length >= 2) (parts[0], parts[1]) = (parts[1], parts[0]); // "Muster, Max"
            return parts.Length == 1
                ? parts[0][..Math.Min(2, parts[0].Length)].ToUpperInvariant()
                : $"{char.ToUpperInvariant(parts[0][0])}{char.ToUpperInvariant(parts[^1][0])}";
        }
    }
}
