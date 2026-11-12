// SPDX-License-Identifier: MIT
using System.Security.Principal;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Auth;

public static class WindowsAccounts
{
    public const string AdministratorsSid = "S-1-5-32-544";

    /// <summary>
    /// Alle Gruppen-SIDs eines Tokens – inklusive der Gruppen des „verknüpften“ Vollzugriffs-Tokens,
    /// denn bei aktiver Benutzerkontensteuerung ist die Administratorengruppe sonst nur „deny-only“.
    /// </summary>
    public static HashSet<string> GetGroupSids(WindowsIdentity id)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (id.Groups is not null)
            foreach (var g in id.Groups) set.Add(g.Value);

        using var linked = GetLinkedIdentity(id);
        if (linked?.Groups is not null)
            foreach (var g in linked.Groups) set.Add(g.Value);
        return set;
    }

    public static bool IsAdministrator(WindowsIdentity id) => GetGroupSids(id).Contains(AdministratorsSid);

    private static WindowsIdentity? GetLinkedIdentity(WindowsIdentity id)
    {
        try
        {
            if (!Native.GetTokenInformation(id.Token, Native.TokenElevationType, out int type, sizeof(int), out _))
                return null;
            if (type != Native.TokenElevationTypeLimited) return null;
            if (!Native.GetTokenInformation(id.Token, Native.TokenLinkedToken, out nint linked, IntPtr.Size, out _))
                return null;
            try { return new WindowsIdentity(linked); }
            finally { Native.CloseHandle(linked); }
        }
        catch { return null; }
    }

    /// <summary>"DOMAIN\Gruppe", "Gruppe" oder "S-1-…" → SID-String; null wenn unbekannt.</summary>
    public static string? ToSid(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        if (name.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return name;
        // „.\Gruppe“ (lokal, Schreibweise von net localgroup) kennt LookupAccountName nicht
        name = Vitrine.Core.Auth.AccountNames.ForLookup(name, Environment.MachineName);
        try { return new NTAccount(name).Translate(typeof(SecurityIdentifier)).Value; }
        catch { return null; }
    }
}
