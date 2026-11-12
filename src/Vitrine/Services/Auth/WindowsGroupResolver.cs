// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Security.Principal;
using Vitrine.Core.Governance;

namespace Vitrine.Services.Auth;

/// <summary>
/// Gruppen für den Berechtigungsbericht auflösen, nur lesend: lokale Gruppen über NetLocalGroupGetMembers, Gruppen einer
/// Domäne über NetGroupGetUsers am Domänencontroller (direkte Benutzer-Mitglieder globaler Gruppen; verschachtelte Gruppen
/// und andere Gruppentypen erscheinen als „nicht ermittelbar“). Entra-Gruppen bleiben IDs – ihre Mitglieder verwaltet Entra ID.
/// </summary>
public sealed class WindowsGroupResolver : IGroupResolver
{
    private readonly LocalGroupDirectory _local = new();

    public GroupResolution Resolve(string entry)
    {
        entry = entry.Trim();
        var sid = entry.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) ? entry : WindowsAccounts.ToSid(entry);
        string? machine;
        try { machine = _local.MachineSid; } catch { machine = null; }
        var kind = GroupEntries.Classify(entry, sid, machine);
        var name = sid is null ? null : NameOf(sid);
        IReadOnlyList<string>? members = kind switch
        {
            GroupKind.Local when sid is not null => _local.MemberSids(sid)?.Select(MemberName).ToList(),
            GroupKind.Domain when name is not null => DomainMembers(name),
            _ => null,
        };
        return new GroupResolution(entry, kind, sid, name, members);
    }

    private static string? NameOf(string sid)
    {
        try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch { return null; }
    }

    /// <summary>Mitglied als Name; Entra-Konten und -Gruppen (S-1-12-1-…) ohne Namen als Objekt-ID.</summary>
    private static string MemberName(string sid) =>
        NameOf(sid) ?? (GroupEntries.ObjectIdFromSid(sid) is { } oid ? $"Entra ID {oid}" : sid);

    private static List<string>? DomainMembers(string qualifiedName)
    {
        int bs = qualifiedName.IndexOf('\\');
        if (bs <= 0) return null;
        string domain = qualifiedName[..bs], group = qualifiedName[(bs + 1)..];
        if (DsGetDcNameW(null, domain, 0, null, DS_RETURN_DNS_NAME, out var info) != 0 || info == 0) return null;
        string? dc;
        try { dc = Marshal.PtrToStringUni(Marshal.ReadIntPtr(info)); } // DOMAIN_CONTROLLER_INFO.DomainControllerName
        finally { NetApiBufferFree(info); }
        if (string.IsNullOrEmpty(dc)) return null;

        var result = new List<string>();
        nint resume = 0;
        int status;
        do
        {
            status = NetGroupGetUsers(dc, group, 0, out var buffer, MAX_PREFERRED_LENGTH, out int read, out _, ref resume);
            try
            {
                if (status is not (NERR_Success or ERROR_MORE_DATA)) return null;
                for (int i = 0; i < read; i++)
                    if (Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)) is { } user) result.Add($@"{domain}\{user}");
            }
            finally { if (buffer != 0) NetApiBufferFree(buffer); }
        } while (status == ERROR_MORE_DATA);
        return result;
    }

    private const int NERR_Success = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int MAX_PREFERRED_LENGTH = -1;
    private const int DS_RETURN_DNS_NAME = 0x40000000;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int DsGetDcNameW(string? computerName, string? domainName, nint domainGuid, string? siteName, int flags, out nint info);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGroupGetUsers(string serverName, string groupName, int level, out nint bufPtr, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref nint resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(nint buffer);
}
