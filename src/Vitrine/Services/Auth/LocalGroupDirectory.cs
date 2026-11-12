// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Vitrine.Core.Auth;

namespace Vitrine.Services.Auth;

/// <summary>
/// Lokale Gruppen dieses Rechners über NetLocalGroupGetMembers (Stufe 0: nur SIDs, auch S-1-12-1-… von Entra-Konten und
/// -Gruppen, ohne Namensauflösung). Nur lesend; je Entsperr-Versuch ein neues Objekt (kein Zwischenspeicher über Versuche).
/// </summary>
public sealed class LocalGroupDirectory : ILocalGroupDirectory
{
    private string? _machineSid;
    private bool _machineSidRead;

    /// <summary>LookupAccountName mit dem Rechnernamen liefert die Kontendomäne (SidTypeDomain); NTAccount.Translate kann das nicht.</summary>
    public string? MachineSid
    {
        get
        {
            if (_machineSidRead) return _machineSid;
            _machineSidRead = true;
            var sid = new byte[68];
            int cb = sid.Length, cch = 256;
            var domain = new StringBuilder(cch);
            if (LookupAccountNameW(null, Environment.MachineName, sid, ref cb, domain, ref cch, out _))
                _machineSid = new SecurityIdentifier(sid, 0).Value;
            return _machineSid;
        }
    }

    public IReadOnlyCollection<string>? MemberSids(string groupSid)
    {
        // NetLocalGroupGetMembers will den Namen (ohne Rechner): SID → „RECHNER\Gruppe“ bzw. „VORDEFINIERT\…“ → „Gruppe“
        string name;
        try { name = new SecurityIdentifier(groupSid).Translate(typeof(NTAccount)).Value; }
        catch { return null; }
        int bs = name.IndexOf('\\');
        if (bs >= 0) name = name[(bs + 1)..];

        var result = new List<string>();
        nint resume = 0;
        int status;
        do
        {
            status = NetLocalGroupGetMembers(null, name, 0, out var buffer, MAX_PREFERRED_LENGTH, out int read, out _, ref resume);
            try
            {
                if (status is not (NERR_Success or ERROR_MORE_DATA)) return null;
                for (int i = 0; i < read; i++)
                {
                    // LOCALGROUP_MEMBERS_INFO_0: ein Zeiger auf die SID
                    var psid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    if (psid != 0) result.Add(new SecurityIdentifier(psid).Value);
                }
            }
            finally { if (buffer != 0) NetApiBufferFree(buffer); }
        } while (status == ERROR_MORE_DATA);
        return result;
    }

    private const int NERR_Success = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int MAX_PREFERRED_LENGTH = -1;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level, out nint bufPtr,
        int prefMaxLen, out int entriesRead, out int totalEntries, ref nint resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(nint buffer);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountNameW(string? systemName, string accountName, byte[] sid, ref int cbSid,
        StringBuilder referencedDomainName, ref int cchReferencedDomainName, out int use);
}
