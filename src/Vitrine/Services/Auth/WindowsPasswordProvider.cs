// SPDX-License-Identifier: MIT
using System.Security.Principal;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Localization;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Auth;

/// <summary>Windows-Kennwort (lokal, Active Directory oder Entra-ID-Konto auf einem Entra-Gerät).</summary>
public sealed class WindowsPasswordProvider : IAuthProvider
{
    private readonly SessionInfo _session;
    private readonly IDeviceJoinInfo _join;

    public WindowsPasswordProvider(SessionInfo session, IDeviceJoinInfo? join = null)
    {
        _session = session;
        _join = join ?? new WindowsDeviceJoinInfo();
    }

    public string Id => "windows";
    public string DisplayName => UI.Loc.T("Method_Windows");
    public string Glyph => "\uE8D7"; // Permissions
    public AuthInputKind Input => AuthInputKind.UsernamePassword;

    public Task<bool> IsAvailableAsync(CancellationToken ct) => Task.FromResult(true);

    public Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct)
        => Task.Run(() => Authenticate(request), ct);

    private AuthOutcome Authenticate(AuthRequest request)
    {
        if (string.IsNullOrEmpty(request.Secret)) return Fail(ErrorCodes.SecretMissing);

        // Genau ein LogonUser-Aufruf (kein zweiter Versuch mit anderer Domäne: zählte doppelt gegen die Sperrschwelle)
        var target = ResolveTarget(request.UserName);
        if (target.IsRefused) return Fail(ErrorCodes.UseUpnForEntra);
        return Logon(target, request.Secret, _session.Sid);
    }

    /// <summary>Benutzer und Domäne für LogonUser aus der Eingabe (auch für die Prüfung durch den Dienst, #15).</summary>
    internal LogonTarget ResolveTarget(string? input) => LogonTarget.Resolve(input, Context());

    /// <summary>
    /// Ein LogonUser-Aufruf und die Identität aus dem Token. Auch im Dienst (SYSTEM) für Signaturen: Dort ist
    /// <paramref name="sessionSid"/> die SID der anfragenden Sitzung (#15).
    /// </summary>
    internal static AuthOutcome Logon(LogonTarget target, string secret, string? sessionSid) => Logon(target, secret, sessionSid, keep: false, out _);

    /// <param name="keep">
    /// Identität (mit eigenem Token) bei Erfolg behalten statt freigeben – im Dienst für das Schreiben der Sicherheitsschlüssel
    /// ins Active Directory als die registrierende Person. Der Aufrufer gibt <paramref name="identity"/> frei.
    /// </param>
    internal static AuthOutcome Logon(LogonTarget target, string secret, string? sessionSid, bool keep, out WindowsIdentity? identity)
    {
        identity = null;
        if (!Native.LogonUser(target.User!, target.Domain, secret, Native.LOGON32_LOGON_INTERACTIVE, Native.LOGON32_PROVIDER_DEFAULT, out var token))
        {
            // Zuordnung Windows-Fehler → VIT-Code gemeinsam mit dem Windows-Anmeldedialog (Vitrine.Core)
            return WindowsLogonErrors.Fail(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
        }

        try
        {
            var id = new WindowsIdentity(token);
            if (keep) identity = id;
            using var dispose = keep ? null : id;
            var sid = id.User?.Value;
            var groups = WindowsAccounts.GetGroupSids(id);
            // Windows meldet Entra-Konten als „AzureAD\Vorname…“; der UPN, mit dem angemeldet wurde, kommt zusätzlich ins Protokoll
            var details = new Dictionary<string, string>();
            if (target.Upn is { } upn) details["upn"] = upn;
            return new AuthOutcome
            {
                Success = true,
                UserName = id.Name,
                DisplayName = id.Name.Contains('\\') ? id.Name[(id.Name.IndexOf('\\') + 1)..] : id.Name,
                UserId = sid,
                Groups = groups,
                IsAdministrator = groups.Contains(WindowsAccounts.AdministratorsSid),
                IsSessionUser = string.Equals(sid, sessionSid, StringComparison.OrdinalIgnoreCase),
                Details = details,
            };
        }
        finally { Native.CloseHandle(token); }
    }

    private static AuthOutcome Fail(string code) => AuthOutcome.Fail(CoreText.Error(code), code);

    private LogonContext Context() => new(_session.UserName, _session.Upn, _session.Domain, _session.IsEntraJoinedAccount,
        _join.Get(), Environment.MachineName);
}
