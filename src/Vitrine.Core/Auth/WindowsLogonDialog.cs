// SPDX-License-Identifier: MIT
using System.ComponentModel;
using Vitrine.Abstractions;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>Windows-Konto aus dem Token einer erfolgreichen Anmeldung.</summary>
/// <param name="Name">„DOMÄNE\name“, bei Entra-Konten „AzureAD\name“.</param>
/// <param name="Sid">SID des Kontos.</param>
/// <param name="Groups">Alle Gruppen-SIDs (auch lokale Gruppen, Entra-Gruppen S-1-12-1-…, verknüpftes Token).</param>
public sealed record WindowsAccountInfo(string Name, string? Sid, IReadOnlyCollection<string> Groups, bool IsAdministrator);

/// <summary>Anmeldedaten aus dem Windows-Anmeldedialog; Dispose überschreibt und gibt sie frei.</summary>
public interface IWindowsCredential : IDisposable;

/// <summary>
/// Windows-Teil des Verfahrens „windowslogon“: Dialog (CredUIPromptForWindowsCredentials) und Prüfung
/// (LsaLogonUser). Hinter einer Schnittstelle, damit Tests nie echte Anmeldungen auslösen.
/// </summary>
public interface IWindowsCredentialDialog
{
    /// <summary>Zeigt den Dialog. Rückgabe: Windows-Fehlercode (0 = Anmeldedaten in <paramref name="credential"/>, 1223 = abgebrochen).</summary>
    int Prompt(nint owner, string caption, string message, out IWindowsCredential? credential);

    /// <summary>Genau ein LsaLogonUser. Rückgabe: Windows-Fehlercode (0 = angemeldet, Konto in <paramref name="account"/>).</summary>
    int Logon(IWindowsCredential credential, out WindowsAccountInfo? account);
}

/// <summary>Windows-Fehlercodes einer Anmeldung → Vitrine-Fehlercodes (Windows-Kennwort und Windows-Anmeldedialog).</summary>
public static class WindowsLogonErrors
{
    public const int Cancelled = 1223;

    /// <summary>Code zum Windows-Fehler; unbekannte Fehler → VIT-0109 (mit Windows-Meldung).</summary>
    public static string CodeFor(int win32Error) => win32Error switch
    {
        1326 => ErrorCodes.WrongCredentials,
        1327 or 1328 or 1329 or 1330 or 1907 => ErrorCodes.AccountRestricted,
        1331 => ErrorCodes.AccountDisabled,
        1909 => ErrorCodes.AccountLockedOut,
        1311 => ErrorCodes.NoLogonServer,
        1385 => ErrorCodes.LogonNotAllowedHere,
        Cancelled => ErrorCodes.SignInCancelled,
        _ => ErrorCodes.WindowsLogonError,
    };

    /// <summary>Fehlgeschlagene Anmeldung mit übersetzter Meldung.</summary>
    public static AuthOutcome Fail(int win32Error)
    {
        var code = CodeFor(win32Error);
        return code == ErrorCodes.WindowsLogonError
            ? AuthOutcome.Fail(CoreText.Error(code, new Win32Exception(win32Error).Message), code)
            : AuthOutcome.Fail(CoreText.Error(code), code);
    }
}

/// <summary>
/// Ablauf des Verfahrens „windowslogon“ (Windows-Anmeldedialog): Dialog zeigen, die Anmeldedaten genau einmal prüfen
/// (zählt wie jede Windows-Anmeldung gegen die Kontosperre), Anmeldedaten in jedem Fall verwerfen, Ergebnis in derselben
/// Form wie beim Windows-Kennwort – damit Unlock.Allowed, AllowedGroups und AllowedUsers unverändert gelten.
/// </summary>
public static class WindowsLogonDialog
{
    public const string MethodId = "windowslogon";

    /// <summary>Nur unter Windows 10 und neuer (CredUIPromptForWindowsCredentials mit allen Anmeldeanbietern).</summary>
    public static bool IsAvailable(Version osVersion, bool credUiPresent) => credUiPresent && osVersion.Major >= 10;

    /// <param name="sessionSid">SID der Sitzung (für <see cref="AuthOutcome.IsSessionUser"/>).</param>
    /// <param name="ct">Abgebrochen (Zeitlimit der externen Anmeldung): Anmeldedaten verwerfen, nicht anmelden.</param>
    public static AuthOutcome Authenticate(IWindowsCredentialDialog dialog, nint owner, string caption, string message,
        string? sessionSid, CancellationToken ct = default)
    {
        IWindowsCredential? credential = null;
        try
        {
            int err = dialog.Prompt(owner, caption, message, out credential);
            if (err != 0 || credential is null)
                return WindowsLogonErrors.Fail(err == 0 ? WindowsLogonErrors.Cancelled : err);
            if (ct.IsCancellationRequested)
                return AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInCancelled), ErrorCodes.SignInCancelled);

            err = dialog.Logon(credential, out var account);
            if (err != 0 || account is null) return WindowsLogonErrors.Fail(err == 0 ? 1326 : err);
            return Outcome(account, sessionSid);
        }
        finally { credential?.Dispose(); }
    }

    /// <summary>Ergebnis wie beim Windows-Kennwort (WindowsPasswordProvider.Logon).</summary>
    public static AuthOutcome Outcome(WindowsAccountInfo account, string? sessionSid) => new()
    {
        Success = true,
        UserName = account.Name,
        DisplayName = account.Name.Contains('\\') ? account.Name[(account.Name.IndexOf('\\') + 1)..] : account.Name,
        UserId = account.Sid,
        Groups = account.Groups,
        IsAdministrator = account.IsAdministrator,
        IsSessionUser = account.Sid is not null && string.Equals(account.Sid, sessionSid, StringComparison.OrdinalIgnoreCase),
    };
}

/// <summary>Kontonamen in Entsperr-Regeln für die Windows-Namensauflösung vorbereiten.</summary>
public static class AccountNames
{
    /// <summary>
    /// „.\Gruppe“ (lokale Gruppe in der Schreibweise von net localgroup) → „RECHNER\Gruppe“: LookupAccountName kennt den
    /// Punkt nicht. Alles andere bleibt (Leerraum am Rand entfernt).
    /// </summary>
    public static string ForLookup(string name, string machineName)
    {
        var n = name.Trim();
        return n.StartsWith(@".\", StringComparison.Ordinal) && n.Length > 2 ? $"{machineName}\\{n[2..]}" : n;
    }
}
