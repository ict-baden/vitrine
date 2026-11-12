// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Localization;
using Windows.Security.Credentials.UI;

namespace Vitrine.Services.Auth;

/// <summary>
/// Windows Hello (Gesicht, Fingerabdruck, PIN) – bestätigt, dass der angemeldete Sitzungsbenutzer selbst vor dem Gerät
/// sitzt. Kann nur den Sitzungsbenutzer anmelden, keine anderen Personen. Braucht die WinRT-API UserConsentVerifier,
/// deshalb zielt die App auf net10.0-windows10.0.19041.0 (richtlinien/02, Ausnahme).
/// </summary>
public sealed class WindowsHelloProvider : IAuthProvider
{
    private readonly SessionInfo _session;

    public WindowsHelloProvider(SessionInfo session) => _session = session;

    public string Id => "hello";
    public string DisplayName => "Windows Hello";
    public string Glyph => ""; // Face
    public AuthInputKind Input => AuthInputKind.External;

    public async Task<bool> IsAvailableAsync(CancellationToken ct)
    {
        try
        {
            return await UserConsentVerifier.CheckAvailabilityAsync().AsTask(ct)
                   == UserConsentVerifierAvailability.Available;
        }
        catch { return false; }
    }

    public async Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        UserConsentVerificationResult result;
        // Zeitlimit: Der Hello-Dialog schließt beim Abbruch der WinRT-Operation nicht zuverlässig – selbst schließen und den
        // Entsperr-Dialog wieder freigeben (wie beim Windows-Anmeldedialog)
        var before = AuthDialogCloser.Snapshot();
        var owner = request.OwnerWindow;
        using var reg = ct.Register(() => AuthDialogCloser.Close(owner, before));
        try
        {
            result = await UserConsentVerifierInterop
                .RequestVerificationForWindowAsync(request.OwnerWindow, $"Vitrine – {request.Reason}")
                .AsTask(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; } // Zeitlimit: wie bisher VIT-0111
        catch (Exception ex)
        {
            return AuthOutcome.Fail(ErrorCodes.WithCode($"{CoreText.T("Error_VIT0120")} {ex.Message}", ErrorCodes.HelloUnavailable),
                ErrorCodes.HelloUnavailable);
        }

        if (result != UserConsentVerificationResult.Verified)
        {
            var code = result switch
            {
                UserConsentVerificationResult.Canceled => ErrorCodes.SignInCancelled,
                UserConsentVerificationResult.RetriesExhausted => ErrorCodes.HelloRetriesExhausted,
                UserConsentVerificationResult.DeviceBusy => ErrorCodes.HelloBusy,
                UserConsentVerificationResult.DisabledByPolicy => ErrorCodes.HelloDisabledByPolicy,
                UserConsentVerificationResult.NotConfiguredForUser => ErrorCodes.HelloNotConfigured,
                _ => ErrorCodes.HelloUnavailable,
            };
            return AuthOutcome.Fail(CoreText.Error(code), code);
        }

        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        var groups = WindowsAccounts.GetGroupSids(id);
        return new AuthOutcome
        {
            Success = true,
            UserName = _session.UserName,
            DisplayName = _session.DisplayName,
            UserId = _session.Sid,
            Groups = groups,
            IsAdministrator = groups.Contains(WindowsAccounts.AdministratorsSid),
            IsSessionUser = true,
        };
    }
}
