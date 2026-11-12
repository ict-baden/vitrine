// SPDX-License-Identifier: MIT
using System.Windows;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Web.WebView2.Core;
using Vitrine.Core.About;
using Vitrine.Core.Auth;
using Vitrine.UI;

namespace Vitrine.Services.Auth;

/// <summary>
/// MSAL-Oberfläche für den Weg <see cref="EntraSignInPath.Embedded"/>: öffnet <see cref="SignInWindow"/> auf dem
/// UI-Thread und gibt MSAL die Umleitung mit dem Code zurück. Nutzer bricht ab → MsalClientException
/// authentication_canceled (VIT-0111 im EntraIdProvider), Zeitlimit → OperationCanceledException.
/// </summary>
internal sealed class EmbeddedWebUi(nint owner, IReadOnlyList<string> allowedHosts) : ICustomWebUi
{
    public async Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        var dispatcher = Application.Current?.Dispatcher ?? throw new SignInWindowException("no UI thread");
        // Reste früherer Versuche (Absturz, gesperrte Dateien) zuerst weg
        EphemeralProfiles.CleanUp(AppPaths.WebViewProfilesDir, DateTime.UtcNow, EphemeralProfiles.StaleAfter);
        var folder = EphemeralProfiles.NewFolder(AppPaths.WebViewProfilesDir);

        var window = await dispatcher.InvokeAsync(() =>
        {
            var w = new SignInWindow(authorizationUri, redirectUri, folder, owner, allowedHosts);
            w.Show();
            w.Activate();
            return w;
        });
        using var registration = cancellationToken.Register(() => dispatcher.BeginInvoke(window.Cancel));
        try
        {
            return await window.Result.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new MsalClientException(MsalError.AuthenticationCanceledError, "The sign-in window was closed.");
        }
    }
}

/// <summary>Ist die Microsoft Edge WebView2 Runtime installiert? (Windows 11: immer; Windows 10 LTSC oft nicht.)</summary>
internal static class WebViewRuntime
{
    private static volatile bool _found;

    /// <summary>
    /// Positiv zwischengespeichert, negativ jedes Mal neu geprüft (die Laufzeit kann nachträglich installiert werden).
    /// Wirft nie: Fehlt die Laufzeit oder WebView2Loader.dll, ist die Antwort false.
    /// </summary>
    public static bool IsAvailable
    {
        get
        {
            if (_found) return true;
            try { _found = !string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString()); }
            catch (Exception ex) when (ex is WebView2RuntimeNotFoundException or DllNotFoundException or BadImageFormatException
                                           or System.Runtime.InteropServices.COMException or EntryPointNotFoundException) { _found = false; }
            return _found;
        }
    }
}
