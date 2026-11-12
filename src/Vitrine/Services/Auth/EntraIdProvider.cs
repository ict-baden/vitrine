// SPDX-License-Identifier: MIT
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
#if WAM_BROKER
using Microsoft.Identity.Client.Broker;
#endif
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Services.Auth;

/// <summary>
/// Anmeldung mit Microsoft Entra ID über MSAL. Standard seit 2026-10-27 (<see cref="EntraSignInPath.Embedded"/>): eigenes
/// Anmeldefenster mit WebView2 (<see cref="EmbeddedWebUi"/>, <see cref="UI.SignInWindow"/>), Umleitung auf
/// http://localhost, Profil nur für den einen Versuch – nichts wird gemerkt, keine Anmeldung über das Konto der
/// Windows-Sitzung, jedes Konto wählbar, Sicherheitsschlüssel (FIDO2) und Passkeys über den Windows-Sicherheitsdialog;
/// auch am Sperrbildschirm. Nur mit <c>Entra.UseBroker = true</c> (und einem Build mit Broker) über den
/// Windows-Kontobroker (WAM, msalruntime.dll aus NativeInterop 0.20.4 unter MIT): Windows Hello for Business und
/// gerätebasierter bedingter Zugriff, aber WAM merkt sich Konten und meldet mit dem Sitzungskonto an (VIT-0191).
/// Fehlt die WebView2-Laufzeit, gibt es ohne Broker keine Microsoft-Anmeldung (VIT-0190) – bewusst kein Rückfall auf
/// den System-Browser, der sich Konten merkt.
/// Welche Verfahren gelten, legt der Mandant fest, nicht Vitrine (docs/entra-id.md). Die Prüfung der Claims (Mandant,
/// Alter, Rollen) steht in <see cref="EntraClaims"/>, die Wahl des Wegs in <see cref="EntraSignInMode"/> (Vitrine.Core).
/// </summary>
public sealed class EntraIdProvider : IAuthProvider
{
    private readonly SessionInfo _session;
    private readonly Func<EntraSettings> _settings;

    public EntraIdProvider(SessionInfo session, Func<EntraSettings> settings)
    {
        _session = session;
        _settings = settings;
    }

    public string Id => "entra";
    public string DisplayName => "Microsoft Entra ID";
    public string Glyph => ""; // Contact
    public AuthInputKind Input => AuthInputKind.External;

    /// <summary>Enthält dieser Build den Windows-Kontobroker (Standard; nicht mit <c>-p:WamBroker=false</c>)?</summary>
    public static bool BrokerIncluded =>
#if WAM_BROKER
        true;
#else
        false;
#endif

    /// <summary>Weg der Anmeldung mit diesen Einstellungen (Broker, eigenes Fenster oder keiner).</summary>
    public static EntraSignInPath PathFor(EntraSettings s) =>
        EntraSignInMode.Choose(BrokerIncluded, s.UseBroker, WebViewRuntime.IsAvailable);

    /// <summary>Wird mit diesen Einstellungen über den Broker angemeldet?</summary>
    public static bool UsesBroker(EntraSettings s) => BrokerIncluded && s.UseBroker;

    /// <summary>Kann Microsoft mit diesen Einstellungen am Sperrbildschirm angeboten werden?</summary>
    public static bool OnLockScreen(EntraSettings s) => EntraSignInMode.OnLockScreen(PathFor(s));

    /// <summary>Hinweise für Einstellungen und Protokoll (VIT-0190, VIT-0191).</summary>
    public static List<UnlockSetupWarning> Warnings(EntraSettings s) =>
        EntraSignInMode.Warnings(s, BrokerIncluded, WebViewRuntime.IsAvailable);

    /// <summary>Umleitungs-URI für die App-Registrierung, passend zum Weg.</summary>
    public static string RedirectUri(EntraSettings s, string? clientId) => EntraSignInMode.RedirectUri(PathFor(s), clientId);

    /// <summary>Kann am Sperrbildschirm angeboten werden? Mit Broker und mit dem eigenen Fenster (ClientId gesetzt).</summary>
    public bool CanUnlock => !string.IsNullOrWhiteSpace(_settings().ClientId) && OnLockScreen(_settings());

    public Task<bool> IsAvailableAsync(CancellationToken ct)
        => Task.FromResult(!string.IsNullOrWhiteSpace(_settings().ClientId));

    public Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct) => AuthenticateAsync(request, ct, nonce: null);

    /// <param name="nonce">
    /// Einmal-Wert des Dienstes für eine Signatur (#15): geht als OpenID-Connect-<c>nonce</c> an Microsoft und kommt im
    /// ID-Token zurück; der Dienst erkennt daran, dass das Token für genau diese Anfrage ausgestellt wurde.
    /// </param>
    public async Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct, string? nonce)
    {
        var s = _settings();
        if (string.IsNullOrWhiteSpace(s.ClientId))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.EntraNotConfigured), ErrorCodes.EntraNotConfigured);
        // Ohne festgelegten Mandanten nähme Vitrine jedes Konto jeder Organisation an – gar nicht erst anmelden
        if (!EntraClaims.TenantPinned(s))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.EntraTenantNotPinned), ErrorCodes.EntraTenantNotPinned);
        // Tippfehler im Authentifizierungskontext: nicht ohne die verlangte Stärke anmelden, sondern ablehnen
        if (EntraClaims.InvalidAuthContext(s, request.Purpose == AuthPurpose.Signature) is { } invalid)
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.AuthContextInvalid, invalid), ErrorCodes.AuthContextInvalid);

        // Ohne Broker nur mit WebView2: kein Rückfall auf den System-Browser (merkt sich Konten, keine Eingaben unter der Sperre)
        var path = PathFor(s);
        if (path == EntraSignInPath.Unavailable)
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.WebViewRuntimeMissing), ErrorCodes.WebViewRuntimeMissing);

        var builder = PublicClientApplicationBuilder.Create(s.ClientId.Trim())
            .WithAuthority(AzureCloudInstance.AzurePublic, s.TenantId.Trim())
            .WithParentActivityOrWindow(() => request.OwnerWindow);

#if WAM_BROKER
        if (path == EntraSignInPath.Broker)
            builder = builder.WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows) { Title = "Vitrine" });
#endif
        builder = builder.WithRedirectUri(EntraSignInMode.RedirectUri(path, s.ClientId));

        var app = builder.Build();

        // Entsperren und Administrator-Bestätigung ohne Vorschlag: jede berechtigte Person, jedes Konto (EntraSignInMode)
        var loginHint = EntraSignInMode.LoginHint(path, request.Purpose, request.UserName, _session.Upn);

        // Zugriffstoken für eine Fachanwendung (freigegeben und geprüft in PipeServer/LockController), sonst nur Anmeldung
        var scopes = request.Scopes.Count > 0 ? request.Scopes.ToArray() : ["User.Read"];
        var context = EntraClaims.AuthContextFor(s, request.Purpose == AuthPurpose.Signature);

        // Entsperren und Administrator-Bestätigung: Das ID-Token muss eine Anmeldung nach diesem Zeitpunkt belegen (auth_time),
        // sonst entsperrte der Broker mit dem Primary Refresh Token des angemeldeten Kontos ohne jede Eingabe (0.3.0)
        DateTimeOffset? freshAfter = request.Purpose is AuthPurpose.Unlock or AuthPurpose.Admin ? DateTimeOffset.UtcNow : null;

        AuthenticationResult result;
        try
        {
            var call = app.AcquireTokenInteractive(scopes)
                .WithPrompt(EntraSignInMode.ForceLogin(path, s.ForceFreshSignIn) ? Prompt.ForceLogin : Prompt.SelectAccount)
                .WithParentActivityOrWindow(request.OwnerWindow);
            // Eigenes Fenster statt Broker bzw. System-Browser: Profil nur für diesen Versuch, danach gelöscht
            if (path == EntraSignInPath.Embedded) call = call.WithCustomWebUi(new EmbeddedWebUi(request.OwnerWindow, s.AllowedSignInHosts));
            if (!string.IsNullOrEmpty(loginHint)) call = call.WithLoginHint(loginHint);
            var extra = new Dictionary<string, (string, bool)>();
            if (!string.IsNullOrEmpty(nonce)) extra["nonce"] = (nonce, false);
            // OIDC max_age=0: erneute Anmeldung verlangen, wo der Weg es beachtet (geprüft wird ohnehin auth_time)
            if (freshAfter is not null) extra["max_age"] = ("0", false);
            if (extra.Count > 0) call = call.WithExtraQueryParameters(extra);
            // Authentifizierungskontext: Entra verlangt dann, was der bedingte Zugriff dafür vorschreibt (z. B. Passkey)
            if (context is not null) call = call.WithClaims(EntraClaims.AuthContextClaims(context));
            result = await call.ExecuteAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when ((ex as UI.SignInHostBlockedException ?? ex.InnerException as UI.SignInHostBlockedException) is { } blocked)
        {
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInHostBlocked, blocked.Host), ErrorCodes.SignInHostBlocked);
        }
        catch (Exception ex) when (ex is UI.SignInWindowException || ex.InnerException is UI.SignInWindowException)
        {
            var reason = (ex as UI.SignInWindowException ?? (UI.SignInWindowException)ex.InnerException!).Message;
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInWindowFailed, reason), ErrorCodes.SignInWindowFailed);
        }
        catch (MsalClientException ex) when (ex.ErrorCode == MsalError.AuthenticationCanceledError)
        {
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInCancelled), ErrorCodes.SignInCancelled);
        }
        catch (MsalException ex)
        {
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.EntraError, ex.Message), ErrorCodes.EntraError);
        }
        catch (OperationCanceledException)
        {
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInCancelled), ErrorCodes.SignInCancelled);
        }
        finally
        {
            // Nichts im Speicher halten – jede Entsperrung ist eine eigene Anmeldung.
            try
            {
                foreach (var acc in await app.GetAccountsAsync().ConfigureAwait(false))
                    try { await app.RemoveAsync(acc).ConfigureAwait(false); } catch { }
            }
            catch { }
        }

        var claims = result.ClaimsPrincipal?.Claims.Select(c => new KeyValuePair<string, string>(c.Type, c.Value)).ToList() ?? [];
        var outcome = EntraClaims.Evaluate(new EntraSignIn(claims, result.TenantId, result.UniqueId, result.Account?.Username),
            s, _session.Sid, DateTimeOffset.UtcNow, context, freshAfter);
        if (!outcome.Success) return outcome;

        var tokens = new Dictionary<string, string>();
        if (s.ShareIdToken && !string.IsNullOrEmpty(result.IdToken)) tokens["id_token"] = result.IdToken;
        // Signatur: Der Dienst prüft das Token selbst (#15); intern, geht nicht an die Anwendung
        if (request.Purpose == AuthPurpose.Signature && !string.IsNullOrEmpty(result.IdToken)) tokens[AuthResults.ProofIdToken] = result.IdToken;
        if (request.Scopes.Count > 0)
        {
            tokens["access_token"] = result.AccessToken;
            tokens["expires_on"] = result.ExpiresOn.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            tokens["scopes"] = string.Join(' ', result.Scopes);
        }
        return tokens.Count == 0 ? outcome : outcome.WithTokens(tokens);
    }
}
