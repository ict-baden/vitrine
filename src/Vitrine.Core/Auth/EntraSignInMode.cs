// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>Weg, auf dem Vitrine mit Microsoft Entra ID anmeldet.</summary>
public enum EntraSignInPath
{
    /// <summary>
    /// Standard seit 2026-10-27: eigenes Anmeldefenster von Vitrine mit WebView2 und einem Profil, das nur für diesen
    /// Versuch existiert (privater Modus, Ordner danach gelöscht). Nichts wird gemerkt, keine Anmeldung über das Konto
    /// der Sitzung, jedes Konto wählbar, Sicherheitsschlüssel (FIDO2) und Passkeys über den Windows-Sicherheitsdialog.
    /// </summary>
    Embedded,
    /// <summary>
    /// Windows-Kontobroker (WAM), nur mit <c>Entra.UseBroker = true</c> in einem Build mit Broker. Merkt sich Konten und
    /// meldet mit dem Konto der Windows-Sitzung an (SSO) – nur für Geräte mit einem persönlichen Benutzer.
    /// </summary>
    Broker,
    /// <summary>Kein Weg: kein Broker gewählt und die WebView2-Laufzeit fehlt (VIT-0190).</summary>
    Unavailable,
}

/// <summary>
/// Entscheidungen rund um die Microsoft-Anmeldung, die nicht von MSAL oder WebView2 abhängen: welcher Weg, welche
/// Umleitungs-URI, ob ein Konto vorgeschlagen wird (login_hint), ob eine neue Anmeldung erzwungen wird, und welche
/// Hinweise Einstellungen und Protokoll zeigen. Die App (EntraIdProvider) setzt sie nur um.
/// Vorgeschichte (Gerätetest 2026-10-26): Mit WAM entsperrte ein Klick über das Primary Refresh Token des technischen
/// Kontos, das Broker-Fenster bekam gesperrt keine Eingaben, der login_hint des Sitzungskontos verhinderte die Wahl
/// eines anderen Kontos, und WAM merkte sich jedes Konto, das sich einmal angemeldet hatte.
/// </summary>
public static class EntraSignInMode
{
    /// <summary>Umleitungs-URI ohne Broker (App-Registrierung: „Mobile und Desktop“).</summary>
    public const string LoopbackRedirectUri = "http://localhost";

    /// <param name="brokerIncluded">Build mit Windows-Kontobroker (nicht <c>-p:WamBroker=false</c>).</param>
    /// <param name="useBroker"><c>Entra.UseBroker</c>.</param>
    /// <param name="webViewAvailable">Microsoft Edge WebView2 Runtime installiert.</param>
    public static EntraSignInPath Choose(bool brokerIncluded, bool useBroker, bool webViewAvailable) =>
        brokerIncluded && useBroker ? EntraSignInPath.Broker
        : webViewAvailable ? EntraSignInPath.Embedded
        : EntraSignInPath.Unavailable;

    /// <summary>
    /// Kann Microsoft am Sperrbildschirm angeboten werden? Mit beiden Wegen: Das eigene Fenster ist ein Fenster von
    /// Vitrine und wird während der Sperre ausdrücklich freigegeben (kein voller Browser über der Sperre).
    /// </summary>
    public static bool OnLockScreen(EntraSignInPath path) => path != EntraSignInPath.Unavailable;

    /// <summary>Umleitungs-URI, die in der App-Registrierung stehen muss.</summary>
    public static string RedirectUri(EntraSignInPath path, string? clientId) =>
        path == EntraSignInPath.Broker ? $"ms-appx-web://microsoft.aad.brokerplugin/{clientId?.Trim()}" : LoopbackRedirectUri;

    /// <summary>
    /// Vorgeschlagenes Konto (login_hint). Entsperren und Administrator-Bestätigung nie: Entsperren darf jede berechtigte
    /// Person, und auf gemeinsam genutzten Geräten ist das Sitzungskonto oft ein technisches Konto. Signaturen nur mit
    /// dem Broker (persönliches Gerät): Die Schnittstelle nennt keine Person, die unterschreiben soll, also wäre im
    /// eigenen Fenster jeder Vorschlag nur das Sitzungskonto – auf gemeinsam genutzten Geräten das falsche.
    /// </summary>
    /// <param name="requestedUser">Name aus dem Dialog (bei externen Verfahren der vorbelegte Name).</param>
    public static string? LoginHint(EntraSignInPath path, AuthPurpose purpose, string? requestedUser, string? sessionUpn)
    {
        if (purpose != AuthPurpose.Signature || path != EntraSignInPath.Broker) return null;
        var hint = requestedUser?.Contains('@') == true ? requestedUser : sessionUpn;
        return string.IsNullOrWhiteSpace(hint) ? null : hint.Trim();
    }

    /// <summary>
    /// prompt=login erzwingen? Im eigenen Fenster immer: Ohne Cookies gibt es nichts auszuwählen, und Entra soll
    /// ausdrücklich nach Anmeldedaten fragen. Mit Broker wie eingestellt (<c>Entra.ForceFreshSignIn</c>, sonst Kontoauswahl).
    /// </summary>
    public static bool ForceLogin(EntraSignInPath path, bool forceFreshSignIn) => path != EntraSignInPath.Broker || forceFreshSignIn;

    /// <summary>
    /// Hinweise zu Microsoft für Einstellungen und Protokoll (je einmal pro Start): VIT-0191, wenn der Broker eingeschaltet
    /// ist (merkt sich Konten, SSO mit dem Sitzungskonto), VIT-0190, wenn Microsoft eingerichtet ist, aber die
    /// WebView2-Laufzeit fehlt.
    /// </summary>
    public static List<UnlockSetupWarning> Warnings(EntraSettings s, bool brokerIncluded, bool webViewAvailable)
    {
        var warnings = new List<UnlockSetupWarning>();
        if (string.IsNullOrWhiteSpace(s.ClientId)) return warnings;
        switch (Choose(brokerIncluded, s.UseBroker, webViewAvailable))
        {
            case EntraSignInPath.Broker:
                warnings.Add(new(ErrorCodes.EntraBrokerRemembersAccounts, "Entra.UseBroker", ""));
                break;
            case EntraSignInPath.Unavailable:
                warnings.Add(new(ErrorCodes.WebViewRuntimeMissing, "Entra.ClientId", ""));
                break;
        }
        return warnings;
    }
}
