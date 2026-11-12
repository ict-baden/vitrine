// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;
using Vitrine.Services.Supervisor;

namespace Vitrine.Services.Auth;

/// <summary>
/// Sicherheitsschlüssel (<c>fido</c>): FIDO2-Schlüssel, die für Vitrine registriert sind, über den Windows-Sicherheitsdialog
/// (webauthn.dll, USB und NFC, PIN Pflicht). Die App holt beim Dienst eine Einmal-Challenge, lässt Windows den Schlüssel
/// fragen und gibt die Antwort an den Dienst; der prüft sie (Vitrine.Core, <see cref="FidoService"/>) und nennt Person,
/// Gruppen und Administrator wie beim Windows-Kennwort. Ohne Dienst nicht verfügbar. Doku: docs/security-keys.md.
/// </summary>
public sealed class FidoProvider : IAuthProvider
{
    private readonly Func<AuditLink?> _link;
    private (DateTime At, bool Available) _cache;

    public FidoProvider(Func<AuditLink?> link) => _link = link;

    /// <summary>
    /// Signatur und Registrar nur, solange der Vitrine-Dialog dafür offen ist (LockController öffnet/schließt). Der
    /// Windows-Sicherheitsdialog zeigt den Zweck nicht.
    /// </summary>
    public FidoPurposeGate Gate { get; } = new();

    public string Id => FidoProtocol.MethodId;
    public string DisplayName => UI.Loc.T("Method_Fido");
    public string Glyph => ""; // USB
    public AuthInputKind Input => AuthInputKind.External;

    /// <summary>WebAuthn-API vorhanden, Dienst erreichbar, mindestens ein aktiver Schlüssel (kurz zwischengespeichert).</summary>
    public async Task<bool> IsAvailableAsync(CancellationToken ct)
    {
        if (DateTime.UtcNow - _cache.At < TimeSpan.FromSeconds(10)) return _cache.Available;
        bool available = false;
        if (WebAuthnApi.Available && _link() is { Connected: true } link)
        {
            var r = await link.FidoAsync(new JsonObject { ["op"] = "fido-status" }).ConfigureAwait(false);
            available = r?["ok"]?.GetValue<bool>() == true && r["active"]?.GetValue<int>() > 0;
        }
        _cache = (DateTime.UtcNow, available);
        return available;
    }

    public Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct) =>
        AuthenticateAsync(request, request.Purpose switch
        {
            AuthPurpose.Signature => FidoPurpose.Signature,
            AuthPurpose.Admin => FidoPurpose.Admin,
            _ => FidoPurpose.Unlock,
        }, ct);

    /// <summary>Anmelden für einen Zweck; bei Signatur und Registrar enthält das Ergebnis das Ticket des Dienstes.</summary>
    public async Task<AuthOutcome> AuthenticateAsync(AuthRequest request, FidoPurpose purpose, CancellationToken ct)
    {
        if (!WebAuthnApi.Available) return Fail(ErrorCodes.FidoUnavailable);
        if (_link() is not { Connected: true } link) return Fail(ErrorCodes.FidoServiceRequired);
        if (!Gate.Allows(purpose)) return Fail(ErrorCodes.FidoPurposeNotOpen);

        var c = await link.FidoAsync(new JsonObject { ["op"] = "fido-challenge", ["purpose"] = purpose.ToString().ToLowerInvariant() }).ConfigureAwait(false);
        if (c is null) return Fail(ErrorCodes.FidoServiceRequired);
        if (c["ok"]?.GetValue<bool>() != true)
        {
            var code = (string?)c["code"] ?? ErrorCodes.SignInFailed;
            return AuthOutcome.Fail((string?)c["error"] ?? CoreText.Error(code), code);
        }
        var challenge = (string)c["challenge"]!;
        var rpId = (string)c["rpId"]!;
        int timeout = c["timeoutMs"]?.GetValue<int>() ?? FidoProtocol.TimeoutMilliseconds;
        var allow = ((JsonArray?)c["allowCredentials"] ?? [])
            .Select(n => FidoProtocol.FromBase64Url((string?)n)).Where(b => b is not null).Select(b => b!).ToList();
        var clientData = FidoProtocol.ClientDataJson(FidoProtocol.TypeGet, challenge, rpId);

        // Viele Schlüssel: in Teilen fragen; „nicht gefunden“ heißt, der nächste Teil ist dran (jeder Teil braucht eine Berührung)
        WebAuthnResult<WebAuthnAssertion>? result = null;
        foreach (var chunk in FidoProtocol.Chunk(allow))
        {
            result = await Task.Run(() => WebAuthnApi.GetAssertion(request.OwnerWindow, rpId, clientData, chunk, timeout, ct), ct).ConfigureAwait(false);
            if (result.Ok || result.HResult != WebAuthnErrors.NotFound) break;
        }
        ct.ThrowIfCancellationRequested();

        // Ablage im AD: Der Schlüssel enthielt keinen der bekannten – vielleicht gerade auf einem anderen Rechner registriert.
        // Einmal mit Abgleich nachfragen und nur die neuen Kennungen anbieten (eine Berührung mehr).
        if (result is { Ok: false } && result.HResult == WebAuthnErrors.NotFound && c["refreshable"]?.GetValue<bool>() == true)
        {
            var again = await link.FidoAsync(new JsonObject
            {
                ["op"] = "fido-challenge", ["purpose"] = purpose.ToString().ToLowerInvariant(), ["refresh"] = "true",
            }).ConfigureAwait(false);
            if (again?["ok"]?.GetValue<bool>() == true)
            {
                var known = allow.Select(Convert.ToBase64String).ToHashSet(StringComparer.Ordinal);
                var added = ((JsonArray?)again["allowCredentials"] ?? [])
                    .Select(n => FidoProtocol.FromBase64Url((string?)n)).Where(b => b is not null && !known.Contains(Convert.ToBase64String(b))).Select(b => b!).ToList();
                if (added.Count > 0)
                {
                    challenge = (string)again["challenge"]!;
                    clientData = FidoProtocol.ClientDataJson(FidoProtocol.TypeGet, challenge, rpId);
                    foreach (var chunk in FidoProtocol.Chunk(added))
                    {
                        result = await Task.Run(() => WebAuthnApi.GetAssertion(request.OwnerWindow, rpId, clientData, chunk, timeout, ct), ct).ConfigureAwait(false);
                        if (result.Ok || result.HResult != WebAuthnErrors.NotFound) break;
                    }
                    ct.ThrowIfCancellationRequested();
                }
            }
        }

        if (result is not { Ok: true, Value: { } a })
        {
            var hr = result?.HResult ?? WebAuthnErrors.NotFound;
            var code = WebAuthnErrors.CodeFor(hr);
            return code == ErrorCodes.FidoWebAuthnError
                ? AuthOutcome.Fail(CoreText.Error(code, result?.ErrorName ?? $"0x{hr:X8}"), code)
                : Fail(code);
        }

        var assertion = new FidoAssertion(challenge, FidoProtocol.ToBase64Url(a.CredentialId), FidoProtocol.ToBase64Url(a.AuthenticatorData),
            FidoProtocol.ToBase64Url(clientData), FidoProtocol.ToBase64Url(a.Signature));
        return purpose switch
        {
            FidoPurpose.Signature => await link.VerifyFidoAsync(assertion, null).ConfigureAwait(false),
            FidoPurpose.Registrar => await link.VerifyFidoAsync(assertion, AuditBroker.PurposeRegistrar).ConfigureAwait(false),
            _ => await link.FidoAssertAsync(assertion, admin: purpose == FidoPurpose.Admin).ConfigureAwait(false),
        };
    }

    private static AuthOutcome Fail(string code) => AuthOutcome.Fail(CoreText.Error(code), code);
}
