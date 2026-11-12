// SPDX-License-Identifier: MIT
using System.Security.Cryptography;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Fido;

/// <summary>Ergebnis der Prüfung einer Anmeldung (Assertion) mit einem Schlüssel.</summary>
/// <param name="Code">Fehlercode bei Ablehnung.</param>
/// <param name="Problem">Grund (englisch, fürs Protokoll).</param>
/// <param name="SignCount">Neuer Zähler (bei Erfolg).</param>
/// <param name="CloneSuspected">Zähler nicht gestiegen: möglicherweise ein kopierter Schlüssel.</param>
/// <param name="SignatureValid">
/// Die Signatur des registrierten Schlüssels passt. Nur dann kann die Antwort vom Schlüssel stammen; Fehler davor kann
/// jeder erzeugen und zählen deshalb nie gegen Schlüssel oder Person (sonst könnte man fremde Personen aussperren).
/// </param>
public sealed record FidoCheck(bool Valid, string? Code, string? Problem, uint SignCount, bool CloneSuspected = false, bool SignatureValid = false)
{
    public static FidoCheck Fail(string code, string problem, bool clone = false, bool signatureValid = false) =>
        new(false, code, problem, 0, clone, signatureValid);
}

/// <summary>
/// Prüft eine Assertion gegen einen registrierten Schlüssel (WebAuthn Level 2, Abschnitt 7.2) – ohne Windows, ohne
/// Netzwerk. Zuerst die Signatur über authData ‖ SHA-256(clientDataJSON) (seit der Prüfung vom 2026-10-30: alles, was
/// vorher scheitert, kann ein beliebiges Programm erzeugen), dann clientDataJSON (Typ, Challenge, Origin), SHA-256 der
/// RP ID, Flags (Anwesenheit und Benutzerüberprüfung Pflicht) und der Zähler.
/// </summary>
public static class FidoVerifier
{
    public static FidoCheck VerifyAssertion(FidoCredential credential, string expectedChallenge, string rpId,
        byte[] authenticatorData, byte[] clientDataJson, byte[] signature)
    {
        if (!string.Equals(credential.RpId, rpId, StringComparison.Ordinal))
            return FidoCheck.Fail(ErrorCodes.FidoKeyUnknown, $"key registered for RP ID '{credential.RpId}', expected '{rpId}'");

        CoseKey key;
        try { key = CoseKey.Parse(FidoProtocol.FromBase64Url(credential.PublicKey) ?? throw new FormatException("public key missing")); }
        catch (Exception ex) when (ex is FormatException or NotSupportedException)
        {
            return FidoCheck.Fail(ErrorCodes.FidoAssertionInvalid, "stored public key unusable: " + ex.Message);
        }
        var signed = authenticatorData.Concat(SHA256.HashData(clientDataJson)).ToArray();
        if (!key.Verify(signed, signature)) return FidoCheck.Fail(ErrorCodes.FidoAssertionInvalid, "signature invalid");

        // Ab hier stammt die Antwort nachweislich vom registrierten Schlüssel
        ClientData client;
        try { client = ClientData.Parse(clientDataJson); }
        catch (FormatException ex) { return FidoCheck.Fail(ErrorCodes.FidoAssertionInvalid, ex.Message, signatureValid: true); }
        if (client.Problem(FidoProtocol.TypeGet, expectedChallenge, rpId) is { } problem)
            return FidoCheck.Fail(ErrorCodes.FidoAssertionInvalid, problem, signatureValid: true);

        AuthenticatorData auth;
        try { auth = AuthenticatorData.Parse(authenticatorData); }
        catch (FormatException ex) { return FidoCheck.Fail(ErrorCodes.FidoAssertionInvalid, ex.Message, signatureValid: true); }
        if (!CryptographicOperations.FixedTimeEquals(auth.RpIdHash, FidoProtocol.RpIdHash(rpId)))
            return FidoCheck.Fail(ErrorCodes.FidoAssertionInvalid, "rpIdHash does not match", signatureValid: true);
        if (!auth.UserPresent) return FidoCheck.Fail(ErrorCodes.FidoUserVerificationMissing, "user presence flag missing", signatureValid: true);
        if (!auth.UserVerified) return FidoCheck.Fail(ErrorCodes.FidoUserVerificationMissing, "user verification flag missing (no PIN)", signatureValid: true);

        // Zähler: Schlüssel ohne Zähler melden immer 0 (dann nichts zu prüfen); sonst muss er steigen
        if ((auth.SignCount != 0 || credential.SignCount != 0) && auth.SignCount <= credential.SignCount)
            return FidoCheck.Fail(ErrorCodes.FidoCloneSuspected, $"signature counter {auth.SignCount} not above stored {credential.SignCount}", clone: true, signatureValid: true);
        return new FidoCheck(true, null, null, auth.SignCount, SignatureValid: true);
    }
}

/// <summary>Ergebnis der Prüfung einer Registrierung.</summary>
public sealed record FidoRegistrationCheck(bool Valid, string? Code, string? Problem, AttestationObject? Attestation, CoseKey? Key,
    AttestationResult? AttestationResult)
{
    public static FidoRegistrationCheck Fail(string code, string problem) => new(false, code, problem, null, null, null);
}

/// <summary>Prüft die Antwort des Schlüssels auf eine Registrierung (WebAuthn Level 2, Abschnitt 7.1).</summary>
public static class FidoRegistrationVerifier
{
    public static FidoRegistrationCheck Verify(string expectedChallenge, string rpId, byte[] clientDataJson, byte[] attestationObject)
    {
        ClientData client;
        try { client = ClientData.Parse(clientDataJson); }
        catch (FormatException ex) { return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, ex.Message); }
        if (client.Problem(FidoProtocol.TypeCreate, expectedChallenge, rpId) is { } problem)
            return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, problem);

        AttestationObject att;
        try { att = AttestationObject.Parse(attestationObject); }
        catch (FormatException ex) { return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, ex.Message); }
        var auth = att.AuthData;
        if (!CryptographicOperations.FixedTimeEquals(auth.RpIdHash, FidoProtocol.RpIdHash(rpId)))
            return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, "rpIdHash does not match");
        if (!auth.UserPresent || !auth.UserVerified)
            return FidoRegistrationCheck.Fail(ErrorCodes.FidoUserVerificationMissing, "user presence or verification flag missing");
        if (auth.Credential is not { } credential)
            return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, "no attested credential data");

        CoseKey key;
        try { key = CoseKey.Parse(credential.PublicKey); }
        catch (NotSupportedException ex) { return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, "unsupported key: " + ex.Message); }
        catch (FormatException ex) { return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, ex.Message); }

        var result = AttestationCheck.Evaluate(att, SHA256.HashData(clientDataJson), key);
        // Eine „packed“-Attestierung, deren Signatur nicht passt, ist kein Hinweis auf ein Modell, sondern auf Manipulation
        if (att.Format == "packed" && !result.Verified)
            return FidoRegistrationCheck.Fail(ErrorCodes.FidoRegistrationInvalid, result.Problem ?? "attestation invalid");
        return new FidoRegistrationCheck(true, null, null, att, key, result);
    }
}
