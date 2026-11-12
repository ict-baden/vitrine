// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Services.Lock;
using Vitrine.Services.Supervisor;

namespace Vitrine.Services.Auth;

/// <summary>Eintrag der Schlüsselliste für die Einstellungen (vom Dienst, ohne öffentlichen Schlüssel).</summary>
public sealed record FidoKeyInfo(string KeyId, string Label, string Person, string? Upn, string Aaguid, string Status, DateTimeOffset? RegisteredAt,
    string RegisteredBy, DateTimeOffset? LastUsedAt, DateTimeOffset? RevokedAt, string? RevokedBy, string? RevokeReason, string RpId)
{
    public bool IsActive => Status == nameof(FidoCredentialStatus.Active);
}

/// <summary>Stand der Schlüssel-Ablage vom Dienst.</summary>
/// <param name="Store">„Local“ oder „ActiveDirectory“.</param>
/// <param name="LastSync">Letzter Abgleich mit dem AD (UTC).</param>
/// <param name="SyncError">Fehler des letzten Abgleichs (Code und englischer Text).</param>
public sealed record FidoAdminStatus(string RpId, int Active, int OtherRpId, string? StoreError, string Store, DateTimeOffset? LastSync,
    string? SyncError, string? Location)
{
    public bool IsDirectory => Store == nameof(FidoStoreKind.ActiveDirectory);
}

/// <summary>Benutzer und Kennwort für das Schreiben ins AD (nur für diesen Vorgang, nie gespeichert).</summary>
public sealed record FidoDirectoryLogin(string User, string Password);

/// <summary>
/// Sicherheitsschlüssel verwalten (Einstellungen): Liste und Stand vom Dienst, Registrieren und Widerrufen. Vorher meldet
/// sich die registrierende Person an (<see cref="LockController.RequireRegistrarAsync"/>, vom Dienst geprüft); Rolle,
/// eigenes Konto, Höchstzahl, Modell und Begründung prüft der Dienst.
/// </summary>
public sealed class FidoAdministration(LockController lockController)
{
    private AuditLink? Link => lockController.AuditLink is { Connected: true } l ? l : null;

    public bool ServiceAvailable => Link is not null;

    /// <summary>Stand: RP ID, Zahl aktiver Schlüssel, Schlüssel einer anderen RP ID, Fehler und Art der Ablage; null ohne Dienst.</summary>
    public async Task<FidoAdminStatus?> StatusAsync()
    {
        if (Link is not { } link) return null;
        var r = await link.FidoAsync(new JsonObject { ["op"] = "fido-status" });
        if (r?["ok"]?.GetValue<bool>() != true) return null;
        return new FidoAdminStatus((string?)r["rpId"] ?? "", r["active"]?.GetValue<int>() ?? 0, r["otherRpId"]?.GetValue<int>() ?? 0,
            (string?)r["storeError"], (string?)r["store"] ?? nameof(FidoStoreKind.Local), Time(r["lastSync"]), (string?)r["syncError"],
            (string?)r["location"]);
    }

    private static DateTimeOffset? Time(JsonNode? n) => DateTimeOffset.TryParse((string?)n, System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t : null;

    /// <summary>
    /// Ablage im AD: Benutzer und Kennwort der registrierenden Person in die Anfrage, wenn der Dienst kein Token ihrer
    /// Kennwort-Anmeldung hat. null = abgebrochen (dann nichts senden).
    /// </summary>
    private static bool AddDirectoryLogin(JsonObject request, AuthOutcome who, FidoAdminStatus? status, Func<string, FidoDirectoryLogin?>? ask)
    {
        if (status is not { IsDirectory: true } || who.Details.GetValueOrDefault("directoryCredential") == "token") return true;
        if (ask?.Invoke(who.UserName ?? "") is not { } login) return false;
        request["directoryUser"] = login.User;
        request["directoryPassword"] = login.Password;
        return true;
    }

    public async Task<(List<FidoKeyInfo>? Keys, string? Error)> ListAsync()
    {
        if (Link is not { } link) return (null, CoreText.Error(ErrorCodes.FidoServiceRequired));
        var r = await link.FidoAsync(new JsonObject { ["op"] = "fido-list" });
        if (r is null) return (null, CoreText.Error(ErrorCodes.FidoServiceRequired));
        if (r["ok"]?.GetValue<bool>() != true) return (null, (string?)r["error"]);
        var list = ((JsonArray?)r["keys"] ?? []).OfType<JsonObject>().Select(k => new FidoKeyInfo(
            (string?)k["keyId"] ?? "", (string?)k["label"] ?? "", (string?)k["person"] ?? "", (string?)k["upn"], (string?)k["aaguid"] ?? "",
            (string?)k["status"] ?? "", Time(k["registeredAt"]), (string?)k["registeredBy"] ?? "", Time(k["lastUsedAt"]), Time(k["revokedAt"]),
            (string?)k["revokedBy"], (string?)k["revokeReason"], (string?)k["rpId"] ?? "")).ToList();
        return (list, null);
    }

    /// <summary>Registrieren: Anmeldung der registrierenden Person, dann Windows-Sicherheitsdialog. Ergebnis: Fehlermeldung oder null.</summary>
    /// <param name="owner">Fenster, über dem der Windows-Sicherheitsdialog erscheint.</param>
    /// <param name="askDirectoryLogin">Ablage im AD: fragt Benutzer (vorbelegt) und Kennwort der registrierenden Person.</param>
    public async Task<string?> RegisterAsync(nint owner, string account, string label, string reason, Func<string, FidoDirectoryLogin?>? askDirectoryLogin = null)
    {
        if (!WebAuthnApi.Available) return CoreText.Error(ErrorCodes.FidoUnavailable);
        if (Link is null) return CoreText.Error(ErrorCodes.FidoServiceRequired);
        if (label.Trim().Length == 0 || !FidoProtocol.ReasonValid(reason)) return CoreText.Error(ErrorCodes.FidoReasonTooShort, FidoProtocol.MinReasonLength);
        var who = await lockController.RequireRegistrarAsync(UI.Loc.F("Keys_RegistrarWhy", account.Trim()));
        if (who is null) return CoreText.Error(ErrorCodes.SignInCancelled);
        if (Link is not { } link) return CoreText.Error(ErrorCodes.FidoServiceRequired);
        var request = new JsonObject
        {
            ["op"] = "fido-register-begin", ["ticket"] = who.Tokens.GetValueOrDefault(AuthResults.Ticket) ?? "", ["account"] = account.Trim(),
            ["label"] = label.Trim(), ["reason"] = reason.Trim(),
        };
        if (!AddDirectoryLogin(request, who, await StatusAsync(), askDirectoryLogin)) return CoreText.Error(ErrorCodes.SignInCancelled);
        var begin = await link.FidoAsync(request);
        if (Failed(begin) is { } e1) return e1;

        var rpId = (string)begin!["rpId"]!;
        var challenge = (string)begin["challenge"]!;
        var userId = FidoProtocol.FromBase64Url((string?)begin["userHandle"]) ?? [];
        var algorithms = ((JsonArray?)begin["algorithms"] ?? []).Select(a => a!.GetValue<int>()).ToList();
        var exclude = ((JsonArray?)begin["excludeCredentials"] ?? []).Select(x => FidoProtocol.FromBase64Url((string?)x)).Where(b => b is not null).Select(b => b!).ToList();
        var clientData = FidoProtocol.ClientDataJson(FidoProtocol.TypeCreate, challenge, rpId);
        var result = await Task.Run(() => WebAuthnApi.MakeCredential(owner, rpId, userId, (string?)begin["userName"] ?? "", (string?)begin["displayName"] ?? "",
            clientData, algorithms, exclude, begin["timeoutMs"]?.GetValue<int>() ?? FidoProtocol.TimeoutMilliseconds, CancellationToken.None));
        if (!result.Ok)
        {
            var code = WebAuthnErrors.CodeFor(result.HResult);
            return code == ErrorCodes.FidoWebAuthnError ? CoreText.Error(code, result.ErrorName ?? "") : CoreText.Error(code);
        }
        var done = await link.FidoAsync(new JsonObject
        {
            ["op"] = "fido-register-complete", ["registrationId"] = (string?)begin["registrationId"],
            ["clientDataJSON"] = FidoProtocol.ToBase64Url(clientData), ["attestationObject"] = FidoProtocol.ToBase64Url(result.Value!.AttestationObject),
        });
        return Failed(done);
    }

    /// <summary>Widerrufen mit Begründung (nach Anmeldung der registrierenden Person). Ergebnis: Fehlermeldung oder null.</summary>
    public async Task<string?> RevokeAsync(FidoKeyInfo key, string reason, Func<string, FidoDirectoryLogin?>? askDirectoryLogin = null)
    {
        if (Link is null) return CoreText.Error(ErrorCodes.FidoServiceRequired);
        if (!FidoProtocol.ReasonValid(reason)) return CoreText.Error(ErrorCodes.FidoReasonTooShort, FidoProtocol.MinReasonLength);
        var who = await lockController.RequireRegistrarAsync(UI.Loc.F("Keys_RevokeWhy", key.Label, key.Person));
        if (who is null) return CoreText.Error(ErrorCodes.SignInCancelled);
        if (Link is not { } link) return CoreText.Error(ErrorCodes.FidoServiceRequired);
        var request = new JsonObject
        {
            ["op"] = "fido-revoke", ["ticket"] = who.Tokens.GetValueOrDefault(AuthResults.Ticket) ?? "", ["keyId"] = key.KeyId, ["reason"] = reason.Trim(),
        };
        if (!AddDirectoryLogin(request, who, await StatusAsync(), askDirectoryLogin)) return CoreText.Error(ErrorCodes.SignInCancelled);
        return Failed(await link.FidoAsync(request));
    }

    private static string? Failed(JsonObject? r) =>
        r is null ? CoreText.Error(ErrorCodes.FidoServiceRequired)
        : r["ok"]?.GetValue<bool>() == true ? null
        // Texte der Schlüssel-Codes in der Sprache der Oberfläche (der Dienst antwortet in seiner); VIT-0409 nennt Minuten
        : (string?)r["code"] is { } code && code.StartsWith("VIT-04", StringComparison.Ordinal) && code != ErrorCodes.FidoBlocked
            ? CoreText.Error(code, FidoProtocol.MinReasonLength)
            : (string?)r["error"] ?? CoreText.Error((string?)r["code"] ?? ErrorCodes.SignInFailed);
}
