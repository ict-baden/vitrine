// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Integration;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Service;

/// <summary>
/// Gegenstelle auf der Protokoll-Pipe, wie der Dienst sie selbst feststellt (Pipe-Handle, Token der Gegenstelle) – nie aus
/// dem Text der Anfrage.
/// </summary>
/// <param name="UserName">DOMÄNE\name aus dem Token der Gegenstelle.</param>
/// <param name="Sid">SID aus dem Token der Gegenstelle.</param>
/// <param name="IsAdministrator">Token mit aktiver Administratorengruppe (als Administrator gestartet).</param>
/// <param name="Groups">
/// Gruppen-SIDs aus dem Token der Gegenstelle, auch „nur verweigern“ (Mitgliedschaft, nicht Rechte) – für Rollenprüfungen
/// beim Lesen (Liste der Sicherheitsschlüssel). Null = unbekannt.
/// </param>
public sealed record AuditClient(int Session, string UserName, string Sid, int ProcessId, bool IsAdministrator = false,
    IReadOnlyCollection<string>? Groups = null);

/// <summary>Was der Dienst zum Prüfen einer Anmeldung braucht und nicht in Vitrine.Core liegt (LogonUser, Netzwerk).</summary>
public interface ISignatureVerifier
{
    /// <summary>Windows-Kennwort mit LogonUser prüfen (Dienst, SYSTEM). IsSessionUser gegen <paramref name="clientSid"/>.</summary>
    Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid);

    /// <summary>
    /// Wie <see cref="WindowsAsync"/>, behält aber bei Erfolg das Token der Anmeldung (für das Schreiben der
    /// Sicherheitsschlüssel ins Active Directory als registrierende Person). Der Aufrufer gibt es frei.
    /// </summary>
    async Task<(AuthOutcome Outcome, IDisposable? Token)> WindowsWithTokenAsync(string user, string? domain, string secret, string clientSid) =>
        (await WindowsAsync(user, domain, secret, clientSid).ConfigureAwait(false), null);

    /// <summary>JSON Web Key Set des Mandanten; null, wenn nicht abrufbar. <paramref name="refresh"/>: nicht aus dem Zwischenspeicher.</summary>
    Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh);

    /// <summary>Konto- oder Gruppenname → SID (für <see cref="UnlockPolicy"/>), null wenn unbekannt.</summary>
    string? ResolveSid(string name);
}

/// <summary>
/// Protokoll-Pipe \\.\pipe\ICT-Baden.Vitrine.Audit zwischen Sitzungs-App und Dienst (#15): eine JSON-Zeile je Anfrage,
/// eine je Antwort, mit derselben <c>id</c>. Anfragen:
/// <list type="bullet">
/// <item><c>write</c>: Ereignis der App (event, actor, method, detail, data, time). Zeit, Nummer, Sitzung und
/// Sitzungsbenutzer setzt der Dienst; Ereignisse, die nur er schreibt (Signatur, Dienst, Formatwechsel), lehnt er ab.</item>
/// <item><c>verify</c>: Anmeldung für eine Signatur prüfen – <c>windows</c> (user, domain, secret: LogonUser im Dienst),
/// <c>entra</c> (idToken: Signatur und Claims im Dienst) oder ein anderes Verfahren (Windows Hello, Plugin: von der App
/// bezeugt, Stufe „client“). Antwort mit einem Einmal-Ticket.</item>
/// <item><c>sign</c>: Signatur mit Ticket, Grund und Bedeutung eintragen; Person und Verfahren kommen aus dem Ticket.</item>
/// <item><c>challenge</c>: Einmal-Nonce für eine Microsoft-Anmeldung; die App gibt sie als OpenID-Connect-<c>nonce</c>
/// an Entra, der Dienst verlangt sie im ID-Token zurück (bindet das Token an diese Signaturanfrage).</item>
/// <item><c>rotate</c>: neuer Schlüssel (nur für eine Gegenstelle mit Administratorrechten, <c>--rotate-audit-key</c>).</item>
/// <item>Sicherheitsschlüssel (<see cref="FidoService"/>, docs/security-keys.md): <c>fido-status</c>, <c>fido-list</c>,
/// <c>fido-challenge</c> (Zweck unlock/admin/signature/registrar), <c>fido-assert</c> (Entsperren und
/// Administrator-Bestätigung: geprüfte Person mit Gruppen, ohne Ticket), <c>fido-register-begin</c>,
/// <c>fido-register-complete</c>, <c>fido-revoke</c> (beide mit einem Ticket des Zwecks „registrar“). Für Signaturen und
/// die Anmeldung der registrierenden Person <c>verify</c> mit <c>method</c> „fido“. Ablage im Active Directory:
/// <c>fido-challenge</c> mit <c>refresh</c> „true“ gleicht vorher ab; <c>fido-register-begin</c> und <c>fido-revoke</c>
/// nehmen <c>directoryUser</c>/<c>directoryPassword</c> der registrierenden Person, wenn das Ticket kein Token ihrer
/// Kennwort-Anmeldung trägt (nur für die Anmeldung am AD, nie gespeichert oder protokolliert).</item>
/// </list>
/// <c>verify</c> mit <c>purpose</c> „registrar“ gibt ein Ticket, das nur für Registrieren und Widerrufen gilt – nur nach
/// einer vom Dienst geprüften Anmeldung (Windows-Kennwort, Microsoft, Sicherheitsschlüssel) und nur für Personen, die
/// <see cref="IRoleCheck.IsRegistrar"/> zulässt.
/// Fehlgeschlagene Prüfungen schreibt der Dienst selbst als <see cref="AuditEventType.SignatureFailed"/> (Antwort mit
/// <c>audited</c>), damit Durchprobieren über die Pipe nicht ohne Spur bleibt.
/// </summary>
public sealed class AuditBroker
{
    /// <summary>Längste Anfrage (ein ID-Token mit vielen Gruppen kann einige Kilobyte haben).</summary>
    public const int MaxLineLength = 64 * 1024;

    /// <summary>Prüfungen je Sitzung und Minute, danach VIT-0314.</summary>
    public const int MaxChecksPerMinute = 10;

    /// <summary>So lange gilt ein Ticket zwischen Prüfung und Signatur.</summary>
    public static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(2);

    /// <summary>So lange gilt eine Nonce (<c>challenge</c>) – Zeit für die Anmeldung im Browser.</summary>
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Toleranz zwischen der Uhr von Microsoft (auth_time) und der des Rechners, wenn Entra.ForceFreshSignIn eine Anmeldung
    /// nach der Signaturanfrage verlangt.
    /// </summary>
    public static readonly TimeSpan AuthTimeSkew = TimeSpan.FromMinutes(2);

    /// <summary>Weicht die Zeit der App so weit ab (gepuffert), steht sie als ClientTime im Eintrag.</summary>
    public static readonly TimeSpan ClientTimeTolerance = TimeSpan.FromSeconds(5);

    /// <summary>Ereignisse, die die App melden darf. Alles andere schreibt nur der Dienst.</summary>
    public static readonly IReadOnlySet<AuditEventType> ClientEvents = new HashSet<AuditEventType>
    {
        AuditEventType.AppStarted, AuditEventType.AppStopped, AuditEventType.Locked, AuditEventType.PromptShown,
        AuditEventType.PromptClosed, AuditEventType.Unlocked, AuditEventType.UnlockFailed, AuditEventType.UnlockDenied,
        AuditEventType.FailureActionTriggered, AuditEventType.SignatureFailed, AuditEventType.ConfigChanged,
        AuditEventType.Error, AuditEventType.SessionEndRefused,
        AuditEventType.UnlockBypass, AuditEventType.ResponsibilityChanged,
        AuditEventType.DesktopSwitchDetected, AuditEventType.WindowsLockDetected,
    };

    /// <param name="Directory">
    /// Nur Zweck „registrar“ mit Windows-Kennwort und Ablage im AD: Token der Anmeldung, damit der Dienst als diese Person ins
    /// AD schreibt. Wird mit dem Ticket eingelöst oder beim Ablauf freigegeben.
    /// </param>
    private sealed record Ticket(AuditClient Client, AuthOutcome Who, string Method, string Assurance, DateTimeOffset Created,
        string Purpose = PurposeSignature, FidoWriteCredential? Directory = null);

    /// <summary>Zweck eines Tickets: Signatur (Standard) oder Registrieren/Widerrufen von Sicherheitsschlüsseln.</summary>
    public const string PurposeSignature = "signature";
    public const string PurposeRegistrar = "registrar";

    private readonly SignedAuditLog _log;
    private readonly ISignatureVerifier _verifier;
    private readonly Func<VitrineConfig> _config;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Dictionary<string, Ticket> _tickets = new(StringComparer.Ordinal);
    private readonly Dictionary<int, Queue<DateTimeOffset>> _checks = new();
    private readonly Dictionary<string, DateTimeOffset> _usedTokens = new(StringComparer.Ordinal);
    private sealed record Challenge(int Session, string Sid, DateTimeOffset Issued);
    private readonly Dictionary<string, Challenge> _challenges = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private FidoService? _fido;

    public AuditBroker(SignedAuditLog log, ISignatureVerifier verifier, Func<VitrineConfig> config, Func<DateTimeOffset>? clock = null)
    {
        _log = log;
        _verifier = verifier;
        _config = config;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Sicherheitsschlüssel anschließen (der FidoService schreibt seine Ereignisse über <see cref="WriteFidoEvent"/> in dieses
    /// Protokoll). Ohne: Verfahren „fido“ nicht verfügbar (VIT-0402).
    /// </summary>
    public FidoService? Fido { get => _fido; set => _fido = value; }

    /// <summary>Protokolleintrag eines Schlüssel-Ereignisses (Rückruf von <see cref="FidoService"/>, nur im Dienst).</summary>
    public void WriteFidoEvent(FidoAuditEvent e) =>
        _log.Write(new AuditRecord(e.Type, e.Client?.UserName ?? "SYSTEM", e.Assurance)
        {
            Session = e.Client?.Session,
            Actor = e.Actor,
            Method = FidoProtocol.MethodId,
            Detail = e.Detail.Length > 4000 ? e.Detail[..4000] : e.Detail,
            Data = e.Data,
        });

    /// <summary>Eine Anfragezeile der Gegenstelle beantworten. Wirft nie; Fehler als <c>{"ok":false,"code":…}</c>.</summary>
    public async Task<JsonObject> HandleAsync(AuditClient client, string line)
    {
        JsonObject? req;
        try { req = JsonNode.Parse(line) as JsonObject; }
        catch (JsonException) { req = null; }
        if (req is null) return Error(null, ErrorCodes.PipeInvalidJson, "Invalid JSON");
        var id = req["id"] is JsonValue idv && idv.TryGetValue<long>(out var n) ? n : (long?)null;
        try
        {
            return Str(req, "op") switch
            {
                "write" => Write(client, req, id),
                "verify" => await VerifyAsync(client, req, id).ConfigureAwait(false),
                "sign" => Sign(client, req, id),
                "rotate" => Rotate(client, id),
                "challenge" => NewChallenge(client, id),
                "fido-status" => await FidoStatusAsync(client, id).ConfigureAwait(false),
                "fido-list" => await FidoListAsync(client, id).ConfigureAwait(false),
                "fido-challenge" => await FidoChallengeAsync(client, req, id).ConfigureAwait(false),
                "fido-assert" => await FidoAssertAsync(client, req, id).ConfigureAwait(false),
                "fido-register-begin" => await FidoRegisterBeginAsync(client, req, id).ConfigureAwait(false),
                "fido-register-complete" => await FidoRegisterCompleteAsync(client, req, id).ConfigureAwait(false),
                "fido-revoke" => await FidoRevokeAsync(client, req, id).ConfigureAwait(false),
                var op => Error(id, ErrorCodes.PipeUnknownCommand, $"Unknown operation '{op}'"),
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or JsonException or ArgumentException)
        {
            return Error(id, ErrorCodes.PipeInvalidJson, ex.Message);
        }
    }

    // ================= write =================

    private JsonObject Write(AuditClient client, JsonObject req, long? id)
    {
        var now = _clock();
        if (!Enum.TryParse<AuditEventType>(Str(req, "event"), ignoreCase: false, out var type) || !Enum.IsDefined(type))
            return Error(id, ErrorCodes.PipeUnknownCommand, "Unknown event");
        if (!ClientEvents.Contains(type))
        {
            // Versuch, ein Ereignis des Dienstes oder eine Signatur ohne Prüfung einzutragen: als Fehler festhalten
            _log.Write(new AuditRecord(AuditEventType.Error, client.UserName, AuditAssurance.Service)
            {
                Session = client.Session,
                Detail = $"{ErrorCodes.ServiceEntryRefused} entry of type {type} from session {client.Session} (PID {client.ProcessId}) refused",
                Data = new() { ["code"] = ErrorCodes.ServiceEntryRefused },
            });
            return Error(id, ErrorCodes.ServiceEntryRefused, $"Entries of type {type} are written by the service only");
        }
        DateTimeOffset? clientTime = DateTimeOffset.TryParse(Str(req, "time"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)
                                     && (t - now).Duration() > ClientTimeTolerance ? t.ToUniversalTime() : null;
        var entry = _log.Write(new AuditRecord(type, client.UserName, AuditAssurance.Client)
        {
            Session = client.Session,
            Actor = Field(req, "actor"),
            Method = Field(req, "method"),
            Detail = Field(req, "detail", 4000),
            Data = DataOf(req["data"]),
            ClientTime = clientTime,
        });
        // Nicht geschrieben (Ordner weg, Platte voll): Fehler, damit die App den Eintrag behält und später erneut sendet –
        // vorher kam „ok“ mit Nummer 0, und der Eintrag war verloren (Prüfung vom 2026-10-26)
        if (entry is null && _log.Enabled) return Error(id, ErrorCodes.AuditWriteFailed, _log.LastError ?? "The entry could not be written");
        return Written(id, entry);
    }

    // ================= verify =================

    private async Task<JsonObject> VerifyAsync(AuditClient client, JsonObject req, long? id)
    {
        if (!TakeCheck(client.Session)) return Error(id, ErrorCodes.ServiceTooManyChecks, "Too many checks, wait a minute");
        var cfg = _config();
        var method = Field(req, "method") ?? "";
        var entered = Field(req, "user");
        // Zweck: Signatur (Standard) oder Anmeldung einer registrierenden Person (Sicherheitsschlüssel); Fehlversuche der
        // registrierenden Person stehen als UnlockFailed im Protokoll, nicht als SignatureFailed
        bool registrar = Str(req, "purpose") == PurposeRegistrar;
        var failType = registrar ? AuditEventType.UnlockFailed : AuditEventType.SignatureFailed;
        // Nur Verfahren, die die App für Signaturen anbietet: Windows immer, Microsoft mit App-Registrierung, Hello und
        // Plugins nur, wenn sie in Unlock.Methods stehen. Ein erfundenes Verfahren wird nie zu einer Signatur.
        if (!SignatureMethodAllowed(method, cfg))
            return Failed(client, id, method, entered, ErrorCodes.ServiceMethodNotAllowed, assurance: AuditAssurance.Client, type: failType);
        // Registrieren nur nach einer Anmeldung, die der Dienst selbst geprüft hat
        if (registrar && method is not ("windows" or "entra" or FidoProtocol.MethodId))
            return Failed(client, id, method, entered, ErrorCodes.ServiceMethodNotAllowed, assurance: AuditAssurance.Client, type: failType);
        AuthOutcome who;
        string assurance;
        FidoWriteCredential? directory = null;
        try
        {
            switch (method)
            {
                case "windows":
                {
                    var domain = Field(req, "domain");
                    var secret = Str(req, "secret");
                    if (string.IsNullOrEmpty(entered) || string.IsNullOrEmpty(secret)) return Error(id, ErrorCodes.SecretMissing, "user and secret required");
                    if (registrar && _fido is { RequiresWriteCredential: true })
                    {
                        // Sicherheitsschlüssel im AD: Das Token der Anmeldung schreibt später als diese Person (kein zweites Kennwort)
                        var (outcome, token) = await _verifier.WindowsWithTokenAsync(entered, domain, secret, client.Sid).ConfigureAwait(false);
                        who = outcome;
                        if (token is not null)
                        {
                            if (outcome.Success) directory = FidoWriteCredential.FromToken(token);
                            else token.Dispose();
                        }
                    }
                    else who = await _verifier.WindowsAsync(entered, domain, secret, client.Sid).ConfigureAwait(false);
                    if (!string.IsNullOrEmpty(domain)) entered = $"{domain}\\{entered}";
                    assurance = AuditAssurance.Verified;
                    break;
                }
                case "entra":
                    who = await EntraAsync(client, Str(req, "idToken"), cfg.Entra).ConfigureAwait(false);
                    assurance = AuditAssurance.Verified;
                    break;
                case FidoProtocol.MethodId:
                {
                    if (_fido is null) return Error(id, ErrorCodes.FidoServiceRequired, CoreText.Error(ErrorCodes.FidoServiceRequired));
                    var r = await _fido.VerifyAsync(client, registrar ? FidoPurpose.Registrar : FidoPurpose.Signature, Assertion(req)).ConfigureAwait(false);
                    // Ablehnungen hat der FidoService schon als FidoKeyRejected/FidoCloneSuspected eingetragen
                    if (!r.Ok)
                    {
                        var e = Error(id, r.Code!, FidoMessage(r.Code!, r.Problem));
                        e["audited"] = true;
                        return e;
                    }
                    who = r.Value!;
                    assurance = AuditAssurance.Verified;
                    break;
                }
                case "hello":
                    // Windows Hello bestätigt nur den Sitzungsbenutzer: Person ist die Gegenstelle selbst
                    who = new AuthOutcome
                    {
                        Success = true, UserName = client.UserName, UserId = client.Sid, IsSessionUser = true,
                        DisplayName = Field(req, "displayName") ?? client.UserName,
                    };
                    assurance = AuditAssurance.Client;
                    break;
                default:
                    // Plugin: Der Dienst kann das Verfahren nicht nachprüfen – Angaben der App, Stufe „client“
                    if (Str(req, "shared") == "true")
                        return Failed(client, id, method, Field(req, "actor") ?? entered, ErrorCodes.PersonalSignatureRequired, assurance: AuditAssurance.Client);
                    if (Field(req, "actor") is not { } actor) return Error(id, ErrorCodes.SignInFailed, "actor required");
                    who = new AuthOutcome
                    {
                        Success = true, UserName = actor, UserId = Field(req, "userId"), DisplayName = Field(req, "displayName"),
                        TenantId = Field(req, "tenant"),
                    };
                    assurance = AuditAssurance.Client;
                    break;
            }
            // „verified“ nur, wo der Dienst selbst geprüft hat (Windows, Microsoft); sonst stammen Person und Ergebnis von der App
            if (!who.Success) return Failed(client, id, method, entered ?? who.UserName, who.ErrorCode ?? ErrorCodes.SignInFailed, who.Error, assurance, failType);
            if (UnlockPolicy.IsShared(who)) return Failed(client, id, method, who.UserName, ErrorCodes.PersonalSignatureRequired, assurance: assurance, type: failType);
            if (registrar)
            {
                // Rolle prüft der Dienst (IRoleCheck); ohne Sicherheitsschlüssel-Dienst gibt es nichts zu registrieren
                if (_fido is null) return Error(id, ErrorCodes.FidoServiceRequired, CoreText.Error(ErrorCodes.FidoServiceRequired));
                if (!_fido.Roles.IsRegistrar(who))
                    return Failed(client, id, method, who.UserName, ErrorCodes.FidoNotRegistrar, assurance: assurance, type: failType);
            }
            else
            {
                // Wie in der App: Für Signaturen zählt nur die Domänenliste (Unlock.AllowedDomains)
                var rules = new UnlockSettings { Allowed = UnlockAllowed.AnyAuthenticated, AllowedDomains = cfg.Unlock.AllowedDomains };
                var decision = UnlockPolicy.Evaluate(who, rules, resolveSid: _verifier.ResolveSid);
                if (!decision.Allowed) return Failed(client, id, method, who.UserName, decision.Code ?? ErrorCodes.NotAllowedToUnlock, decision.Reason, assurance);
            }

            var details = new Dictionary<string, string>(who.Details) { ["method"] = method };
            // Die App muss dann kein Kennwort für das AD mehr erfragen
            if (directory is not null) details["directoryCredential"] = "token";
            who = who.WithDetails(details);
            var ticket = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            lock (_gate)
            {
                Expire();
                _tickets[ticket] = new Ticket(client, who, method, assurance, _clock(), registrar ? PurposeRegistrar : PurposeSignature, directory);
                directory = null; // gehört jetzt dem Ticket
            }
            var answer = new JsonObject
            {
                ["id"] = id, ["ok"] = true, ["ticket"] = ticket, ["user"] = who.UserName, ["displayName"] = who.DisplayName,
                ["userId"] = who.UserId, ["tenant"] = who.TenantId, ["sessionUser"] = who.IsSessionUser, ["admin"] = who.IsAdministrator,
                ["assurance"] = assurance,
            };
            var d = new JsonObject();
            foreach (var (k, v) in details) d[k] = v;
            answer["details"] = d;
            return answer;
        }
        finally
        {
            // Nicht an ein Ticket gegangen (Ablehnung, Fehler): Token sofort freigeben
            directory?.Dispose();
        }
    }

    private async Task<AuthOutcome> EntraAsync(AuditClient client, string? idToken, EntraSettings s)
    {
        static AuthOutcome Reject(string code, string problem) =>
            AuthOutcome.Fail(CoreText.Error(code, problem), code);
        if (string.IsNullOrWhiteSpace(idToken)) return Reject(ErrorCodes.ServiceEntraTokenRejected, "no ID token");
        if (string.IsNullOrWhiteSpace(s.ClientId)) return AuthOutcome.Fail(CoreText.Error(ErrorCodes.EntraNotConfigured), ErrorCodes.EntraNotConfigured);
        if (EntraIdToken.Peek(idToken) is not { Tenant: { } tenant }) return Reject(ErrorCodes.ServiceEntraTokenRejected, "not a JWT");
        // Schlüssel nur für zugelassene Mandanten holen
        if (!Guid.TryParse(tenant, out var g) || !EntraClaims.AllowedTenants(s).Contains(g.ToString("D")))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.TenantNotAllowed), ErrorCodes.TenantNotAllowed);

        var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(idToken)));
        lock (_gate)
        {
            Expire();
            if (_usedTokens.ContainsKey(tokenHash)) return Reject(ErrorCodes.ServiceEntraTokenRejected, "already used");
        }
        var now = _clock();
        EntraTokenCheck? check = null;
        foreach (var refresh in new[] { false, true })
        {
            var jwks = await _verifier.EntraKeysAsync(g.ToString("D"), s.ClientId.Trim(), refresh).ConfigureAwait(false);
            if (jwks is null) return AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceEntraKeysUnavailable), ErrorCodes.ServiceEntraKeysUnavailable);
            check = EntraIdToken.Validate(idToken, jwks, s, now);
            // Unbekannter Schlüssel: Microsoft wechselt die Schlüssel – einmal neu holen
            if (check.Valid || check.Problem?.StartsWith("unknown signing key", StringComparison.Ordinal) != true) break;
        }
        if (check is not { Valid: true }) return Reject(ErrorCodes.ServiceEntraTokenRejected, check?.Problem ?? "invalid");
        string? Claim(string type) => check.Claims!.FirstOrDefault(c => c.Key == type).Value;

        // Nonce des Dienstes: Das Token wurde für genau diese Anfrage dieser Sitzung ausgestellt (einmal, kurz gültig).
        // Ohne sie könnte, wer die App steuert, ein frisches Token aus einer alten Browser-Sitzung (SSO) einer anderen Person holen.
        Challenge? challenge;
        lock (_gate)
        {
            Expire();
            if (Claim("nonce") is not { } nonce || !_challenges.Remove(nonce, out challenge) ||
                challenge.Session != client.Session || challenge.Sid != client.Sid)
                return Reject(ErrorCodes.ServiceEntraTokenRejected, "nonce does not match a challenge of this session");
            _usedTokens[tokenHash] = now;
        }
        // auth_time ist Pflicht (optionaler Claim der App-Registrierung): Nur so sieht der Dienst, wann die Person sich
        // wirklich angemeldet hat – iat ist bei SSO frisch, auch ohne neue Anmeldung
        if (!long.TryParse(Claim("auth_time"), System.Globalization.NumberStyles.Integer, CultureInfo.InvariantCulture, out var authSeconds))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceEntraAuthTimeMissing), ErrorCodes.ServiceEntraAuthTimeMissing);
        var authTime = DateTimeOffset.FromUnixTimeSeconds(authSeconds);
        if (s.ForceFreshSignIn && authTime < challenge.Issued - AuthTimeSkew)
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceEntraNotFresh), ErrorCodes.ServiceEntraNotFresh);
        if (s.MaxAuthAgeSeconds > 0 && now - authTime > TimeSpan.FromSeconds(s.MaxAuthAgeSeconds))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceEntraNotFresh), ErrorCodes.ServiceEntraNotFresh);

        return EntraClaims.Evaluate(new EntraSignIn(check.Claims!, Claim("tid"), Claim("oid"), Claim("preferred_username")), s, client.Sid,
            now, EntraClaims.AuthContextFor(s, signature: true));
    }

    // ================= sign =================

    private JsonObject Sign(AuditClient client, JsonObject req, long? id)
    {
        var key = Str(req, "ticket") ?? "";
        Ticket? t;
        lock (_gate)
        {
            Expire();
            if (_tickets.Remove(key, out t) && (t.Client.Session != client.Session || t.Client.Sid != client.Sid || t.Purpose != PurposeSignature)) t = null;
        }
        if (t is null) return Error(id, ErrorCodes.ServiceTicketInvalid, "Ticket unknown, expired or already used");
        var reason = Field(req, "reason") ?? "";
        var meaning = Field(req, "meaning");
        var data = new Dictionary<string, string>();
        if (t.Who.UserId is not null) data["userId"] = t.Who.UserId;
        if (t.Who.DisplayName is not null) data["displayName"] = t.Who.DisplayName;
        if (t.Who.TenantId is not null) data["tenant"] = t.Who.TenantId;
        foreach (var (k, v) in t.Who.Details) data.TryAdd(k, v);
        data["reason"] = reason;
        if (meaning is not null) data["meaning"] = meaning;
        if (Field(req, "requester") is { } requester) data["requester"] = requester;
        if (Field(req, "clientProcess") is { } process) data["clientProcess"] = process;
        var entry = _log.Write(new AuditRecord(AuditEventType.SignatureGranted, client.UserName, t.Assurance)
        {
            Session = client.Session,
            Actor = t.Who.UserName,
            Method = t.Method,
            Detail = $"{reason}{(meaning is null ? "" : $" – {meaning}")}",
            Data = data,
        });
        // Ohne Eintrag keine Signatur – außer das Protokoll ist ausgeschaltet (dann wie bisher auditSeq 0)
        if (entry is null && _config().Audit.Enabled)
            return Error(id, ErrorCodes.AuditServiceUnavailable, "The signature could not be recorded");
        var answer = Written(id, entry);
        answer["assurance"] = t.Assurance;
        return answer;
    }

    // ================= challenge =================

    private JsonObject NewChallenge(AuditClient client, long? id)
    {
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        lock (_gate)
        {
            Expire();
            // Wenige offene je Sitzung: Ein Programm in der Sitzung soll den Speicher des Dienstes nicht füllen
            var mine = _challenges.Where(p => p.Value.Session == client.Session).OrderBy(p => p.Value.Issued).ToList();
            foreach (var (k, _) in mine.Take(Math.Max(0, mine.Count - 4))) _challenges.Remove(k);
            _challenges[nonce] = new Challenge(client.Session, client.Sid, _clock());
        }
        return new JsonObject { ["id"] = id, ["ok"] = true, ["nonce"] = nonce };
    }

    /// <summary>Verfahren, das die App für Signaturen anbieten darf (wie LockController.RequestSignatureAsync).</summary>
    private static bool SignatureMethodAllowed(string method, VitrineConfig cfg) => method switch
    {
        "" or "pin" => false,
        "windows" => true,
        "entra" => !string.IsNullOrWhiteSpace(cfg.Entra.ClientId),
        _ => cfg.Unlock.Methods.Contains(method, StringComparer.OrdinalIgnoreCase),
    };

    // ================= Sicherheitsschlüssel =================

    private JsonObject? FidoMissing(long? id) =>
        _fido is null ? Error(id, ErrorCodes.FidoServiceRequired, CoreText.Error(ErrorCodes.FidoServiceRequired)) : null;

    /// <summary>Meldung zu einem Code des FidoService (VIT-0409 mit Minuten, VIT-0417 mit Mindestlänge).</summary>
    private static string FidoMessage(string code, string? problem) => code switch
    {
        ErrorCodes.FidoBlocked => CoreText.Error(code, problem ?? "?"),
        ErrorCodes.FidoReasonTooShort => CoreText.Error(code, FidoProtocol.MinReasonLength),
        _ => CoreText.Error(code),
    };

    private static FidoAssertion Assertion(JsonObject req) => new(Str(req, "challenge") ?? "", Str(req, "credentialId") ?? "",
        Str(req, "authenticatorData") ?? "", Str(req, "clientDataJSON") ?? "", Str(req, "signature") ?? "");

    /// <summary>
    /// Darf die Gegenstelle (der Windows-Benutzer der Sitzung) die Liste der Schlüssel sehen? Nur mit einer der Rollen
    /// Registrierende, Einstellungs-Administratoren oder Prüfer – die Liste nennt Personen, SIDs, UPNs und Widerrufsgründe
    /// (Prüfung vom 2026-10-30).
    /// </summary>
    private bool MaySeeKeys(AuditClient client)
    {
        if (_fido is null) return false;
        var groups = client.Groups ?? [];
        var who = new AuthOutcome
        {
            Success = true, UserName = client.UserName, UserId = client.Sid, Groups = groups,
            IsAdministrator = client.IsAdministrator || groups.Contains(EntraLocalGroups.AdministratorsSid, StringComparer.OrdinalIgnoreCase),
        };
        var roles = _fido.Roles;
        return roles.IsRegistrar(who) || roles.IsConfigAdmin(who) || roles.IsAuditor(who);
    }

    /// <summary>Stand: für alle nur Zahlen; Ort und Fehler der Ablage nur für Rolleninhaber.</summary>
    private async Task<JsonObject> FidoStatusAsync(AuditClient client, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        var s = await _fido!.StatusAsync().ConfigureAwait(false);
        var o = new JsonObject { ["id"] = id, ["ok"] = true, ["rpId"] = s.RpId, ["active"] = s.Active, ["otherRpId"] = s.OtherRpId };
        bool privileged = MaySeeKeys(client);
        o["mayList"] = privileged;
        if (s.StoreError is not null) o["storeError"] = privileged ? s.StoreError : s.StoreError.Split(' ')[0];
        if (privileged && s.Store is { } store)
        {
            o["store"] = store.Kind.ToString();
            if (store.LastSync is { } at) o["lastSync"] = at.ToString("O", CultureInfo.InvariantCulture);
            if (store.SyncError is not null) o["syncError"] = store.SyncError;
            if (store.Location is not null) o["location"] = store.Location;
        }
        return o;
    }

    private async Task<JsonObject> FidoListAsync(AuditClient client, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        if (!MaySeeKeys(client)) return Error(id, ErrorCodes.FidoListNotAllowed, CoreText.Error(ErrorCodes.FidoListNotAllowed));
        try
        {
            var list = await _fido!.ListAsync().ConfigureAwait(false);
            var keys = new JsonArray();
            // Ohne öffentlichen Schlüssel und ohne Credential-ID: Die Liste ist zum Anzeigen da
            foreach (var c in list)
                keys.Add(new JsonObject
                {
                    ["keyId"] = c.IdHash, ["label"] = c.Label, ["person"] = c.PersonName, ["personSid"] = c.PersonSid, ["upn"] = c.PersonUpn,
                    ["aaguid"] = c.Aaguid, ["attestation"] = c.AttestationFormat, ["rpId"] = c.RpId, ["status"] = c.Status.ToString(),
                    ["registeredAt"] = c.RegisteredAt.ToString("O", CultureInfo.InvariantCulture), ["registeredBy"] = c.RegisteredByName,
                    ["registeredOn"] = c.RegisteredOn,
                    ["lastUsedAt"] = c.LastUsedAt?.ToString("O", CultureInfo.InvariantCulture),
                    ["revokedAt"] = c.RevokedAt?.ToString("O", CultureInfo.InvariantCulture), ["revokedBy"] = c.RevokedByName,
                    ["revokeReason"] = c.RevokeReason,
                });
            return new JsonObject { ["id"] = id, ["ok"] = true, ["keys"] = keys };
        }
        catch (FidoStoreException ex) { return Error(id, ex.Code, CoreText.Error(ex.Code)); }
    }

    private async Task<JsonObject> FidoChallengeAsync(AuditClient client, JsonObject req, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        if (!Enum.TryParse<FidoPurpose>(Str(req, "purpose"), ignoreCase: true, out var purpose) || !Enum.IsDefined(purpose) ||
            int.TryParse(Str(req, "purpose"), out _))
            return Error(id, ErrorCodes.PipeInvalidJson, "purpose must be unlock, admin, signature or registrar");
        var r = await _fido!.ChallengeAsync(client, purpose, refresh: Str(req, "refresh") == "true").ConfigureAwait(false);
        if (!r.Ok) return Error(id, r.Code!, CoreText.Error(r.Code!));
        var c = r.Value!;
        return new JsonObject
        {
            ["id"] = id, ["ok"] = true, ["challenge"] = c.Challenge, ["rpId"] = c.RpId, ["timeoutMs"] = c.TimeoutMs,
            // Zentrale Ablage: Die App darf bei „kein passender Schlüssel“ einmal mit refresh nachfragen
            ["refreshable"] = _fido.RequiresWriteCredential,
            ["allowCredentials"] = new JsonArray(c.AllowCredentials.Select(a => (JsonNode?)JsonValue.Create(a)).ToArray()),
        };
    }

    /// <summary>Entsperren und Administrator-Bestätigung: geprüfte Person mit Gruppen. Die Regeln (Unlock.*) prüft die App.</summary>
    private async Task<JsonObject> FidoAssertAsync(AuditClient client, JsonObject req, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        if (!TakeCheck(client.Session)) return Error(id, ErrorCodes.ServiceTooManyChecks, "Too many checks, wait a minute");
        var purpose = Str(req, "purpose") == "admin" ? FidoPurpose.Admin : FidoPurpose.Unlock;
        var r = await _fido!.VerifyAsync(client, purpose, Assertion(req)).ConfigureAwait(false);
        if (!r.Ok)
        {
            var e = Error(id, r.Code!, FidoMessage(r.Code!, r.Problem));
            e["audited"] = true;
            return e;
        }
        var who = r.Value!;
        var answer = new JsonObject
        {
            ["id"] = id, ["ok"] = true, ["user"] = who.UserName, ["displayName"] = who.DisplayName, ["userId"] = who.UserId,
            ["sessionUser"] = who.IsSessionUser, ["admin"] = who.IsAdministrator, ["assurance"] = AuditAssurance.Verified,
            ["groups"] = new JsonArray(who.Groups.Select(g => (JsonNode?)JsonValue.Create(g)).ToArray()),
        };
        var d = new JsonObject();
        foreach (var (k, v) in who.Details) d[k] = v;
        answer["details"] = d;
        return answer;
    }

    /// <summary>Ticket des Zwecks „registrar“ einlösen (einmal, gleiche Sitzung und gleicher Benutzer, vom Dienst geprüft).</summary>
    private Ticket? TakeRegistrarTicket(AuditClient client, JsonObject req)
    {
        var key = Str(req, "ticket") ?? "";
        lock (_gate)
        {
            Expire();
            if (!_tickets.Remove(key, out var t)) return null;
            if (t.Client.Session == client.Session && t.Client.Sid == client.Sid && t.Purpose == PurposeRegistrar &&
                t.Assurance == AuditAssurance.Verified) return t;
            t.Directory?.Dispose();
            return null;
        }
    }

    /// <summary>
    /// Anmeldedaten für das AD: Token aus der Kennwort-Anmeldung der registrierenden Person (im Ticket), sonst Benutzer und
    /// Kennwort aus der Anfrage (<c>directoryUser</c>, <c>directoryPassword</c>; nur für die Anmeldung am AD, nie gespeichert).
    /// Das jeweils andere wird verworfen.
    /// </summary>
    private static FidoWriteCredential? DirectoryCredential(Ticket t, JsonObject req)
    {
        var fromRequest = FidoWriteCredential.FromPassword(Field(req, "directoryUser"), Str(req, "directoryPassword"));
        if (t.Directory is null) return fromRequest;
        fromRequest?.Dispose();
        return t.Directory;
    }

    private async Task<JsonObject> FidoRegisterBeginAsync(AuditClient client, JsonObject req, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        if (TakeRegistrarTicket(client, req) is not { } t) return Error(id, ErrorCodes.ServiceTicketInvalid, CoreText.Error(ErrorCodes.ServiceTicketInvalid));
        var r = await _fido!.BeginRegistrationAsync(client, t.Who, Field(req, "account"), Field(req, "label"), Field(req, "reason", 1000),
            directory: DirectoryCredential(t, req)).ConfigureAwait(false);
        if (!r.Ok)
        {
            var e = Error(id, r.Code!, FidoMessage(r.Code!, r.Problem));
            e["audited"] = true;
            return e;
        }
        var s = r.Value!;
        return new JsonObject
        {
            ["id"] = id, ["ok"] = true, ["registrationId"] = s.RegistrationId, ["challenge"] = s.Challenge, ["rpId"] = s.RpId,
            ["userHandle"] = s.UserHandle, ["userName"] = s.UserName, ["displayName"] = s.DisplayName, ["timeoutMs"] = s.TimeoutMs,
            ["excludeCredentials"] = new JsonArray(s.ExcludeCredentials.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
            ["algorithms"] = new JsonArray(s.Algorithms.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
        };
    }

    private async Task<JsonObject> FidoRegisterCompleteAsync(AuditClient client, JsonObject req, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        var r = await _fido!.CompleteRegistrationAsync(client, Str(req, "registrationId"), Str(req, "clientDataJSON"), Str(req, "attestationObject"))
            .ConfigureAwait(false);
        if (!r.Ok)
        {
            var e = Error(id, r.Code!, FidoMessage(r.Code!, r.Problem));
            e["audited"] = r.Code != ErrorCodes.FidoRegistrationExpired;
            return e;
        }
        var c = r.Value!;
        return new JsonObject
        {
            ["id"] = id, ["ok"] = true, ["keyId"] = c.IdHash, ["label"] = c.Label, ["person"] = c.PersonName, ["aaguid"] = c.Aaguid,
            ["attestation"] = c.AttestationFormat, ["attestationVerified"] = c.AttestationVerified,
        };
    }

    private async Task<JsonObject> FidoRevokeAsync(AuditClient client, JsonObject req, long? id)
    {
        if (FidoMissing(id) is { } missing) return missing;
        if (TakeRegistrarTicket(client, req) is not { } t) return Error(id, ErrorCodes.ServiceTicketInvalid, CoreText.Error(ErrorCodes.ServiceTicketInvalid));
        var r = await _fido!.RevokeAsync(client, t.Who, Field(req, "keyId"), Field(req, "reason", 1000), directory: DirectoryCredential(t, req))
            .ConfigureAwait(false);
        if (!r.Ok) return Error(id, r.Code!, FidoMessage(r.Code!, r.Problem));
        return new JsonObject { ["id"] = id, ["ok"] = true, ["keyId"] = r.Value!.IdHash };
    }

    // ================= rotate =================

    private JsonObject Rotate(AuditClient client, long? id)
    {
        if (!client.IsAdministrator) return Error(id, ErrorCodes.AdminRequired, "Administrator rights required");
        var entry = _log.RotateKey(client.UserName, client.UserName);
        if (entry is null) return Error(id, ErrorCodes.AuditKeyError, _log.LastError ?? "rotation failed");
        var answer = Written(id, entry);
        answer["key"] = entry.Data?.GetValueOrDefault("key");
        answer["fingerprint"] = entry.Data?.GetValueOrDefault("fingerprint");
        return answer;
    }

    // ================= Hilfen =================

    /// <param name="assurance">„verified“, wenn der Dienst die Anmeldung selbst geprüft hat; sonst „client“ (Person und Ergebnis von der App).</param>
    private JsonObject Failed(AuditClient client, long? id, string method, string? actor, string code, string? message = null,
        string assurance = AuditAssurance.Verified, AuditEventType type = AuditEventType.SignatureFailed)
    {
        _log.Write(new AuditRecord(type, client.UserName, assurance)
        {
            Session = client.Session,
            Actor = actor,
            Method = method.Length == 0 ? null : method,
            Detail = code,
            Data = new() { ["code"] = code },
        });
        var e = Error(id, code, message ?? CoreText.Error(code));
        e["audited"] = true;
        return e;
    }

    private bool TakeCheck(int session)
    {
        var now = _clock();
        lock (_gate)
        {
            if (!_checks.TryGetValue(session, out var q)) _checks[session] = q = new Queue<DateTimeOffset>();
            while (q.Count > 0 && now - q.Peek() > TimeSpan.FromMinutes(1)) q.Dequeue();
            if (q.Count >= MaxChecksPerMinute) return false;
            q.Enqueue(now);
            return true;
        }
    }

    private void Expire()
    {
        var now = _clock();
        foreach (var k in _tickets.Where(p => now - p.Value.Created > TicketLifetime).Select(p => p.Key).ToList())
        {
            _tickets[k].Directory?.Dispose();
            _tickets.Remove(k);
        }
        // Benutzte Token länger merken, als sie frisch genug wären (EntraIdToken.MaxTokenAge)
        foreach (var k in _usedTokens.Where(p => now - p.Value > TimeSpan.FromHours(1)).Select(p => p.Key).ToList()) _usedTokens.Remove(k);
        foreach (var k in _challenges.Where(p => now - p.Value.Issued > ChallengeLifetime).Select(p => p.Key).ToList()) _challenges.Remove(k);
    }

    private static JsonObject Written(long? id, AuditEntry? e) => new()
    {
        ["id"] = id, ["ok"] = true, ["seq"] = e?.Seq ?? 0, ["hash"] = e?.Hash ?? "",
    };

    private static JsonObject Error(long? id, string code, string message) => new()
    {
        ["id"] = id, ["ok"] = false, ["code"] = code, ["error"] = message,
    };

    private static string? Str(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// <summary>Textfeld der App: Steuerzeichen entfernt, gekürzt; leer = null.</summary>
    private static string? Field(JsonObject o, string name, int max = PipeProtocol.MaxFieldLength) => Clean(Str(o, name), max);

    private static string? Clean(string? s, int max)
    {
        var c = PipeProtocol.Clean(s);
        if (string.IsNullOrEmpty(c)) return null;
        return c.Length > max ? c[..max] : c;
    }

    /// <summary>Data der App: höchstens 32 Einträge, Schlüssel und Werte bereinigt.</summary>
    private static Dictionary<string, string>? DataOf(JsonNode? node)
    {
        if (node is not JsonObject o) return null;
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in o)
        {
            if (d.Count >= 32) break;
            if (Clean(k, 64) is not { } key || v is not JsonValue jv || !jv.TryGetValue<string>(out var text)) continue;
            if (Clean(text, PipeProtocol.MaxFieldLength) is { } value) d[key] = value;
        }
        return d.Count == 0 ? null : d;
    }
}
