// SPDX-License-Identifier: MIT
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Vitrine.Core.Fido;

/// <summary>Wofür ein Sicherheitsschlüssel gerade benutzt wird (bindet die Einmal-Challenge des Dienstes an den Zweck).</summary>
public enum FidoPurpose
{
    Unlock,
    Admin,
    Signature,
    /// <summary>Anmeldung einer registrierenden Person vor dem Registrieren oder Widerrufen eines Schlüssels.</summary>
    Registrar,
}

/// <summary>
/// Feste Werte und kleine Hilfen des Verfahrens „Sicherheitsschlüssel“ (<c>fido</c>). Die Windows-WebAuthn-API
/// (webauthn.dll) bekommt das clientDataJSON von Vitrine und bildet nur dessen Hash; den Inhalt prüft der Dienst.
/// </summary>
public static class FidoProtocol
{
    public const string MethodId = "fido";

    /// <summary>Zufällige Bytes einer Challenge (WebAuthn verlangt mindestens 16).</summary>
    public const int ChallengeBytes = 32;

    /// <summary>So lange gilt eine Challenge zum Anmelden – Zeit für PIN und Berührung.</summary>
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);

    /// <summary>So lange gilt eine begonnene Registrierung.</summary>
    public static readonly TimeSpan RegistrationLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Zeitlimit für den Windows-Sicherheitsdialog (Millisekunden).</summary>
    public const int TimeoutMilliseconds = 120_000;

    /// <summary>
    /// Höchstens so viele Schlüssel-IDs je Aufruf von GetAssertion (allowCredentials). Mehr werden in Teilen nacheinander
    /// angefragt; viele Schlüssel nehmen nicht beliebig lange Listen an.
    /// </summary>
    public const int MaxAllowListChunk = 16;

    /// <summary>Mindestlänge der Begründung beim Registrieren und Widerrufen.</summary>
    public const int MinReasonLength = 10;

    /// <summary>Höchstlänge der Bezeichnung eines Schlüssels.</summary>
    public const int MaxLabelLength = 64;

    /// <summary>COSE-Algorithmen: ES256 (Pflicht), RS256. EdDSA nicht – .NET bringt dafür keine Prüfung mit.</summary>
    public const int AlgEs256 = -7;
    public const int AlgRs256 = -257;
    public const int AlgEdDsa = -8;

    /// <summary>Algorithmen, die Vitrine beim Registrieren anbietet und prüfen kann (Reihenfolge = Vorzug).</summary>
    public static readonly IReadOnlyList<int> SupportedAlgorithms = [AlgEs256, AlgRs256];

    public const string TypeCreate = "webauthn.create";
    public const string TypeGet = "webauthn.get";

    /// <summary>
    /// Origin im clientDataJSON. Bewusst kein https-Origin: Ein Browser erzeugt nie „vitrine://…“, eine Anmeldung auf einer
    /// Webseite mit derselben RP ID passt also nie zu einer Prüfung des Dienstes.
    /// </summary>
    public static string Origin(string rpId) => "vitrine://" + rpId;

    /// <summary>
    /// clientDataJSON wie ein Browser (WebAuthn Level 2, Abschnitt 5.8.1): type, challenge (Base64url), origin, crossOrigin.
    /// </summary>
    public static byte[] ClientDataJson(string type, string challenge, string rpId)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("type", type);
            w.WriteString("challenge", challenge);
            w.WriteString("origin", Origin(rpId));
            w.WriteBoolean("crossOrigin", false);
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>Neue Challenge (Base64url ohne Auffüllung).</summary>
    public static string NewChallenge() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(ChallengeBytes));

    /// <summary>Kennung eines Schlüssels fürs Protokoll und zum Nachschlagen: SHA-256 der Credential-ID, hex klein.</summary>
    public static string IdHash(ReadOnlySpan<byte> credentialId) => Convert.ToHexString(SHA256.HashData(credentialId)).ToLowerInvariant();

    /// <summary>SHA-256 der RP ID, wie er in den Authenticator-Daten steht.</summary>
    public static byte[] RpIdHash(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));

    public static string ToBase64Url(ReadOnlySpan<byte> data) => Base64Url.EncodeToString(data);

    /// <summary>Base64url (auch mit Auffüllung oder als Standard-Base64) → Bytes; null bei ungültigem Text.</summary>
    public static byte[]? FromBase64Url(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var t = text.Trim().TrimEnd('=').Replace('+', '-').Replace('/', '_');
        try { return Base64Url.DecodeFromChars(t); }
        catch (FormatException) { return null; }
    }

    /// <summary>AAGUID einheitlich schreiben (GUID, klein, mit Bindestrichen); null, wenn es keine ist.</summary>
    public static string? NormalizeAaguid(string? text) =>
        Guid.TryParse(text?.Trim(), out var g) ? g.ToString("D") : null;

    /// <summary>Darf ein Schlüssel dieses Modells benutzt werden? Leere Liste = jedes Modell.</summary>
    public static bool ModelAllowed(string? aaguid, IReadOnlyCollection<string> allowedModels)
    {
        var allowed = allowedModels.Select(NormalizeAaguid).Where(a => a is not null).ToList();
        // Liste nur aus ungültigen Einträgen: nichts zulassen statt alles (Tippfehler soll nicht jedes Modell erlauben)
        if (allowedModels.Any(m => !string.IsNullOrWhiteSpace(m)) && allowed.Count == 0) return false;
        if (allowed.Count == 0) return true;
        return NormalizeAaguid(aaguid) is { } a && allowed.Contains(a, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Liste in Teile zu höchstens <paramref name="size"/> Einträgen (Reihenfolge bleibt).</summary>
    public static List<List<T>> Chunk<T>(IReadOnlyList<T> items, int size = MaxAllowListChunk)
    {
        var result = new List<List<T>>();
        for (int i = 0; i < items.Count; i += size) result.Add(items.Skip(i).Take(size).ToList());
        return result;
    }

    /// <summary>Ist der Text eine brauchbare Begründung (getrimmt mindestens <see cref="MinReasonLength"/> Zeichen)?</summary>
    public static bool ReasonValid(string? reason) => (reason?.Trim().Length ?? 0) >= MinReasonLength;
}

/// <summary>Fehler der Windows-WebAuthn-API (HRESULT) → Fehlercode von Vitrine.</summary>
public static class WebAuthnErrors
{
    public const int UserCancelled = unchecked((int)0x80090036);   // NTE_USER_CANCELLED
    public const int Cancelled = unchecked((int)0x800704C7);       // HRESULT_FROM_WIN32(ERROR_CANCELLED)
    public const int Timeout = unchecked((int)0x800705B4);         // HRESULT_FROM_WIN32(ERROR_TIMEOUT)
    public const int NotFound = unchecked((int)0x80090011);        // NTE_NOT_FOUND: kein passender Schlüssel
    public const int Exists = unchecked((int)0x8009000F);          // NTE_EXISTS: Schlüssel steht in der Ausschlussliste

    public static string CodeFor(int hresult) => hresult switch
    {
        UserCancelled or Cancelled or Timeout => Localization.ErrorCodes.SignInCancelled,
        NotFound => Localization.ErrorCodes.FidoNoMatchingKey,
        Exists => Localization.ErrorCodes.FidoKeyAlreadyRegistered,
        _ => Localization.ErrorCodes.FidoWebAuthnError,
    };
}

/// <summary>Hinweise zur Einrichtung des Verfahrens „fido“ (Einstellungen, Protokoll beim Start).</summary>
public static class FidoSetup
{
    /// <summary>Prozesse des Windows-Sicherheitsdialogs für Sicherheitsschlüssel (Windows 10 bzw. neuere Windows-Versionen).</summary>
    public static readonly IReadOnlyList<string> DialogProcesses = ["CredentialUIBroker.exe", "CredDialogHost.exe"];

    /// <summary>
    /// Prozesse des Sicherheitsdialogs, die in Security.AuthUiProcesses fehlen, während „fido“ eingeschaltet ist – deren
    /// Fenster bekämen während der Sperre keine Eingaben (PIN). Leer = alles in Ordnung.
    /// </summary>
    public static List<string> MissingDialogProcesses(IEnumerable<string> methods, IEnumerable<string> authUiProcesses)
    {
        if (!methods.Any(m => string.Equals(m?.Trim(), FidoProtocol.MethodId, StringComparison.OrdinalIgnoreCase))) return [];
        var set = authUiProcesses.Select(p => p.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return DialogProcesses.Where(p => !set.Contains(p)).ToList();
    }
}

/// <summary>Hinweise zur Einrichtung als <see cref="Auth.UnlockSetupWarning"/> (Einstellungen, einmal je Start ins Protokoll).</summary>
public static class FidoWarnings
{
    public static List<Auth.UnlockSetupWarning> For(Config.VitrineConfig cfg)
    {
        var missing = FidoSetup.MissingDialogProcesses(cfg.Unlock.Methods, cfg.Security.AuthUiProcesses);
        return missing.Count == 0 ? [] : [new(Localization.ErrorCodes.FidoDialogBlocked, "Security.AuthUiProcesses", string.Join(", ", missing))];
    }
}

/// <summary>
/// Wofür die App gerade einen Sicherheitsschlüssel benutzen darf. Der Windows-Sicherheitsdialog zeigt nur die RP ID, nicht
/// den Zweck; ein Programm in der Sitzung soll daher keine Signatur oder Registrierung auslösen können, während die Person
/// meint zu entsperren. Signatur und Registrar nur, solange der Vitrine-Dialog dafür offen ist (Prüfung vom 2026-10-30).
/// </summary>
public sealed class FidoPurposeGate
{
    private readonly Dictionary<FidoPurpose, int> _open = new();
    private readonly object _gate = new();

    /// <summary>Dialog für <paramref name="purpose"/> ist offen, bis das Ergebnis freigegeben wird.</summary>
    public IDisposable Open(FidoPurpose purpose)
    {
        lock (_gate) _open[purpose] = _open.GetValueOrDefault(purpose) + 1;
        return new Closer(this, purpose);
    }

    /// <summary>Entsperren und Administrator-Bestätigung immer; Signatur und Registrar nur bei offenem Dialog dafür.</summary>
    public bool Allows(FidoPurpose purpose)
    {
        if (purpose is FidoPurpose.Unlock or FidoPurpose.Admin) return true;
        lock (_gate) return _open.GetValueOrDefault(purpose) > 0;
    }

    private void Close(FidoPurpose purpose)
    {
        lock (_gate) _open[purpose] = Math.Max(0, _open.GetValueOrDefault(purpose) - 1);
    }

    private sealed class Closer(FidoPurposeGate owner, FidoPurpose purpose) : IDisposable
    {
        private int _done;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0) owner.Close(purpose);
        }
    }
}
