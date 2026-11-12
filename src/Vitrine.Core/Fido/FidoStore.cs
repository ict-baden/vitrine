// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Text.Json.Serialization;

using Vitrine.Core.Config;

namespace Vitrine.Core.Fido;

public enum FidoCredentialStatus { Active, Revoked }

/// <summary>
/// Ein registrierter Sicherheitsschlüssel. Schreibt nur der Dienst; der öffentliche Schlüssel, der Zähler und die Person
/// kommen nie von der Sitzungs-App.
/// </summary>
public sealed class FidoCredential
{
    /// <summary>Credential-ID (Base64url), so wie der Schlüssel sie bei der Registrierung geliefert hat.</summary>
    public string CredentialId { get; set; } = "";
    /// <summary>SHA-256 der Credential-ID (hex): Schlüssel zum Nachschlagen und Kennung im Protokoll.</summary>
    public string IdHash { get; set; } = "";
    /// <summary>RP ID, mit der registriert wurde (Fido.RpId zum Zeitpunkt der Registrierung).</summary>
    public string RpId { get; set; } = "";
    /// <summary>Öffentlicher Schlüssel im COSE-Format (Base64url).</summary>
    public string PublicKey { get; set; } = "";
    public int Algorithm { get; set; }
    /// <summary>Modell des Schlüssels (AAGUID) – Angabe des Schlüssels, die Zertifikatskette prüft Vitrine nicht.</summary>
    public string Aaguid { get; set; } = "";
    public string AttestationFormat { get; set; } = "";
    public bool AttestationVerified { get; set; }
    public string? AttestationCertificate { get; set; }
    /// <summary>user.id bei der Registrierung (zufällig, Base64url).</summary>
    public string UserHandle { get; set; } = "";
    public string PersonSid { get; set; } = "";
    public string PersonName { get; set; } = "";
    public string? PersonUpn { get; set; }
    public string Label { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTimeOffset RegisteredAt { get; set; }
    public string RegisteredBySid { get; set; } = "";
    public string RegisteredByName { get; set; } = "";
    /// <summary>Rechner, auf dem registriert wurde.</summary>
    public string RegisteredOn { get; set; } = "";
    public FidoCredentialStatus Status { get; set; } = FidoCredentialStatus.Active;
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedBySid { get; set; }
    public string? RevokedByName { get; set; }
    public string? RevokeReason { get; set; }
    /// <summary>Signaturzähler des Schlüssels (nur vom Dienst fortgeschrieben).</summary>
    public uint SignCount { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }

    public bool IsActive => Status == FidoCredentialStatus.Active;
}

/// <summary>Widerruf: wer, wann, warum.</summary>
public sealed record FidoRevocation(DateTimeOffset At, string BySid, string ByName, string Reason);

/// <summary>Zuletzt bekannte Gruppen einer Person (für die Anmeldung ohne Domänencontroller).</summary>
public sealed class FidoGroupSnapshot
{
    public string Sid { get; set; } = "";
    public string? Name { get; set; }
    public List<string> Groups { get; set; } = new();
    /// <summary>Woher: <see cref="FidoGroupsSource.Live"/> (S4U-Anmeldung) oder <see cref="FidoGroupsSource.Local"/> (lokale Gruppen).</summary>
    public string Source { get; set; } = FidoGroupsSource.Live;
    public DateTimeOffset ResolvedAt { get; set; }
}

/// <summary>Fehler eines Speichers mit Fehlercode (VIT-0420 nicht geschützt, VIT-0421 nicht les- oder schreibbar).</summary>
public sealed class FidoStoreException(string code, string message, Exception? inner = null) : Exception(message, inner)
{
    public string Code { get; } = code;
}

/// <summary>
/// Ablage der registrierten Schlüssel. Erste Umsetzung: geschützte Datei des Dienstes (<see cref="JsonFidoStore"/>); weitere
/// (z. B. Active Directory) implementieren dieselbe Schnittstelle. Alle Methoden asynchron, Fehler als
/// <see cref="FidoStoreException"/>.
/// </summary>
public interface IFidoCredentialStore
{
    /// <summary>Schlüssel zur Kennung (SHA-256 der Credential-ID, hex), null wenn unbekannt.</summary>
    Task<FidoCredential?> GetAsync(string idHash, CancellationToken ct = default);

    /// <summary>Alle Schlüssel, oder nur die einer Person (SID); auch widerrufene.</summary>
    Task<IReadOnlyList<FidoCredential>> ListAsync(string? personSid = null, CancellationToken ct = default);

    /// <summary>
    /// Neuen Schlüssel ablegen; gibt es die Kennung schon, <see cref="FidoStoreException"/> mit VIT-0419.
    /// <paramref name="writer"/>: Schreibzugang aus <see cref="OpenWriterAsync"/> (nur Ablagen mit
    /// <see cref="RequiresWriteCredential"/>).
    /// </summary>
    Task AddAsync(FidoCredential credential, IFidoStoreWriter? writer = null, CancellationToken ct = default);

    /// <summary>Widerrufen; false, wenn unbekannt oder schon widerrufen.</summary>
    Task<bool> RevokeAsync(string idHash, FidoRevocation revocation, IFidoStoreWriter? writer = null, CancellationToken ct = default);

    /// <summary>Nach einer gültigen Anmeldung: Zähler und Zeit fortschreiben. false, wenn unbekannt.</summary>
    Task<bool> TouchAsync(string idHash, uint signCount, DateTimeOffset usedAt, CancellationToken ct = default);

    /// <summary>Art und Stand der Ablage (für Einstellungen, Bericht, Protokoll).</summary>
    FidoStoreInfo Info => new(FidoStoreKind.Local, null, null);

    /// <summary>
    /// Schreiben braucht die Anmeldedaten der registrierenden Person (Active Directory). Die lokale Datei schreibt der Dienst
    /// selbst.
    /// </summary>
    bool RequiresWriteCredential => false;

    /// <summary>
    /// Schreibzugang mit den Anmeldedaten der registrierenden Person öffnen (nur bei <see cref="RequiresWriteCredential"/>;
    /// sonst null). Prüft, dass die angemeldete Identität <paramref name="registrarSid"/> ist. Fehler als
    /// <see cref="FidoStoreException"/> (VIT-0470, VIT-0472, VIT-0473, VIT-0474). <paramref name="credential"/> gehört danach
    /// dem Aufrufer weiter (er gibt ihn frei).
    /// </summary>
    Task<IFidoStoreWriter?> OpenWriterAsync(FidoWriteCredential? credential, string registrarSid, CancellationToken ct = default) =>
        Task.FromResult<IFidoStoreWriter?>(null);

    /// <summary>Mit der zentralen Ablage abgleichen (lokal: nichts). <paramref name="force"/>: auch wenn noch frisch (begrenzt).</summary>
    Task SyncAsync(bool force, CancellationToken ct = default) => Task.CompletedTask;
}

/// <summary>Art und Stand einer Ablage.</summary>
/// <param name="LastSync">Letzter erfolgreicher Abgleich mit dem AD (UTC); null bei lokaler Ablage oder noch nie.</param>
/// <param name="SyncError">Fehler des letzten Abgleichs (Code und Text), null wenn er gelang.</param>
public sealed record FidoStoreInfo(FidoStoreKind Kind, DateTimeOffset? LastSync, string? SyncError, string? Location = null);

/// <summary>Offener Schreibzugang einer Ablage (AD: Verbindung, angemeldet als die registrierende Person).</summary>
public interface IFidoStoreWriter : IDisposable
{
    /// <summary>SID der Identität, mit der geschrieben wird.</summary>
    string BoundSid { get; }
}

/// <summary>
/// Anmeldedaten der registrierenden Person zum Schreiben ins AD: ein Windows-Token aus der Kennwort-Anmeldung, die der
/// Dienst gerade geprüft hat, oder Benutzer und Kennwort. Nur im Speicher, nach dem Öffnen des Schreibzugangs freigegeben;
/// das Kennwort wird nie gespeichert.
/// </summary>
public sealed class FidoWriteCredential : IDisposable
{
    private FidoWriteCredential(IDisposable? token, string? user, string? password)
    {
        Token = token;
        User = user;
        Password = password;
    }

    /// <summary>Token (Windows: WindowsIdentity aus LogonUser); null bei Benutzer und Kennwort.</summary>
    public IDisposable? Token { get; private set; }
    public string? User { get; }
    public string? Password { get; private set; }

    public static FidoWriteCredential FromToken(IDisposable token) => new(token, null, null);

    public static FidoWriteCredential? FromPassword(string? user, string? password) =>
        string.IsNullOrWhiteSpace(user) || string.IsNullOrEmpty(password) ? null : new(null, user.Trim(), password);

    public void Dispose()
    {
        Token?.Dispose();
        Token = null;
        Password = null;
    }
}

/// <summary>Zwischenspeicher der Gruppen je Person (immer lokal beim Dienst, auch bei einer anderen Schlüssel-Ablage).</summary>
public interface IFidoGroupCache
{
    Task<FidoGroupSnapshot?> GetAsync(string sid, CancellationToken ct = default);
    Task SetAsync(FidoGroupSnapshot snapshot, CancellationToken ct = default);
}

/// <summary>Datei der Ablage. Windows: geschützte Datei unter %ProgramData% (nur SYSTEM schreibt); Tests: Speicher.</summary>
public interface IFidoStoreFile
{
    /// <summary>Inhalt oder null, wenn es die Datei nicht gibt. <see cref="FidoStoreException"/> (VIT-0420), wenn Benutzer sie ändern könnten.</summary>
    string? Read();

    /// <summary>Ersetzt den Inhalt vollständig (neue Datei, dann umbenennen) und schützt die Datei.</summary>
    void Write(string json);
}

/// <summary>Inhalt der Datei fido-credentials.json.</summary>
public sealed class FidoStoreDocument
{
    public int Version { get; set; } = 1;
    public List<FidoCredential> Credentials { get; set; } = new();
    public List<FidoGroupSnapshot> People { get; set; } = new();
}

/// <summary>
/// Ablage als JSON-Datei (<c>%ProgramData%\ICT-Baden\Vitrine\fido-credentials.json</c>). Jede Operation liest die Datei
/// und schreibt sie bei Änderungen vollständig neu; ein Schreiber (der Dienst), Zugriffe nacheinander.
/// </summary>
public sealed class JsonFidoStore(IFidoStoreFile file) : IFidoCredentialStore, IFidoGroupCache
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<FidoCredential?> GetAsync(string idHash, CancellationToken ct = default) =>
        await Read(d => d.Credentials.FirstOrDefault(c => string.Equals(c.IdHash, idHash, StringComparison.OrdinalIgnoreCase)), ct).ConfigureAwait(false);

    public async Task<IReadOnlyList<FidoCredential>> ListAsync(string? personSid = null, CancellationToken ct = default) =>
        await Read<IReadOnlyList<FidoCredential>>(d => d.Credentials
            .Where(c => personSid is null || string.Equals(c.PersonSid, personSid, StringComparison.OrdinalIgnoreCase)).ToList(), ct).ConfigureAwait(false);

    public Task AddAsync(FidoCredential credential, IFidoStoreWriter? writer = null, CancellationToken ct = default) => Change(d =>
    {
        if (d.Credentials.Any(c => string.Equals(c.IdHash, credential.IdHash, StringComparison.OrdinalIgnoreCase)))
            throw new FidoStoreException(Localization.ErrorCodes.FidoKeyAlreadyRegistered, "credential already registered");
        d.Credentials.Add(credential);
        return true;
    }, ct);

    public Task<bool> RevokeAsync(string idHash, FidoRevocation revocation, IFidoStoreWriter? writer = null, CancellationToken ct = default) => Change(d =>
    {
        var c = d.Credentials.FirstOrDefault(c => string.Equals(c.IdHash, idHash, StringComparison.OrdinalIgnoreCase));
        if (c is not { IsActive: true }) return false;
        c.Status = FidoCredentialStatus.Revoked;
        c.RevokedAt = revocation.At;
        c.RevokedBySid = revocation.BySid;
        c.RevokedByName = revocation.ByName;
        c.RevokeReason = revocation.Reason;
        return true;
    }, ct);

    public Task<bool> TouchAsync(string idHash, uint signCount, DateTimeOffset usedAt, CancellationToken ct = default) => Change(d =>
    {
        var c = d.Credentials.FirstOrDefault(c => string.Equals(c.IdHash, idHash, StringComparison.OrdinalIgnoreCase));
        if (c is null) return false;
        c.SignCount = signCount;
        c.LastUsedAt = usedAt;
        return true;
    }, ct);

    async Task<FidoGroupSnapshot?> IFidoGroupCache.GetAsync(string sid, CancellationToken ct) =>
        await Read(d => d.People.FirstOrDefault(p => string.Equals(p.Sid, sid, StringComparison.OrdinalIgnoreCase)), ct).ConfigureAwait(false);

    public Task SetAsync(FidoGroupSnapshot snapshot, CancellationToken ct = default) => Change(d =>
    {
        d.People.RemoveAll(p => string.Equals(p.Sid, snapshot.Sid, StringComparison.OrdinalIgnoreCase));
        d.People.Add(snapshot);
        return true;
    }, ct);

    private async Task<T> Read<T>(Func<FidoStoreDocument, T> f, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { return f(Load()); }
        finally { _gate.Release(); }
    }

    private async Task<bool> Change(Func<FidoStoreDocument, bool> f, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var d = Load();
            if (!f(d)) return false;
            try { file.Write(JsonSerializer.Serialize(d, Json)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
            {
                throw new FidoStoreException(Localization.ErrorCodes.FidoStoreError, ex.Message, ex);
            }
            return true;
        }
        finally { _gate.Release(); }
    }

    private FidoStoreDocument Load()
    {
        string? text;
        try { text = file.Read(); }
        catch (FidoStoreException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            throw new FidoStoreException(Localization.ErrorCodes.FidoStoreError, ex.Message, ex);
        }
        if (string.IsNullOrWhiteSpace(text)) return new FidoStoreDocument();
        try { return JsonSerializer.Deserialize<FidoStoreDocument>(text, Json) ?? new FidoStoreDocument(); }
        // Eine kaputte Datei nie still durch eine leere ersetzen: Fehler, Schreiben unterbleibt
        catch (JsonException ex) { throw new FidoStoreException(Localization.ErrorCodes.FidoStoreError, "store unreadable: " + ex.Message, ex); }
    }
}
