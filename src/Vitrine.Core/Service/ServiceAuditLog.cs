// SPDX-License-Identifier: MIT
using Vitrine.Core.Audit;

namespace Vitrine.Core.Service;

/// <summary>
/// Einziger Weg, auf dem der Dienst ins Protokoll schreibt: signiert (<see cref="SignedAuditLog"/>, Format 3), solange er
/// das Protokoll übernommen hat, sonst wie früher (<see cref="AuditLog"/>, Format 2 – ohne Überwachung oder ohne Schlüssel).
/// Vorher schrieb ein Zweig (Win+L-Aufräumen nach Verlust der App) am signierten Protokoll vorbei eine unsignierte Zeile in
/// die Monatsdatei; die Prüfung meldete danach VIT-0308 (Prüfung vom 2026-10-26).
/// Lässt sich eine signierte Zeile nicht schreiben (Ordner weg, Platte voll), geht sie wenigstens an <c>errorSink</c>
/// (Ereignisprotokoll) – nie unsigniert in die Datei.
/// </summary>
public sealed class ServiceAuditLog(AuditLog unsigned, IAuditSink? errorSink = null)
{
    private volatile SignedAuditLog? _signed;

    /// <summary>Signiertes Protokoll des Dienstes; null = der Dienst schreibt unsigniert (Format 2).</summary>
    public SignedAuditLog? Signed
    {
        get => _signed;
        set => _signed = value;
    }

    public AuditEntry? Write(AuditEventType type, string? detail = null)
    {
        if (_signed is { } signed)
        {
            var entry = signed.Write(new AuditRecord(type, "SYSTEM", AuditAssurance.Service) { Detail = detail });
            if (entry is null && signed.LastError is { } err)
            {
                try { errorSink?.Write(new AuditEntry { Event = AuditEventType.Error, SessionUser = "SYSTEM", Detail = $"{type}: {detail} ({err})" }); }
                catch { /* Ereignisprotokoll ist ein Zusatz */ }
            }
            return entry;
        }
        return unsigned.Write(type, detail: detail);
    }
}
