// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Config;

/// <summary>
/// Eingebautes Verfahren „Sicherheitsschlüssel“ (<c>fido</c>): FIDO2-Schlüssel, die für Vitrine registriert sind, prüft der
/// Dienst selbst (ohne Microsoft Entra ID, auch ohne Netzwerk). Eine PIN bzw. Benutzerüberprüfung am Schlüssel ist immer
/// Pflicht und nicht einstellbar. Doku: docs/security-keys.md.
/// </summary>
public sealed class FidoSettings
{
    /// <summary>Standard-Kennung der vertrauenden Seite: bewusst kein DNS-Name, damit keine Webseite sie beanspruchen kann.</summary>
    public const string DefaultRpId = "vitrine";

    /// <summary>
    /// Kennung der vertrauenden Seite (WebAuthn „RP ID“), mit der Schlüssel registriert und geprüft werden. Nach der ersten
    /// Registrierung nicht mehr ändern: Schlüssel gelten nur für die Kennung, mit der sie registriert wurden (VIT-0422).
    /// </summary>
    public string RpId { get; set; } = DefaultRpId;

    /// <summary>Registrierende dürfen auch für ihr eigenes Konto einen Schlüssel registrieren (Vier-Augen-Prinzip aus).</summary>
    public bool AllowSelfRegistration { get; set; } = false;

    /// <summary>Zugelassene Schlüsselmodelle als AAGUID. Leer = jedes Modell.</summary>
    public List<string> AllowedModels { get; set; } = new();

    /// <summary>Höchstens so viele aktive Schlüssel je Person.</summary>
    public int MaxKeysPerPerson { get; set; } = 2;

    /// <summary>Nach so vielen abgelehnten Anmeldungen mit einem Schlüssel bzw. für eine Person vorübergehend gesperrt.</summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>So lange (Minuten) bleibt ein Schlüssel bzw. eine Person nach zu vielen Fehlversuchen gesperrt.</summary>
    public int BlockMinutes { get; set; } = 5;

    /// <summary>
    /// Ohne Domänencontroller gelten die zuletzt gelesenen Gruppen höchstens so viele Stunden, danach wird abgelehnt (VIT-0412).
    /// </summary>
    public int OfflineMaxHours { get; set; } = 24;

    /// <summary>
    /// Ablage der registrierten Schlüssel: <see cref="FidoStoreKind.Local"/> (geschützte Datei dieses Rechners, Standard) oder
    /// <see cref="FidoStoreKind.ActiveDirectory"/> (ein Objekt je Schlüssel im AD, gilt auf allen Rechnern der Domäne).
    /// Wird beim Start des Dienstes gelesen.
    /// </summary>
    public FidoStoreKind Store { get; set; } = FidoStoreKind.Local;

    /// <summary>
    /// Container von Vitrine im AD (DN, z. B. „CN=Vitrine,CN=Program Data,DC=contoso,DC=com“); die Schlüssel liegen in
    /// „CN=SecurityKeys“ darunter. Leer = „CN=Vitrine,CN=Program Data,&lt;Domäne&gt;“.
    /// </summary>
    public string DirectoryContainer { get; set; } = "";

    /// <summary>Alle so viele Minuten liest der Dienst die Schlüssel aus dem AD neu (1–1440).</summary>
    public int SyncMinutes { get; set; } = 15;
}

/// <summary>Wo die registrierten Sicherheitsschlüssel liegen.</summary>
public enum FidoStoreKind
{
    /// <summary>Datei des Dienstes auf diesem Rechner (%ProgramData%\ICT-Baden\Vitrine\fido-credentials.json).</summary>
    Local,
    /// <summary>Active Directory (serviceConnectionPoint-Objekte unter CN=SecurityKeys), lokal zwischengespeichert.</summary>
    ActiveDirectory,
}
