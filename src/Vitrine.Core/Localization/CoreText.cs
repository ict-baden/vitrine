// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Resources;

namespace Vitrine.Core.Localization;

/// <summary>
/// Texte aus Vitrine.Core (Resources/CoreStrings*.resx): Meldungen der Anmeldeverfahren, Entsperr-Regeln,
/// Protokollprüfung (richtlinien/13: kein Text fest im Code). Ein fehlender Schlüssel erscheint als „[Key]“ und fällt
/// im Test <c>TextKeyTests</c> auf.
/// </summary>
public static class CoreText
{
    public static readonly ResourceManager Strings = new("Vitrine.Core.Resources.CoreStrings", typeof(CoreText).Assembly);

    public static string T(string key) => Strings.GetString(key, CultureInfo.CurrentUICulture) ?? $"[{key}]";

    public static string F(string key, params object?[] args) => string.Format(CultureInfo.CurrentCulture, T(key), args);

    /// <summary>Meldung mit Fehlercode („Text (VIT-0101)“), Text aus <c>Error_VIT0101</c>.</summary>
    public static string Error(string code, params object?[] args) => ErrorCodes.Format(Strings, code, args);
}

/// <summary>
/// Fehlercodes (richtlinien/13 Punkt 9): Jede Fehlermeldung zeigt zum übersetzten Text einen Code, den der Support
/// unabhängig von der Sprache zuordnen kann. Texte stehen unter <c>Error_VIT&lt;nnnn&gt;</c> in der Sprachdatei dessen, der
/// den Fehler meldet (CoreStrings oder UiStrings der App); die Schnittstelle antwortet auf Englisch mit Code.
/// Liste mit Bedeutung: docs/error-codes.md.
/// </summary>
public static class ErrorCodes
{
    // ---- App und Konfiguration (UiStrings) ----
    public const string ConfigUnreadable = "VIT-0001";
    public const string PolicyUnreadable = "VIT-0002";
    public const string PluginNotLoaded = "VIT-0003";
    public const string PluginIdTaken = "VIT-0004";
    public const string HotkeyInUse = "VIT-0005";
    public const string SaveFailed = "VIT-0006";
    public const string SaveNeedsAdmin = "VIT-0007";
    public const string ApplyConfigInvalid = "VIT-0008";
    public const string AdminTaskFailed = "VIT-0009";
    public const string Unexpected = "VIT-0010";
    public const string PreferencesNotSaved = "VIT-0011";
    public const string ConfigNotProtected = "VIT-0012";
    public const string PluginsNotProtected = "VIT-0013";
    public const string ApplyConfigRefused = "VIT-0014";
    public const string ConfigEntryInvalid = "VIT-0015";
    public const string UnlockFallsBackToWindows = "VIT-0016";
    public const string UnlockRulesNeverMatch = "VIT-0017";

    // ---- Protokoll (CoreStrings) ----
    public const string LogLineUnreadable = "VIT-0020";
    public const string LogChainBroken = "VIT-0021";
    public const string LogEntryModified = "VIT-0022";
    public const string LogFileUnreadable = "VIT-0023";

    // ---- Anmeldung (CoreStrings) ----
    public const string SignInFailed = "VIT-0100";
    public const string WrongCredentials = "VIT-0101";
    public const string AccountRestricted = "VIT-0102";
    public const string AccountDisabled = "VIT-0103";
    public const string AccountLockedOut = "VIT-0104";
    public const string NoLogonServer = "VIT-0105";
    public const string LogonNotAllowedHere = "VIT-0106";
    public const string SecretMissing = "VIT-0107";
    public const string UseUpnForEntra = "VIT-0108";
    public const string WindowsLogonError = "VIT-0109";

    public const string EntraNotConfigured = "VIT-0110";
    public const string SignInCancelled = "VIT-0111";
    public const string EntraError = "VIT-0112";
    public const string TenantNotAllowed = "VIT-0113";
    public const string SignInTooOld = "VIT-0114";
    public const string AuthContextNotMet = "VIT-0115";
    public const string AuthContextInvalid = "VIT-0116";
    public const string EntraTenantNotPinned = "VIT-0117";

    /// <summary>Microsoft zum Entsperren: ID-Token ohne auth_time – Einmal-Klick-Anmeldung (SSO) wird abgelehnt.</summary>
    public const string EntraAuthTimeMissing = "VIT-0180";
    /// <summary>Microsoft zum Entsperren: keine Anmeldung nach Beginn des Versuchs (Windows hat eine bestehende verwendet).</summary>
    public const string EntraSignInNotFresh = "VIT-0181";

    // ---- Anmeldefenster für Microsoft (WebView2, seit 2026-10-27; CoreStrings) ----
    /// <summary>Microsoft Edge WebView2 Runtime fehlt: kein Anmeldefenster, Microsoft nicht verfügbar (auch nicht am Sperrbildschirm).</summary>
    public const string WebViewRuntimeMissing = "VIT-0190";
    /// <summary>Warnung: Entra.UseBroker ist an – der Windows-Kontobroker merkt sich Konten und meldet mit dem Sitzungskonto an.</summary>
    public const string EntraBrokerRemembersAccounts = "VIT-0191";
    /// <summary>Das Anmeldefenster ließ sich nicht öffnen (WebView2 startet nicht).</summary>
    public const string SignInWindowFailed = "VIT-0192";
    /// <summary>Das Anmeldefenster sollte eine Adresse öffnen, die weder Microsoft noch in Entra.AllowedSignInHosts ist.</summary>
    public const string SignInHostBlocked = "VIT-0193";
    /// <summary>Der Windows-Anmeldedialog eines abgebrochenen Versuchs ist noch offen und ließ sich nicht schließen.</summary>
    public const string WindowsLogonStillOpen = "VIT-0194";

    public const string HelloUnavailable = "VIT-0120";
    public const string HelloRetriesExhausted = "VIT-0122";
    public const string HelloBusy = "VIT-0123";
    public const string HelloDisabledByPolicy = "VIT-0124";
    public const string HelloNotConfigured = "VIT-0125";

    public const string UnlockPasswordNotSet = "VIT-0130";
    public const string UnlockPasswordWrong = "VIT-0131";

    public const string NotAllowedToUnlock = "VIT-0140";
    public const string DomainNotAllowed = "VIT-0141";
    public const string AdminRequired = "VIT-0142";
    public const string PersonalAdminRequired = "VIT-0143";
    public const string PersonalSignatureRequired = "VIT-0144";
    public const string PleaseWait = "VIT-0145";

    public const string PinTooShort = "VIT-0150";
    public const string PinMismatch = "VIT-0151";

    // ---- Windows sperren (Win+L, Rückfall LockWorkStation; nur Protokoll) ----
    public const string FallbackLockFailed = "VIT-0160";
    public const string FallbackLockDisconnected = "VIT-0161";
    public const string WinLNotDisabled = "VIT-0162";
    public const string WinLMachinePolicy = "VIT-0163";

    // ---- Eigener Sperr-Desktop (Lock.Mode = Desktop) und Fluchterkennung; nur Protokoll ----
    /// <summary>Sperr-Desktop konnte nicht angelegt werden – diese Sperre läuft mit Abdeckungen.</summary>
    public const string LockDesktopCreateFailed = "VIT-0450";
    /// <summary>Wechsel auf den Sperr-Desktop gescheitert – diese Sperre läuft mit Abdeckungen.</summary>
    public const string LockDesktopSwitchFailed = "VIT-0451";
    /// <summary>Nach einem fremden Desktop-Wechsel ließ sich der erwartete Desktop nicht zurückholen – Windows wird gesperrt.</summary>
    public const string LockDesktopRestoreFailed = "VIT-0452";
    /// <summary>Oberfläche auf dem Sperr-Desktop (eigener Thread, Fenster) startete nicht – diese Sperre läuft mit Abdeckungen.</summary>
    public const string LockDesktopUiFailed = "VIT-0453";
    /// <summary>Zurück auf den Standard-Desktop gescheitert (Entsperren, externe Anmeldung); wird wiederholt.</summary>
    public const string LockDesktopReturnFailed = "VIT-0454";
    /// <summary>Verwaister Sperr-Desktop war noch Eingabe-Desktop (Absturz); Wächter bzw. Start haben zurückgeschaltet.</summary>
    public const string LockDesktopStranded = "VIT-0455";
    /// <summary>Entsperr-Dialog nicht auf dem Sperr-Desktop darstellbar – er erscheint auf dem Standard-Desktop mit Abdeckungen.</summary>
    public const string LockDesktopPromptFailed = "VIT-0456";
    /// <summary>Vorschau des Standard-Desktops nicht erstellbar – der Sperr-Desktop zeigt keine Vorschau.</summary>
    public const string LockDesktopPreviewFailed = "VIT-0457";

    // ---- Schnittstelle (Named Pipe; Antworten auf Englisch mit Code, UiStrings nur für den Dialog) ----
    public const string PipeInvalidJson = "VIT-0201";
    public const string PipeObjectExpected = "VIT-0202";
    public const string PipeReasonMissing = "VIT-0203";
    public const string PipeUnknownCommand = "VIT-0204";
    public const string PipeDisabled = "VIT-0205";
    public const string PipeSignatureNotGiven = "VIT-0206";
    public const string PipeRequestTooLong = "VIT-0207";
    public const string PipeFieldTooLong = "VIT-0208";
    public const string PipeLocked = "VIT-0209";
    public const string PipeNameTaken = "VIT-0210";
    public const string PipeScopeNotAllowed = "VIT-0211";
    public const string PipeScopesMixed = "VIT-0212";
    public const string PipeEntraRequired = "VIT-0213";

    // ---- Protokoll des Dienstes, Format 3 (#15; CoreStrings) ----
    /// <summary>Signatur abgelehnt: Der Dienst sollte das Protokoll schreiben, ist aber nicht erreichbar.</summary>
    public const string AuditServiceUnavailable = "VIT-0300";
    public const string LogSignatureInvalid = "VIT-0301";
    public const string LogUnknownKey = "VIT-0302";
    public const string LogSequenceGap = "VIT-0303";
    public const string LogTruncated = "VIT-0304";
    public const string LogAnchorMismatch = "VIT-0305";
    public const string LogFileMissing = "VIT-0306";
    public const string LogWrongMonth = "VIT-0307";
    public const string LogUnsignedAfterSigned = "VIT-0308";
    public const string LogPreviousFileMismatch = "VIT-0309";
    public const string LogNoPublicKey = "VIT-0310";
    /// <summary>Der Dienst hat das ID-Token von Microsoft Entra ID nicht anerkannt (Signatur, Aussteller, Zielgruppe, Alter, schon benutzt).</summary>
    public const string ServiceEntraTokenRejected = "VIT-0311";
    /// <summary>Der Dienst konnte die Signaturschlüssel von Microsoft nicht abrufen.</summary>
    public const string ServiceEntraKeysUnavailable = "VIT-0312";
    /// <summary>Bestätigung der Anmeldung beim Dienst abgelaufen, unbekannt oder schon benutzt.</summary>
    public const string ServiceTicketInvalid = "VIT-0313";
    /// <summary>Zu viele Anmeldeprüfungen aus einer Sitzung in kurzer Zeit.</summary>
    public const string ServiceTooManyChecks = "VIT-0314";
    /// <summary>Nur Protokoll: Der Dienst hat einen Eintrag der Sitzungs-App abgelehnt (Ereignis, das nur er schreibt).</summary>
    public const string ServiceEntryRefused = "VIT-0315";
    /// <summary>Nur Protokoll: Ende der Protokolldatei passt nicht zum Anker (abgeschnitten, ersetzt, gelöscht).</summary>
    public const string ServiceAnchorMismatch = "VIT-0316";
    /// <summary>Schlüssel des Protokolls nicht anlegbar oder nicht ladbar.</summary>
    public const string AuditKeyError = "VIT-0317";
    /// <summary>Nur Protokoll: Einträge gingen verloren, weil der Puffer der App voll war.</summary>
    public const string AuditBufferOverflow = "VIT-0318";
    /// <summary>Signaturverfahren, das der Dienst nicht kennt oder für Signaturen nicht zulässt.</summary>
    public const string ServiceMethodNotAllowed = "VIT-0319";
    /// <summary>ID-Token einer Microsoft-Signatur ohne auth_time (optionaler Claim fehlt in der App-Registrierung).</summary>
    public const string ServiceEntraAuthTimeMissing = "VIT-0320";
    /// <summary>Microsoft-Anmeldung nicht frisch: vor der Signaturanfrage oder älter als Entra.MaxAuthAgeSeconds.</summary>
    public const string ServiceEntraNotFresh = "VIT-0321";
    /// <summary>Der Dienst konnte einen Eintrag nicht schreiben; die App behält ihn und sendet ihn später erneut.</summary>
    public const string AuditWriteFailed = "VIT-0322";
    /// <summary>Nur Protokoll: Audit.Directory können Benutzer ändern – der Dienst schreibt in den Standardordner.</summary>
    public const string AuditDirectoryNotProtected = "VIT-0323";
    /// <summary>Zeile mit einem anderen als dem aktuellen Schlüssel signiert, ohne AuditKeyRotated dazwischen.</summary>
    public const string LogKeyNotCurrent = "VIT-0324";
    /// <summary>Sitzungs-App: Einträge kommen seit über einer Minute nicht beim Dienst an (Ereignisprotokoll, Einstellungen).</summary>
    public const string AuditNotDelivered = "VIT-0330";
    /// <summary>Nur Protokoll (Dienst): Gegenstelle auf einer Pipe des Dienstes ist nicht Vitrine.exe aus dem Programmordner.</summary>
    public const string AuditClientRejected = "VIT-0331";
    /// <summary>Nur Protokoll (Dienst): Benutzer der Gegenstelle auf der Protokoll-Pipe nicht feststellbar.</summary>
    public const string AuditClientUnidentified = "VIT-0332";
    /// <summary>Nur Protokoll (Dienst): unerwarteter Fehler beim Bedienen einer Verbindung der Protokoll-Pipe.</summary>
    public const string AuditPipeFailed = "VIT-0333";

    // ---- Rollen, Notfall-Anmeldung, Begründungen, Berechtigungsbericht (0.5.0; Texte VIT-0430–0434 CoreStrings, 0435 UiStrings) ----
    /// <summary>Warnung: Niemand hat die Rolle „Einstellungen“ (Administratoren ausgenommen, Rollengruppe leer).</summary>
    public const string NoConfigAdmin = "VIT-0430";
    /// <summary>Die angemeldete Person hat keine der verlangten Rollen.</summary>
    public const string RoleRequired = "VIT-0431";
    /// <summary>Notfall-Anmeldung: Person in keiner Notfall-Gruppe (oder Notfall-Anmeldung aus).</summary>
    public const string EmergencyNotAllowed = "VIT-0432";
    /// <summary>Begründung fehlt oder ist zu kurz.</summary>
    public const string ReasonTooShort = "VIT-0433";
    /// <summary>Notfall-Anmeldung nur mit dem Windows-Kennwort.</summary>
    public const string EmergencyNeedsWindowsPassword = "VIT-0434";
    /// <summary>Berechtigungsbericht konnte nicht geschrieben werden.</summary>
    public const string ReportFailed = "VIT-0435";
    // ---- Sicherheitsschlüssel (Verfahren „fido“, docs/security-keys.md; CoreStrings) ----
    /// <summary>Windows-WebAuthn-API fehlt oder ist zu alt (webauthn.dll, Windows 10 1903 und neuer).</summary>
    public const string FidoUnavailable = "VIT-0400";
    /// <summary>Kein aktiver Sicherheitsschlüssel registriert.</summary>
    public const string FidoNoKeys = "VIT-0401";
    /// <summary>Der Dienst ist nicht erreichbar oder schreibt das Protokoll nicht – er prüft die Schlüssel.</summary>
    public const string FidoServiceRequired = "VIT-0402";
    /// <summary>Challenge unbekannt, abgelaufen, schon benutzt oder aus einer anderen Sitzung.</summary>
    public const string FidoChallengeInvalid = "VIT-0403";
    /// <summary>Antwort des Schlüssels ungültig (Signatur, RP ID, clientDataJSON).</summary>
    public const string FidoAssertionInvalid = "VIT-0404";
    /// <summary>Schlüssel nicht (für diese RP ID) registriert.</summary>
    public const string FidoKeyUnknown = "VIT-0405";
    public const string FidoKeyRevoked = "VIT-0406";
    public const string FidoModelNotAllowed = "VIT-0407";
    /// <summary>Signaturzähler nicht gestiegen: möglicherweise kopierter Schlüssel.</summary>
    public const string FidoCloneSuspected = "VIT-0408";
    /// <summary>Nach Fehlversuchen vorübergehend gesperrt ({0} Minuten).</summary>
    public const string FidoBlocked = "VIT-0409";
    /// <summary>Schlüssel hat Anwesenheit oder PIN nicht bestätigt.</summary>
    public const string FidoUserVerificationMissing = "VIT-0410";
    /// <summary>Konto deaktiviert, gesperrt, abgelaufen, eingeschränkt oder nicht mehr vorhanden.</summary>
    public const string FidoAccountUnusable = "VIT-0411";
    /// <summary>Kein Domänencontroller und keine ausreichend frischen Gruppen (Fido.OfflineMaxHours).</summary>
    public const string FidoOfflineTooLong = "VIT-0412";
    /// <summary>Registrieren: Konto nicht gefunden.</summary>
    public const string FidoAccountNotFound = "VIT-0413";
    /// <summary>Registrieren für das eigene Konto ist nicht erlaubt (Fido.AllowSelfRegistration).</summary>
    public const string FidoSelfRegistration = "VIT-0414";
    /// <summary>Höchstzahl aktiver Schlüssel der Person erreicht (Fido.MaxKeysPerPerson).</summary>
    public const string FidoTooManyKeys = "VIT-0415";
    /// <summary>Die angemeldete Person darf keine Schlüssel registrieren oder widerrufen.</summary>
    public const string FidoNotRegistrar = "VIT-0416";
    /// <summary>Bezeichnung oder Begründung fehlt bzw. zu kurz.</summary>
    public const string FidoReasonTooShort = "VIT-0417";
    /// <summary>Antwort des Schlüssels auf die Registrierung ungültig oder Schlüsseltyp nicht unterstützt.</summary>
    public const string FidoRegistrationInvalid = "VIT-0418";
    public const string FidoKeyAlreadyRegistered = "VIT-0419";
    /// <summary>Ablage der Schlüssel können Benutzer ändern: nicht benutzt (wie VIT-0012).</summary>
    public const string FidoStoreNotProtected = "VIT-0420";
    /// <summary>Ablage der Schlüssel nicht les- oder schreibbar.</summary>
    public const string FidoStoreError = "VIT-0421";
    /// <summary>Warnung: Schlüssel sind mit einer anderen RP ID registriert als Fido.RpId und gelten nicht.</summary>
    public const string FidoRpIdChanged = "VIT-0422";
    /// <summary>Warnung: Der Windows-Sicherheitsdialog fehlt in Security.AuthUiProcesses – er bekäme während der Sperre keine Eingaben.</summary>
    public const string FidoDialogBlocked = "VIT-0423";
    /// <summary>Auf dem vorgehaltenen Schlüssel ist keiner der registrierten Schlüssel (Windows: NTE_NOT_FOUND).</summary>
    public const string FidoNoMatchingKey = "VIT-0424";
    /// <summary>Sonstiger Fehler des Windows-Sicherheitsdialogs ({0}).</summary>
    public const string FidoWebAuthnError = "VIT-0425";
    /// <summary>Registrierung abgelaufen, unbekannt oder aus einer anderen Sitzung.</summary>
    public const string FidoRegistrationExpired = "VIT-0426";
    /// <summary>Liste der Schlüssel nur für Registrierende, Einstellungs-Administratoren und Prüfer.</summary>
    public const string FidoListNotAllowed = "VIT-0427";
    /// <summary>Schlüssel für eine Signatur oder Registrierung nur aus dem offenen Dialog dafür (nicht nebenbei).</summary>
    public const string FidoPurposeNotOpen = "VIT-0428";

    // ---- Sicherheitsschlüssel im Active Directory (Fido.Store = ActiveDirectory) ----
    /// <summary>Schreiben ins AD braucht das Windows-Kennwort der registrierenden Person (kein Token, kein Kennwort übergeben).</summary>
    public const string FidoDirectoryCredentialRequired = "VIT-0470";
    /// <summary>AD nicht erreichbar oder nicht lesbar: Der Dienst arbeitet mit dem Zwischenspeicher.</summary>
    public const string FidoDirectoryUnavailable = "VIT-0471";
    /// <summary>Anmeldung am AD abgelehnt oder keine Rechte zum Schreiben (Kennwort falsch, Rechte auf CN=SecurityKeys fehlen).</summary>
    public const string FidoDirectoryAccessDenied = "VIT-0472";
    /// <summary>Am AD angemeldet ist eine andere Person als die registrierende.</summary>
    public const string FidoDirectoryIdentityMismatch = "VIT-0473";
    /// <summary>Kein Domänenmitglied, Domäne nicht gefunden oder Container fehlt (Initialize-VitrineDirectory.ps1).</summary>
    public const string FidoDirectoryNotConfigured = "VIT-0474";
    /// <summary>Ein Objekt im AD ist kein gültiger Schlüssel (Inhalt, Version, Kennung) und wird ignoriert.</summary>
    public const string FidoDirectoryEntryInvalid = "VIT-0475";
    /// <summary>Noch nie mit dem AD abgeglichen: keine Schlüssel bekannt.</summary>
    public const string FidoDirectoryNeverSynced = "VIT-0476";

    /// <summary>Alle Codes (für Tests und docs/error-codes.md).</summary>
    public static IReadOnlyList<string> All { get; } = typeof(ErrorCodes)
        .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
        .Where(f => f.IsLiteral && f.FieldType == typeof(string))
        .Select(f => (string)f.GetRawConstantValue()!)
        .Order(StringComparer.Ordinal)
        .ToList();

    /// <summary>Schlüssel des Texts in der .resx: "VIT-0101" → "Error_VIT0101".</summary>
    public static string Key(string code) => "Error_" + code.Replace("-", "", StringComparison.Ordinal);

    /// <summary>„Text (VIT-0101)“ in der Schreibweise der Sprache (ErrorFormat in der jeweiligen .resx).</summary>
    public static string Format(ResourceManager strings, string code, params object?[] args)
    {
        var culture = CultureInfo.CurrentUICulture;
        var text = strings.GetString(Key(code), culture) ?? $"[{Key(code)}]";
        if (args.Length > 0) text = string.Format(CultureInfo.CurrentCulture, text, args);
        return WithCode(text, code);
    }

    /// <summary>Hängt den Code an einen schon übersetzten Text an (z. B. Meldung eines Plugins).</summary>
    public static string WithCode(string text, string? code)
    {
        if (string.IsNullOrEmpty(code) || text.Contains(code, StringComparison.Ordinal)) return text;
        var pattern = CoreText.Strings.GetString("ErrorFormat", CultureInfo.CurrentUICulture) ?? "{0} ({1})";
        return string.Format(CultureInfo.CurrentCulture, pattern, text, code);
    }
}
