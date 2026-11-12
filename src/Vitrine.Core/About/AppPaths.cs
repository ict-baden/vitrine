// SPDX-License-Identifier: MIT
namespace Vitrine.Core.About;

/// <summary>
/// Kennungen und Ablageorte nach richtlinien/12 an einer Stelle. Bis 2026-10 hießen sie anders („Vitrine“ ohne
/// Herstellerpräfix); die alten Orte werden gelesen, wenn es die neuen noch nicht gibt (Übergang, docs/installation.md).
/// </summary>
public static class AppPaths
{
    /// <summary>Herstellerpräfix für Registry, Ordner, Mutex und Pipe (richtlinien/12, unabhängig von der Firmierung).</summary>
    public const string Vendor = "ICT-Baden";

    // ---------------- Registry ----------------

    /// <summary>Gruppenrichtlinien und Intune (ADMX): HKLM bzw. HKCU\SOFTWARE\Policies\ICT-Baden\Vitrine.</summary>
    public const string PolicyKey = @"SOFTWARE\Policies\" + Vendor + @"\" + AppInfo.Name;

    /// <summary>Alter Richtlinienpfad (Stand bis 2026-10-19, ADMX ohne Herstellerpräfix); wird weiter gelesen.</summary>
    public const string LegacyPolicyKey = @"SOFTWARE\Policies\" + AppInfo.Name;

    /// <summary>Eigene Einträge des Installers: HKLM\SOFTWARE\ICT-Baden\Vitrine.</summary>
    public const string ProductKey = @"SOFTWARE\" + Vendor + @"\" + AppInfo.Name;

    /// <summary>
    /// Gesperrte Sitzungen über einen Neustart des Dienstes hinweg (Update der MSI): flüchtiger Schlüssel (nur im Speicher,
    /// weg nach dem Neustart von Windows), schreibt nur der Dienst (SYSTEM), Rechte von HKLM\SOFTWARE.
    /// </summary>
    public const string ServiceStateKey = ProductKey + @"\ServiceState";

    /// <summary>
    /// Zustand pro Benutzer unter HKCU\Software\ICT-Baden\Vitrine\State: Merkwert für DisableLockWorkstation
    /// (<see cref="Lock.LockWorkstationPolicy"/>). In der Registry statt in einer Datei, damit der Dienst (SYSTEM) ihn über
    /// HKU\&lt;SID&gt; findet.
    /// </summary>
    public const string UserStateKey = @"Software\" + Vendor + @"\" + AppInfo.Name + @"\State";

    /// <summary>
    /// Protokoll des Dienstes (#15): Anker (letzte Nummer und Hash je Monat), öffentliche Schlüssel und ob der Dienst das
    /// Protokoll schreibt. Legt der Dienst an; schreiben darf nur SYSTEM, lesen alle (für --verify-log).
    /// </summary>
    public const string AuditStateKey = ProductKey + @"\Audit";

    /// <summary>Name der CNG-Maschinenschlüssel des Protokolls (dahinter eine laufende Nummer).</summary>
    public const string AuditKeyName = Vendor + "." + AppInfo.Name + ".Audit";

    /// <summary>
    /// Signaturzähler der Sicherheitsschlüssel je Rechner, wenn die Schlüssel im Active Directory liegen (Fido.Store =
    /// ActiveDirectory): ein Wert je Schlüssel. Legt der Dienst an; nur SYSTEM hat Zugriff.
    /// </summary>
    public const string FidoCountersKey = ProductKey + @"\FidoCounters";

    // ---------------- Windows-Kennungen ----------------

    /// <summary>Quelle im Ereignisprotokoll „Anwendung“.</summary>
    public const string EventSource = Vendor + " " + AppInfo.Name;

    /// <summary>Alte Quelle; wird noch beschrieben, wenn nur sie registriert ist (Filter in SIEM-Systemen).</summary>
    public const string LegacyEventSource = AppInfo.Name;

    /// <summary>Einzelinstanz pro Sitzung (Local\ ist schon pro Sitzung).</summary>
    public const string SingleInstanceMutex = @"Local\" + Vendor + "." + AppInfo.Name + ".SingleInstance";

    /// <summary>
    /// Lokale Schnittstelle: \\.\pipe\ICT-Baden.Vitrine.&lt;Sitzung&gt;. Pipes sind nicht pro Sitzung getrennt, deshalb
    /// steht die Sitzungsnummer im Namen.
    /// </summary>
    public static string PipeName(int sessionId) => $"{Vendor}.{AppInfo.Name}.{sessionId}";

    /// <summary>Windows-Dienst (Name in der Dienstverwaltung), überwacht die Sitzungs-Apps.</summary>
    public const string ServiceName = Vendor + "." + AppInfo.Name;

    /// <summary>Anzeigename des Dienstes.</summary>
    public const string ServiceDisplayName = Vendor + " " + AppInfo.Name;

    /// <summary>Pipe des Dienstes (\\.\pipe\ICT-Baden.Vitrine.Service), über die sich die Sitzungs-Apps melden.</summary>
    public const string ServicePipe = Vendor + "." + AppInfo.Name + ".Service";

    /// <summary>Pipe des Dienstes für das Protokoll (\\.\pipe\ICT-Baden.Vitrine.Audit): Einträge und Signaturen der Sitzungs-Apps.</summary>
    public const string AuditPipe = Vendor + "." + AppInfo.Name + ".Audit";

    /// <summary>
    /// Anfang des Namens von Vitrines eigenem Desktop für <c>Lock.Mode = Desktop</c> (in WinSta0, also pro Sitzung). Dahinter
    /// hängt Vitrine einen zufälligen Teil an: Ein Programm des Benutzers soll den Desktop nicht vorab unter dem erwarteten
    /// Namen anlegen können (CreateDesktop öffnet sonst den vorhandenen, mit dessen Fenstern und Rechten). Wächter und
    /// Neustart erkennen verwaiste Sperr-Desktops an diesem Anfang.
    /// </summary>
    public const string LockDesktopPrefix = "Vitrine-Lock";

    // ---------------- Ordner ----------------

    /// <summary>%ProgramData%\ICT-Baden\Vitrine – Gerätekonfiguration und Protokolle.</summary>
    public static string MachineDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Vendor, AppInfo.Name);

    /// <summary>%ProgramData%\Vitrine – alter Ort der Gerätekonfiguration.</summary>
    public static string LegacyMachineDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppInfo.Name);

    /// <summary>%LocalAppData%\Vitrine – Daten pro Benutzer (Sprache, Strg+Alt+Entf-Sicherung, Sperrmarke, Ersatzprotokoll).</summary>
    public static string UserDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppInfo.Name);

    /// <summary>%AppData%\Vitrine – alter Ort der Benutzer-Konfiguration.</summary>
    public static string LegacyUserDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppInfo.Name);

    public static string MachineConfigFile => Path.Combine(MachineDir, "config.json");

    /// <summary>Registrierte Sicherheitsschlüssel (Verfahren „fido“): schreibt nur der Dienst (SYSTEM), Benutzer lesen.</summary>
    public static string FidoCredentialsFile => Path.Combine(MachineDir, "fido-credentials.json");

    /// <summary>Zwischenspeicher der Sicherheitsschlüssel aus dem Active Directory: schreibt nur der Dienst, Benutzer lesen.</summary>
    public static string FidoDirectoryCacheFile => Path.Combine(MachineDir, "fido-directory-cache.json");
    public static string LegacyMachineConfigFile => Path.Combine(LegacyMachineDir, "config.json");
    public static string UserConfigFile => Path.Combine(UserDir, "config.json");
    public static string LegacyUserConfigFile => Path.Combine(LegacyUserDir, "config.json");

    /// <summary>Standardordner des Protokolls.</summary>
    public static string MachineLogDir => Path.Combine(MachineDir, "Logs");

    /// <summary>Alter Standardordner des Protokolls (nur noch zum Anzeigen älterer Dateien).</summary>
    public static string LegacyMachineLogDir => Path.Combine(LegacyMachineDir, "Logs");

    /// <summary>Ersatz, wenn der Protokollordner nicht beschreibbar ist.</summary>
    public static string UserLogDir => Path.Combine(UserDir, "Logs");

    /// <summary>
    /// %LocalAppData%\ICT-Baden\Vitrine\WebView – Profilordner des Anmeldefensters von Microsoft (WebView2), je Versuch
    /// ein Unterordner mit zufälligem Namen, nach dem Versuch gelöscht (<see cref="Auth.EphemeralProfiles"/>).
    /// </summary>
    public static string WebViewProfilesDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Vendor, AppInfo.Name, "WebView");

    /// <summary>Einstellungen des Benutzers, die keine Adminrechte brauchen (Sprache).</summary>
    public static string PreferencesFile => Path.Combine(UserDir, "preferences.json");
}
