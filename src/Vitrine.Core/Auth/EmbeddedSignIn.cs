// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Auth;

/// <summary>Was das eigene Anmeldefenster mit einer Navigation tut.</summary>
public enum SignInNavigation
{
    /// <summary>Weiter (Anmeldeseiten über HTTPS, about:blank).</summary>
    Allow,
    /// <summary>Umleitung auf die Umleitungs-URI: nicht laden, sondern an MSAL zurückgeben (Code in der Adresse).</summary>
    Complete,
    /// <summary>Abbrechen: alles andere (http zu anderen Hosts, file:, javascript:, eigene Protokolle).</summary>
    Block,
}

/// <summary>
/// Regeln für das eigene Anmeldefenster (WebView2), ohne WebView2 testbar: Erkennen der Umleitung, erlaubte
/// Navigationen. Die Umleitung wird nie geladen – auf http://localhost lauscht niemand, und der Code soll nicht an
/// einen fremden Dienst auf Port 80 gehen.
/// </summary>
public static class EmbeddedSignIn
{
    /// <summary>
    /// Ist <paramref name="candidate"/> die Umleitung auf <paramref name="redirect"/>? Schema, Host und Port genau,
    /// Pfad gleich (leer = „/“), Abfrage und Fragment beliebig (dort stehen code, state bzw. error). Nicht
    /// „http://localhost.contoso.com“, nicht „http://localhost@contoso.com“, nicht „https://localhost“.
    /// </summary>
    public static bool IsRedirect(Uri? candidate, Uri redirect)
    {
        if (candidate is null || !candidate.IsAbsoluteUri || !redirect.IsAbsoluteUri) return false;
        if (!string.IsNullOrEmpty(candidate.UserInfo)) return false;
        return string.Equals(candidate.Scheme, redirect.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(candidate.Host, redirect.Host, StringComparison.OrdinalIgnoreCase)
            && candidate.Port == redirect.Port
            && string.Equals(NormalizePath(candidate.AbsolutePath), NormalizePath(redirect.AbsolutePath), StringComparison.Ordinal);
    }

    private static string NormalizePath(string path) => path.Length == 0 ? "/" : path;

    /// <summary>
    /// Adressen von Microsoft, die die Anmeldung selbst braucht (Seiten, nicht Skripte/Bilder – die laden von den CDNs
    /// aadcdn.msftauth.net, aadcdn.msauth.net, logincdn.msauth.net u. a. und sind keine Navigationen). login.microsoft.com:
    /// FIDO2/Passkeys (rpId); device.login.microsoftonline.com: gerätebasierte Anmeldung; *.certauth.login.microsoftonline.com:
    /// zertifikatbasierte Anmeldung. Bewusst nicht: autologon.microsoftazuread-sso.com (nahtloses SSO mit dem Kerberos-Ticket
    /// der Windows-Sitzung – genau das soll nicht passieren), login.live.com (private Microsoft-Konten), Seiten zur
    /// Kennwortrücksetzung und Registrierung (mysignins, passwordreset), Hilfe- und Rechtsseiten.
    /// </summary>
    public static readonly IReadOnlyList<string> MicrosoftHosts =
    [
        "login.microsoftonline.com",
        "login.microsoft.com",
        "device.login.microsoftonline.com",
        "*.certauth.login.microsoftonline.com",
        "certauth.login.microsoftonline.com",
    ];

    /// <summary>
    /// Entscheidung für eine Navigation im Anmeldefenster (Hauptseite und Frames). Erlaubt sind nur HTTPS-Seiten auf
    /// <see cref="MicrosoftHosts"/> und den vom Administrator eingetragenen Hosts (<c>Entra.AllowedSignInHosts</c>, z. B.
    /// der eigene AD FS) sowie about:blank. Vorher war jede HTTPS-Seite erlaubt (unabhängige Prüfung 2026-10-27): Über
    /// Links oder die Weiterleitung zu einem Verbund-Anmeldedienst ließ sich eine fremde Seite öffnen, deren Datei- oder
    /// Druckdialog unter der Sperre Eingaben bekam.
    /// </summary>
    public static SignInNavigation Decide(string? uri, Uri redirect, IEnumerable<string>? extraHosts = null)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u)) return SignInNavigation.Block;
        if (IsRedirect(u, redirect)) return SignInNavigation.Complete;
        if (string.Equals(u.AbsoluteUri, "about:blank", StringComparison.OrdinalIgnoreCase)) return SignInNavigation.Allow;
        if (u.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(u.UserInfo) || !u.IsDefaultPort) return SignInNavigation.Block;
        return HostAllowed(u.IdnHost, MicrosoftHosts.Concat(extraHosts ?? [])) ? SignInNavigation.Allow : SignInNavigation.Block;
    }

    /// <summary>
    /// Host in der Liste? Einträge sind Hostnamen („adfs.contoso.com“) oder „*.contoso.com“ (nur Unterdomänen, nicht
    /// contoso.com selbst). Groß-/Kleinschreibung egal; Einträge mit Schema, Pfad, Port oder Leerzeichen gelten nicht.
    /// </summary>
    public static bool HostAllowed(string host, IEnumerable<string> entries)
    {
        if (string.IsNullOrEmpty(host)) return false;
        host = host.TrimEnd('.').ToLowerInvariant();
        foreach (var raw in entries)
        {
            var e = NormalizeHostEntry(raw);
            if (e is null) continue;
            if (e.StartsWith("*.", StringComparison.Ordinal))
            {
                if (host.EndsWith(e[1..], StringComparison.Ordinal) && host.Length > e.Length - 1) return true;
            }
            else if (host == e) return true;
        }
        return false;
    }

    /// <summary>Gültiger Eintrag für Entra.AllowedSignInHosts, vereinheitlicht; null = ungültig (wird ignoriert).</summary>
    public static string? NormalizeHostEntry(string? entry)
    {
        var e = entry?.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(e) || e.Length > 253) return null;
        var bare = e.StartsWith("*.", StringComparison.Ordinal) ? e[2..] : e;
        // Mindestens zwei Teile („*.com“ oder „localhost“ nicht), nur Buchstaben, Ziffern, Bindestrich, Punkt
        if (!bare.Contains('.') || bare.StartsWith('.') || bare.Contains("..", StringComparison.Ordinal)) return null;
        if (!bare.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.')) return null;
        return e;
    }

    /// <summary>Host einer abgelehnten Adresse für die Meldung (VIT-0193), sonst die Adresse gekürzt.</summary>
    public static string BlockedTarget(string? uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host) ? u.Host
        : (uri ?? "").Length > 60 ? uri![..60] + "…" : uri ?? "";
}

/// <summary>
/// Profilordner des Anmeldefensters (WebView2-Benutzerdatenordner): pro Versuch ein neuer Ordner mit zufälligem Namen,
/// danach gelöscht; beim Start räumt Vitrine Reste auf (Absturz, gesperrte Dateien). Gelöscht werden nur Ordner, deren
/// Name eine GUID ist („N“-Format) – nie etwas anderes im Ordner.
/// </summary>
public static class EphemeralProfiles
{
    /// <summary>
    /// Mindestalter, ab dem ein fremder Rest beim Aufräumen gelöscht wird. Länger als jede Anmeldung
    /// (LockShield.ExternalAuthTimeout), damit eine zweite Vitrine desselben Benutzers (zweite Sitzung) ihren laufenden
    /// Versuch behält.
    /// </summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(10);

    /// <summary>Neuer, noch nicht angelegter Ordner unter <paramref name="root"/>.</summary>
    public static string NewFolder(string root) => Path.Combine(root, Guid.NewGuid().ToString("N"));

    /// <summary>Name eines Profilordners von Vitrine?</summary>
    public static bool IsProfileFolderName(string? name) => Guid.TryParseExact(name, "N", out _);

    /// <summary>Profilordner, die beim Aufräumen gelöscht werden: GUID-Name und mindestens <paramref name="minAge"/> alt.</summary>
    public static IEnumerable<string> Stale(IEnumerable<(string Path, DateTime CreatedUtc)> folders, DateTime nowUtc, TimeSpan minAge) =>
        folders.Where(f => IsProfileFolderName(System.IO.Path.GetFileName(f.Path)) && nowUtc - f.CreatedUtc >= minAge).Select(f => f.Path);

    /// <summary>Löscht einen Profilordner samt Inhalt (schreibgeschützte Dateien eingeschlossen). true = weg.</summary>
    public static bool TryDelete(string folder)
    {
        if (!IsProfileFolderName(Path.GetFileName(folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)))) return false;
        try
        {
            if (!Directory.Exists(folder)) return true;
            // Verknüpfungen (Junctions) nicht verfolgen: nur den Link entfernen, nie das Ziel leeren (auch darin nicht,
            // Directory.Delete folgt ihnen nicht)
            if (new DirectoryInfo(folder).LinkTarget is not null) { Directory.Delete(folder); return true; }
            foreach (var f in new DirectoryInfo(folder).EnumerateFileSystemInfos("*", new EnumerationOptions
                     { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true }))
                if (f.Attributes.HasFlag(FileAttributes.ReadOnly)) f.Attributes &= ~FileAttributes.ReadOnly;
            Directory.Delete(folder, recursive: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return !Directory.Exists(folder);
        }
    }

    /// <summary>Löscht mehrmals mit Pause (Dateien der Browser-Prozesse werden kurz nach deren Ende frei).</summary>
    public static async Task<bool> DeleteWithRetryAsync(string folder, int attempts, TimeSpan delay)
    {
        for (int i = 0; i < attempts; i++)
        {
            if (TryDelete(folder)) return true;
            if (i < attempts - 1) await Task.Delay(delay).ConfigureAwait(false);
        }
        return false;
    }

    /// <summary>Reste aufräumen (Start, vor jedem Versuch). Gibt die Zahl der verbliebenen Reste zurück.</summary>
    public static int CleanUp(string root, DateTime nowUtc, TimeSpan minAge)
    {
        if (!Directory.Exists(root)) return 0;
        List<(string, DateTime)> folders;
        try { folders = new DirectoryInfo(root).EnumerateDirectories().Select(d => (d.FullName, d.CreationTimeUtc)).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
        return Stale(folders, nowUtc, minAge).Count(f => !TryDelete(f));
    }
}
