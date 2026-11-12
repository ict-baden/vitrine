// SPDX-License-Identifier: MIT
using System.Net.Http.Json;
using Microsoft.Win32;
using Vitrine.Abstractions;

namespace Vitrine.Plugin.HttpAuth;

/// <summary>
/// Beispiel für einen Anmelde-Adapter (nur als Quelltext, nicht Teil der Releases). Prüft Benutzername + Kennwort gegen
/// einen HTTP-Dienst, z. B. die Benutzerverwaltung eines LIMS oder einen firmeneigenen GxP-Auth-Dienst.
///
/// Einrichtung:
///   1. DLL nach %ProgramFiles%\Vitrine\Plugins kopieren (nur Administratoren dürfen dort schreiben)
///   2. HKLM\SOFTWARE\Policies\ICT-Baden\Vitrine\Plugins\HttpAuth  →  Url (REG_SZ, nur https),
///      z. B. https://lims.contoso.local/api/verify
///   3. In Vitrine unter Entsperren → Verfahren die ID „httpauth“ aktivieren (Methods-Liste)
///
/// Erwartetes Protokoll:
///   POST {Url}   {"user":"…","password":"…","reason":"…","machine":"…"}
///   200          {"ok":true,"user":"jdoe","displayName":"…","roles":["QA","Vitrine.Unlock"],"admin":false}
///   200/401      {"ok":false,"error":"…"}
///
/// Texte: Ein echtes Plugin gehört wie Vitrine in fünf Sprachen übersetzt (richtlinien/13); das Beispiel meldet auf
/// Englisch und mit eigenem Fehlercode (AuthOutcome.ErrorCode), damit der Support Meldungen zuordnen kann.
/// </summary>
public sealed class HttpAuthProvider : IAuthProvider
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public string Id => "httpauth";
    public string DisplayName => "LIMS account";
    public string Glyph => ""; // Education
    public AuthInputKind Input => AuthInputKind.UsernamePassword;

    private static string? Url
    {
        get
        {
            foreach (var key in new[] { @"SOFTWARE\Policies\ICT-Baden\Vitrine\Plugins\HttpAuth", @"SOFTWARE\Policies\Vitrine\Plugins\HttpAuth" })
            {
                using var k = Registry.LocalMachine.OpenSubKey(key);
                if (k?.GetValue("Url") is string url) return url;
            }
            return null;
        }
    }

    public Task<bool> IsAvailableAsync(CancellationToken ct)
        => Task.FromResult(Uri.TryCreate(Url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps);

    public async Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrEmpty(request.Secret))
            return AuthOutcome.Fail("Please enter user name and password.", "HTTPAUTH-0001");
        if (!Uri.TryCreate(Url, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
            return AuthOutcome.Fail("The plugin is not set up (https URL missing).", "HTTPAUTH-0002");
        try
        {
            using var resp = await Http.PostAsJsonAsync(url, new
            {
                user = request.UserName,
                password = request.Secret,
                reason = request.Reason,
                machine = Environment.MachineName,
            }, ct);
            var r = await resp.Content.ReadFromJsonAsync<Reply>(cancellationToken: ct);
            if (r is null || !r.Ok || !resp.IsSuccessStatusCode)
                return AuthOutcome.Fail(r?.Error ?? $"Sign-in rejected ({(int)resp.StatusCode}).", "HTTPAUTH-0003");
            return new AuthOutcome
            {
                Success = true,
                UserName = r.User ?? request.UserName,
                DisplayName = r.DisplayName ?? r.User ?? request.UserName,
                UserId = r.User ?? request.UserName,
                Groups = r.Roles ?? Array.Empty<string>(),
                IsAdministrator = r.Admin,
                // Ein Konto im Fachsystem ist nicht ohne Weiteres der Windows-Benutzer der Sitzung. Wer entsperren darf,
                // regeln die Gruppen (roles) und Konten in den Entsperr-Einstellungen.
                IsSessionUser = false,
                Details = new Dictionary<string, string> { ["system"] = url.Host },
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or NotSupportedException)
        {
            return AuthOutcome.Fail($"The line-of-business system cannot be reached: {ex.Message}", "HTTPAUTH-0004");
        }
    }

    private sealed record Reply(bool Ok, string? User, string? DisplayName, string[]? Roles, bool Admin, string? Error);
}
