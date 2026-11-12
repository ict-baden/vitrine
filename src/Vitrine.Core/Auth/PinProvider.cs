// SPDX-License-Identifier: MIT
using System.Security.Cryptography;
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>
/// Eigenes Entsperr-Kennwort. Gemeinsames Geheimnis – das Protokoll kann damit keine Person zuordnen. Für
/// GxP-Umgebungen nicht empfohlen, nie für Signaturen oder Admin-Aktionen.
/// </summary>
public sealed class PinProvider : IAuthProvider
{
    /// <summary>PBKDF2-Runden für neue Hashes.</summary>
    public const int Iterations = 210_000;

    /// <summary>
    /// Mindestlänge beim Festlegen. Der Hash steht in der Gerätekonfiguration, die jeder Benutzer lesen kann; kurze
    /// Kennwörter ließen sich offline durchprobieren (vor 2026-10-19: 6 Zeichen).
    /// </summary>
    public const int MinLength = 10;

    // Grenzen für gespeicherte Hashes: eine präparierte Konfiguration darf die Prüfung nicht beliebig lange laufen
    // lassen (Rundenzahl) oder das Kennwort durch einen Hash mit 0 Runden bzw. leerem Schlüssel wertlos machen.
    private const int MinIterations = 10_000;
    private const int MaxIterations = 10_000_000;

    private readonly Func<UnlockSettings> _settings;

    public PinProvider(Func<UnlockSettings> settings) => _settings = settings;

    public string Id => "pin";
    public string DisplayName => CoreText.T("Pin_DisplayName");
    public string Glyph => ""; // Dialpad
    public AuthInputKind Input => AuthInputKind.Secret;

    public Task<bool> IsAvailableAsync(CancellationToken ct) => Task.FromResult(!string.IsNullOrEmpty(_settings().PinHash));

    public Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        var hash = _settings().PinHash;
        if (string.IsNullOrEmpty(hash))
            return Task.FromResult(AuthOutcome.Fail(CoreText.Error(ErrorCodes.UnlockPasswordNotSet), ErrorCodes.UnlockPasswordNotSet));
        if (string.IsNullOrEmpty(request.Secret))
            return Task.FromResult(AuthOutcome.Fail(CoreText.Error(ErrorCodes.SecretMissing), ErrorCodes.SecretMissing));

        return Task.Run(() => Verify(request.Secret, hash)
            ? new AuthOutcome
            {
                Success = true,
                UserName = DisplayName,
                DisplayName = DisplayName,
                Details = new Dictionary<string, string> { [UnlockPolicy.SharedSecretDetail] = "true" },
            }
            : AuthOutcome.Fail(CoreText.Error(ErrorCodes.UnlockPasswordWrong), ErrorCodes.UnlockPasswordWrong), ct);
    }

    public static string Hash(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}";
    }

    /// <summary>Prüft ein Kennwort gegen den gespeicherten Hash. Ungültige oder unsichere Hashes gelten als falsch.</summary>
    public static bool Verify(string secret, string stored)
    {
        var p = stored.Split('$');
        if (p.Length != 4 || p[0] != "pbkdf2-sha256" || !int.TryParse(p[1], out var it)) return false;
        if (it < MinIterations || it > MaxIterations) return false;
        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(p[2]);
            expected = Convert.FromBase64String(p[3]);
        }
        catch (FormatException) { return false; }
        if (salt.Length < 8 || expected.Length is < 16 or > 64) return false;
        var actual = Rfc2898DeriveBytes.Pbkdf2(secret, salt, it, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
