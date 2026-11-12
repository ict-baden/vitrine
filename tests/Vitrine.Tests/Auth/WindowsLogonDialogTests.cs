// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;

namespace Vitrine.Tests.Auth;

public sealed class WindowsLogonDialogTests
{
    private const string SessionSid = "S-1-5-21-1-2-3-1001";
    private const string UnlockGroupSid = "S-1-5-21-9-9-9-1010";

    /// <summary>Attrappe für Dialog und LsaLogonUser – nie eine echte Anmeldung.</summary>
    private sealed class FakeDialog : IWindowsCredentialDialog
    {
        public int PromptResult;
        public int LogonResult;
        public WindowsAccountInfo? Account = new(@"AzureAD\jdoe@contoso.com", "S-1-12-1-1-2-3-4", ["S-1-1-0", UnlockGroupSid], false);
        public int Logons;
        public FakeCredential? Credential;
        public Action? DuringPrompt;

        public int Prompt(nint owner, string caption, string message, out IWindowsCredential? credential)
        {
            DuringPrompt?.Invoke();
            Credential = new FakeCredential();
            credential = PromptResult == 0 ? Credential : null;
            if (PromptResult != 0) Credential.Dispose();
            return PromptResult;
        }

        public int Logon(IWindowsCredential credential, out WindowsAccountInfo? account)
        {
            Logons++;
            Assert.False(((FakeCredential)credential).Disposed);
            account = LogonResult == 0 ? Account : null;
            return LogonResult;
        }
    }

    private sealed class FakeCredential : IWindowsCredential
    {
        public bool Disposed;
        public void Dispose() => Disposed = true;
    }

    private static AuthOutcome Run(FakeDialog d, CancellationToken ct = default) =>
        WindowsLogonDialog.Authenticate(d, 0, "Vitrine – Unlock", "msg", SessionSid, ct);

    [Fact]
    public void Erfolg_liefert_Konto_wie_das_Windows_Kennwort_und_verwirft_die_Anmeldedaten()
    {
        var d = new FakeDialog();
        var o = Run(d);
        Assert.True(o.Success);
        Assert.Equal(@"AzureAD\jdoe@contoso.com", o.UserName);
        Assert.Equal("jdoe@contoso.com", o.DisplayName);
        Assert.Equal("S-1-12-1-1-2-3-4", o.UserId);
        Assert.Contains(UnlockGroupSid, o.Groups);
        Assert.False(o.IsSessionUser);
        Assert.False(o.IsAdministrator);
        Assert.Equal(1, d.Logons);
        Assert.True(d.Credential!.Disposed);
    }

    [Fact]
    public void Sitzungsbenutzer_und_Administrator_aus_dem_Token()
    {
        var d = new FakeDialog { Account = new(@"WIN11TEST\tech", SessionSid, ["S-1-5-32-544"], true) };
        var o = Run(d);
        Assert.True(o.IsSessionUser);
        Assert.True(o.IsAdministrator);
    }

    [Fact]
    public void Abbrechen_meldet_VIT_0111_ohne_Anmeldung()
    {
        var d = new FakeDialog { PromptResult = WindowsLogonErrors.Cancelled };
        var o = Run(d);
        Assert.False(o.Success);
        Assert.Equal("VIT-0111", o.ErrorCode);
        Assert.Equal(0, d.Logons);
        Assert.True(d.Credential!.Disposed);
    }

    [Theory]
    [InlineData(1326, "VIT-0101")]
    [InlineData(1330, "VIT-0102")]
    [InlineData(1331, "VIT-0103")]
    [InlineData(1909, "VIT-0104")]
    [InlineData(1311, "VIT-0105")]
    [InlineData(1385, "VIT-0106")]
    [InlineData(5, "VIT-0109")]
    public void Fehler_der_Anmeldung_wie_beim_Windows_Kennwort_genau_ein_Versuch(int win32, string code)
    {
        var d = new FakeDialog { LogonResult = win32 };
        var o = Run(d);
        Assert.False(o.Success);
        Assert.Equal(code, o.ErrorCode);
        Assert.Contains(code, o.Error);
        Assert.Equal(1, d.Logons);
        Assert.True(d.Credential!.Disposed);
    }

    [Fact]
    public void Anderer_Fehler_des_Dialogs_ist_VIT_0109()
    {
        var d = new FakeDialog { PromptResult = 87 };
        Assert.Equal("VIT-0109", Run(d).ErrorCode);
        Assert.Equal(0, d.Logons);
    }

    [Fact]
    public void Zeitlimit_waehrend_des_Dialogs_verwirft_die_Anmeldedaten_ohne_Anmeldung()
    {
        using var cts = new CancellationTokenSource();
        var d = new FakeDialog { DuringPrompt = cts.Cancel };
        var o = Run(d, cts.Token);
        Assert.Equal("VIT-0111", o.ErrorCode);
        Assert.Equal(0, d.Logons);
        Assert.True(d.Credential!.Disposed);
    }

    [Theory]
    [InlineData(10, true, true)]
    [InlineData(10, false, false)]
    [InlineData(6, true, false)]
    public void Verfuegbar_ab_Windows_10_mit_credui(int major, bool present, bool expected) =>
        Assert.Equal(expected, WindowsLogonDialog.IsAvailable(new Version(major, 0, 19045), present));

    [Theory]
    [InlineData(@".\Vitrine-Entsperrer", @"WIN11TEST\Vitrine-Entsperrer")]
    [InlineData(@" Vitrine-Entsperrer ", "Vitrine-Entsperrer")]
    [InlineData(@"WIN11TEST\Vitrine-Entsperrer", @"WIN11TEST\Vitrine-Entsperrer")]
    [InlineData(@".\", @".\")]
    public void Lokale_Gruppen_fuer_die_Namensaufloesung(string entry, string expected) =>
        Assert.Equal(expected, AccountNames.ForLookup(entry, "WIN11TEST"));

    [Theory]
    [InlineData("Vitrine-Entsperrer")]
    [InlineData(@"WIN11TEST\Vitrine-Entsperrer")]
    [InlineData(@".\Vitrine-Entsperrer")]
    [InlineData(UnlockGroupSid)]
    public void Lokale_Gruppe_in_AllowedGroups_entsperrt_ueber_die_SID_aus_dem_Token(string entry)
    {
        var o = Run(new FakeDialog());
        var rules = new UnlockSettings { Allowed = UnlockAllowed.Groups, AllowedGroups = [entry] };
        // Wie WindowsAccounts.ToSid: Name → SID (hier ohne Windows nachgebildet)
        string? Resolve(string name) => AccountNames.ForLookup(name, "WIN11TEST") switch
        {
            "Vitrine-Entsperrer" or @"WIN11TEST\Vitrine-Entsperrer" => UnlockGroupSid,
            var n when n.StartsWith("S-1-", StringComparison.Ordinal) => n,
            _ => null,
        };
        Assert.True(UnlockPolicy.Evaluate(o, rules, resolveSid: Resolve).Allowed);
        var other = new UnlockSettings { Allowed = UnlockAllowed.Groups, AllowedGroups = ["Andere-Gruppe"] };
        Assert.Equal("VIT-0140", UnlockPolicy.Evaluate(o, other, resolveSid: Resolve).Code);
    }

    [Fact]
    public void Windows_Anmeldedialog_zaehlt_als_Windows_Anmeldung_fuer_die_Warnungen()
    {
        var s = new UnlockSettings { Methods = [WindowsLogonDialog.MethodId], AllowedDomains = ["contoso.com"] };
        Assert.Contains(LockScreenMethods.Warnings(s, entraOnLockScreen: true), w => w.Code == "VIT-0017");
    }

    [Fact]
    public void Schalter_in_den_Einstellungen_haelt_die_Reihenfolge()
    {
        var s = new UnlockSettings { Methods = ["pin", "entra"] };
        s.MethodWindowsLogon = true;
        Assert.Equal(["entra", "windowslogon", "pin"], s.Methods);
        Assert.True(s.MethodWindowsLogon);
        Assert.DoesNotContain("windowslogon", new UnlockSettings().Methods);
    }
}

public sealed class EntraFreshSignInTests
{
    private static readonly DateTimeOffset Started = new(2026, 10, 27, 9, 0, 0, TimeSpan.Zero);
    private const string Tenant = "aaaaaaaa-0000-0000-0000-000000000001";

    private static AuthOutcome Evaluate(long? authTime, DateTimeOffset? started)
    {
        var claims = new List<KeyValuePair<string, string>> { new("tid", Tenant), new("oid", "oid-1"), new("preferred_username", "jdoe@contoso.com") };
        if (authTime is { } t) claims.Add(new("auth_time", t.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return EntraClaims.Evaluate(new EntraSignIn(claims, null, null, null), new EntraSettings { TenantId = Tenant }, null, Started.AddSeconds(20),
            signInStartedAt: started);
    }

    [Fact]
    public void Frische_Anmeldung_nach_Beginn_entsperrt() =>
        Assert.True(Evaluate(Started.AddSeconds(10).ToUnixTimeSeconds(), Started).Success);

    [Fact]
    public void Alte_Anmeldung_per_SSO_wird_abgelehnt()
    {
        // Typisch: auth_time der Windows-Anmeldung des technischen Kontos (Primary Refresh Token)
        var o = Evaluate(Started.AddHours(-3).ToUnixTimeSeconds(), Started);
        Assert.False(o.Success);
        Assert.Equal("VIT-0181", o.ErrorCode);
    }

    [Fact]
    public void Ohne_auth_time_abgelehnt()
    {
        var o = Evaluate(null, Started);
        Assert.False(o.Success);
        Assert.Equal("VIT-0180", o.ErrorCode);
        Assert.Contains("auth_time", o.Error);
    }

    [Fact]
    public void Uhrabweichung_bis_120_Sekunden_toleriert()
    {
        Assert.True(Evaluate(Started.AddSeconds(-120).ToUnixTimeSeconds(), Started).Success);
        Assert.Equal("VIT-0181", Evaluate(Started.AddSeconds(-121).ToUnixTimeSeconds(), Started).ErrorCode);
    }

    [Fact]
    public void Ohne_Beginn_keine_Pruefung_wie_bisher() =>
        Assert.True(Evaluate(null, null).Success);

    /// <summary>
    /// Rechneruhr weicht ab: <paramref name="skewMinutes"/> &gt; 0 = Rechner geht vor. Entra-Zeit: Beginn 9:00, Anmeldung
    /// 9:00:10, Token ausgestellt (iat) 9:00:20; der Rechner sieht Beginn und Empfang um die Abweichung verschoben.
    /// </summary>
    private static AuthOutcome WithClock(double skewMinutes, long authTime, bool withIat = true)
    {
        var skew = TimeSpan.FromMinutes(skewMinutes);
        var claims = new List<KeyValuePair<string, string>> { new("tid", Tenant), new("oid", "oid-1"),
            new("auth_time", authTime.ToString(System.Globalization.CultureInfo.InvariantCulture)) };
        if (withIat) claims.Add(new("iat", Started.AddSeconds(20).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return EntraClaims.Evaluate(new EntraSignIn(claims, null, null, null), new EntraSettings { TenantId = Tenant }, null,
            Started.AddSeconds(21) + skew, signInStartedAt: Started + skew);
    }

    [Theory]
    [InlineData(10)]    // Uhr 10 Minuten vor: früher VIT-0181
    [InlineData(-10)]   // Uhr 10 Minuten nach
    [InlineData(600)]   // Uhr 10 Stunden vor
    [InlineData(0)]
    public void Frische_in_der_Zeit_von_Entra_unabhaengig_von_der_Rechneruhr(double skewMinutes)
    {
        Assert.True(WithClock(skewMinutes, Started.AddSeconds(10).ToUnixTimeSeconds()).Success);
        // Alte Anmeldung (SSO) bleibt abgelehnt – auch wenn die Uhr nachgeht
        Assert.Equal("VIT-0181", WithClock(skewMinutes, Started.AddHours(-3).ToUnixTimeSeconds()).ErrorCode);
        Assert.Equal("VIT-0181", WithClock(skewMinutes, Started.AddSeconds(-125).ToUnixTimeSeconds()).ErrorCode);
    }

    [Fact]
    public void Ohne_iat_gilt_die_Rechneruhr_wie_bisher()
    {
        Assert.Equal("VIT-0181", WithClock(10, Started.AddSeconds(10).ToUnixTimeSeconds(), withIat: false).ErrorCode);
        Assert.True(WithClock(1, Started.AddSeconds(10).ToUnixTimeSeconds(), withIat: false).Success);
        Assert.Equal(TimeSpan.FromMinutes(-10), EntraClaims.ClockOffset(Started.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), Started.AddMinutes(10)));
        Assert.Equal(TimeSpan.Zero, EntraClaims.ClockOffset("x", Started));
    }

    [Fact]
    public void Hoechstalter_ebenfalls_in_der_Zeit_von_Entra()
    {
        // Uhr 10 Minuten vor, MaxAuthAgeSeconds 300, Anmeldung 20 s vor Ausstellung: nicht zu alt
        var claims = new List<KeyValuePair<string, string>> { new("tid", Tenant), new("oid", "oid-1"),
            new("auth_time", Started.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("iat", Started.AddSeconds(20).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)) };
        var o = EntraClaims.Evaluate(new EntraSignIn(claims, null, null, null), new EntraSettings { TenantId = Tenant, MaxAuthAgeSeconds = 300 },
            null, Started.AddMinutes(10).AddSeconds(21));
        Assert.True(o.Success);
    }
}
