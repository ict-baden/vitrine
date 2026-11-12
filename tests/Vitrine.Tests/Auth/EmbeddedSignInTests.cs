// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;

namespace Vitrine.Tests.Auth;

/// <summary>
/// Microsoft-Anmeldung im eigenen Fenster (WebView2) statt über WAM (Gerätetest 2026-10-26): Wahl des Wegs, Umleitung,
/// erlaubte Navigationen, Vorschlag eines Kontos, Profilordner, Freigabe von Anmeldefenstern unter der Sperre.
/// Ohne echtes WebView2, ohne Anmeldung.
/// </summary>
public sealed class EmbeddedSignInTests
{
    private static readonly Uri Redirect = new(EntraSignInMode.LoopbackRedirectUri);

    // ---------- Weg ----------

    [Fact]
    public void Standard_ist_das_eigene_Fenster_ohne_Broker()
    {
        var s = new EntraSettings();
        Assert.False(s.UseBroker);
        Assert.Equal(EntraSignInPath.Embedded, EntraSignInMode.Choose(brokerIncluded: true, s.UseBroker, webViewAvailable: true));
        Assert.Equal(EntraSignInPath.Embedded, EntraSignInMode.Choose(brokerIncluded: false, useBroker: true, webViewAvailable: true));
        Assert.Equal(EntraSignInPath.Broker, EntraSignInMode.Choose(brokerIncluded: true, useBroker: true, webViewAvailable: false));
        Assert.Equal(EntraSignInPath.Unavailable, EntraSignInMode.Choose(brokerIncluded: true, useBroker: false, webViewAvailable: false));
        Assert.Equal(EntraSignInPath.Unavailable, EntraSignInMode.Choose(brokerIncluded: false, useBroker: true, webViewAvailable: false));
    }

    [Fact]
    public void Microsoft_am_Sperrbildschirm_mit_eigenem_Fenster_und_mit_Broker()
    {
        Assert.True(EntraSignInMode.OnLockScreen(EntraSignInPath.Embedded));
        Assert.True(EntraSignInMode.OnLockScreen(EntraSignInPath.Broker));
        Assert.False(EntraSignInMode.OnLockScreen(EntraSignInPath.Unavailable));

        // VIT-0016 nur noch, wenn das Fenster nicht geht (WebView2-Laufzeit fehlt) und kein Broker benutzt wird
        var only = new UnlockSettings { Methods = ["entra"] };
        Assert.Empty(LockScreenMethods.Warnings(only, EntraSignInMode.OnLockScreen(EntraSignInPath.Embedded)));
        Assert.Equal(["entra"], LockScreenMethods.Filter(only.Methods, EntraSignInMode.OnLockScreen(EntraSignInPath.Embedded)));
        Assert.Equal(ErrorCodes.UnlockFallsBackToWindows,
            Assert.Single(LockScreenMethods.Warnings(only, EntraSignInMode.OnLockScreen(EntraSignInPath.Unavailable))).Code);
    }

    [Fact]
    public void Umleitungs_URI_passt_zum_Weg()
    {
        Assert.Equal("http://localhost", EntraSignInMode.RedirectUri(EntraSignInPath.Embedded, "abc"));
        Assert.Equal("http://localhost", EntraSignInMode.RedirectUri(EntraSignInPath.Unavailable, "abc"));
        Assert.Equal("ms-appx-web://microsoft.aad.brokerplugin/abc", EntraSignInMode.RedirectUri(EntraSignInPath.Broker, " abc "));
    }

    [Theory]
    [InlineData(EntraSignInPath.Embedded)]
    [InlineData(EntraSignInPath.Broker)]
    public void Entsperren_und_Admin_ohne_vorgeschlagenes_Konto(EntraSignInPath path)
    {
        // Jede berechtigte Person darf entsperren; das Sitzungskonto ist oft ein technisches Konto
        Assert.Null(EntraSignInMode.LoginHint(path, AuthPurpose.Unlock, "tech@contoso.com", "tech@contoso.com"));
        Assert.Null(EntraSignInMode.LoginHint(path, AuthPurpose.Admin, "admin@contoso.com", "tech@contoso.com"));
    }

    [Fact]
    public void Signatur_schlaegt_nur_mit_Broker_ein_Konto_vor()
    {
        Assert.Null(EntraSignInMode.LoginHint(EntraSignInPath.Embedded, AuthPurpose.Signature, "jdoe@contoso.com", "jdoe@contoso.com"));
        Assert.Equal("jdoe@contoso.com", EntraSignInMode.LoginHint(EntraSignInPath.Broker, AuthPurpose.Signature, "jdoe@contoso.com", "x@contoso.com"));
        Assert.Equal("x@contoso.com", EntraSignInMode.LoginHint(EntraSignInPath.Broker, AuthPurpose.Signature, "CONTOSO\\jdoe", "x@contoso.com"));
        Assert.Null(EntraSignInMode.LoginHint(EntraSignInPath.Broker, AuthPurpose.Signature, null, " "));
    }

    [Fact]
    public void Eigenes_Fenster_verlangt_immer_eine_neue_Anmeldung()
    {
        Assert.True(EntraSignInMode.ForceLogin(EntraSignInPath.Embedded, forceFreshSignIn: false));
        Assert.True(EntraSignInMode.ForceLogin(EntraSignInPath.Embedded, forceFreshSignIn: true));
        Assert.True(EntraSignInMode.ForceLogin(EntraSignInPath.Broker, forceFreshSignIn: true));
        Assert.False(EntraSignInMode.ForceLogin(EntraSignInPath.Broker, forceFreshSignIn: false));
    }

    [Fact]
    public void Hinweise_Broker_merkt_sich_Konten_und_fehlende_WebView2_Laufzeit()
    {
        var s = new EntraSettings { ClientId = "11111111-1111-1111-1111-111111111111" };
        Assert.Empty(EntraSignInMode.Warnings(s, brokerIncluded: true, webViewAvailable: true));
        Assert.Equal(["VIT-0190 Entra.ClientId"], EntraSignInMode.Warnings(s, true, webViewAvailable: false).Select(w => w.AuditDetail));

        s.UseBroker = true;
        var w = Assert.Single(EntraSignInMode.Warnings(s, brokerIncluded: true, webViewAvailable: true));
        Assert.Equal(ErrorCodes.EntraBrokerRemembersAccounts, w.Code);
        Assert.Equal("VIT-0191 Entra.UseBroker", w.AuditDetail);
        using (new TestSupport.UiCulture("en")) Assert.EndsWith("(VIT-0191)", w.Message);
        // Build ohne Broker: der Schalter wirkt nicht, also keine Warnung
        Assert.Empty(EntraSignInMode.Warnings(s, brokerIncluded: false, webViewAvailable: true));
        // Ohne App-Registrierung ist Microsoft ohnehin aus
        Assert.Empty(EntraSignInMode.Warnings(new EntraSettings { UseBroker = true }, true, false));
    }

    // ---------- Umleitung und Navigation ----------

    [Theory]
    [InlineData("http://localhost/?code=abc&state=x", true)]
    [InlineData("http://localhost?code=abc", true)]
    [InlineData("http://LOCALHOST/?error=access_denied", true)]
    [InlineData("http://localhost:80/?code=abc", true)]
    [InlineData("http://localhost/#code=abc", true)]
    [InlineData("http://localhost:8080/?code=abc", false)]
    [InlineData("https://localhost/?code=abc", false)]
    [InlineData("http://localhost.contoso.com/?code=abc", false)]
    [InlineData("http://localhost@contoso.com/?code=abc", false)]
    [InlineData("http://user@localhost/?code=abc", false)]
    [InlineData("http://localhost/other?code=abc", false)]
    [InlineData("http://127.0.0.1/?code=abc", false)]
    public void Umleitung_wird_genau_erkannt(string uri, bool expected) =>
        Assert.Equal(expected, EmbeddedSignIn.IsRedirect(new Uri(uri), Redirect));

    [Theory]
    [InlineData("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x", SignInNavigation.Allow)]
    [InlineData("https://login.microsoft.com/common/fido/get", SignInNavigation.Allow)]
    [InlineData("https://t123.certauth.login.microsoftonline.com/x", SignInNavigation.Allow)]
    [InlineData("https://adfs.contoso.com/adfs/ls/", SignInNavigation.Block)] // nur mit Entra.AllowedSignInHosts
    [InlineData("https://attacker.example/upload.html", SignInNavigation.Block)]
    [InlineData("https://login.microsoftonline.com.attacker.example/", SignInNavigation.Block)]
    [InlineData("https://login.microsoftonline.com:8443/", SignInNavigation.Block)]
    [InlineData("https://autologon.microsoftazuread-sso.com/x", SignInNavigation.Block)] // nahtloses SSO der Sitzung
    [InlineData("https://login.live.com/", SignInNavigation.Block)]
    [InlineData("about:blank", SignInNavigation.Allow)]
    [InlineData("http://localhost/?code=abc", SignInNavigation.Complete)]
    [InlineData("http://login.contoso.com/", SignInNavigation.Block)]
    [InlineData("file:///C:/Windows/win.ini", SignInNavigation.Block)]
    [InlineData("javascript:alert(1)", SignInNavigation.Block)]
    [InlineData("ms-settings:privacy", SignInNavigation.Block)]
    [InlineData("https://user:pw@login.microsoftonline.com/", SignInNavigation.Block)]
    [InlineData("not a uri", SignInNavigation.Block)]
    [InlineData(null, SignInNavigation.Block)]
    public void Nur_HTTPS_und_die_Umleitung(string? uri, SignInNavigation expected) =>
        Assert.Equal(expected, EmbeddedSignIn.Decide(uri, Redirect));

    [Theory]
    [InlineData("https://adfs.contoso.com/adfs/ls/", true)]
    [InlineData("https://ADFS.Contoso.com/", true)]
    [InlineData("https://dev-1.okta.com/login", true)]
    [InlineData("https://okta.com/login", false)]          // *.okta.com: nur Unterdomänen
    [InlineData("https://evil-okta.com/", false)]
    [InlineData("https://adfs.contoso.com.evil.example/", false)]
    [InlineData("http://adfs.contoso.com/", false)]        // nur HTTPS
    [InlineData("https://other.contoso.com/", false)]
    public void Weitere_Anmelde_Hosts_vom_Administrator(string uri, bool allowed) =>
        Assert.Equal(allowed ? SignInNavigation.Allow : SignInNavigation.Block,
            EmbeddedSignIn.Decide(uri, Redirect, ["adfs.contoso.com", "*.okta.com", "*.com", "https://x.contoso.com/", "bad host", ""]));

    [Theory]
    [InlineData("adfs.contoso.com", "adfs.contoso.com")]
    [InlineData(" *.Okta.com. ", "*.okta.com")]
    [InlineData("*.com", null)]
    [InlineData("localhost", null)]
    [InlineData("https://adfs.contoso.com", null)]
    [InlineData("adfs.contoso.com:443", null)]
    [InlineData("adfs.contoso.com/path", null)]
    [InlineData("a..b.com", null)]
    [InlineData("", null)]
    public void Eintraege_fuer_Anmelde_Hosts_werden_geprueft(string entry, string? normalized) =>
        Assert.Equal(normalized, EmbeddedSignIn.NormalizeHostEntry(entry));

    [Fact]
    public void Abgelehnte_Adresse_nennt_den_Host()
    {
        Assert.Equal("attacker.example", EmbeddedSignIn.BlockedTarget("https://attacker.example/a?b=c"));
        Assert.Equal("javascript:alert(1)", EmbeddedSignIn.BlockedTarget("javascript:alert(1)"));
    }

    // ---------- Profilordner ----------

    [Fact]
    public void Profilordner_haben_zufaellige_GUID_Namen()
    {
        var a = EphemeralProfiles.NewFolder("C:\\root");
        var b = EphemeralProfiles.NewFolder("C:\\root");
        Assert.NotEqual(a, b);
        Assert.True(EphemeralProfiles.IsProfileFolderName(Path.GetFileName(a)));
        Assert.False(EphemeralProfiles.IsProfileFolderName("Logs"));
        Assert.False(EphemeralProfiles.IsProfileFolderName("{" + Guid.NewGuid() + "}"));
        Assert.False(EphemeralProfiles.IsProfileFolderName(null));
    }

    [Fact]
    public void Aufraeumen_nur_alte_Profilordner()
    {
        var now = new DateTime(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);
        var old = Guid.NewGuid().ToString("N");
        var young = Guid.NewGuid().ToString("N");
        var stale = EphemeralProfiles.Stale(
        [
            (Path.Combine("r", old), now - TimeSpan.FromHours(1)),
            (Path.Combine("r", young), now - TimeSpan.FromMinutes(1)), // laufender Versuch einer zweiten Sitzung
            (Path.Combine("r", "EBWebView"), now - TimeSpan.FromDays(3)), // fremder Ordner: nie
        ], now, EphemeralProfiles.StaleAfter).ToList();
        Assert.Equal([Path.Combine("r", old)], stale);
        Assert.True(EphemeralProfiles.StaleAfter > LockShield.ExternalAuthTimeout);
    }

    [Fact]
    public async Task Loeschen_auch_mit_schreibgeschuetzten_Dateien_und_nie_fremde_Ordner()
    {
        var root = Path.Combine(Path.GetTempPath(), "vitrine-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var profile = EphemeralProfiles.NewFolder(root);
            Directory.CreateDirectory(Path.Combine(profile, "EBWebView", "Default"));
            var file = Path.Combine(profile, "EBWebView", "Default", "Cookies");
            await File.WriteAllTextAsync(file, "x");
            File.SetAttributes(file, FileAttributes.ReadOnly);
            var foreign = Path.Combine(root, "keep");
            Directory.CreateDirectory(foreign);

            Assert.False(EphemeralProfiles.TryDelete(foreign)); // kein GUID-Name: nie löschen
            Assert.True(Directory.Exists(foreign));
            Assert.True(await EphemeralProfiles.DeleteWithRetryAsync(profile, 3, TimeSpan.FromMilliseconds(10)));
            Assert.False(Directory.Exists(profile));
            Assert.True(EphemeralProfiles.TryDelete(profile)); // schon weg = gelöscht

            // Aufräumen: alte Reste weg, junge und fremde bleiben
            var stale = EphemeralProfiles.NewFolder(root);
            var fresh = EphemeralProfiles.NewFolder(root);
            Directory.CreateDirectory(stale);
            Directory.CreateDirectory(fresh);
            // Gerade angelegt: bleiben (laufender Versuch); zwei Stunden später: weg (Erstellzeit lässt sich nicht überall setzen)
            Assert.Equal(0, EphemeralProfiles.CleanUp(root, DateTime.UtcNow, EphemeralProfiles.StaleAfter));
            Assert.True(Directory.Exists(stale) && Directory.Exists(fresh));
            Assert.Equal(0, EphemeralProfiles.CleanUp(root, DateTime.UtcNow + TimeSpan.FromHours(2), EphemeralProfiles.StaleAfter));
            Assert.False(Directory.Exists(stale) || Directory.Exists(fresh));
            Assert.True(Directory.Exists(foreign));
            Assert.Equal(0, EphemeralProfiles.CleanUp(Path.Combine(root, "fehlt"), DateTime.UtcNow, TimeSpan.Zero));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    // ---------- Eingaben unter der Sperre ----------

    [Fact]
    public void Fenster_eines_freigegebenen_Fensters_bekommen_Eingaben()
    {
        // 30 gehört 20, 20 gehört dem Dialog 10 (freigegeben); 40 gehört niemandem; 50 ↔ 60 Schleife
        var owners = new Dictionary<nint, nint> { [30] = 20, [20] = 10, [50] = 60, [60] = 50 };
        nint Owner(nint w) => owners.GetValueOrDefault(w);
        bool Allowed(nint w) => w == 10;

        Assert.True(WindowOwnership.OwnedByAllowed(20, Owner, Allowed));
        Assert.True(WindowOwnership.OwnedByAllowed(30, Owner, Allowed));
        Assert.False(WindowOwnership.OwnedByAllowed(40, Owner, Allowed));
        Assert.False(WindowOwnership.OwnedByAllowed(10, Owner, Allowed)); // selbst: entscheidet die Freigabe, nicht der Besitzer
        Assert.False(WindowOwnership.OwnedByAllowed(50, Owner, Allowed)); // Schleife endet
        Assert.False(WindowOwnership.OwnedByAllowed(0, Owner, Allowed));
    }

    [Fact]
    public void Anmeldedialoge_von_Windows_sind_im_Standard_freigegeben()
    {
        var p = new SecuritySettings().AuthUiProcesses;
        Assert.Contains("CredentialUIBroker.exe", p); // Windows-Sicherheitsdialog: PIN des Sicherheitsschlüssels
        Assert.Contains("CredDialogHost.exe", p);
        Assert.Contains("AccountsControlHost.exe", p); // Kontoauswahl von WAM
        Assert.DoesNotContain(p, n => n.StartsWith("msedge.exe", StringComparison.OrdinalIgnoreCase)); // kein Browser
    }
}
