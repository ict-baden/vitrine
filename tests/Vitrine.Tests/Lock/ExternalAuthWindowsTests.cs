// SPDX-License-Identifier: MIT
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Lock;

namespace Vitrine.Tests.Lock;

/// <summary>
/// Welche fremden Fenster während einer externen Anmeldung Eingaben bekommen (unabhängige Prüfung 2026-10-27: Datei- und
/// Druckdialoge aus dem Anmeldefenster, Prozesse nur am Dateinamen erkannt). Ohne Fenster, ohne Hooks.
/// </summary>
public sealed class ExternalAuthWindowsTests
{
    private static readonly TrustedRoots Roots = new(@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)");
    private static readonly IReadOnlySet<string> Allowed = new SecuritySettings().AuthUiProcesses.ToHashSet(StringComparer.OrdinalIgnoreCase);

    private const string WebView = @"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\141.0.1.0\msedgewebview2.exe";
    private const string Vitrine = @"C:\Program Files\ICT-Baden\Vitrine\Vitrine.exe";

    private static bool Allow(string? cls, string path, bool own = false, bool ourWebView = false, bool owned = false, bool pre = false) =>
        ExternalAuthWindows.Allow(new AuthWindowFacts(cls, path, own, ourWebView, owned, pre), Allowed, Roots);

    [Fact]
    public void Datei_und_Druckdialog_des_Anmeldefensters_bekommen_keine_Eingaben()
    {
        // Angriff: fremde Seite im Anmeldefenster → <input type=file> / window.print() → Standarddialog, dem Anmeldefenster gehörend
        Assert.False(Allow("#32770", WebView, ourWebView: true, owned: true));
        Assert.False(Allow("#32770", Vitrine, own: true, owned: true));
        Assert.False(Allow("NUIDialog", WebView, ourWebView: true, owned: true));
        Assert.False(Allow("#32770", WebView)); // auch über die Prozessliste nicht
        // Auswahlliste einer Seite (WebView2-Popup) schon
        Assert.True(Allow("Chrome_WidgetWin_1", WebView, ourWebView: true, owned: true));
    }

    [Fact]
    public void Besitzer_Regel_nur_fuer_Vitrine_und_das_eigene_WebView2()
    {
        // Fremder Prozess, dessen Fenster dem Dialog gehört (Besitzer lässt sich prozessübergreifend setzen): nicht
        Assert.False(Allow("Window", @"C:\Users\x\Downloads\tool.exe", owned: true));
        // WebView2 von Teams/Outlook mit Fenster, das dem Dialog gehört: nur über die Prozessliste (neu erschienen)
        Assert.False(Allow("Chrome_WidgetWin_1", WebView, owned: true, pre: true));
        Assert.True(Allow("Chrome_WidgetWin_1", WebView, owned: true));
        Assert.True(Allow("Window", Vitrine, own: true, owned: true));
        Assert.False(Allow("Window", Vitrine, own: true, owned: false));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\CredentialUIBroker.exe", true)]
    [InlineData(@"C:\WINDOWS\system32\credentialuibroker.exe", true)]
    [InlineData(@"\\?\C:\Windows\System32\CredentialUIBroker.exe", true)]
    [InlineData(@"C:\Windows\SystemApps\microsoft.creddialoghost_cw5n1h2txyewy\CredDialogHost.exe", true)]
    [InlineData(@"C:\Windows\SystemApps\Microsoft.AccountsControl_cw5n1h2txyewy\AccountsControlHost.exe", true)]
    [InlineData(@"C:\Windows\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Microsoft.AAD.BrokerPlugin.exe", true)]
    [InlineData(@"C:\Users\x\Downloads\CredDialogHost.exe", false)]           // gleicher Name, falscher Ort
    [InlineData(@"C:\Program Files\Evil\CredentialUIBroker.exe", false)]       // reine Anmelde-Prozesse nur aus Windows
    [InlineData(@"C:\Windows\Temp\CredentialUIBroker.exe", false)]
    [InlineData(@"C:\Windows\System32\..\Temp\CredentialUIBroker.exe", false)]
    [InlineData(@"C:\Windows\System32Evil\CredentialUIBroker.exe", false)]
    [InlineData(WebView, true)]
    [InlineData(@"C:\Program Files\Microsoft\EdgeWebView\Application\141.0.1.0\msedgewebview2.exe", true)]
    [InlineData(@"C:\Users\x\AppData\Local\Microsoft\EdgeWebView\Application\141\msedgewebview2.exe", false)]
    [InlineData(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedgewebview2.exe", false)]
    [InlineData(@"C:\Windows\System32\msedgewebview2.exe", false)]
    public void Prozesse_nur_von_geschuetzten_Orten(string path, bool trusted)
    {
        var name = path[(path.LastIndexOf('\\') + 1)..];
        var canonical = Allowed.First(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(trusted, ExternalAuthWindows.IsTrustedLocation(canonical, path, Roots));
        Assert.Equal(trusted, Allow("Credential Dialog Xaml Host", path));
    }

    [Fact]
    public void Weitere_Prozesse_des_Administrators_aus_Program_Files()
    {
        var allowed = new HashSet<string>(["vendorauth.exe"], StringComparer.OrdinalIgnoreCase);
        bool A(string p) => ExternalAuthWindows.Allow(new AuthWindowFacts("W", p, false, false, false, false), allowed, Roots);
        Assert.True(A(@"C:\Program Files\Vendor\VendorAuth.exe"));
        Assert.True(A(@"C:\Windows\System32\VendorAuth.exe"));
        Assert.False(A(@"C:\Users\x\AppData\Local\Vendor\VendorAuth.exe"));
        Assert.False(A(@"C:\Program Files\Vendor\Other.exe")); // nicht in der Liste
    }

    [Fact]
    public void Reine_Anmelde_Prozesse_auch_mit_schon_sichtbaren_Fenstern_andere_nicht()
    {
        Assert.True(Allow("X", @"C:\Windows\System32\CredentialUIBroker.exe", pre: true));
        Assert.True(Allow("#32770", @"C:\Windows\System32\CredentialUIBroker.exe")); // alter Windows-Sicherheitsdialog
        Assert.False(Allow("Chrome_WidgetWin_1", WebView, pre: true));
        Assert.False(Allow("X", null!));
    }

    // ---------- Windows-Anmeldedialog nach Zeitlimit schließen ----------

    [Fact]
    public void Nach_Zeitlimit_nur_die_Dialoge_dieses_Versuchs_schliessen()
    {
        nint owner = 100;
        var before = new HashSet<nint> { 3 };
        var windows = new[]
        {
            new TopWindow(1, owner, "CredentialUIBroker.exe"),  // gehört dem Entsperr-Dialog
            new TopWindow(2, 0, "CredDialogHost.exe"),           // neu, ohne Besitzer
            new TopWindow(3, 0, "CredentialUIBroker.exe"),      // war schon offen (anderer Dialog)
            new TopWindow(4, owner, "notepad.exe"),             // anderer Prozess: nie
            new TopWindow(5, 0, null),
        };
        Assert.Equal([(nint)1, 2], OwnedAuthDialogs.ToClose(windows, owner, before));
    }

    [Fact]
    public void Hoechstens_ein_Windows_Anmeldedialog_gleichzeitig()
    {
        var gate = new PromptGate();
        Assert.True(gate.TryEnter());
        Assert.True(gate.Busy);
        Assert.False(gate.TryEnter());
        gate.Exit();
        Assert.False(gate.Busy);
        Assert.True(gate.TryEnter());
    }
}
