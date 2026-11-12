// SPDX-License-Identifier: MIT
using Vitrine.UI;

namespace Vitrine.Tests.Windows;

/// <summary>Anmeldefenster ohne echtes WebView2: nur das Skript, das in jedes Dokument kommt.</summary>
public sealed class SignInWindowTests
{
    [Fact]
    public void Anmeldefenster_verhindert_Drucken_und_Dateiauswahl()
    {
        // Läuft in jedem Dokument vor dessen eigenen Skripten (AddScriptToExecuteOnDocumentCreatedAsync)
        var script = SignInWindow.HardeningScript;
        Assert.Contains("'print'", script);
        Assert.Contains("showOpenFilePicker", script);
        Assert.Contains("showDirectoryPicker", script);
        Assert.Contains("=== 'file'", script);
        Assert.Contains("label.control", script);
    }
}
