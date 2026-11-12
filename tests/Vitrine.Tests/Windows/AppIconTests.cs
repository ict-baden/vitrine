// SPDX-License-Identifier: MIT
using Vitrine.UI;

namespace Vitrine.Tests.Windows;

/// <summary>App-Symbol in passender Größe aus der .ico (#17).</summary>
[Collection(WpfCollection.Name)]
public sealed class AppIconTests
{
    private static readonly int[] IcoSizes = [16, 24, 32, 48, 64, 128, 256];

    [Theory]
    [InlineData(16, 16)]    // Flyout-Größe 16 bei 100 %
    [InlineData(20, 24)]    // Flyout 20 × 20 bei 100 %
    [InlineData(30, 32)]    // Flyout bei 150 %
    [InlineData(34, 48)]    // Kopfzeile der Einstellungen bei 100 %
    [InlineData(51, 64)]    // … bei 150 %
    [InlineData(68, 128)]   // … bei 200 %
    [InlineData(64, 64)]    // Info-Seite bei 100 %
    [InlineData(96, 128)]   // … bei 150 %
    [InlineData(128, 128)]  // … bei 200 %
    [InlineData(600, 256)]  // größer als vorhanden: größtes Bild
    public void Waehlt_das_kleinste_Bild_das_gross_genug_ist(double pixels, int expected) =>
        Assert.Equal(expected, AppIcon.PickSize(IcoSizes, pixels));

    [Fact]
    public void Ico_enthaelt_alle_Groessen_und_liefert_scharfe_Bilder()
    {
        WpfHost.Run(() =>
        {
            Assert.Equal(256, AppIcon.Frame(256).PixelWidth);
            Assert.Equal(64, AppIcon.Frame(51).PixelWidth);
            Assert.Equal(48, AppIcon.Frame(34).PixelWidth);
            Assert.Equal(24, AppIcon.Frame(20).PixelWidth);
        });
    }
}
