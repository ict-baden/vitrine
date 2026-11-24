// SPDX-License-Identifier: MIT
using Vitrine.Core.Lock;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Lock;

public sealed class ScreenMasksTests
{
    private static readonly PixelRect Monitor = new(0, 0, 1000, 500);

    [Theory]
    [InlineData("1:0,0,30,100", 1, 0, 0, 30, 100)]
    [InlineData("*:70,0,30,12.5", 0, 70, 0, 30, 12.5)]
    [InlineData(" 2 : 10 , 20 , 30 , 40 ", 2, 10, 20, 30, 40)]
    [InlineData("1:90,90,50,50", 1, 90, 90, 10, 10)] // auf den Monitor begrenzt
    public void Bereich_aus_Text(string text, int monitor, double x, double y, double w, double h)
    {
        var m = MaskRegion.Parse(text)!;
        Assert.Equal((monitor, x, y, w, h), (m.Monitor, m.X, m.Y, m.Width, m.Height));
        Assert.Equal(m.Format(), MaskRegion.Parse(m.Format())!.Format());
    }

    [Theory]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("1:0,0,30")]
    [InlineData("x:0,0,30,30")]
    [InlineData("-1:0,0,30,30")]
    [InlineData("1:0,0,0,30")]
    [InlineData("1:0,0,NaN,30")]
    [InlineData("1:100,0,30,30")]
    public void Ungueltige_Bereiche(string text) => Assert.Null(MaskRegion.Parse(text));

    [Fact]
    public void Formatierung_ist_kulturunabhaengig()
    {
        using var _ = new UiCulture("de");
        Assert.Equal("*:12.5,0,30,10", new MaskRegion { Monitor = 0, X = 12.5, Width = 30, Height = 10 }.Format());
    }

    [Fact]
    public void Monitore_Hauptmonitor_zuerst_dann_von_links()
    {
        var numbers = ScreenMasks.NumberMonitors([
            (new PixelRect(1920, 0, 3840, 1080), false),
            (new PixelRect(-1920, 0, 0, 1080), false),
            (new PixelRect(0, 0, 1920, 1080), true),
        ]);
        Assert.Equal([3, 2, 1], numbers);
    }

    [Fact]
    public void Masken_in_Pixeln_je_Monitor()
    {
        MaskRegion[] masks = [MaskRegion.Parse("1:0,0,30,100")!, MaskRegion.Parse("2:0,0,50,50")!, MaskRegion.Parse("*:90,90,10,10")!];
        Assert.Equal([new PixelRect(0, 0, 300, 500), new PixelRect(900, 450, 1000, 500)], ScreenMasks.MaskRects(masks, 1, Monitor));
        Assert.Equal([new PixelRect(0, 0, 500, 250), new PixelRect(900, 450, 1000, 500)], ScreenMasks.MaskRects(masks, 2, Monitor));
        Assert.Single(ScreenMasks.MaskRects(masks, 3, Monitor));
    }

    [Fact]
    public void Prozent_werden_nach_aussen_gerundet()
    {
        // Lieber ein Pixel mehr verdecken als eine Kante Patientendaten zeigen
        var r = ScreenMasks.MaskRects([new MaskRegion { Monitor = 1, X = 10.05, Y = 0, Width = 10.01, Height = 0.1 }], 1, Monitor).Single();
        Assert.Equal(new PixelRect(100, 0, 201, 1), r);
    }

    [Fact]
    public void Freigegebenes_Fenster_ohne_Ueberdeckung()
    {
        var areas = ScreenMasks.RevealedAreas([(new PixelRect(100, 100, 400, 300), true)], Monitor);
        Assert.Equal([new PixelRect(100, 100, 400, 300)], areas);
    }

    [Fact]
    public void Fenster_darueber_bleibt_verdeckt()
    {
        // Mail-Fenster liegt oben rechts über dem freigegebenen Chromatogramm
        var areas = ScreenMasks.RevealedAreas([
            (new PixelRect(300, 0, 600, 200), false),
            (new PixelRect(100, 100, 400, 300), true),
        ], Monitor);
        Assert.Equal(300 * 200 - 100 * 100, areas.Sum(a => a.Width * a.Height));
        Assert.All(areas, a => Assert.True(a.Intersect(new PixelRect(300, 0, 600, 200)).IsEmpty));
    }

    [Fact]
    public void Fenster_darunter_aendert_nichts()
    {
        var areas = ScreenMasks.RevealedAreas([
            (new PixelRect(100, 100, 400, 300), true),
            (new PixelRect(0, 0, 1000, 500), false),
        ], Monitor);
        Assert.Equal([new PixelRect(100, 100, 400, 300)], areas);
    }

    [Fact]
    public void Ueberlappende_freigegebene_Fenster_ergeben_getrennte_Teile()
    {
        var areas = ScreenMasks.RevealedAreas([
            (new PixelRect(0, 0, 200, 200), true),
            (new PixelRect(100, 100, 300, 300), true),
        ], Monitor);
        Assert.Equal(200 * 200 + 200 * 200 - 100 * 100, areas.Sum(a => a.Width * a.Height));
        for (int i = 0; i < areas.Count; i++)
            for (int j = i + 1; j < areas.Count; j++)
                Assert.True(areas[i].Intersect(areas[j]).IsEmpty);
    }

    [Fact]
    public void Fenster_auf_zweitem_Monitor_relativ_zu_ihm()
    {
        var second = new PixelRect(1000, 0, 2000, 500);
        var areas = ScreenMasks.RevealedAreas([(new PixelRect(900, 50, 1100, 150), true)], second);
        Assert.Equal([new PixelRect(0, 50, 100, 150)], areas);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Lab\mes.exe", true)]
    [InlineData("mes.EXE", true)]
    [InlineData("Mes", true)]
    [InlineData("outlook.exe", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    public void Programm_erkennen(string? image, bool expected) =>
        Assert.Equal(expected, ScreenMasks.IsRevealed(image, ["mes.exe", " ", "lims"]));

    [Fact]
    public void Rechteck_abziehen()
    {
        var parts = new PixelRect(0, 0, 10, 10).Subtract(new PixelRect(2, 2, 4, 4)).ToList();
        Assert.Equal(4, parts.Count);
        Assert.Equal(100 - 4, parts.Sum(p => p.Width * p.Height));
        Assert.Empty(new PixelRect(0, 0, 10, 10).Subtract(new PixelRect(-1, -1, 11, 11)));
        Assert.Equal([new PixelRect(0, 0, 10, 10)], new PixelRect(0, 0, 10, 10).Subtract(new PixelRect(20, 20, 30, 30)));
    }
}
