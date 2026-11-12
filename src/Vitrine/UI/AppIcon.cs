// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Vitrine.UI;

/// <summary>
/// App-Symbol in passender Auflösung (#17). <c>&lt;Image Source="vitrine.ico"/&gt;</c> nimmt nur das erste Bild der
/// .ico (16 × 16) und skaliert es hoch – unscharf. Dieses Element wählt das kleinste Bild der .ico, das bei Größe × DPI
/// noch mindestens so groß ist, und verkleinert es mit hoher Qualität. Bei DPI-Wechsel (anderer Bildschirm) neu.
/// </summary>
public sealed class AppIcon : Image
{
    public static readonly Uri IconUri = new("pack://application:,,,/Vitrine;component/Assets/vitrine.ico");

    private static IReadOnlyList<BitmapFrame>? _frames;

    /// <summary>Mindest-Skalierung beim Auswählen (Screenshots zeichnen mit 2-facher Auflösung).</summary>
    internal static double MinScale { get; set; } = 1;

    public AppIcon()
    {
        Stretch = Stretch.Uniform;
        RenderOptions.SetBitmapScalingMode(this, BitmapScalingMode.HighQuality);
        Loaded += (_, _) => Update(VisualTreeHelper.GetDpi(this).DpiScaleX);
        DpiChanged += (_, e) => Update(e.NewDpi.DpiScaleX);
    }

    protected override void OnInitialized(EventArgs e)
    {
        base.OnInitialized(e);
        Update(VisualTreeHelper.GetDpi(this).DpiScaleX);
    }

    private void Update(double scale)
    {
        var size = double.IsNaN(Width) ? Math.Max(ActualWidth, 16) : Width;
        var frame = Frame(size * Math.Max(scale, MinScale));
        if (!ReferenceEquals(Source, frame)) Source = frame;
    }

    /// <summary>Bild der .ico für die gewünschte Kantenlänge in Pixeln.</summary>
    public static BitmapFrame Frame(double pixels)
    {
        var frames = _frames ??= Load();
        var best = PickSize(frames.Select(f => f.PixelWidth), pixels);
        return frames.First(f => f.PixelWidth == best);
    }

    /// <summary>Kleinste vorhandene Größe ≥ <paramref name="pixels"/>, sonst die größte.</summary>
    internal static int PickSize(IEnumerable<int> available, double pixels)
    {
        var sizes = available.Distinct().Order().ToList();
        if (sizes.Count == 0) throw new ArgumentException("no sizes", nameof(available));
        foreach (var s in sizes)
            if (s >= Math.Ceiling(pixels - 0.01)) return s;
        return sizes[^1];
    }

    private static List<BitmapFrame> Load()
    {
        using var stream = Application.GetResourceStream(IconUri)!.Stream;
        var decoder = BitmapDecoder.Create(stream, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        var frames = decoder.Frames.ToList();
        foreach (var f in frames)
            if (f.CanFreeze) f.Freeze();
        return frames;
    }
}
