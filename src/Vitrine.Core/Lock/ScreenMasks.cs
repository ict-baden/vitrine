// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Vitrine.Core.Lock;

/// <summary>Rechteck in Bildschirmpixeln (rechts und unten exklusiv, wie RECT unter Windows).</summary>
public readonly record struct PixelRect(int Left, int Top, int Right, int Bottom)
{
    public int Width => Math.Max(0, Right - Left);
    public int Height => Math.Max(0, Bottom - Top);
    public bool IsEmpty => Width == 0 || Height == 0;

    public PixelRect Intersect(PixelRect o)
    {
        var r = new PixelRect(Math.Max(Left, o.Left), Math.Max(Top, o.Top), Math.Min(Right, o.Right), Math.Min(Bottom, o.Bottom));
        return r.IsEmpty ? default : r;
    }

    public PixelRect Offset(int dx, int dy) => new(Left + dx, Top + dy, Right + dx, Bottom + dy);

    /// <summary>Dieses Rechteck ohne <paramref name="cut"/>: bis zu vier Teile, die sich nicht überlappen.</summary>
    public IEnumerable<PixelRect> Subtract(PixelRect cut)
    {
        var i = Intersect(cut);
        if (i.IsEmpty) { if (!IsEmpty) yield return this; yield break; }
        if (i.Top > Top) yield return new PixelRect(Left, Top, Right, i.Top);
        if (i.Bottom < Bottom) yield return new PixelRect(Left, i.Bottom, Right, Bottom);
        if (i.Left > Left) yield return new PixelRect(Left, i.Top, i.Left, i.Bottom);
        if (i.Right < Right) yield return new PixelRect(i.Right, i.Top, Right, i.Bottom);
    }
}

/// <summary>
/// Verdeckter Bereich während der Sperre, in Prozent des Monitors (bleibt bei anderer Auflösung an derselben Stelle).
/// Textform für Richtlinien: „Monitor:X,Y,Breite,Höhe“, z. B. „1:0,0,30,100“ (linkes Drittel von Monitor 1) oder
/// „*:70,0,30,12“ (oben rechts auf jedem Monitor). In config.json gilt die Textform ebenso wie die Objektform
/// (<see cref="MaskRegionJsonConverter"/>).
/// </summary>
[System.Text.Json.Serialization.JsonConverter(typeof(MaskRegionJsonConverter))]
public sealed class MaskRegion
{
    /// <summary>Monitor-Nummer wie in den Einstellungen (1 = Hauptmonitor), 0 = jeder Monitor.</summary>
    public int Monitor { get; set; }
    public double X { get; set; }
    public double Y { get; set; }
    public double Width { get; set; }
    public double Height { get; set; }

    public static MaskRegion? Parse(string text)
    {
        var parts = text.Split(':', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2) return null;
        int monitor;
        if (parts[0] == "*") monitor = 0;
        else if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out monitor) || monitor < 0) return null;

        var n = parts[1].Split(',', StringSplitOptions.TrimEntries);
        if (n.Length != 4) return null;
        var v = new double[4];
        for (int i = 0; i < 4; i++)
            if (!double.TryParse(n[i], NumberStyles.Float, CultureInfo.InvariantCulture, out v[i]) || double.IsNaN(v[i])) return null;
        var r = new MaskRegion { Monitor = monitor, X = v[0], Y = v[1], Width = v[2], Height = v[3] }.Normalized();
        return r.Width > 0 && r.Height > 0 ? r : null;
    }

    public string Format()
    {
        static string F(double d) => Math.Round(d, 2).ToString(CultureInfo.InvariantCulture);
        return $"{(Monitor == 0 ? "*" : Monitor.ToString(CultureInfo.InvariantCulture))}:{F(X)},{F(Y)},{F(Width)},{F(Height)}";
    }

    /// <summary>Auf den Monitor begrenzt (0–100 %), negative Größen auf 0.</summary>
    public MaskRegion Normalized()
    {
        double x = Math.Clamp(X, 0, 100), y = Math.Clamp(Y, 0, 100);
        return new MaskRegion
        {
            Monitor = Math.Max(0, Monitor),
            X = x,
            Y = y,
            Width = Math.Clamp(Width, 0, 100 - x),
            Height = Math.Clamp(Height, 0, 100 - y),
        };
    }

    public override string ToString() => Format();
}

/// <summary>
/// JSON für <see cref="MaskRegion"/>: liest die Textform „1:0,0,30,100“ (wie in der Richtlinie und in docs/settings.md)
/// und die Objektform <c>{"Monitor":1,"X":0,…}</c>, schreibt die Objektform (so lesen es auch ältere Builds). Vorher
/// verwarf die Textform in config.json die ganze Gerätekonfiguration (Prüfung vom 2026-10-20).
/// </summary>
public sealed class MaskRegionJsonConverter : System.Text.Json.Serialization.JsonConverter<MaskRegion>
{
    public override MaskRegion? Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case System.Text.Json.JsonTokenType.Null:
                return null;
            case System.Text.Json.JsonTokenType.String:
                var text = reader.GetString() ?? "";
                return MaskRegion.Parse(text) ?? throw new System.Text.Json.JsonException(
                    $"Invalid covered area '{text}' (expected monitor:x,y,width,height in percent, e.g. 1:0,0,30,100)");
            case System.Text.Json.JsonTokenType.StartObject:
                using (var doc = System.Text.Json.JsonDocument.ParseValue(ref reader))
                {
                    double Number(string name) => doc.RootElement.EnumerateObject()
                        .FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) is { Value.ValueKind: System.Text.Json.JsonValueKind.Number } p
                        ? p.Value.GetDouble() : 0;
                    return new MaskRegion { Monitor = (int)Number("Monitor"), X = Number("X"), Y = Number("Y"), Width = Number("Width"), Height = Number("Height") };
                }
            default:
                throw new System.Text.Json.JsonException("Covered area: text or object expected");
        }
    }

    public override void Write(System.Text.Json.Utf8JsonWriter writer, MaskRegion value, System.Text.Json.JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteNumber("Monitor", value.Monitor);
        writer.WriteNumber("X", value.X);
        writer.WriteNumber("Y", value.Y);
        writer.WriteNumber("Width", value.Width);
        writer.WriteNumber("Height", value.Height);
        writer.WriteEndObject();
    }
}

/// <summary>
/// Geometrie für verdeckte Bereiche und den Modus „Nur freigegebene Programme zeigen“. Ohne Windows-Aufrufe, damit
/// sie unter Linux getestet wird; die App liefert Monitore und Fenster (in Z-Reihenfolge) und zeichnet das Ergebnis.
/// </summary>
public static class ScreenMasks
{
    /// <summary>
    /// Nummern der Monitore (1 = Hauptmonitor, dann von links nach rechts, oben nach unten) – dieselbe Zählung in den
    /// Einstellungen, im Zeichen-Fenster und in der Richtlinie. Ergebnis: Nummer je Eingabe-Index.
    /// </summary>
    public static int[] NumberMonitors(IReadOnlyList<(PixelRect Bounds, bool Primary)> monitors)
    {
        var order = Enumerable.Range(0, monitors.Count)
            .OrderByDescending(i => monitors[i].Primary)
            .ThenBy(i => monitors[i].Bounds.Left)
            .ThenBy(i => monitors[i].Bounds.Top)
            .ToList();
        var numbers = new int[monitors.Count];
        for (int n = 0; n < order.Count; n++) numbers[order[n]] = n + 1;
        return numbers;
    }

    /// <summary>Verdeckte Bereiche eines Monitors in Pixeln, relativ zu seiner linken oberen Ecke.</summary>
    public static List<PixelRect> MaskRects(IEnumerable<MaskRegion> masks, int monitorNumber, PixelRect bounds)
    {
        var list = new List<PixelRect>();
        foreach (var raw in masks)
        {
            var m = raw.Normalized();
            if (m.Monitor != 0 && m.Monitor != monitorNumber) continue;
            int l = (int)Math.Floor(m.X / 100 * bounds.Width), t = (int)Math.Floor(m.Y / 100 * bounds.Height);
            int r = (int)Math.Ceiling((m.X + m.Width) / 100 * bounds.Width), b = (int)Math.Ceiling((m.Y + m.Height) / 100 * bounds.Height);
            var rect = new PixelRect(l, t, Math.Min(r, bounds.Width), Math.Min(b, bounds.Height));
            if (!rect.IsEmpty) list.Add(rect);
        }
        return list;
    }

    /// <summary>
    /// Sichtbare Teile der freigegebenen Fenster auf einem Monitor, relativ zu ihm. <paramref name="windowsTopToBottom"/>
    /// in Z-Reihenfolge (oberstes zuerst). Was ein anderes Fenster darüber verdeckt, bleibt verdeckt – sonst schiene
    /// ein darüberliegendes Mail-Fenster durch das „Loch“ des freigegebenen Programms. Die Teile überlappen sich nicht.
    /// </summary>
    public static List<PixelRect> RevealedAreas(IEnumerable<(PixelRect Rect, bool Reveal)> windowsTopToBottom, PixelRect monitor)
    {
        var visible = new List<PixelRect>();
        var covered = new List<PixelRect>();
        foreach (var (rect, reveal) in windowsTopToBottom)
        {
            var onMonitor = rect.Intersect(monitor);
            if (onMonitor.IsEmpty) continue;
            if (reveal)
            {
                IEnumerable<PixelRect> parts = [onMonitor];
                foreach (var c in covered) parts = parts.SelectMany(p => p.Subtract(c)).ToList();
                visible.AddRange(parts.Select(p => p.Offset(-monitor.Left, -monitor.Top)));
            }
            covered.Add(onMonitor);
        }
        return visible;
    }

    /// <summary>Gehört der Prozess zu den freigegebenen Programmen? Vergleich des Exe-Namens, ohne Groß/Klein und „.exe“.</summary>
    public static bool IsRevealed(string? imageName, IEnumerable<string> processes)
    {
        if (string.IsNullOrEmpty(imageName)) return false;
        var name = Strip(imageName);
        return processes.Any(p => !string.IsNullOrWhiteSpace(p) && string.Equals(Strip(p), name, StringComparison.OrdinalIgnoreCase));

        // Nur der Dateiname, auch unter Linux mit Windows-Pfad (Tests)
        static string Strip(string s)
        {
            s = s.Trim();
            s = s[(s.LastIndexOfAny(['\\', '/']) + 1)..];
            return s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? s[..^4] : s;
        }
    }
}
