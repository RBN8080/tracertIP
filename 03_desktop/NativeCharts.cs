using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace TracertIP.Desktop;

internal static class NativeCharts
{
    public static void Latency(Canvas canvas, Round[] rounds, RouteEvent[] events, DateTimeOffset start, DateTimeOffset end,
        ElementTheme theme, RouteEvent? selected = null)
    {
        var width = canvas.ActualWidth;
        var height = canvas.ActualHeight;
        if (width < 100 || height < 60)
            return;
        canvas.Children.Clear();
        var dark = theme == ElementTheme.Dark;
        var text = dark ? Brush(171, 185, 205) : Brush(75, 88, 103);
        var grid = dark ? Brush(62, 76, 94) : Brush(203, 214, 227);
        var line = dark ? Brush(113, 224, 208) : Brush(0, 109, 99);
        var rtts = rounds.Select(r => r.Rtt).ToArray();
        var scale = Math.Max(5, Math.Ceiling(rtts.OfType<double>().DefaultIfEmpty(0).Max() / 5) * 5);
        const double left = 49, top = 14;
        var right = width - 9;
        var bottom = height - 27;
        var seconds = Math.Max(1, (end - start).TotalSeconds);
        double X(DateTimeOffset t) => left + (t - start).TotalSeconds / seconds * (right - left);
        double Y(double v) => bottom - v / scale * (bottom - top);

        for (var i = 0; i <= 4; i++)
        {
            var tick = scale * i / 4;
            var y = Y(tick);
            Stroke(canvas, left, y, right, y, grid);
            Label(canvas, i == 4 ? $"{tick:0} ms" : $"{tick:0}", 0, y - 8, text);
            var at = start.AddSeconds(seconds * i / 4);
            Label(canvas, at.ToLocalTime().ToString("HH:mm"), Math.Min(X(at), right - 31), bottom + 7, text);
        }

        foreach (var change in events.Where(e => e.State != "dropped" && e.Time >= start && e.Time <= end))
        {
            var x = X(change.Time);
            var eventBrush = change.State == "confirmed"
                ? dark ? Brush(255, 155, 155) : Brush(160, 41, 55)
                : dark ? Brush(255, 199, 119) : Brush(135, 73, 10);
            Stroke(canvas, x, top, x, bottom, eventBrush, change == selected ? 2 : 1, true);
        }

        PointCollection segment = [];
        DateTimeOffset? previous = null;
        for (var i = 0; i < rounds.Length; i++)
        {
            var r = rounds[i];
            if (rtts[i] is not { } value)
            {
                Finish();
                previous = null;
                continue;
            }
            if (previous != null && r.Start - previous >= TimeSpan.FromSeconds(7))
                Finish();
            segment.Add(new Point(X(r.Start), Y(value)));
            previous = r.Start;
        }
        Finish();
        if (rtts.All(v => v == null))
            Label(canvas, rounds.Length == 0 ? "Sin mediciones" : "Sin respuestas del destino", left + 12, top + 22, text);

        void Finish()
        {
            if (segment.Count == 1)
            {
                var dot = new Ellipse { Width = 4, Height = 4, Fill = line };
                Canvas.SetLeft(dot, segment[0].X - 2);
                Canvas.SetTop(dot, segment[0].Y - 2);
                canvas.Children.Add(dot);
            }
            else if (segment.Count > 1)
            {
                canvas.Children.Add(new Polyline { Points = segment, Stroke = line, StrokeThickness = 1.6 });
            }
            segment = [];
        }
    }

    public static void Heat(Canvas canvas, Round[] rounds, ElementTheme theme)
    {
        var width = canvas.ActualWidth;
        var height = canvas.ActualHeight;
        if (width < 90 || height < 50)
            return;
        canvas.Children.Clear();
        if (rounds.Length == 0)
            return;

        var dark = theme == ElementTheme.Dark;
        var ink = dark ? Brush(171, 185, 205) : Brush(75, 88, 103);
        var gap = dark ? Brush(62, 76, 94) : Brush(203, 214, 227);
        var maxTtl = rounds.SelectMany(r => r.Hops).Select(p => p.Ttl).DefaultIfEmpty(1).Max();
        var columns = Math.Min(150, rounds.Length);
        var cw = (width - 34) / columns;
        var ch = height / maxTtl;
        for (var ttl = 1; ttl <= maxTtl; ttl += Math.Max(1, maxTtl / 8))
            Label(canvas, ttl.ToString(), 4, (ttl - 1) * ch, ink);

        for (var i = 0; i < columns; i++)
        {
            var r = rounds[columns == 1 ? 0 : i * (rounds.Length - 1) / (columns - 1)];
            foreach (var hop in r.Hops)
            {
                var tile = new Rectangle { Width = cw + 0.3, Height = ch + 0.3, Fill = hop.RttMs is double ms ? HeatBrush(ms) : gap };
                Canvas.SetLeft(tile, 32 + cw * i);
                Canvas.SetTop(tile, (hop.Ttl - 1) * ch);
                canvas.Children.Add(tile);
            }
        }
    }

    private static SolidColorBrush HeatBrush(double ms)
    {
        var p = Math.Clamp(Math.Log10(Math.Max(1, ms)) / Math.Log10(400), 0, 1);
        return Brush((byte)(54 + 190 * p), (byte)(28 + 199 * p), (byte)(110 - 63 * p));
    }

    private static void Stroke(Canvas c, double x1, double y1, double x2, double y2, Brush brush, double thickness = 1, bool dashed = false)
    {
        var segment = new Line { X1 = x1, Y1 = y1, X2 = x2, Y2 = y2, Stroke = brush, StrokeThickness = thickness };
        if (dashed)
            segment.StrokeDashArray = [4, 4];
        c.Children.Add(segment);
    }

    private static void Label(Canvas c, string text, double x, double y, Brush brush)
    {
        var label = new TextBlock { Text = text, FontSize = 10, Foreground = brush };
        Canvas.SetLeft(label, x);
        Canvas.SetTop(label, y);
        c.Children.Add(label);
    }

    private static SolidColorBrush Brush(byte red, byte green, byte blue) => new(Color.FromArgb(255, red, green, blue));
}
