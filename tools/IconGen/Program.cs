// 生成 RDPSafe 图标：assets/rdpsafe.ico（多尺寸 PNG 内嵌）与 assets/rdpsafe.png
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

var outDir = args.Length > 0 ? args[0] : Path.Combine("..", "..", "assets");
Directory.CreateDirectory(outDir);
int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };
var pngs = new List<byte[]>();

foreach (var s in sizes)
{
    using var bmp = new Bitmap(s, s);
    using (var g = Graphics.FromImage(bmp))
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);
        float k = s / 256f;
        PointF P(float x, float y) => new(x * k, y * k);

        using var path = new GraphicsPath();
        path.AddBezier(P(128, 12), P(170, 40), P(205, 44), P(232, 46));
        path.AddBezier(P(232, 46), P(236, 150), P(200, 214), P(128, 246));
        path.AddBezier(P(128, 246), P(56, 214), P(20, 150), P(24, 46));
        path.AddBezier(P(24, 46), P(51, 44), P(86, 40), P(128, 12));
        path.CloseFigure();

        using var brush = new LinearGradientBrush(new RectangleF(0, 0, s, s),
            Color.FromArgb(99, 102, 241), Color.FromArgb(20, 184, 166), 60f);
        g.FillPath(brush, path);

        using var pen = new Pen(Color.White, Math.Max(1.6f, 26 * k))
        {
            StartCap = LineCap.Round,
            EndCap = LineCap.Round,
            LineJoin = LineJoin.Round,
        };
        g.DrawLines(pen, new[] { P(82, 130), P(116, 164), P(178, 98) });
    }

    using var ms = new MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    pngs.Add(ms.ToArray());
    if (s == 256) bmp.Save(Path.Combine(outDir, "rdpsafe.png"), ImageFormat.Png);
}

using var file = File.Create(Path.Combine(outDir, "rdpsafe.ico"));
using var w = new BinaryWriter(file);
w.Write((ushort)0);
w.Write((ushort)1);
w.Write((ushort)sizes.Length);
var offset = 6 + 16 * sizes.Length;
for (var i = 0; i < sizes.Length; i++)
{
    var b = (byte)(sizes[i] >= 256 ? 0 : sizes[i]);
    w.Write(b);
    w.Write(b);
    w.Write((byte)0);
    w.Write((byte)0);
    w.Write((ushort)1);
    w.Write((ushort)32);
    w.Write((uint)pngs[i].Length);
    w.Write((uint)offset);
    offset += pngs[i].Length;
}
foreach (var d in pngs) w.Write(d);
Console.WriteLine($"已生成 {Path.GetFullPath(outDir)}");
