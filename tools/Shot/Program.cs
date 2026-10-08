// 开发辅助：通过 UI 自动化切换 RDPSafe 各页面并截图，用于界面走查。
// 用法：Shot <输出目录> [页面名...]
using System.Diagnostics;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Windows.Automation;

Native.SetProcessDpiAwarenessContext(new IntPtr(-4));
var outDir = args.Length > 0 ? args[0] : "shots";
Directory.CreateDirectory(outDir);
var pages = args.Length > 1 ? args[1..] : new[] { "概览", "登录记录", "封禁管理", "黑白名单", "防火墙规则", "操作日志", "设置" };

var proc = Process.GetProcessesByName("RDPSafe").FirstOrDefault(p => p.MainWindowHandle != IntPtr.Zero)
           ?? throw new InvalidOperationException("RDPSafe 未运行");
var hwnd = proc.MainWindowHandle;
Native.ShowWindow(hwnd, 9);
Native.SetForegroundWindow(hwnd);
Thread.Sleep(800);
var root = AutomationElement.FromHandle(hwnd);

// 关闭可能存在的首次启动对话框
foreach (var name in new[] { "取消", "知道了" })
{
    var btn = root.FindFirst(TreeScope.Descendants, new AndCondition(
        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button),
        new PropertyCondition(AutomationElement.NameProperty, name)));
    if (btn?.GetCurrentPattern(InvokePattern.Pattern) is InvokePattern ip) { ip.Invoke(); Thread.Sleep(500); }
}

var items = root.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
foreach (var page in pages)
{
    AutomationElement? target = null;
    foreach (AutomationElement it in items)
    {
        var text = it.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, page));
        if (text != null) { target = it; break; }
    }
    if (target?.GetCurrentPattern(SelectionItemPattern.Pattern) is SelectionItemPattern sel) sel.Select();
    Thread.Sleep(2500);
    Capture(hwnd, Path.Combine(outDir, $"{Array.IndexOf(pages, page) + 1}-{page}.png"));
    Console.WriteLine($"captured {page}");
}

static void Capture(IntPtr hwnd, string file)
{
    Native.SetForegroundWindow(hwnd);
    Thread.Sleep(300);
    Native.GetWindowRect(hwnd, out var r);
    using var bmp = new Bitmap(r.Right - r.Left, r.Bottom - r.Top);
    using (var g = Graphics.FromImage(bmp))
        g.CopyFromScreen(r.Left, r.Top, 0, 0, bmp.Size);
    bmp.Save(file, ImageFormat.Png);
}

static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int cmd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
}
