using System.Windows;
using Forms = System.Windows.Forms;

namespace RDPSafe.App.Services;

/// <summary>系统托盘图标。</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;

    public TrayIcon(Action open, Action exit)
    {
        var stream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/rdpsafe.ico"))!.Stream;
        var menu = new Forms.ContextMenuStrip { ShowImageMargin = false, Font = new System.Drawing.Font("Microsoft YaHei UI", 9f) };
        menu.Items.Add("打开 RDPSafe", null, (_, _) => open());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("退出界面（防护服务继续运行）", null, (_, _) => exit());

        _icon = new Forms.NotifyIcon
        {
            Icon = new System.Drawing.Icon(stream),
            Text = $"RDPSafe v{Core.AppInfo.Version} · RDP 防暴力破解",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left) open();
        };
        _icon.BalloonTipClicked += (_, _) => open();
    }

    public void Notify(string title, string text) =>
        _icon.ShowBalloonTip(4000, title, text, Forms.ToolTipIcon.Info);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
