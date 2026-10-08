using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;

namespace RDPSafe.App.ViewModels;

public sealed class HourBar
{
    public string Label { get; init; } = "";
    public bool ShowLabel { get; init; }
    public double FailHeight { get; init; }
    public double SuccessHeight { get; init; }
    public string Tip { get; init; } = "";
}

public sealed partial class DashboardViewModel : PageViewModel
{
    private const double ChartHeight = 150;

    public override string Title => "概览";
    public override string Subtitle => "实时掌握远程桌面的安全态势";
    public override string Glyph => Glyphs.Home;

    [ObservableProperty]
    private DashboardStats _stats = new();

    [ObservableProperty]
    private long _chartMax;

    [ObservableProperty]
    private long _last24Failures;

    public ObservableCollection<HourBar> Bars { get; } = new();
    public ObservableCollection<AttackerStat> TopAttackers { get; } = new();
    public ObservableCollection<BanRecord> RecentBans { get; } = new();

    public override async Task RefreshAsync()
    {
        var (stats, hourly, top, recent, settings) = await Engine.QueryAsync(s => (
            s.GetDashboard(),
            s.GetHourly(24),
            s.GetTopAttackers(TimeUtil.Now() - 86400, 8),
            s.GetRecentBans(6),
            s.LoadSettings()));

        Stats = stats;
        State.PolicyText = settings.Describe();

        var max = Math.Max(1, hourly.Max(h => h.Failures + h.Successes));
        ChartMax = max;
        Last24Failures = hourly.Sum(h => h.Failures);
        Bars.Clear();
        for (var i = 0; i < hourly.Count; i++)
        {
            var h = hourly[i];
            var t = TimeUtil.ToLocal(h.Hour);
            Bars.Add(new HourBar
            {
                Label = t.ToString("HH:00"),
                ShowLabel = i % 4 == 3,
                FailHeight = h.Failures == 0 ? 0 : Math.Max(3, h.Failures * ChartHeight / max),
                SuccessHeight = h.Successes == 0 ? 0 : Math.Max(3, h.Successes * ChartHeight / max),
                Tip = $"{t:MM-dd HH:00} – {t.AddHours(1):HH:00}\n失败 {h.Failures:N0} 次 · 成功 {h.Successes:N0} 次",
            });
        }

        Replace(TopAttackers, top);
        Replace(RecentBans, recent);
    }

    public override Task OnTickAsync(int tick) => tick % 2 == 0 ? RefreshAsync() : Task.CompletedTask;

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();
        foreach (var i in items) target.Add(i);
    }

    [RelayCommand]
    private async Task BanAttacker(AttackerStat? a)
    {
        if (a == null) return;
        if (!await Ui.ConfirmAsync("封禁 IP", $"确定要永久封禁 {a.Ip}（{a.Country}）吗？\n该 IP 的所有入站连接都将被防火墙阻止。", "封禁", danger: true)) return;
        Ui.Show(await Engine.BanAsync(a.Ip, null, "从概览手动封禁"));
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task WhitelistAttacker(AttackerStat? a)
    {
        if (a == null) return;
        if (!await Ui.ConfirmAsync("加入白名单", $"确定将 {a.Ip}（{a.Country}）加入白名单吗？\n白名单中的 IP 永远不会被封禁。")) return;
        Ui.Show(await Engine.AddListAsync(ListKinds.White, a.Ip, "从概览添加"));
        await RefreshAsync();
    }

    [RelayCommand]
    private void ViewLogins(AttackerStat? a)
    {
        if (a != null) MainViewModel.Instance.ShowLogins(a.Ip);
    }

    [RelayCommand]
    private void GoTo(string page) => MainViewModel.Instance.Navigate(page);

    [RelayCommand]
    private async Task EnableFirewall()
    {
        var port = Core.Platform.RdpSessions.GetRdpPort();
        if (!await Ui.ConfirmAsync("开启 Windows 防火墙",
                $"当前网络（{State.FirewallOffProfiles}）的 Windows 防火墙已关闭，RDPSafe 的封禁规则不会生效。\n\n" +
                $"开启前会先自动创建远程桌面端口 {port}（TCP/UDP）的放行规则，保证你仍能远程连接。\n\n" +
                "注意：开启后，没有放行规则的其他对外服务（如网站、数据库端口）将无法从外部访问，" +
                "请确认这些服务已有放行规则，或开启后在“防火墙规则”页补充。确定开启吗？", "开启防火墙")) return;
        try
        {
            await Task.Run(() => Core.Firewall.FirewallApi.EnableForActiveProfiles(port));
            Engine.Store.Log(LogLevels.Config, $"开启 Windows 防火墙（已确保远程桌面端口 {port} 放行）");
            Ui.Show("防火墙已开启，封禁规则现已生效");
        }
        catch (Exception ex)
        {
            Ui.Show($"开启防火墙失败：{ex.InnerException?.Message ?? ex.Message}", true);
        }
        await MainViewModel.Instance.RefreshStatusAsync();
    }
}
