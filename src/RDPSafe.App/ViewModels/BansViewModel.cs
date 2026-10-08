using System.Collections;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;

namespace RDPSafe.App.ViewModels;

public sealed partial class BansViewModel : PageViewModel
{
    public override string Title => "封禁管理";
    public override string Subtitle => "被防火墙阻止的来源 IP";
    public override string Glyph => Glyphs.Lock;

    public ObservableCollection<BanRecord> Items { get; } = new();

    [ObservableProperty]
    private bool _activeOnly = true;

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyCanExecuteChangedFor(nameof(UnbanSelectedCommand))]
    private IList? _selectedRows;

    [ObservableProperty]
    private bool _showBanForm;

    [ObservableProperty]
    private string _banIp = "";

    [ObservableProperty]
    private string _banNote = "";

    /// <summary>封禁时长（小时），0 表示永久</summary>
    [ObservableProperty]
    private int _banHours;

    [ObservableProperty]
    private string _summary = "";

    public bool HasSelection => SelectedRows is { Count: > 0 };

    partial void OnActiveOnlyChanged(bool value) => _ = RefreshAsync();

    public override async Task RefreshAsync()
    {
        var active = ActiveOnly;
        var search = Search;
        var (rows, stats) = await Engine.QueryAsync(s => (s.QueryBans(active, search, 5000), s.GetDashboard()));
        Items.Clear();
        foreach (var r in rows) Items.Add(r);
        Summary = $"当前封禁 {stats.ActiveBans:N0} 个 · 今日新增 {stats.TodayNewBans:N0} · 历史累计 {stats.TotalBans:N0}";
    }

    public override Task OnTickAsync(int tick) =>
        tick % 4 == 0 && !HasSelection && !ShowBanForm ? RefreshAsync() : Task.CompletedTask;

    [RelayCommand]
    private Task Query() => RefreshAsync();

    [RelayCommand]
    private void ToggleBanForm()
    {
        ShowBanForm = !ShowBanForm;
        if (ShowBanForm)
        {
            BanIp = "";
            BanNote = "";
            BanHours = 0;
        }
    }

    [RelayCommand]
    private async Task SubmitBan()
    {
        if (string.IsNullOrWhiteSpace(BanIp))
        {
            Ui.Show("请输入要封禁的 IP 或网段", true);
            return;
        }
        var r = await Engine.BanAsync(BanIp.Trim(), BanHours > 0 ? BanHours : null, string.IsNullOrWhiteSpace(BanNote) ? null : BanNote.Trim());
        Ui.Show(r);
        if (!r.Ok) return;
        ShowBanForm = false;
        await RefreshAsync();
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private async Task UnbanSelected()
    {
        var ips = Selected<BanRecord>(SelectedRows).Where(b => b.Active).Select(b => b.Ip).Distinct().ToList();
        if (ips.Count == 0)
        {
            Ui.Show("所选记录均已解封", true);
            return;
        }
        if (!await Ui.ConfirmAsync("解封 IP", $"确定解封 {string.Join("、", ips.Take(5))}{(ips.Count > 5 ? $" 等 {ips.Count} 个 IP" : "")} 吗？\n若对方继续尝试登录失败，将会被再次封禁。", "解封")) return;
        Ui.Show(await Engine.UnbanAsync(ips));
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task UnbanOne(BanRecord? b)
    {
        if (b is not { Active: true }) return;
        if (!await Ui.ConfirmAsync("解封 IP", $"确定解封 {b.Ip}（{b.Country}）吗？", "解封")) return;
        Ui.Show(await Engine.UnbanAsync(new[] { b.Ip }));
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task WhitelistOne(BanRecord? b)
    {
        if (b == null) return;
        if (!await Ui.ConfirmAsync("加入白名单", $"确定将 {b.Ip}（{b.Country}）加入白名单吗？\n该 IP 会被立即解封，且以后不再封禁。")) return;
        Ui.Show(await Engine.AddListAsync(ListKinds.White, b.Ip, "从封禁管理添加"));
        await RefreshAsync();
    }

    [RelayCommand]
    private void CopyIp(BanRecord? b)
    {
        if (b != null) Ui.CopyText(b.Ip);
    }

    [RelayCommand]
    private void ViewLogins(BanRecord? b)
    {
        if (b != null) MainViewModel.Instance.ShowLogins(b.Ip);
    }
}
