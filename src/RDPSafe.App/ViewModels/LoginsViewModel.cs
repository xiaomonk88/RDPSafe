using System.Collections;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;

namespace RDPSafe.App.ViewModels;

public enum ResultFilter { All, Failure, Success }

public sealed partial class LoginsViewModel : PageViewModel
{
    private const int Limit = 1000;
    private long _maxId;

    public override string Title => "登录记录";
    public override string Subtitle => "远程桌面登录尝试明细，最近 1000 条";
    public override string Glyph => Glyphs.History;

    public ObservableCollection<LoginEvent> Items { get; } = new();

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private ResultFilter _filter = ResultFilter.All;

    [ObservableProperty]
    private bool _live = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(SelectionText))]
    [NotifyCanExecuteChangedFor(nameof(BanSelectedCommand), nameof(WhitelistSelectedCommand))]
    private IList? _selectedRows;

    [ObservableProperty]
    private long _totalCount;

    public bool HasSelection => SelectedRows is { Count: > 0 };
    public string SelectionText => HasSelection ? $"已选 {SelectedIps().Count} 个 IP" : "";

    partial void OnFilterChanged(ResultFilter value) => _ = RefreshAsync();

    partial void OnLiveChanged(bool value)
    {
        if (value) _ = RefreshAsync();
    }

    private bool? SuccessFilter => Filter switch
    {
        ResultFilter.Failure => false,
        ResultFilter.Success => true,
        _ => null,
    };

    public override async Task RefreshAsync()
    {
        var search = Search;
        var succ = SuccessFilter;
        var (rows, total) = await Engine.QueryAsync(s => (s.QueryEvents(search, succ, Limit), s.CountEvents()));
        Items.Clear();
        foreach (var r in rows) Items.Add(r);
        _maxId = rows.Count > 0 ? rows[0].Id : await Engine.QueryAsync(s => s.QueryEvents(null, null, 1).FirstOrDefault()?.Id ?? 0);
        TotalCount = total;
    }

    public override async Task OnTickAsync(int tick)
    {
        if (!Live || HasSelection) return;
        var search = Search;
        var succ = SuccessFilter;
        var after = _maxId;
        var rows = await Engine.QueryAsync(s => s.QueryEvents(search, succ, Limit, after));
        if (rows.Count == 0) return;
        _maxId = rows[0].Id;
        for (var i = rows.Count - 1; i >= 0; i--) Items.Insert(0, rows[i]);
        while (Items.Count > Limit) Items.RemoveAt(Items.Count - 1);
        TotalCount += rows.Count;
    }

    private List<string> SelectedIps() => Selected<LoginEvent>(SelectedRows).Select(e => e.Ip).Distinct().ToList();

    [RelayCommand]
    private Task Query() => RefreshAsync();

    [RelayCommand]
    private Task ClearSearch()
    {
        Search = "";
        return RefreshAsync();
    }

    public async Task FilterByIp(string ip)
    {
        Search = ip;
        Filter = ResultFilter.All;
        await RefreshAsync();
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private async Task BanSelected()
    {
        var ips = SelectedIps();
        if (ips.Count == 0) return;
        var list = string.Join("、", ips.Take(5)) + (ips.Count > 5 ? $" 等 {ips.Count} 个" : "");
        if (!await Ui.ConfirmAsync("封禁 IP", $"确定要永久封禁 {list} 吗？", "封禁", danger: true)) return;
        await BanIps(ips);
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private async Task WhitelistSelected()
    {
        var ips = SelectedIps();
        if (ips.Count == 0) return;
        if (!await Ui.ConfirmAsync("加入白名单", $"确定将 {string.Join("、", ips.Take(5))}{(ips.Count > 5 ? " 等" : "")} 加入白名单吗？\n白名单 IP 永不封禁，已封禁的会立即解封。")) return;
        foreach (var ip in ips) Ui.Show(await Engine.AddListAsync(ListKinds.White, ip, "从登录记录添加"));
    }

    [RelayCommand]
    private async Task BanOne(LoginEvent? e)
    {
        if (e == null) return;
        if (!await Ui.ConfirmAsync("封禁 IP", $"确定要永久封禁 {e.Ip}（{e.Country}）吗？", "封禁", danger: true)) return;
        await BanIps(new List<string> { e.Ip });
    }

    [RelayCommand]
    private async Task WhitelistOne(LoginEvent? e)
    {
        if (e == null) return;
        if (!await Ui.ConfirmAsync("加入白名单", $"确定将 {e.Ip}（{e.Country}）加入白名单吗？")) return;
        Ui.Show(await Engine.AddListAsync(ListKinds.White, e.Ip, "从登录记录添加"));
    }

    [RelayCommand]
    private void CopyIp(LoginEvent? e)
    {
        if (e != null) Ui.CopyText(e.Ip);
    }

    [RelayCommand]
    private Task OnlyThisIp(LoginEvent? e) => e == null ? Task.CompletedTask : FilterByIp(e.Ip);

    private async Task BanIps(List<string> ips)
    {
        var ok = 0;
        OpResult? last = null;
        foreach (var ip in ips)
        {
            last = await Engine.BanAsync(ip, null, "从登录记录手动封禁");
            if (last.Ok) ok++;
        }
        Ui.Show(ips.Count == 1 || last == null ? last! : new OpResult { Ok = ok > 0, Message = $"已封禁 {ok}/{ips.Count} 个 IP" });
    }

    [RelayCommand]
    private async Task ClearAll()
    {
        if (!await Ui.ConfirmAsync("清空登录记录", "将删除全部登录记录（不影响封禁与名单），此操作不可恢复。确定继续吗？", "清空", danger: true)) return;
        Ui.Show(await Engine.ClearLoginsAsync());
        await RefreshAsync();
    }
}
