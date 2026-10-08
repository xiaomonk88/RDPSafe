using System.Collections;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;
using RDPSafe.Core.Platform;

namespace RDPSafe.App.ViewModels;

/// <summary>黑名单或白名单的一侧。</summary>
public sealed partial class IpListModel : ObservableObject
{
    private readonly ListsViewModel _owner;

    public IpListModel(ListsViewModel owner, string kind)
    {
        _owner = owner;
        Kind = kind;
    }

    public string Kind { get; }
    public bool IsBlack => Kind == ListKinds.Black;
    public string Title => IsBlack ? "黑名单" : "白名单";
    public string Description => IsBlack ? "名单内 IP 永久封禁，不会自动解封" : "名单内 IP 永不封禁，优先级最高";

    public ObservableCollection<ListEntry> Items { get; } = new();

    [ObservableProperty]
    private string _newIp = "";

    [ObservableProperty]
    private string _newNote = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyCanExecuteChangedFor(nameof(RemoveSelectedCommand))]
    private IList? _selectedRows;

    public bool HasSelection => SelectedRows is { Count: > 0 };

    public void Load(IEnumerable<ListEntry> entries)
    {
        Items.Clear();
        foreach (var e in entries) Items.Add(e);
    }

    [RelayCommand]
    private async Task Add()
    {
        if (string.IsNullOrWhiteSpace(NewIp))
        {
            Ui.Show("请输入 IP 地址或网段（如 1.2.3.4 或 10.0.0.0/24）", true);
            return;
        }
        var r = await EngineClient.Instance.AddListAsync(Kind, NewIp.Trim(), string.IsNullOrWhiteSpace(NewNote) ? null : NewNote.Trim());
        Ui.Show(r);
        if (!r.Ok) return;
        NewIp = "";
        NewNote = "";
        await _owner.RefreshAsync();
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private async Task RemoveSelected()
    {
        var ips = (SelectedRows ?? Array.Empty<object>()).OfType<ListEntry>().Select(e => e.Ip).ToList();
        if (ips.Count == 0) return;
        var msg = IsBlack
            ? $"确定将 {string.Join("、", ips.Take(5))}{(ips.Count > 5 ? " 等" : "")} 移出黑名单并解封吗？"
            : $"确定将 {string.Join("、", ips.Take(5))}{(ips.Count > 5 ? " 等" : "")} 移出白名单吗？\n移出后这些 IP 若多次登录失败将会被封禁。";
        if (!await Ui.ConfirmAsync($"移出{Title}", msg, "移除", danger: !IsBlack)) return;
        Ui.Show(await EngineClient.Instance.RemoveListAsync(Kind, ips));
        await _owner.RefreshAsync();
    }

    [RelayCommand]
    private void CopyIp(ListEntry? e)
    {
        if (e != null) Ui.CopyText(e.Ip);
    }
}

public sealed partial class ListsViewModel : PageViewModel
{
    public override string Title => "黑白名单";
    public override string Subtitle => "手动指定永久封禁或永不封禁的 IP / 网段";
    public override string Glyph => Glyphs.List;

    public IpListModel Black { get; }
    public IpListModel White { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowMyIpHint))]
    private string? _myIp;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowMyIpHint))]
    private bool _myIpWhitelisted;

    public bool ShowMyIpHint => MyIp != null && !MyIpWhitelisted;

    public ListsViewModel()
    {
        Black = new IpListModel(this, ListKinds.Black);
        White = new IpListModel(this, ListKinds.White);
    }

    public override async Task RefreshAsync()
    {
        var (black, white, myIp) = await Engine.QueryAsync(s =>
            (s.GetList(ListKinds.Black), s.GetList(ListKinds.White), Engine.GetMyRdpIp()));
        Black.Load(black);
        White.Load(white);
        MyIp = myIp;
        MyIpWhitelisted = myIp != null && new Core.Net.IpMatcher(white.Select(w => w.Ip)).Contains(myIp);
    }

    [RelayCommand]
    private async Task AddMyIp()
    {
        if (MyIp == null) return;
        Ui.Show(await Engine.AddListAsync(ListKinds.White, MyIp, "当前远程会话"));
        await RefreshAsync();
    }
}
