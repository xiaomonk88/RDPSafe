using System.Collections;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.App.Views;
using RDPSafe.Core.Firewall;

namespace RDPSafe.App.ViewModels;

public enum ActionFilter { All, Allow, Block }

public sealed partial class FirewallViewModel : PageViewModel
{
    private List<FwRule> _all = new();

    public override string Title => "防火墙规则";
    public override string Subtitle => "管理 Windows 防火墙入站规则";
    public override string Glyph => Glyphs.Shield;

    public ObservableCollection<FwRule> Items { get; } = new();

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private ActionFilter _filter = ActionFilter.All;

    [ObservableProperty]
    private bool _onlyEnabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(SingleSelection))]
    [NotifyCanExecuteChangedFor(nameof(EditCommand), nameof(ToggleCommand), nameof(DeleteCommand))]
    private IList? _selectedRows;

    [ObservableProperty]
    private string _summary = "";

    public bool HasSelection => SelectedRows is { Count: > 0 };
    public bool SingleSelection => SelectedRows is { Count: 1 };

    partial void OnSearchChanged(string value) => ApplyFilter();
    partial void OnFilterChanged(ActionFilter value) => ApplyFilter();
    partial void OnOnlyEnabledChanged(bool value) => ApplyFilter();

    public override Task RefreshAsync() => RunBusy(async () =>
    {
        _all = await Task.Run(() => FirewallApi.ListRules(FwDirection.In)
            .OrderByDescending(r => r.IsManaged)
            .ThenBy(r => r.Name, StringComparer.CurrentCulture)
            .ToList());
        ApplyFilter();
    });

    private void ApplyFilter()
    {
        var q = Search.Trim();
        var rows = _all.Where(r =>
            (Filter == ActionFilter.All || (Filter == ActionFilter.Allow ? r.Action == FwAction.Allow : r.Action == FwAction.Block)) &&
            (!OnlyEnabled || r.Enabled) &&
            (q.Length == 0 ||
             r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
             r.LocalPorts.Contains(q, StringComparison.OrdinalIgnoreCase) ||
             r.RemoteAddresses.Contains(q, StringComparison.OrdinalIgnoreCase) ||
             r.ApplicationName.Contains(q, StringComparison.OrdinalIgnoreCase)));
        Items.Clear();
        foreach (var r in rows) Items.Add(r);
        Summary = $"共 {_all.Count} 条入站规则 · 显示 {Items.Count} 条 · 已启用 {_all.Count(r => r.Enabled)} 条";
    }

    private List<FwRule> SelectedRules() => Selected<FwRule>(SelectedRows);

    [RelayCommand]
    private async Task New()
    {
        var rule = RuleEditWindow.Edit(null);
        if (rule == null) return;
        await Apply(() => FirewallApi.Add(rule), $"已创建规则“{rule.Name}”");
    }

    [RelayCommand(CanExecute = nameof(SingleSelection))]
    private Task Edit() => EditRule(SelectedRules().FirstOrDefault());

    [RelayCommand]
    private async Task EditRule(FwRule? original)
    {
        if (original == null) return;
        if (original.IsManaged)
        {
            Ui.Show("RDPSafe 封禁规则由引擎自动维护，请在“封禁管理”中操作", true);
            return;
        }
        var updated = RuleEditWindow.Edit(original);
        if (updated == null || updated == original) return;
        await Apply(() => FirewallApi.Update(original, updated), $"已保存规则“{updated.Name}”");
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private async Task Toggle()
    {
        var rules = SelectedRules().Where(r => !r.IsManaged).ToList();
        if (rules.Count == 0)
        {
            Ui.Show("RDPSafe 封禁规则由引擎自动维护，不能在此修改", true);
            return;
        }
        var enable = rules.Any(r => !r.Enabled);
        await Apply(() =>
        {
            foreach (var r in rules) FirewallApi.SetEnabled(r, enable);
        }, $"已{(enable ? "启用" : "禁用")} {rules.Count} 条规则");
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private async Task Delete()
    {
        var rules = SelectedRules().Where(r => !r.IsManaged).ToList();
        if (rules.Count == 0)
        {
            Ui.Show("RDPSafe 封禁规则由引擎自动维护，不能在此删除", true);
            return;
        }
        var names = string.Join("\n", rules.Take(6).Select(r => "· " + r.Name)) + (rules.Count > 6 ? $"\n… 共 {rules.Count} 条" : "");
        if (!await Ui.ConfirmAsync("删除防火墙规则", $"确定删除以下规则吗？此操作不可撤销。\n\n{names}", "删除", danger: true)) return;
        await Apply(() =>
        {
            foreach (var r in rules) FirewallApi.Delete(r);
        }, $"已删除 {rules.Count} 条规则");
    }

    private async Task Apply(Action action, string success)
    {
        try
        {
            await Task.Run(action);
            Ui.Show(success);
        }
        catch (Exception ex)
        {
            Ui.Show($"操作失败：{ex.InnerException?.Message ?? ex.Message}", true);
        }
        await RefreshAsync();
    }
}

public enum ProtocolChoice { Tcp, Udp, Any, Icmp }

public sealed partial class RuleEditViewModel : ObservableObject
{
    public RuleEditViewModel(FwRule? rule)
    {
        IsNew = rule == null;
        rule ??= new FwRule { Action = FwAction.Allow, Protocol = FwProtocols.Tcp, Enabled = true };
        Original = rule;
        _name = rule.Name;
        _description = rule.Description;
        _allow = rule.Action == FwAction.Allow;
        _protocol = rule.Protocol switch
        {
            FwProtocols.Tcp => ProtocolChoice.Tcp,
            FwProtocols.Udp => ProtocolChoice.Udp,
            FwProtocols.Icmpv4 => ProtocolChoice.Icmp,
            _ => ProtocolChoice.Any,
        };
        _localPorts = Clean(rule.LocalPorts);
        _remotePorts = Clean(rule.RemotePorts);
        _remoteAddresses = Clean(rule.RemoteAddresses);
        _program = rule.ApplicationName;
        _enabled = rule.Enabled;
        CustomProtocol = _protocol == ProtocolChoice.Any && rule.Protocol != FwProtocols.Any ? rule.Protocol : null;

        static string Clean(string s) => s == "*" ? "" : s;
    }

    public bool IsNew { get; }
    public FwRule Original { get; }
    public int? CustomProtocol { get; }
    public string WindowTitle => IsNew ? "新建入站规则" : "编辑入站规则";

    [ObservableProperty]
    private string _name;

    [ObservableProperty]
    private string _description;

    [ObservableProperty]
    private bool _allow;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PortsEnabled))]
    private ProtocolChoice _protocol;

    [ObservableProperty]
    private string _localPorts;

    [ObservableProperty]
    private string _remotePorts;

    [ObservableProperty]
    private string _remoteAddresses;

    [ObservableProperty]
    private string _program;

    [ObservableProperty]
    private bool _enabled;

    [ObservableProperty]
    private string _error = "";

    public bool PortsEnabled => Protocol is ProtocolChoice.Tcp or ProtocolChoice.Udp;

    public FwRule? Build()
    {
        if (string.IsNullOrWhiteSpace(Name))
        {
            Error = "请填写规则名称";
            return null;
        }
        if (Name.StartsWith(BlockRules.Prefix, StringComparison.Ordinal))
        {
            Error = $"名称不能以 {BlockRules.Prefix} 开头（保留给 RDPSafe）";
            return null;
        }
        var protocol = Protocol switch
        {
            ProtocolChoice.Tcp => FwProtocols.Tcp,
            ProtocolChoice.Udp => FwProtocols.Udp,
            ProtocolChoice.Icmp => FwProtocols.Icmpv4,
            _ => CustomProtocol ?? FwProtocols.Any,
        };
        return Original with
        {
            Name = Name.Trim(),
            Description = Description?.Trim() ?? "",
            Direction = FwDirection.In,
            Action = Allow ? FwAction.Allow : FwAction.Block,
            Protocol = protocol,
            LocalPorts = PortsEnabled ? Star(LocalPorts) : Original.LocalPorts,
            RemotePorts = PortsEnabled ? Star(RemotePorts) : Original.RemotePorts,
            RemoteAddresses = Star(RemoteAddresses),
            ApplicationName = Program?.Trim() ?? "",
            Enabled = Enabled,
        };

        static string Star(string? s) => string.IsNullOrWhiteSpace(s) ? "*" : s.Replace("，", ",").Replace(" ", "").Trim();
    }
}
