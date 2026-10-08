using CommunityToolkit.Mvvm.ComponentModel;
using RDPSafe.Core;
using RDPSafe.Core.Data;
using RDPSafe.Core.Engine;
using RDPSafe.Core.Ipc;
using RDPSafe.Core.Net;
using RDPSafe.Core.Platform;

namespace RDPSafe.App.Services;

/// <summary>全局共享状态：引擎在线情况、服务状态等，由主窗口定时刷新。</summary>
public sealed partial class AppState : ObservableObject
{
    public static AppState Instance { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Online), nameof(StatusTitle), nameof(StatusDetail), nameof(UptimeText), nameof(Protected))]
    private EngineStatus? _engine;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusTitle), nameof(StatusDetail), nameof(ServiceStateText))]
    private EngineServiceState _serviceState = EngineServiceState.Unknown;

    [ObservableProperty]
    private string _policyText = "";

    /// <summary>当前网络中防火墙关闭的配置文件，如“专用、公用”；为空表示防火墙正常开启。</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FirewallOff), nameof(StatusTitle), nameof(StatusDetail), nameof(Protected))]
    private string _firewallOffProfiles = "";

    public bool FirewallOff => FirewallOffProfiles.Length > 0;

    public bool Online => Engine?.Running == true;

    /// <summary>引擎运行且防火墙开启，封禁真正生效。</summary>
    public bool Protected => Online && !FirewallOff;

    public string StatusTitle => Online
        ? (FirewallOff ? "防护未生效" : "防护中")
        : ServiceState switch
        {
            EngineServiceState.NotInstalled => "引擎未安装",
            EngineServiceState.Starting => "引擎启动中",
            EngineServiceState.Running => "引擎连接中",
            _ => "引擎已停止",
        };

    public string StatusDetail => Online
        ? (FirewallOff ? "Windows 防火墙已关闭，封禁无法拦截"
            : Engine!.CollectorError is { } err ? $"采集异常：{err}" : $"已持续运行 {UptimeText}")
        : ServiceState == EngineServiceState.NotInstalled ? "请在“设置”中安装防护服务" : "当前未在监控登录事件";

    public string UptimeText
    {
        get
        {
            if (Engine is not { StartedAt: > 0 } e) return "—";
            var s = TimeUtil.Now() - e.StartedAt;
            return s < 3600 ? $"{Math.Max(1, s / 60)} 分钟" : s < 86400 ? $"{s / 3600} 小时 {s % 3600 / 60} 分钟" : $"{s / 86400} 天 {s % 86400 / 3600} 小时";
        }
    }

    public string ServiceStateText => ServiceState switch
    {
        EngineServiceState.NotInstalled => "未安装",
        EngineServiceState.Stopped => "已停止",
        EngineServiceState.Starting => "启动中",
        EngineServiceState.Running => "运行中",
        EngineServiceState.Stopping => "停止中",
        _ => "未知",
    };
}

/// <summary>
/// 界面访问引擎的入口：服务在线时经命名管道下发命令，离线时直接操作数据库与防火墙。
/// </summary>
public sealed class EngineClient
{
    public static EngineClient Instance { get; } = new();

    public Store Store { get; } = new();
    public GeoLookup Geo => GeoLookup.Shared;

    private readonly Lazy<LocalCommands> _local;

    private EngineClient()
    {
        _local = new Lazy<LocalCommands>(() => new LocalCommands(Store, Geo));
    }

    public async Task RefreshStatusAsync()
    {
        var state = await Task.Run(EngineService.GetState);
        EngineStatus? status = null;
        if (state == EngineServiceState.Running)
        {
            var resp = await PipeClient.SendAsync(new PipeRequest { Cmd = PipeCommands.Status }, connectTimeoutMs: 600, replyTimeoutMs: 3000);
            status = resp?.Status;
        }
        var firewallOff = await Task.Run(() =>
        {
            try { return string.Join("、", Core.Firewall.FirewallApi.GetDisabledActiveProfiles()); }
            catch { return ""; }
        });
        var app = AppState.Instance;
        app.ServiceState = state;
        app.Engine = status;
        app.FirewallOffProfiles = firewallOff;
    }

    public Task<OpResult> BanAsync(string ip, int? hours, string? note) =>
        ExecAsync(new PipeRequest { Cmd = PipeCommands.Ban, Ip = ip, Hours = hours, Note = note });

    public Task<OpResult> UnbanAsync(IEnumerable<string> ips) =>
        ExecAsync(new PipeRequest { Cmd = PipeCommands.Unban, Ips = ips.Distinct().ToArray() });

    public Task<OpResult> AddListAsync(string kind, string ip, string? note) =>
        ExecAsync(new PipeRequest { Cmd = PipeCommands.AddList, Kind = kind, Ip = ip, Note = note });

    public Task<OpResult> RemoveListAsync(string kind, IEnumerable<string> ips) =>
        ExecAsync(new PipeRequest { Cmd = PipeCommands.RemoveList, Kind = kind, Ips = ips.Distinct().ToArray() });

    public Task<OpResult> SaveSettingsAsync(AppSettings s) =>
        ExecAsync(new PipeRequest { Cmd = PipeCommands.SaveSettings, Settings = s });

    public Task<OpResult> ClearLoginsAsync() => ExecAsync(new PipeRequest { Cmd = PipeCommands.ClearLogins });

    public Task<OpResult> ResetDataAsync() => ExecAsync(new PipeRequest { Cmd = PipeCommands.ResetData });

    private async Task<OpResult> ExecAsync(PipeRequest req)
    {
        if (AppState.Instance.Online)
        {
            var resp = await PipeClient.SendAsync(req);
            if (resp != null) return new OpResult { Ok = resp.Ok, Message = resp.Message };
        }
        return await Task.Run(() => LocalCommands.Dispatch(_local.Value, req));
    }

    /// <summary>
    /// 当前界面所在远程会话的真实来源 IP。只有一个远程连接时直接取其对端地址；
    /// 有多个时取当前用户最近一次成功登录、且仍处于连接中的 IP；无法确定时返回 null。
    /// </summary>
    public string? GetMyRdpIp()
    {
        if (!RdpSessions.IsRemoteSession()) return null;
        var peers = RdpSessions.GetConnectedClientIps();
        if (peers.Count <= 1) return peers.FirstOrDefault();
        var user = Environment.UserName;
        return Store.QueryEvents(user, success: true, limit: 50)
            .FirstOrDefault(e => peers.Contains(e.Ip) && string.Equals(e.Username, user, StringComparison.OrdinalIgnoreCase))?.Ip;
    }

    /// <summary>在后台线程执行数据库查询。</summary>
    public Task<T> QueryAsync<T>(Func<Store, T> query) => Task.Run(() => query(Store));
}
