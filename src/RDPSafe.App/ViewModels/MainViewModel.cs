using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;
using RDPSafe.Core.Platform;

namespace RDPSafe.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    public static MainViewModel Instance { get; } = new();

    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(3) };
    private int _tick;
    private bool _ticking;
    private long _lastBanId = -1;

    public DashboardViewModel Dashboard { get; } = new();
    public LoginsViewModel Logins { get; } = new();
    public BansViewModel Bans { get; } = new();
    public ListsViewModel Lists { get; } = new();
    public FirewallViewModel Firewall { get; } = new();
    public LogsViewModel Logs { get; } = new();
    public SettingsViewModel Settings { get; } = new();

    public ObservableCollection<PageViewModel> Pages { get; }

    public AppState State => AppState.Instance;
    public Ui Ui => Ui.Instance;
    public string Version => $"v{AppInfo.Version}";
    public string WindowTitle => $"RDPSafe v{AppInfo.Version}";

    [ObservableProperty]
    private PageViewModel _currentPage;

    [ObservableProperty]
    private long _activeBans;

    /// <summary>有新封禁时触发（用于托盘通知）。</summary>
    public event Action<List<BanRecord>>? NewBans;

    private MainViewModel()
    {
        Pages = new ObservableCollection<PageViewModel> { Dashboard, Logins, Bans, Lists, Firewall, Logs, Settings };
        _currentPage = Dashboard;
        _timer.Tick += async (_, _) => await OnTimer();
    }

    partial void OnCurrentPageChanged(PageViewModel value) => _ = SafeRun(value.OnActivatedAsync);

    public void Start()
    {
        _timer.Start();
        _ = OnTimer();
        _ = SafeRun(CurrentPage.OnActivatedAsync);
    }

    /// <summary>停止定时刷新（完全卸载前调用，避免重新创建数据库）。</summary>
    public void Stop() => _timer.Stop();

    public void Navigate(string page)
    {
        var target = Pages.FirstOrDefault(p => p.GetType().Name.StartsWith(page, StringComparison.OrdinalIgnoreCase));
        if (target != null) CurrentPage = target;
    }

    public void ShowLogins(string ip)
    {
        if (CurrentPage != Logins)
        {
            Logins.Search = ip;
            Logins.Filter = ResultFilter.All;
            CurrentPage = Logins;
        }
        else
        {
            _ = Logins.FilterByIp(ip);
        }
    }

    public async Task RefreshStatusAsync()
    {
        await EngineClient.Instance.RefreshStatusAsync();
        ActiveBans = await EngineClient.Instance.QueryAsync(s => s.GetDashboard().ActiveBans);
    }

    private async Task OnTimer()
    {
        if (_ticking) return;
        _ticking = true;
        try
        {
            _tick++;
            await RefreshStatusAsync();
            await CheckNewBans();
            if (Ui.Dialog == null) await CurrentPage.OnTickAsync(_tick);
        }
        catch
        {
            // 定时刷新失败不打扰用户
        }
        finally
        {
            _ticking = false;
        }
    }

    private async Task CheckNewBans()
    {
        if (_lastBanId < 0)
        {
            _lastBanId = await EngineClient.Instance.QueryAsync(s => s.MaxBanId());
            return;
        }
        var after = _lastBanId;
        var bans = await EngineClient.Instance.QueryAsync(s => s.GetBansAfter(after));
        if (bans.Count == 0) return;
        _lastBanId = bans[^1].Id;
        NewBans?.Invoke(bans);
    }

    private static async Task SafeRun(Func<Task> f)
    {
        try
        {
            await f();
        }
        catch (Exception ex)
        {
            Ui.Show(ex.Message, true);
        }
    }

    [RelayCommand]
    private Task RefreshPage() => SafeRun(CurrentPage.RefreshAsync);

    /// <summary>首次启动引导：安装服务、自动加白当前远程 IP。</summary>
    public async Task RunFirstRunChecksAsync()
    {
        var client = EngineClient.Instance;
        var myIp = await Task.Run(client.GetMyRdpIp);
        if (myIp != null)
        {
            var white = await client.QueryAsync(s => s.GetList(ListKinds.White));
            if (white.Count == 0)
            {
                var r = await client.AddListAsync(ListKinds.White, myIp, "首次启动自动添加（当前远程会话）");
                if (r.Ok) Ui.Show($"已将你当前的远程 IP {myIp} 加入白名单，防止误封自己");
            }
        }

        // 服务已安装但指向旧程序（如 v1.0 的 RDPSafe.Service.exe，或程序目录被移动）
        if (State.ServiceState != EngineServiceState.NotInstalled && !EngineService.PointsTo(SettingsViewModel.AppExe))
        {
            if (await Ui.ConfirmAsync("更新防护服务",
                    $"检测到防护服务指向的不是当前程序：\n{EngineService.GetImagePath()}\n\n" +
                    "可能是从旧版本升级或移动了程序目录。现在把服务更新到当前程序吗？（数据与设置会保留）", "更新服务"))
            {
                await Settings.RepairService();
            }
            return;
        }

        if (State.ServiceState == EngineServiceState.NotInstalled)
        {
            if (await Ui.ConfirmAsync("安装防护服务",
                    "RDPSafe 防护引擎以 Windows 服务形式运行，开机即生效、无需登录。\n\n现在安装并启动防护服务吗？", "安装并启动"))
            {
                Settings.InstallServiceCommand.Execute(null);
            }
        }
        else if (State.ServiceState == EngineServiceState.Stopped)
        {
            if (await Ui.ConfirmAsync("防护服务未运行", "防护服务已安装但处于停止状态，当前不会自动封禁攻击来源。\n\n现在启动吗？", "启动服务"))
            {
                Settings.StartServiceCommand.Execute(null);
            }
        }
    }
}
