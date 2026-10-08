using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;
using RDPSafe.Core.Platform;

namespace RDPSafe.App.ViewModels;

public sealed partial class SettingsViewModel : PageViewModel
{
    public const string CloseToTrayKey = "ui.closeToTray";

    public override string Title => "设置";
    public override string Subtitle => "检测策略、封禁规则与系统集成";
    public override string Glyph => Glyphs.Settings;

    public static string AppExe => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "RDPSafe.exe");

    // 检测策略
    [ObservableProperty] private int _maxFailures;
    [ObservableProperty] private int _windowMinutes;
    [ObservableProperty] private string _instantBanUsers = "";
    [ObservableProperty] private bool _protectPrivateIps;
    [ObservableProperty] private bool _skipActiveSessions;
    [ObservableProperty] private bool _autoWhitelistOnSuccess;

    // 封禁
    [ObservableProperty] private bool _autoUnban;
    [ObservableProperty] private int _banHours;
    [ObservableProperty] private bool _progressiveBan;
    [ObservableProperty] private bool _killConnections;

    // 引擎
    [ObservableProperty] private int _pollSeconds;
    [ObservableProperty] private int _retentionHours;

    // 系统
    [ObservableProperty] private bool? _auditEnabled;
    [ObservableProperty] private bool _trayAutoStart;
    [ObservableProperty] private bool _closeToTray = true;
    [ObservableProperty] private bool _dirty;

    private bool _loading;

    public string AuditText => AuditEnabled switch
    {
        true => "已开启",
        false => "未开启（无法记录登录事件）",
        _ => "未知",
    };

    partial void OnAuditEnabledChanged(bool? value) => OnPropertyChanged(nameof(AuditText));

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loading) return;
        switch (e.PropertyName)
        {
            // 输入框：攒到底部保存条统一保存
            case nameof(MaxFailures) or nameof(WindowMinutes) or nameof(InstantBanUsers)
                or nameof(BanHours) or nameof(PollSeconds) or nameof(RetentionHours):
                Dirty = true;
                break;

            // 开关：点击即保存
            case nameof(ProtectPrivateIps):
                _ = SaveSwitch(e.PropertyName, "内网地址参与检测", ProtectPrivateIps, (s, v) => s.ProtectPrivateIps = v);
                break;
            case nameof(AutoWhitelistOnSuccess):
                _ = SaveSwitch(e.PropertyName, "登录成功自动加入白名单", AutoWhitelistOnSuccess, (s, v) => s.AutoWhitelistOnSuccess = v);
                break;
            case nameof(SkipActiveSessions):
                _ = SaveSwitch(e.PropertyName, "防止误封自己", SkipActiveSessions, (s, v) => s.SkipActiveSessions = v);
                break;
            case nameof(AutoUnban):
                _ = SaveSwitch(e.PropertyName, "自动解封", AutoUnban, (s, v) => s.AutoUnban = v);
                break;
            case nameof(ProgressiveBan):
                _ = SaveSwitch(e.PropertyName, "递增封禁", ProgressiveBan, (s, v) => s.ProgressiveBan = v);
                break;
            case nameof(KillConnections):
                _ = SaveSwitch(e.PropertyName, "封禁时断开现有连接", KillConnections, (s, v) => s.KillConnections = v);
                break;
        }
    }

    /// <summary>只把这一个开关写入已保存的设置，不夹带输入框里尚未保存的修改。失败时回滚开关。</summary>
    private async Task SaveSwitch(string property, string label, bool value, Action<AppSettings, bool> apply)
    {
        var s = await Engine.QueryAsync(st => st.LoadSettings());
        apply(s, value);
        var r = await Engine.SaveSettingsAsync(s);
        if (r.Ok)
        {
            Ui.Show($"已{(value ? "开启" : "关闭")}：{label}");
            return;
        }
        Ui.Show($"保存失败：{r.Message}", true);
        _loading = true;
        GetType().GetProperty(property)!.SetValue(this, !value);
        _loading = false;
    }

    public override async Task RefreshAsync()
    {
        var (s, closeToTray, audit, tray) = await Engine.QueryAsync(st => (
            st.LoadSettings(),
            st.GetValue(CloseToTrayKey) != "0",
            AuditPolicy.IsLogonAuditEnabled(),
            SafeTray()));
        _loading = true;
        MaxFailures = s.MaxFailures;
        WindowMinutes = s.WindowMinutes;
        InstantBanUsers = s.InstantBanUsers.Replace(",", ", ");
        ProtectPrivateIps = s.ProtectPrivateIps;
        SkipActiveSessions = s.SkipActiveSessions;
        AutoWhitelistOnSuccess = s.AutoWhitelistOnSuccess;
        AutoUnban = s.AutoUnban;
        BanHours = s.BanHours;
        ProgressiveBan = s.ProgressiveBan;
        KillConnections = s.KillConnections;
        PollSeconds = s.PollSeconds;
        RetentionHours = s.RetentionHours;
        CloseToTray = closeToTray;
        AuditEnabled = audit;
        TrayAutoStart = tray;
        Dirty = false;
        _loading = false;

        static bool SafeTray()
        {
            try { return Core.Platform.TrayAutoStart.IsEnabled(); } catch { return false; }
        }
    }

    [RelayCommand]
    private async Task Save()
    {
        var s = new AppSettings
        {
            MaxFailures = MaxFailures,
            WindowMinutes = WindowMinutes,
            InstantBanUsers = InstantBanUsers,
            ProtectPrivateIps = ProtectPrivateIps,
            SkipActiveSessions = SkipActiveSessions,
            AutoWhitelistOnSuccess = AutoWhitelistOnSuccess,
            AutoUnban = AutoUnban,
            BanHours = BanHours,
            ProgressiveBan = ProgressiveBan,
            KillConnections = KillConnections,
            PollSeconds = PollSeconds,
            RetentionHours = RetentionHours,
        };
        var r = await Engine.SaveSettingsAsync(s);
        Ui.Show(r.Ok ? (State.Online ? "设置已保存，引擎已即时生效" : "设置已保存，将在引擎启动后生效") : r.Message, !r.Ok);
        if (r.Ok) await RefreshAsync();
    }

    [RelayCommand]
    private Task Revert() => RefreshAsync();

    [RelayCommand]
    private async Task ResetDefaults()
    {
        var d = new AppSettings();
        if (!await Ui.ConfirmAsync("恢复默认设置", $"将把检测、封禁与引擎参数全部恢复为默认值并立即保存：\n{d.Describe()}，轮询 {d.PollSeconds} 秒，日志保留 {d.RetentionHours} 小时。", "恢复默认")) return;
        var r = await Engine.SaveSettingsAsync(d);
        Ui.Show(r.Ok ? "已恢复默认设置" : r.Message, !r.Ok);
        await RefreshAsync();
    }

    [RelayCommand]
    private void FillCommonUsers()
    {
        var common = new[] { "admin", "administrator", "test", "user", "guest", "root", "support", "backup", "scanner" };
        InstantBanUsers = string.Join(", ", AppSettings.ParseUsers(InstantBanUsers + "," + string.Join(",", common)));
    }

    // ───────────────────────── 系统集成 ─────────────────────────

    partial void OnCloseToTrayChanged(bool value)
    {
        if (_loading) return;
        Engine.Store.SetValue(CloseToTrayKey, value ? "1" : "0");
    }

    partial void OnTrayAutoStartChanged(bool value)
    {
        if (_loading) return;
        _ = Task.Run(() => Core.Platform.TrayAutoStart.Set(value, AppExe)).ContinueWith(t =>
        {
            if (t.Exception != null) Ui.Show($"设置开机启动失败：{t.Exception.InnerException?.Message}", true);
            else Ui.Show(value ? "已设置登录后自动在托盘启动" : "已取消登录后自动启动");
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    [RelayCommand]
    private Task InstallService() => RunBusy(async () =>
    {
        await Task.Run(() =>
        {
            EngineService.Install(AppExe);
            EngineService.Start();
        });
        Ui.Show("防护服务已安装并启动");
        await MainViewModel.Instance.RefreshStatusAsync();
    });

    /// <summary>服务指向旧程序（升级自旧版或程序目录被移动）时，重新注册到当前程序。</summary>
    public Task RepairService() => RunBusy(async () =>
    {
        await Task.Run(() => EngineService.Reinstall(AppExe));
        Engine.Store.Log(LogLevels.Config, $"防护服务已重新注册到 {AppExe}");
        Ui.Show("防护服务已更新到当前程序并启动");
        await MainViewModel.Instance.RefreshStatusAsync();
    });

    [RelayCommand]
    private Task StartService() => RunBusy(async () =>
    {
        await Task.Run(EngineService.Start);
        Ui.Show("防护服务已启动");
        await MainViewModel.Instance.RefreshStatusAsync();
    });

    [RelayCommand]
    private async Task StopService()
    {
        if (!await Ui.ConfirmAsync("停止防护服务", "停止后将不再监控登录事件，也不会自动封禁新的攻击来源（已封禁的 IP 仍保持封禁）。确定停止吗？", "停止", danger: true)) return;
        await RunBusy(async () =>
        {
            await Task.Run(EngineService.Stop);
            Ui.Show("防护服务已停止");
            await MainViewModel.Instance.RefreshStatusAsync();
        });
    }

    [RelayCommand]
    private Task RestartService() => RunBusy(async () =>
    {
        await Task.Run(() =>
        {
            EngineService.Stop();
            EngineService.Start();
        });
        Ui.Show("防护服务已重启");
        await MainViewModel.Instance.RefreshStatusAsync();
    });

    [RelayCommand]
    private async Task UninstallService()
    {
        if (!await Ui.ConfirmAsync("卸载防护服务", "卸载后系统将失去自动防护。已有封禁规则会保留在防火墙中。确定卸载吗？", "卸载", danger: true)) return;
        await RunBusy(async () =>
        {
            await Task.Run(EngineService.Uninstall);
            Ui.Show("防护服务已卸载");
            await MainViewModel.Instance.RefreshStatusAsync();
        });
    }

    [RelayCommand]
    private Task FixAudit() => RunBusy(async () =>
    {
        await Task.Run(AuditPolicy.EnableLogonAudit);
        AuditEnabled = await Task.Run(AuditPolicy.IsLogonAuditEnabled);
        Engine.Store.Log(LogLevels.Config, "手动开启“审核登录（成功/失败）”策略");
        Ui.Show(AuditEnabled == true ? "已开启登录审核" : "已提交，但策略可能被组策略覆盖", AuditEnabled != true);
    });

    [RelayCommand]
    private void OpenDataDir()
    {
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Paths.DataDir}\"") { UseShellExecute = true });
    }

    [RelayCommand]
    private async Task ResetData()
    {
        if (!await Ui.ConfirmAsync("清空历史数据",
                "将删除：全部登录记录、操作日志、已解封的历史封禁记录，统计从零开始重新记录。\n\n" +
                "保留：当前封禁中的 IP（继续拦截）、黑白名单、所有设置。\n\n此操作不可恢复，确定继续吗？", "清空数据", danger: true)) return;
        await RunBusy(async () =>
        {
            Ui.Show(await Engine.ResetDataAsync());
            await MainViewModel.Instance.RefreshStatusAsync();
        });
    }

    [RelayCommand]
    private async Task FullUninstall()
    {
        if (!await Ui.ConfirmAsync("完全卸载 RDPSafe",
                "将依次执行：\n" +
                "1. 停止并删除防护服务\n" +
                "2. 删除防火墙中全部 RDPSafe 封禁规则（所有被封 IP 恢复访问）\n" +
                "3. 删除“登录后在托盘启动”计划任务\n" +
                "4. 删除数据目录（登录记录、封禁记录、黑白名单、日志、设置）\n\n" +
                "完成后界面将退出。此操作不可恢复，确定继续吗？", "完全卸载", danger: true)) return;

        IsBusy = true;
        MainViewModel.Instance.Stop();
        App.DataRemoved = true;
        var results = await Task.Run(Core.Platform.Uninstaller.RemoveEverything);
        IsBusy = false;

        var lines = string.Join("\n", results.Select(r => $"{(r.Ok ? "✓" : "✗")} {r.Name}：{r.Detail}"));
        var ok = results.All(r => r.Ok);
        await Ui.AlertAsync(ok ? "卸载完成" : "卸载未全部完成",
            $"{lines}\n\n" +
            (ok ? "" : "失败的项目可稍后重试，或以管理员身份运行 RDPSafe.Service.exe --uninstall-all。\n\n") +
            $"程序文件位于：\n{AppContext.BaseDirectory}\n界面退出后可直接删除该文件夹。");
        ((App)System.Windows.Application.Current).ExitApp();
    }

    [RelayCommand]
    private async Task RemoveAllBlockRules()
    {
        if (!await Ui.ConfirmAsync("解封全部 IP",
                "将解封所有自动/手动封禁的 IP（黑名单不受影响），并同步更新防火墙规则。\n若引擎正在运行，后续攻击仍会被重新封禁。确定继续吗？", "全部解封", danger: true)) return;
        var ips = await Engine.QueryAsync(s => s.GetActiveBans().Where(b => b.Reason != BanReasons.Blacklist).Select(b => b.Ip).ToList());
        if (ips.Count == 0)
        {
            Ui.Show("当前没有封禁中的 IP");
            return;
        }
        Ui.Show(await Engine.UnbanAsync(ips));
    }
}
