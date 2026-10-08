using System.Windows;
using System.Windows.Threading;
using RDPSafe.App.Services;
using RDPSafe.App.ViewModels;
using RDPSafe.App.Views;

namespace RDPSafe.App;

public partial class App : Application
{
    private const string MutexName = @"Global\RDPSafe.App.Instance";
    private const string ShowEventName = @"Global\RDPSafe.App.Show";

    /// <summary>已完全卸载、数据目录已删除，此后不得再写数据库。</summary>
    public static bool DataRemoved { get; set; }

    private Mutex? _mutex;
    private EventWaitHandle? _showEvent;
    private TrayIcon? _tray;
    private MainWindow? _window;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 单实例：已运行时唤醒已有窗口
        _mutex = new Mutex(true, MutexName, out var isNew);
        if (!isNew)
        {
            try
            {
                EventWaitHandle.OpenExisting(ShowEventName).Set();
            }
            catch
            {
            }
            Shutdown();
            return;
        }
        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        new Thread(() =>
        {
            while (_showEvent.WaitOne())
                Dispatcher.BeginInvoke(ShowMainWindow);
        }) { IsBackground = true }.Start();

        DispatcherUnhandledException += OnUnhandledException;

        try
        {
            EngineClient.Instance.Store.Init();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"无法初始化数据库：{ex.Message}", "RDPSafe", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        var vm = MainViewModel.Instance;
        _tray = new TrayIcon(ShowMainWindow, ExitApp);
        vm.NewBans += bans =>
        {
            if (_window is { IsVisible: true, WindowState: not WindowState.Minimized, IsActive: true }) return;
            var first = bans[0];
            var text = bans.Count == 1
                ? $"{first.Ip}（{first.Country}）· {first.ReasonText}"
                : $"{first.Ip} 等 {bans.Count} 个 IP";
            _tray.Notify("已封禁攻击来源", text);
        };

        _window = new MainWindow { DataContext = vm };
        vm.Start();

        var trayOnly = e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase);
        if (!trayOnly)
        {
            _window.Show();
            _window.Activate();
        }
        _window.Dispatcher.BeginInvoke(async () =>
        {
            await vm.RefreshStatusAsync();
            if (!trayOnly) await vm.RunFirstRunChecksAsync();
        }, DispatcherPriority.ApplicationIdle);
    }

    public void ShowMainWindow()
    {
        if (_window == null) return;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true;
        _window.Topmost = false;
        _window.Focus();
    }

    public void HideToTray(bool firstTime)
    {
        _window?.Hide();
        if (firstTime) _tray?.Notify("RDPSafe 仍在后台运行", "防护服务独立运行，关闭界面不影响防护。双击托盘图标可重新打开。");
    }

    public void ExitApp()
    {
        _tray?.Dispose();
        _tray = null;
        _window?.ForceClose();
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _showEvent?.Dispose();
        try
        {
            _mutex?.ReleaseMutex();
        }
        catch
        {
        }
        base.OnExit(e);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        try
        {
            if (!DataRemoved) EngineClient.Instance.Store.Log(Core.LogLevels.Error, $"界面异常：{e.Exception.Message}");
        }
        catch
        {
        }
        Ui.Show($"发生错误：{e.Exception.Message}", true);
    }
}
