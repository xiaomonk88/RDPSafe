using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RDPSafe.Core;
using RDPSafe.Core.Data;
using RDPSafe.Core.Engine;
using RDPSafe.Core.Firewall;
using RDPSafe.Core.Ipc;
using RDPSafe.Core.Net;
using RDPSafe.Core.Platform;

namespace RDPSafe.App;

/// <summary>
/// 程序入口。同一个 exe 有三种运行方式：
///   RDPSafe.exe                 打开管理界面
///   RDPSafe.exe --service       作为 Windows 服务运行防护引擎（由服务控制管理器启动）
///   RDPSafe.exe --install 等     命令行维护功能
/// </summary>
public static class Program
{
    public const string ServiceArg = "--service";

    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Contains(ServiceArg, StringComparer.OrdinalIgnoreCase)) return RunService(args);
        if (args.Length > 0 && args[0].StartsWith("--", StringComparison.Ordinal) && args[0] != "--tray") return RunCommand(args[0]);

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }

    private static int RunService(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args.Where(a => !a.Equals(ServiceArg, StringComparison.OrdinalIgnoreCase)).ToArray());
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddWindowsService(o => o.ServiceName = AppInfo.ServiceName);
        builder.Services.AddHostedService<EngineWorker>();
        builder.Build().Run();
        return 0;
    }

    private static int RunCommand(string cmd)
    {
        // WinExe 没有控制台，从命令行调用时附加到父进程的控制台以便输出
        AttachConsole(-1);
        Console.WriteLine();
        try
        {
            switch (cmd)
            {
                case "--install":
                    EngineService.Install(Environment.ProcessPath!);
                    EngineService.Start();
                    Console.WriteLine("服务已安装并启动");
                    return 0;
                case "--uninstall":
                    EngineService.Uninstall();
                    Console.WriteLine("服务已卸载");
                    return 0;
                case "--uninstall-all":
                    var results = Uninstaller.RemoveEverything();
                    foreach (var r in results) Console.WriteLine($"[{(r.Ok ? "完成" : "失败")}] {r.Name}：{r.Detail}");
                    return results.All(r => r.Ok) ? 0 : 1;
                case "--remove-rules":
                    Console.WriteLine($"已删除 {BlockRules.RemoveAll()} 条 RDPSafe 防火墙规则");
                    return 0;
                case "--version":
                    Console.WriteLine($"RDPSafe v{AppInfo.Version}");
                    return 0;
                default:
                    Console.WriteLine($"RDPSafe v{AppInfo.Version}");
                    Console.WriteLine("用法：RDPSafe.exe [--install | --uninstall | --uninstall-all | --remove-rules | --version]");
                    Console.WriteLine("      不带参数运行打开管理界面；--service 由 Windows 服务管理器使用。");
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);
}

/// <summary>服务模式下的后台工作：防护引擎 + 命名管道服务端。</summary>
internal sealed class EngineWorker(ILogger<EngineWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 让出启动线程，避免阻塞服务控制管理器
        await Task.Yield();
        var store = new Store();
        using var engine = new ProtectionEngine(store, GeoLookup.Shared);
        var pipe = new PipeServer(engine.Handle);
        try
        {
            await Task.WhenAll(engine.RunAsync(stoppingToken), pipe.RunAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "防护引擎异常退出");
            store.Log(LogLevels.Error, $"防护引擎异常退出：{ex.Message}");
            throw;
        }
    }
}
