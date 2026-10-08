using System.Diagnostics;
using System.ServiceProcess;
using System.Text;

namespace RDPSafe.Core.Platform;

public static class ProcessRunner
{
    private static readonly Encoding OemEncoding = CreateOemEncoding();

    private static Encoding CreateOemEncoding()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        try { return Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage); }
        catch { return Encoding.UTF8; }
    }

    public static (int ExitCode, string Output) Run(string file, string args, int timeoutMs = 30_000)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = OemEncoding,
            StandardErrorEncoding = OemEncoding,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"无法启动 {file}");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(); } catch { }
            throw new System.TimeoutException($"{file} 执行超时");
        }
        return (p.ExitCode, (stdout.Result + stderr.Result).Trim());
    }
}

public enum EngineServiceState { NotInstalled, Stopped, Starting, Running, Stopping, Unknown }

/// <summary>防护引擎 Windows 服务的安装与控制。</summary>
public static class EngineService
{
    public static EngineServiceState GetState()
    {
        try
        {
            using var sc = new ServiceController(AppInfo.ServiceName);
            return sc.Status switch
            {
                ServiceControllerStatus.Running => EngineServiceState.Running,
                ServiceControllerStatus.Stopped => EngineServiceState.Stopped,
                ServiceControllerStatus.StartPending or ServiceControllerStatus.ContinuePending => EngineServiceState.Starting,
                ServiceControllerStatus.StopPending or ServiceControllerStatus.PausePending => EngineServiceState.Stopping,
                _ => EngineServiceState.Unknown,
            };
        }
        catch (InvalidOperationException)
        {
            return EngineServiceState.NotInstalled;
        }
    }

    public const string ServiceArg = "--service";

    /// <summary>服务注册的命令行（注册表 ImagePath）；未安装时为 null。</summary>
    public static string? GetImagePath()
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AppInfo.ServiceName}");
        return key?.GetValue("ImagePath") as string;
    }

    /// <summary>已安装的服务是否指向给定 exe（程序被移动或从旧版升级后会不一致）。</summary>
    public static bool PointsTo(string exePath)
    {
        var image = GetImagePath();
        return image != null
               && image.Contains(exePath, StringComparison.OrdinalIgnoreCase)
               && image.Contains(ServiceArg, StringComparison.OrdinalIgnoreCase);
    }

    public static void Install(string exePath)
    {
        Sc($"create {AppInfo.ServiceName} binPath= \"\\\"{exePath}\\\" {ServiceArg}\" start= delayed-auto DisplayName= \"{AppInfo.ServiceDisplayName}\"");
        Sc($"description {AppInfo.ServiceName} \"监控远程桌面登录事件，自动封禁暴力破解来源 IP。\"", ignoreError: true);
        Sc($"failure {AppInfo.ServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/60000", ignoreError: true);
    }

    /// <summary>重新注册服务到指定 exe 并启动（升级或移动程序目录后使用）。</summary>
    public static void Reinstall(string exePath)
    {
        Uninstall();
        // 删除后服务可能短暂处于“标记为删除”状态，稍候重试
        for (var i = 0; ; i++)
        {
            try
            {
                Install(exePath);
                break;
            }
            catch (InvalidOperationException) when (i < 10)
            {
                Thread.Sleep(1000);
            }
        }
        Start();
    }

    public static void Uninstall()
    {
        if (GetState() == EngineServiceState.NotInstalled) return;
        try { Stop(); } catch { }
        Sc($"delete {AppInfo.ServiceName}");
    }

    public static void Start()
    {
        using var sc = new ServiceController(AppInfo.ServiceName);
        if (sc.Status == ServiceControllerStatus.Running) return;
        sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
    }

    public static void Stop()
    {
        using var sc = new ServiceController(AppInfo.ServiceName);
        if (sc.Status == ServiceControllerStatus.Stopped) return;
        sc.Stop();
        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
    }

    private static void Sc(string args, bool ignoreError = false)
    {
        var (code, output) = ProcessRunner.Run("sc.exe", args);
        if (code != 0 && !ignoreError) throw new InvalidOperationException($"sc.exe 执行失败（{code}）：{output}");
    }
}

/// <summary>通过计划任务实现“登录时以最高权限启动托盘程序”。</summary>
public static class TrayAutoStart
{
    private const string TaskName = "RDPSafe Tray";

    public static bool IsEnabled() => ProcessRunner.Run("schtasks.exe", $"/Query /TN \"{TaskName}\"").ExitCode == 0;

    public static void Set(bool enabled, string exePath)
    {
        var (code, output) = enabled
            ? ProcessRunner.Run("schtasks.exe", $"/Create /TN \"{TaskName}\" /TR \"\\\"{exePath}\\\" --tray\" /SC ONLOGON /RL HIGHEST /F")
            : ProcessRunner.Run("schtasks.exe", $"/Delete /TN \"{TaskName}\" /F");
        if (code != 0 && enabled) throw new InvalidOperationException(output);
    }
}
