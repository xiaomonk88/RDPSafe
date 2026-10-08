using Microsoft.Data.Sqlite;
using RDPSafe.Core.Firewall;

namespace RDPSafe.Core.Platform;

/// <summary>完全卸载：服务、防火墙规则、计划任务与数据目录。程序文件需由用户自行删除。</summary>
public static class Uninstaller
{
    public sealed record StepResult(string Name, bool Ok, string Detail);

    public static List<StepResult> RemoveEverything()
    {
        var results = new List<StepResult>();

        Step("停止并删除防护服务", () =>
        {
            var installed = EngineService.GetState() != EngineServiceState.NotInstalled;
            EngineService.Uninstall();
            return installed ? "已删除" : "未安装，跳过";
        });

        Step("删除防火墙封禁规则", () => $"已删除 {BlockRules.RemoveAll()} 条规则");

        Step("删除登录自启任务", () =>
        {
            var existed = TrayAutoStart.IsEnabled();
            TrayAutoStart.Set(false, "");
            return existed ? "已删除" : "不存在，跳过";
        });

        Step("删除数据目录", () =>
        {
            if (!Directory.Exists(Paths.DataDir)) return "不存在，跳过";
            SqliteConnection.ClearAllPools();
            // 服务进程退出、文件句柄释放可能稍有延迟
            for (var i = 0; ; i++)
            {
                try
                {
                    Directory.Delete(Paths.DataDir, recursive: true);
                    return Paths.DataDir;
                }
                catch (IOException) when (i < 10)
                {
                    Thread.Sleep(500);
                }
                catch (UnauthorizedAccessException) when (i < 10)
                {
                    Thread.Sleep(500);
                }
            }
        });

        return results;

        void Step(string name, Func<string> action)
        {
            try
            {
                results.Add(new StepResult(name, true, action()));
            }
            catch (Exception ex)
            {
                results.Add(new StepResult(name, false, ex.Message));
            }
        }
    }
}
