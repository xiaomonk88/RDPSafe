namespace RDPSafe.Core;

public static class AppInfo
{
    public const string Name = "RDPSafe";
    public const string ServiceName = "RDPSafe";
    public const string ServiceDisplayName = "RDPSafe 防护引擎";
    public const string PipeName = "RDPSafe.Engine";
    public const string RepoUrl = "https://github.com/xiaomonk88/RDPSafe";
    public const string LatestReleaseApi = "https://api.github.com/repos/xiaomonk88/RDPSafe/releases/latest";
    public static readonly string Version =
        typeof(AppInfo).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
}

public static class TimeUtil
{
    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    public static long ToUnix(DateTime dt) => new DateTimeOffset(dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Local) : dt).ToUnixTimeSeconds();
    public static DateTime ToLocal(long unix) => DateTimeOffset.FromUnixTimeSeconds(unix).LocalDateTime;
    public static long TodayStart() => ToUnix(DateTime.Today);
}

public sealed class LoginEvent
{
    public long Id { get; set; }
    public long Time { get; set; }
    public string Ip { get; set; } = "";
    public string? Country { get; set; }
    public string? Username { get; set; }
    public bool Success { get; set; }
    public int LogonType { get; set; }
    /// <summary>事件来源：4625 / 4624 / 140 / 4625+140</summary>
    public string Source { get; set; } = "";
    public long RecordId { get; set; }

    public DateTime LocalTime => TimeUtil.ToLocal(Time);
}

public static class BanReasons
{
    public const string Auto = "auto";
    public const string Instant = "instant";
    public const string Manual = "manual";
    public const string Blacklist = "blacklist";

    public static string Display(string reason) => reason switch
    {
        Auto => "暴力破解",
        Instant => "敏感用户名",
        Manual => "手动封禁",
        Blacklist => "黑名单",
        _ => reason,
    };
}

public sealed class BanRecord
{
    public long Id { get; set; }
    public string Ip { get; set; } = "";
    public string? Country { get; set; }
    public long BanTime { get; set; }
    /// <summary>到期时间，null 表示永久</summary>
    public long? ExpireAt { get; set; }
    public long? UnbanTime { get; set; }
    public string Reason { get; set; } = BanReasons.Auto;
    public string? Note { get; set; }
    public string? UnbanReason { get; set; }
    public bool Active { get; set; }

    public DateTime BanLocal => TimeUtil.ToLocal(BanTime);
    public DateTime? ExpireLocal => ExpireAt is { } e ? TimeUtil.ToLocal(e) : null;
    public DateTime? UnbanLocal => UnbanTime is { } u ? TimeUtil.ToLocal(u) : null;
    public string ReasonText => BanReasons.Display(Reason);
}

public static class ListKinds
{
    public const string Black = "black";
    public const string White = "white";
}

public sealed class ListEntry
{
    public long Id { get; set; }
    public string Kind { get; set; } = ListKinds.White;
    public string Ip { get; set; } = "";
    public string? Country { get; set; }
    public string? Note { get; set; }
    public long Created { get; set; }

    public DateTime CreatedLocal => TimeUtil.ToLocal(Created);
}

public static class LogLevels
{
    public const string Info = "info";
    public const string Warn = "warn";
    public const string Error = "error";
    public const string Ban = "ban";
    public const string Unban = "unban";
    public const string Config = "config";
}

public sealed class OpLog
{
    public long Id { get; set; }
    public long Time { get; set; }
    public string Level { get; set; } = LogLevels.Info;
    public string Message { get; set; } = "";

    public DateTime LocalTime => TimeUtil.ToLocal(Time);
}

public sealed class AppSettings
{
    // 检测
    public int MaxFailures { get; set; } = 3;
    public int WindowMinutes { get; set; } = 120;
    /// <summary>一次失败即封禁的用户名，逗号分隔</summary>
    public string InstantBanUsers { get; set; } = "";
    /// <summary>内网地址也参与检测与封禁</summary>
    public bool ProtectPrivateIps { get; set; } = true;
    /// <summary>不封禁当前存在活动 RDP 会话的 IP（防自锁）</summary>
    public bool SkipActiveSessions { get; set; } = true;
    /// <summary>远程桌面登录成功的来源 IP 自动加入白名单</summary>
    public bool AutoWhitelistOnSuccess { get; set; } = false;

    // 封禁
    public bool AutoUnban { get; set; } = false;
    public int BanHours { get; set; } = 24;
    /// <summary>重复被封的 IP 封禁时长翻倍</summary>
    public bool ProgressiveBan { get; set; } = false;
    /// <summary>封禁时断开该 IP 已建立的 TCP 连接</summary>
    public bool KillConnections { get; set; } = true;

    // 引擎
    public int PollSeconds { get; set; } = 5;
    public int RetentionHours { get; set; } = 96;

    public AppSettings Normalize()
    {
        MaxFailures = Math.Clamp(MaxFailures, 1, 1000);
        WindowMinutes = Math.Clamp(WindowMinutes, 1, 10080);
        BanHours = Math.Clamp(BanHours, 1, 87600);
        PollSeconds = Math.Clamp(PollSeconds, 1, 300);
        RetentionHours = Math.Clamp(RetentionHours, 1, 87600);
        InstantBanUsers = string.Join(",", ParseUsers(InstantBanUsers));
        return this;
    }

    public static IEnumerable<string> ParseUsers(string? s) =>
        (s ?? "").Split(new[] { ',', '，', ';', ' ', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Distinct(StringComparer.OrdinalIgnoreCase);

    public string Describe() =>
        $"{WindowMinutes} 分钟内失败 {MaxFailures} 次 → 封禁" +
        (AutoUnban ? $" {BanHours} 小时{(ProgressiveBan ? "（递增）" : "")}" : "（永久）");
}

public sealed class EngineStatus
{
    public bool Running { get; set; }
    public string Version { get; set; } = AppInfo.Version;
    public long StartedAt { get; set; }
    public long? LastEventTime { get; set; }
    public int LastBatch { get; set; }
    public long TotalProcessed { get; set; }
    public bool? AuditEnabled { get; set; }
    public bool RdpLogAvailable { get; set; }
    public string? CollectorError { get; set; }
}

public sealed class OpResult
{
    public bool Ok { get; set; }
    public string Message { get; set; } = "";

    public static OpResult Success(string msg) => new() { Ok = true, Message = msg };
    public static OpResult Fail(string msg) => new() { Ok = false, Message = msg };
}

public sealed class DashboardStats
{
    public long TodayFailures { get; set; }
    public long TodaySuccesses { get; set; }
    public long TodayAttackIps { get; set; }
    public long ActiveBans { get; set; }
    public long TodayNewBans { get; set; }
    public long TotalBans { get; set; }
}

public sealed class AttackerStat
{
    public string Ip { get; set; } = "";
    public string? Country { get; set; }
    public long Count { get; set; }
    public long LastTime { get; set; }
    public bool Banned { get; set; }
}

public sealed class HourBucket
{
    public long Hour { get; set; }
    public long Failures { get; set; }
    public long Successes { get; set; }
}
