using System.Diagnostics.Eventing.Reader;
using RDPSafe.Core.Net;

namespace RDPSafe.Core.Engine;

public enum RawKind { Failure4625, Success4624, Failure140 }

public sealed record RawEvent(RawKind Kind, DateTime TimeUtc, string? Ip, string? User, int LogonType, long RecordId);

/// <summary>
/// 从事件日志增量读取登录事件。以 RecordId 游标为准做可靠增量读取，
/// EventLogWatcher 仅作为“有新事件”的唤醒信号，从而兼顾实时性与不漏不重。
/// </summary>
public sealed class EventCollector : IDisposable
{
    public const string SecurityLog = "Security";
    public const string RdpLog = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

    private static readonly EventLogPropertySelector SecuritySelector = new(new[]
    {
        "Event/EventData/Data[@Name='TargetUserName']",
        "Event/EventData/Data[@Name='LogonType']",
        "Event/EventData/Data[@Name='IpAddress']",
    });

    private readonly List<EventLogWatcher> _watchers = new();
    private readonly Dictionary<string, EventBookmark?> _bookmarks = new();

    public event Action? NewEventsSignaled;

    public bool RdpLogAvailable { get; private set; }

    public void StartWatchers()
    {
        RdpLogAvailable = ChannelExists(RdpLog);
        TryWatch(SecurityLog, "*[System[(EventID=4625 or EventID=4624)]]");
        if (RdpLogAvailable) TryWatch(RdpLog, "*[System[(EventID=140)]]");
    }

    private void TryWatch(string channel, string xpath)
    {
        try
        {
            var w = new EventLogWatcher(new EventLogQuery(channel, PathType.LogName, xpath));
            w.EventRecordWritten += (_, e) =>
            {
                e.EventRecord?.Dispose();
                NewEventsSignaled?.Invoke();
            };
            w.Enabled = true;
            _watchers.Add(w);
        }
        catch
        {
            // 订阅失败时依赖定时轮询兜底
        }
    }

    private static bool ChannelExists(string channel)
    {
        try
        {
            EventLogSession.GlobalSession.GetLogInformation(channel, PathType.LogName);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 读取游标之后的新事件。cursor 为 null 表示首次运行，按 firstRunSince 时间回溯导入。
    /// 返回事件与新游标。
    /// </summary>
    public (List<RawEvent> Events, long Cursor) ReadSecurity(long? cursor, TimeSpan firstRunSince)
        => Read(SecurityLog, cursor, firstRunSince,
            filter: "(EventID=4625 or EventID=4624)",
            parse: ParseSecurity);

    public (List<RawEvent> Events, long Cursor) ReadRdp(long? cursor, TimeSpan firstRunSince)
        => RdpLogAvailable
            ? Read(RdpLog, cursor, firstRunSince, filter: "EventID=140", parse: ParseRdp)
            : (new List<RawEvent>(), cursor ?? 0);

    private (List<RawEvent>, long) Read(string channel, long? cursor, TimeSpan firstRunSince, string filter, Func<EventRecord, RawEvent?> parse)
    {
        var list = new List<RawEvent>();
        long newest;
        try
        {
            var info = EventLogSession.GlobalSession.GetLogInformation(channel, PathType.LogName);
            newest = (info.OldestRecordNumber ?? 0) + (info.RecordCount ?? 0) - 1;
        }
        catch
        {
            return (list, cursor ?? 0);
        }

        // 日志被清空或重建后游标会大于最新记录号，此时从头读取
        if (cursor is { } c0 && c0 > newest)
        {
            cursor = 0;
            _bookmarks[channel] = null;
        }

        var maxId = cursor ?? 0;
        _bookmarks.TryGetValue(channel, out var bookmark);
        try
        {
            ReadInto(bookmark);
        }
        catch (EventLogException) when (bookmark != null)
        {
            // 书签失效（日志被覆盖/清空），退回到按 RecordId 查询
            _bookmarks[channel] = null;
            ReadInto(null);
        }
        return (list, Math.Max(maxId, cursor ?? newest));

        void ReadInto(EventBookmark? bm)
        {
            string xpath;
            if (bm != null) xpath = $"*[System[{filter}]]";
            else if (cursor is { } c) xpath = $"*[System[{filter} and EventRecordID > {c}]]";
            else xpath = $"*[System[{filter} and TimeCreated[timediff(@SystemTime) <= {(long)firstRunSince.TotalMilliseconds}]]]";

            var query = new EventLogQuery(channel, PathType.LogName, xpath);
            using var reader = bm != null ? new EventLogReader(query, bm) : new EventLogReader(query);
            EventBookmark? last = null;
            while (reader.ReadEvent() is { } rec)
            {
                using (rec)
                {
                    var id = rec.RecordId ?? 0;
                    last = rec.Bookmark;
                    if (cursor is { } cur && id <= cur) continue;
                    maxId = Math.Max(maxId, id);
                    if (parse(rec) is { } ev) list.Add(ev);
                }
            }
            if (last != null) _bookmarks[channel] = last;
        }
    }

    private static RawEvent? ParseSecurity(EventRecord rec)
    {
        if (rec is not EventLogRecord r) return null;
        var v = r.GetPropertyValues(SecuritySelector);
        var user = v.Count > 0 ? v[0]?.ToString() : null;
        var logonType = v.Count > 1 && v[1] != null ? Convert.ToInt32(v[1]) : 0;
        var ip = IpUtil.Normalize(v.Count > 2 ? v[2]?.ToString() : null);
        var time = (r.TimeCreated ?? DateTime.Now).ToUniversalTime();
        var id = r.RecordId ?? 0;

        if (r.Id == 4625) return new RawEvent(RawKind.Failure4625, time, ip, user, logonType, id);

        // 4624 仅统计远程桌面登录：10=新建远程会话，7=重连已有会话（与本地解锁同类型，靠外部来源 IP 区分），
        // 12=Remote Credential Guard。NLA 预认证产生的类型 3 不计，避免一次登录记两条。
        if (r.Id == 4624 && (logonType is 10 or 7 or 12) && ip != null && !IpUtil.IsLoopback(ip))
            return new RawEvent(RawKind.Success4624, time, ip, user, logonType, id);
        return null;
    }

    private static RawEvent? ParseRdp(EventRecord rec)
    {
        if (rec.Id != 140) return null;
        var ip = IpUtil.Normalize(rec.Properties.Count > 0 ? rec.Properties[0].Value?.ToString() : null);
        if (ip == null) return null;
        return new RawEvent(RawKind.Failure140, (rec.TimeCreated ?? DateTime.Now).ToUniversalTime(), ip, null, 3, rec.RecordId ?? 0);
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.Enabled = false;
                w.Dispose();
            }
            catch
            {
            }
        }
        _watchers.Clear();
    }
}

/// <summary>
/// 关联 Security 4625 与 RdpCoreTS 140 事件：
/// 开启 NLA 时 4625 常缺少来源 IP，而 140 事件包含 IP 但无用户名。
/// 二者在时间上相邻（±3 秒），据此合并、去重。
/// </summary>
public sealed class EventCorrelator
{
    private static readonly TimeSpan MatchWindow = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan HoldTime = TimeSpan.FromSeconds(6);

    private readonly List<RawEvent> _pendingNoIp = new();
    private readonly List<RawEvent> _pending140 = new();
    private readonly Dictionary<string, DateTime> _recent4625 = new();

    public List<LoginEvent> Process(IEnumerable<RawEvent> events, DateTime nowUtc)
    {
        var output = new List<LoginEvent>();
        foreach (var e in events.OrderBy(e => e.TimeUtc))
        {
            switch (e.Kind)
            {
                case RawKind.Success4624:
                    output.Add(ToLogin(e, e.Ip!, e.User, success: true, "4624"));
                    break;

                case RawKind.Failure4625 when e.Ip != null:
                    if (IpUtil.IsLoopback(e.Ip)) break;
                    output.Add(ToLogin(e, e.Ip, e.User, success: false, "4625"));
                    _recent4625[e.Ip] = e.TimeUtc;
                    _pending140.RemoveAll(p => p.Ip == e.Ip && Near(p, e));
                    break;

                case RawKind.Failure4625:
                {
                    var match = Closest(_pending140, e);
                    if (match != null)
                    {
                        _pending140.Remove(match);
                        output.Add(ToLogin(e, match.Ip!, e.User, success: false, "4625+140"));
                    }
                    else
                    {
                        _pendingNoIp.Add(e);
                    }
                    break;
                }

                case RawKind.Failure140:
                {
                    if (_recent4625.TryGetValue(e.Ip!, out var t) && (e.TimeUtc - t).Duration() <= MatchWindow) break;
                    var match = Closest(_pendingNoIp, e);
                    if (match != null)
                    {
                        _pendingNoIp.Remove(match);
                        output.Add(ToLogin(match, e.Ip!, match.User, success: false, "4625+140"));
                    }
                    else
                    {
                        _pending140.Add(e);
                    }
                    break;
                }
            }
        }

        // 超时未匹配：140 单独记为失败；缺 IP 的 4625 无法处置，丢弃
        var cutoff = nowUtc - HoldTime;
        foreach (var p in _pending140.Where(p => p.TimeUtc < cutoff).ToList())
        {
            _pending140.Remove(p);
            output.Add(ToLogin(p, p.Ip!, null, success: false, "140"));
        }
        _pendingNoIp.RemoveAll(p => p.TimeUtc < cutoff);
        foreach (var key in _recent4625.Where(kv => kv.Value < cutoff - HoldTime).Select(kv => kv.Key).ToList())
            _recent4625.Remove(key);

        output.Sort((a, b) => a.Time.CompareTo(b.Time));
        return output;
    }

    private static bool Near(RawEvent a, RawEvent b) => (a.TimeUtc - b.TimeUtc).Duration() <= MatchWindow;

    private static RawEvent? Closest(List<RawEvent> pool, RawEvent e) =>
        pool.Where(p => Near(p, e)).OrderBy(p => (p.TimeUtc - e.TimeUtc).Duration()).FirstOrDefault();

    private static LoginEvent ToLogin(RawEvent e, string ip, string? user, bool success, string source) => new()
    {
        Time = TimeUtil.ToUnix(e.TimeUtc),
        Ip = ip,
        Username = string.IsNullOrWhiteSpace(user) || user == "-" ? null : user,
        Success = success,
        LogonType = e.LogonType,
        Source = source,
        RecordId = e.RecordId,
    };
}
