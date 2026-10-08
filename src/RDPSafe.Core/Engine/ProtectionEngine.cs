using RDPSafe.Core.Data;
using RDPSafe.Core.Ipc;
using RDPSafe.Core.Net;
using RDPSafe.Core.Platform;

namespace RDPSafe.Core.Engine;

/// <summary>引擎对外提供的操作。服务内由引擎实现，服务未运行时由 <see cref="LocalCommands"/> 实现。</summary>
public interface IEngineCommands
{
    OpResult Ban(string ip, int? hours, string? note);
    OpResult Unban(string[] ips);
    OpResult AddList(string kind, string ip, string? note);
    OpResult RemoveList(string kind, string[] ips);
    OpResult SaveSettings(AppSettings settings);
    OpResult ClearLogins();
    OpResult ResetData();
}

/// <summary>防护引擎：事件采集 → 关联 → 入库 → 检测 → 封禁，以及定时维护任务。</summary>
public sealed class ProtectionEngine : IEngineCommands, IDisposable
{
    private const string CursorSecurity = "cursor.security";
    private const string CursorRdp = "cursor.rdp";

    private readonly Store _store;
    private readonly GeoLookup _geo;
    private readonly BanService _bans;
    private readonly EventCollector _collector = new();
    private readonly EventCorrelator _correlator = new();
    private readonly SemaphoreSlim _signal = new(0, 1);
    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<long>> _windows = new();
    private readonly EngineStatus _status = new();

    private AppSettings _settings = new();
    private IpMatcher _whitelist = new(Array.Empty<string>());
    private IpMatcher _activeBans = new(Array.Empty<string>());
    private HashSet<string> _instantUsers = new(StringComparer.OrdinalIgnoreCase);

    private int _minuteFailures, _minuteSuccesses;
    private DateTime _nextExpire, _nextPurge, _nextReconcile, _nextMinute;
    private string? _lastError;

    public ProtectionEngine(Store store, GeoLookup geo)
    {
        _store = store;
        _geo = geo;
        _bans = new BanService(store, geo);
    }

    public EngineStatus Status
    {
        get
        {
            lock (_status)
            {
                return new EngineStatus
                {
                    Running = _status.Running,
                    StartedAt = _status.StartedAt,
                    LastEventTime = _status.LastEventTime,
                    LastBatch = _status.LastBatch,
                    TotalProcessed = _status.TotalProcessed,
                    AuditEnabled = _status.AuditEnabled,
                    RdpLogAvailable = _status.RdpLogAvailable,
                    CollectorError = _status.CollectorError,
                };
            }
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _store.Init();
        lock (_lock)
        {
            _settings = _store.LoadSettings();
            ReloadState();
            WarmUp();
        }
        EnsureAudit();
        _store.Log(LogLevels.Info, $"防护引擎启动（v{AppInfo.Version}），策略：{_settings.Describe()}");

        Safe(() => _bans.SyncFirewall(force: true), "同步防火墙规则");
        CheckFirewallState();
        _collector.StartWatchers();
        _collector.NewEventsSignaled += () =>
        {
            if (_signal.CurrentCount == 0) _signal.Release();
        };
        lock (_status)
        {
            _status.Running = true;
            _status.StartedAt = TimeUtil.Now();
            _status.RdpLogAvailable = _collector.RdpLogAvailable;
        }
        if (!_collector.RdpLogAvailable)
            _store.Log(LogLevels.Warn, "未找到 RdpCoreTS 运行日志，开启 NLA 时部分失败事件可能缺少来源 IP");

        var now = DateTime.UtcNow;
        _nextExpire = now;
        _nextPurge = now;
        _nextReconcile = now.AddMinutes(10);
        _nextMinute = now.AddMinutes(1);

        while (!ct.IsCancellationRequested)
        {
            ProcessOnce();
            RunMaintenance();
            try
            {
                if (await _signal.WaitAsync(TimeSpan.FromSeconds(_settings.PollSeconds), ct))
                    await Task.Delay(300, ct); // 合并突发事件
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        lock (_status) _status.Running = false;
        _store.Log(LogLevels.Info, "防护引擎停止");
    }

    // ───────────────────────── 事件处理 ─────────────────────────

    private void ProcessOnce()
    {
        try
        {
            lock (_lock)
            {
                var firstRun = TimeSpan.FromHours(Math.Min(_settings.RetentionHours, 48));
                var (sec, secCursor) = _collector.ReadSecurity(ParseCursor(CursorSecurity), firstRun);
                var (rdp, rdpCursor) = _collector.ReadRdp(ParseCursor(CursorRdp), firstRun);
                var events = _correlator.Process(sec.Concat(rdp), DateTime.UtcNow);
                foreach (var e in events) e.Country = _geo.Lookup(e.Ip);

                using (var conn = _store.Open())
                using (var tx = conn.BeginTransaction())
                {
                    if (events.Count > 0) _store.InsertEvents(conn, tx, events);
                    _store.SetValue(CursorSecurity, secCursor.ToString(), conn, tx);
                    _store.SetValue(CursorRdp, rdpCursor.ToString(), conn, tx);
                    tx.Commit();
                }

                Detect(events);

                lock (_status)
                {
                    _status.LastBatch = events.Count;
                    _status.TotalProcessed += events.Count;
                    if (events.Count > 0) _status.LastEventTime = events[^1].Time;
                    _status.CollectorError = null;
                }
                _minuteFailures += events.Count(e => !e.Success);
                _minuteSuccesses += events.Count(e => e.Success);
            }
            _lastError = null;
        }
        catch (Exception ex)
        {
            lock (_status) _status.CollectorError = ex.Message;
            if (_lastError != ex.Message) _store.Log(LogLevels.Error, $"处理事件出错：{ex.Message}");
            _lastError = ex.Message;
        }
    }

    private long? ParseCursor(string key) => long.TryParse(_store.GetValue(key), out var v) ? v : null;

    private void Detect(List<LoginEvent> events)
    {
        var now = TimeUtil.Now();
        var window = _settings.WindowMinutes * 60L;
        var newBans = new List<string>();
        HashSet<string>? sessions = null;

        foreach (var e in events)
        {
            if (e.Success)
            {
                AutoWhitelist(e, now);
                continue;
            }
            if (_whitelist.Contains(e.Ip) || _activeBans.Contains(e.Ip) || newBans.Contains(e.Ip)) continue;
            if (!_settings.ProtectPrivateIps && IpUtil.IsPrivate(e.Ip)) continue;

            string reason, note;
            if (e.Username != null && _instantUsers.Contains(StripDomain(e.Username)))
            {
                reason = BanReasons.Instant;
                note = $"尝试用户名 {e.Username}";
            }
            else
            {
                if (!_windows.TryGetValue(e.Ip, out var q)) _windows[e.Ip] = q = new Queue<long>();
                q.Enqueue(e.Time);
                while (q.Count > 0 && q.Peek() < e.Time - window) q.Dequeue();
                // 首次运行导入的历史事件只用于填充窗口，不触发封禁
                if (q.Count < _settings.MaxFailures || now - e.Time > window) continue;
                reason = BanReasons.Auto;
                note = $"{_settings.WindowMinutes} 分钟内失败 {q.Count} 次";
            }

            if (_settings.SkipActiveSessions)
            {
                sessions ??= SafeGet(RdpSessions.GetConnectedClientIps) ?? new HashSet<string>();
                if (sessions.Contains(e.Ip))
                {
                    _windows.Remove(e.Ip);
                    _store.Log(LogLevels.Warn, $"跳过封禁 {e.Ip}：该 IP 存在活动的远程桌面会话（{note}）");
                    continue;
                }
            }

            if (_bans.AddBan(e.Ip, reason, ComputeExpiry(e.Ip), note) != null) newBans.Add(e.Ip);
            _windows.Remove(e.Ip);
        }

        if (newBans.Count == 0) return;
        _activeBans = new IpMatcher(_store.GetActiveBans().Select(b => b.Ip));
        Safe(() => _bans.SyncFirewall(), "写入防火墙规则");
        if (_settings.KillConnections) BanService.KillConnections(newBans);
    }

    /// <summary>登录成功的来源 IP 自动加入白名单（仅处理最近 1 小时内的事件，避免首次导入时批量加入历史 IP）。</summary>
    private void AutoWhitelist(LoginEvent e, long now)
    {
        if (!_settings.AutoWhitelistOnSuccess || now - e.Time > 3600 || _whitelist.Contains(e.Ip)) return;
        var note = $"登录成功自动加入（用户 {e.Username ?? "未知"}）";
        var r = _bans.AddToList(ListKinds.White, e.Ip, note, killConnections: false);
        if (!r.Ok) return;
        _windows.Remove(e.Ip);
        ReloadState();
    }

    private long? ComputeExpiry(string ip)
    {
        if (!_settings.AutoUnban) return null;
        var hours = (long)_settings.BanHours;
        if (_settings.ProgressiveBan)
        {
            var previous = Math.Min(_store.CountPreviousBans(ip), 10);
            hours = Math.Min(hours << previous, 24L * 365);
        }
        return TimeUtil.Now() + hours * 3600;
    }

    private static string StripDomain(string user)
    {
        var i = user.LastIndexOf('\\');
        return i >= 0 ? user[(i + 1)..] : user;
    }

    // ───────────────────────── 维护任务 ─────────────────────────

    private void RunMaintenance()
    {
        var now = DateTime.UtcNow;
        if (now >= _nextExpire)
        {
            _nextExpire = now.AddSeconds(30);
            lock (_lock)
            {
                if (SafeGet(_bans.ExpireDue) > 0) ReloadState();
            }
        }
        if (now >= _nextMinute)
        {
            _nextMinute = now.AddMinutes(1);
            if (_minuteFailures + _minuteSuccesses > 0)
                _store.Log(LogLevels.Info, $"过去 1 分钟处理 {_minuteFailures + _minuteSuccesses} 条登录事件（失败 {_minuteFailures}，成功 {_minuteSuccesses}）");
            _minuteFailures = _minuteSuccesses = 0;
            lock (_lock)
            {
                // 兜底：吸收服务外（界面离线模式）对名单的修改，并清理过期窗口
                ReloadState();
                var cutoff = TimeUtil.Now() - _settings.WindowMinutes * 60L;
                foreach (var ip in _windows.Where(kv => kv.Value.Count == 0 || kv.Value.Last() < cutoff).Select(kv => kv.Key).ToList())
                    _windows.Remove(ip);
            }
            CheckFirewallState();
        }
        if (now >= _nextPurge)
        {
            _nextPurge = now.AddHours(1);
            var (events, logs) = _store.Purge(TimeUtil.Now() - _settings.RetentionHours * 3600L);
            if (events + logs > 0)
                _store.Log(LogLevels.Info, $"自动清理了 {events} 条登录记录、{logs} 条操作日志（超过 {_settings.RetentionHours} 小时）");
        }
        if (now >= _nextReconcile)
        {
            _nextReconcile = now.AddMinutes(10);
            Safe(() => _bans.SyncFirewall(force: true), "防火墙对账");
            EnsureAudit();
        }
    }

    private string? _firewallOff;

    /// <summary>防火墙关闭时封禁规则不生效，状态变化时写日志提醒。</summary>
    private void CheckFirewallState()
    {
        List<string> off;
        try
        {
            off = Firewall.FirewallApi.GetDisabledActiveProfiles();
        }
        catch
        {
            return;
        }
        var key = string.Join("、", off);
        if (key == (_firewallOff ?? "")) return;
        if (off.Count > 0)
            _store.Log(LogLevels.Warn, $"Windows 防火墙在当前网络（{key}）处于关闭状态，封禁规则不会生效！请在“概览”页开启防火墙");
        else if (_firewallOff != null)
            _store.Log(LogLevels.Info, "Windows 防火墙已开启，封禁规则恢复生效");
        _firewallOff = key;
    }

    private void EnsureAudit()
    {
        var enabled = AuditPolicy.IsLogonAuditEnabled();
        if (enabled == false)
        {
            try
            {
                AuditPolicy.EnableLogonAudit();
                enabled = AuditPolicy.IsLogonAuditEnabled();
                _store.Log(LogLevels.Config, "检测到登录审核未开启，已自动开启“审核登录（成功/失败）”");
            }
            catch (Exception ex)
            {
                _store.Log(LogLevels.Error, $"开启登录审核失败：{ex.Message}");
            }
        }
        lock (_status) _status.AuditEnabled = enabled;
    }

    private void ReloadState()
    {
        _whitelist = _bans.LoadWhitelist();
        _activeBans = new IpMatcher(_store.GetActiveBans().Select(b => b.Ip));
        _instantUsers = new HashSet<string>(AppSettings.ParseUsers(_settings.InstantBanUsers), StringComparer.OrdinalIgnoreCase);
    }

    private void WarmUp()
    {
        var since = TimeUtil.Now() - _settings.WindowMinutes * 60L;
        foreach (var (ip, time) in _store.GetFailuresSince(since))
        {
            if (!_windows.TryGetValue(ip, out var q)) _windows[ip] = q = new Queue<long>();
            q.Enqueue(time);
        }
    }

    private void Safe(Action action, string what)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            _store.Log(LogLevels.Error, $"{what}失败：{ex.Message}");
        }
    }

    private T? SafeGet<T>(Func<T> f)
    {
        try
        {
            return f();
        }
        catch (Exception ex)
        {
            _store.Log(LogLevels.Error, ex.Message);
            return default;
        }
    }

    // ───────────────────────── 命令 ─────────────────────────

    private OpResult Locked(Func<OpResult> f)
    {
        lock (_lock)
        {
            try
            {
                var r = f();
                ReloadState();
                return r;
            }
            catch (Exception ex)
            {
                return OpResult.Fail(ex.Message);
            }
        }
    }

    public OpResult Ban(string ip, int? hours, string? note) =>
        Locked(() => _bans.ManualBan(ip, hours, note, _settings.KillConnections));

    public OpResult Unban(string[] ips) => Locked(() =>
    {
        foreach (var ip in ips) _windows.Remove(ip);
        return _bans.Unban(ips);
    });

    public OpResult AddList(string kind, string ip, string? note) =>
        Locked(() => _bans.AddToList(kind, ip, note, _settings.KillConnections));

    public OpResult RemoveList(string kind, string[] ips) => Locked(() => _bans.RemoveFromList(kind, ips));

    public OpResult SaveSettings(AppSettings settings) => Locked(() =>
    {
        var r = _bans.SaveSettings(settings);
        _settings = _store.LoadSettings();
        if (_signal.CurrentCount == 0) _signal.Release();
        return r;
    });

    public OpResult ClearLogins() => Locked(() =>
    {
        _windows.Clear();
        return _bans.ClearLogins();
    });

    public OpResult ResetData() => Locked(() =>
    {
        _windows.Clear();
        _minuteFailures = _minuteSuccesses = 0;
        lock (_status)
        {
            _status.TotalProcessed = 0;
            _status.LastBatch = 0;
        }
        return _bans.ResetData();
    });

    public PipeResponse Handle(PipeRequest req) => req.Cmd switch
    {
        PipeCommands.Status => new PipeResponse { Ok = true, Status = Status },
        _ => PipeResponse.From(LocalCommands.Dispatch(this, req)),
    };

    public void Dispose()
    {
        _collector.Dispose();
        _signal.Dispose();
    }
}

/// <summary>服务未运行时，界面直接执行操作（引擎启动后会自动加载这些变更）。</summary>
public sealed class LocalCommands : IEngineCommands
{
    private readonly BanService _bans;
    private readonly Store _store;

    public LocalCommands(Store store, GeoLookup geo)
    {
        _store = store;
        _bans = new BanService(store, geo);
    }

    private bool Kill => _store.LoadSettings().KillConnections;

    public OpResult Ban(string ip, int? hours, string? note) => Try(() => _bans.ManualBan(ip, hours, note, Kill));
    public OpResult Unban(string[] ips) => Try(() => _bans.Unban(ips));
    public OpResult AddList(string kind, string ip, string? note) => Try(() => _bans.AddToList(kind, ip, note, Kill));
    public OpResult RemoveList(string kind, string[] ips) => Try(() => _bans.RemoveFromList(kind, ips));
    public OpResult SaveSettings(AppSettings settings) => Try(() => _bans.SaveSettings(settings));
    public OpResult ClearLogins() => Try(_bans.ClearLogins);
    public OpResult ResetData() => Try(_bans.ResetData);

    private static OpResult Try(Func<OpResult> f)
    {
        try
        {
            return f();
        }
        catch (Exception ex)
        {
            return OpResult.Fail(ex.Message);
        }
    }

    public static OpResult Dispatch(IEngineCommands c, PipeRequest r) => r.Cmd switch
    {
        PipeCommands.Ban => c.Ban(r.Ip ?? "", r.Hours, r.Note),
        PipeCommands.Unban => c.Unban(r.Ips ?? Array.Empty<string>()),
        PipeCommands.AddList => c.AddList(r.Kind ?? "", r.Ip ?? "", r.Note),
        PipeCommands.RemoveList => c.RemoveList(r.Kind ?? "", r.Ips ?? Array.Empty<string>()),
        PipeCommands.SaveSettings => r.Settings != null ? c.SaveSettings(r.Settings) : OpResult.Fail("缺少设置参数"),
        PipeCommands.ClearLogins => c.ClearLogins(),
        PipeCommands.ResetData => c.ResetData(),
        _ => OpResult.Fail($"未知命令：{r.Cmd}"),
    };
}
