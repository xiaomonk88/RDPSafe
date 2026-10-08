using RDPSafe.Core.Data;
using RDPSafe.Core.Firewall;
using RDPSafe.Core.Net;

namespace RDPSafe.Core.Engine;

/// <summary>
/// 封禁、解封与黑白名单的业务操作（数据库 + 防火墙）。
/// 服务内由 <see cref="ProtectionEngine"/> 调用；服务未运行时界面也可直接使用。
/// </summary>
public sealed class BanService
{
    private readonly Store _store;
    private readonly GeoLookup _geo;

    public BanService(Store store, GeoLookup geo)
    {
        _store = store;
        _geo = geo;
    }

    public IpMatcher LoadWhitelist() => new(_store.GetList(ListKinds.White).Select(e => e.Ip));

    /// <summary>写入封禁记录。不同步防火墙，调用方批量处理后调用 <see cref="SyncFirewall"/>。</summary>
    public BanRecord? AddBan(string ip, string reason, long? expireAt, string? note)
    {
        if (_store.GetActiveBan(ip) != null) return null;
        var ban = new BanRecord
        {
            Ip = ip,
            Country = _geo.Lookup(ip),
            BanTime = TimeUtil.Now(),
            ExpireAt = expireAt,
            Reason = reason,
            Note = note,
            Active = true,
        };
        ban.Id = _store.InsertBan(ban);
        var until = expireAt is { } e ? $"至 {TimeUtil.ToLocal(e):yyyy-MM-dd HH:mm}" : "永久";
        _store.Log(LogLevels.Ban, $"封禁 {ip}（{ban.Country}）{until}，原因：{BanReasons.Display(reason)}{(string.IsNullOrEmpty(note) ? "" : "，" + note)}");
        return ban;
    }

    public void SyncFirewall(bool force = false)
    {
        var ips = _store.GetActiveBans().Select(b => b.Ip).ToList();
        BlockRules.Sync(ips, force);
    }

    public static void KillConnections(IEnumerable<string> ips)
    {
        foreach (var ip in ips)
        {
            try { TcpKiller.Kill(ip); } catch { }
        }
    }

    // ───────────────────────── 用户操作 ─────────────────────────

    public OpResult ManualBan(string input, int? hours, string? note, bool killConnections)
    {
        if (!IpUtil.TryParseEntry(input, out var ip)) return OpResult.Fail($"无效的 IP 或网段：{input}");
        if (LoadWhitelist().Contains(ip)) return OpResult.Fail($"{ip} 在白名单中，请先将其移出白名单");
        long? expire = hours is > 0 ? TimeUtil.Now() + hours.Value * 3600L : null;
        if (AddBan(ip, BanReasons.Manual, expire, note) == null) return OpResult.Fail($"{ip} 已处于封禁状态");
        SyncFirewall();
        if (killConnections) KillConnections(new[] { ip });
        return OpResult.Success($"已封禁 {ip}");
    }

    public OpResult Unban(IReadOnlyCollection<string> ips, string why = "手动解封")
    {
        var n = 0;
        foreach (var ip in ips)
        {
            if (_store.DeactivateBan(ip, why) <= 0) continue;
            n++;
            _store.Log(LogLevels.Unban, $"解封 {ip}（{why}）");
        }
        if (n > 0) SyncFirewall();
        return n > 0 ? OpResult.Success($"已解封 {n} 个 IP") : OpResult.Fail("所选 IP 当前未被封禁");
    }

    public int ExpireDue()
    {
        var due = _store.GetExpiredBanIps(TimeUtil.Now());
        foreach (var ip in due)
        {
            _store.DeactivateBan(ip, "到期自动解封");
            _store.Log(LogLevels.Unban, $"解封 {ip}（到期自动解封）");
        }
        if (due.Count > 0) SyncFirewall();
        return due.Count;
    }

    public OpResult AddToList(string kind, string input, string? note, bool killConnections)
    {
        if (!IpUtil.TryParseEntry(input, out var ip)) return OpResult.Fail($"无效的 IP 或网段：{input}");
        if (kind == ListKinds.Black && LoadWhitelist().Contains(ip)) return OpResult.Fail($"{ip} 在白名单中，不能同时加入黑名单");

        var entry = new ListEntry { Kind = kind, Ip = ip, Country = _geo.Lookup(ip), Note = note?.Trim(), Created = TimeUtil.Now() };
        if (!_store.AddListEntry(entry)) return OpResult.Fail($"{ip} 已在{KindName(kind)}中");

        if (kind == ListKinds.White)
        {
            _store.Log(LogLevels.Config, $"加入白名单 {ip}{(string.IsNullOrEmpty(note) ? "" : "（" + note + "）")}");
            // 白名单优先：移除黑名单并解封
            if (_store.RemoveListEntry(ListKinds.Black, ip) > 0) _store.Log(LogLevels.Config, $"从黑名单移除 {ip}（已加入白名单）");
            var unbanned = _store.DeactivateBan(ip, "加入白名单") > 0;
            if (unbanned)
            {
                _store.Log(LogLevels.Unban, $"解封 {ip}（加入白名单）");
                SyncFirewall();
            }
            return OpResult.Success(unbanned ? $"已将 {ip} 加入白名单并解封" : $"已将 {ip} 加入白名单");
        }

        _store.Log(LogLevels.Config, $"加入黑名单 {ip}{(string.IsNullOrEmpty(note) ? "" : "（" + note + "）")}");
        _store.DeactivateBan(ip, "转为黑名单永久封禁");
        AddBan(ip, BanReasons.Blacklist, null, note);
        SyncFirewall();
        if (killConnections) KillConnections(new[] { ip });
        return OpResult.Success($"已将 {ip} 加入黑名单并永久封禁");
    }

    public OpResult RemoveFromList(string kind, IReadOnlyCollection<string> ips)
    {
        var n = 0;
        var changedBans = false;
        foreach (var ip in ips)
        {
            if (_store.RemoveListEntry(kind, ip) <= 0) continue;
            n++;
            _store.Log(LogLevels.Config, $"从{KindName(kind)}移除 {ip}");
            if (kind == ListKinds.Black && _store.DeactivateBan(ip, "移出黑名单") > 0)
            {
                _store.Log(LogLevels.Unban, $"解封 {ip}（移出黑名单）");
                changedBans = true;
            }
        }
        if (changedBans) SyncFirewall();
        return n > 0 ? OpResult.Success($"已从{KindName(kind)}移除 {n} 项") : OpResult.Fail("未找到所选条目");
    }

    public OpResult ClearLogins()
    {
        var n = _store.ClearEvents();
        _store.Log(LogLevels.Config, $"清空登录记录（{n} 条）");
        return OpResult.Success($"已清空 {n} 条登录记录");
    }

    public OpResult ResetData()
    {
        var (events, logs, bans) = _store.ResetHistory();
        _store.Log(LogLevels.Config, $"清空历史数据：登录记录 {events} 条、操作日志 {logs} 条、已解封记录 {bans} 条，从现在起重新记录");
        return OpResult.Success($"已清空 {events:N0} 条登录记录、{logs:N0} 条日志、{bans:N0} 条历史封禁");
    }

    public OpResult SaveSettings(AppSettings s)
    {
        _store.SaveSettings(s.Normalize());
        _store.Log(LogLevels.Config, $"保存设置：{s.Describe()}，轮询 {s.PollSeconds} 秒，日志保留 {s.RetentionHours} 小时");
        return OpResult.Success("设置已保存");
    }

    private static string KindName(string kind) => kind == ListKinds.Black ? "黑名单" : "白名单";
}
