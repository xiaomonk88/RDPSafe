using System.Text.Json;
using Dapper;
using Microsoft.Data.Sqlite;

namespace RDPSafe.Core.Data;

/// <summary>SQLite 数据访问。服务与界面共用，WAL 模式支持并发读。</summary>
public sealed class Store
{
    private readonly string _connString;

    static Store()
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;
    }

    public Store(string? path = null)
    {
        _connString = new SqliteConnectionStringBuilder
        {
            DataSource = path ?? Paths.Database,
            Pooling = true,
            DefaultTimeout = 30,
        }.ToString();
    }

    public SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connString);
        conn.Open();
        conn.Execute("PRAGMA busy_timeout=10000; PRAGMA foreign_keys=ON;");
        return conn;
    }

    public void Init()
    {
        Paths.EnsureDataDir();
        using var c = Open();
        c.Execute("PRAGMA journal_mode=WAL;");
        c.Execute("""
            CREATE TABLE IF NOT EXISTS login_events(
              id INTEGER PRIMARY KEY,
              time INTEGER NOT NULL,
              ip TEXT NOT NULL,
              country TEXT,
              username TEXT,
              success INTEGER NOT NULL,
              logon_type INTEGER NOT NULL DEFAULT 0,
              source TEXT NOT NULL,
              record_id INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS ix_le_time ON login_events(time);
            CREATE INDEX IF NOT EXISTS ix_le_ip_time ON login_events(ip, time);
            CREATE UNIQUE INDEX IF NOT EXISTS ux_le_record ON login_events(source, record_id) WHERE record_id > 0;

            CREATE TABLE IF NOT EXISTS bans(
              id INTEGER PRIMARY KEY,
              ip TEXT NOT NULL,
              country TEXT,
              ban_time INTEGER NOT NULL,
              expire_at INTEGER,
              unban_time INTEGER,
              reason TEXT NOT NULL,
              note TEXT,
              unban_reason TEXT,
              active INTEGER NOT NULL DEFAULT 1);
            CREATE UNIQUE INDEX IF NOT EXISTS ux_bans_active ON bans(ip) WHERE active = 1;
            CREATE INDEX IF NOT EXISTS ix_bans_time ON bans(ban_time);

            CREATE TABLE IF NOT EXISTS ip_lists(
              id INTEGER PRIMARY KEY,
              kind TEXT NOT NULL CHECK(kind IN ('black','white')),
              ip TEXT NOT NULL,
              country TEXT,
              note TEXT,
              created INTEGER NOT NULL,
              UNIQUE(kind, ip));

            CREATE TABLE IF NOT EXISTS op_logs(
              id INTEGER PRIMARY KEY,
              time INTEGER NOT NULL,
              level TEXT NOT NULL,
              message TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_op_time ON op_logs(time);

            CREATE TABLE IF NOT EXISTS settings(
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL);
            """);
    }

    // ───────────────────────── settings ─────────────────────────

    public string? GetValue(string key)
    {
        using var c = Open();
        return c.QueryFirstOrDefault<string>("SELECT value FROM settings WHERE key=@key", new { key });
    }

    public void SetValue(string key, string value, SqliteConnection? conn = null, SqliteTransaction? tx = null)
    {
        const string sql = "INSERT INTO settings(key,value) VALUES(@key,@value) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
        if (conn != null)
        {
            conn.Execute(sql, new { key, value }, tx);
            return;
        }
        using var c = Open();
        c.Execute(sql, new { key, value });
    }

    public AppSettings LoadSettings()
    {
        var json = GetValue("app");
        if (string.IsNullOrEmpty(json)) return new AppSettings();
        try
        {
            return (JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings()).Normalize();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void SaveSettings(AppSettings s) => SetValue("app", JsonSerializer.Serialize(s.Normalize()));

    // ───────────────────────── login events ─────────────────────────

    public void InsertEvents(SqliteConnection c, SqliteTransaction tx, IEnumerable<LoginEvent> events)
    {
        c.Execute("""
            INSERT OR IGNORE INTO login_events(time,ip,country,username,success,logon_type,source,record_id)
            VALUES(@Time,@Ip,@Country,@Username,@Success,@LogonType,@Source,@RecordId)
            """, events, tx);
    }

    /// <param name="success">null=全部，true=成功，false=失败</param>
    public List<LoginEvent> QueryEvents(string? search, bool? success, int limit, long afterId = 0)
    {
        using var c = Open();
        var where = new List<string> { "id > @afterId" };
        if (!string.IsNullOrWhiteSpace(search)) where.Add("(ip LIKE @like OR username LIKE @like OR country LIKE @like)");
        if (success != null) where.Add("success = @succ");
        var sql = $"SELECT * FROM login_events WHERE {string.Join(" AND ", where)} ORDER BY id DESC LIMIT @limit";
        return c.Query<LoginEvent>(sql, new
        {
            afterId,
            like = $"%{search?.Trim()}%",
            succ = success == true ? 1 : 0,
            limit,
        }).AsList();
    }

    public long CountEvents()
    {
        using var c = Open();
        return c.ExecuteScalar<long>("SELECT COUNT(*) FROM login_events");
    }

    /// <summary>窗口期内的失败记录，用于引擎启动时预热检测窗口。</summary>
    public List<(string Ip, long Time)> GetFailuresSince(long since)
    {
        using var c = Open();
        return c.Query<(string, long)>("SELECT ip, time FROM login_events WHERE success=0 AND time>=@since ORDER BY time", new { since }).AsList();
    }

    public int ClearEvents()
    {
        using var c = Open();
        return c.Execute("DELETE FROM login_events");
    }

    /// <summary>清空历史数据：登录记录、操作日志、已解封的封禁记录。保留封禁中的 IP、黑白名单与设置。</summary>
    public (int Events, int Logs, int Bans) ResetHistory()
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        var e = c.Execute("DELETE FROM login_events", transaction: tx);
        var l = c.Execute("DELETE FROM op_logs", transaction: tx);
        var b = c.Execute("DELETE FROM bans WHERE active=0", transaction: tx);
        tx.Commit();
        c.Execute("VACUUM");
        return (e, l, b);
    }

    public (int Events, int Logs) Purge(long olderThan)
    {
        using var c = Open();
        var e = c.Execute("DELETE FROM login_events WHERE time < @olderThan", new { olderThan });
        var l = c.Execute("DELETE FROM op_logs WHERE time < @olderThan", new { olderThan });
        return (e, l);
    }

    // ───────────────────────── statistics ─────────────────────────

    public DashboardStats GetDashboard()
    {
        var today = TimeUtil.TodayStart();
        using var c = Open();
        return c.QuerySingle<DashboardStats>("""
            SELECT
              (SELECT COUNT(*) FROM login_events WHERE time>=@today AND success=0) AS TodayFailures,
              (SELECT COUNT(*) FROM login_events WHERE time>=@today AND success=1) AS TodaySuccesses,
              (SELECT COUNT(DISTINCT ip) FROM login_events WHERE time>=@today AND success=0) AS TodayAttackIps,
              (SELECT COUNT(*) FROM bans WHERE active=1) AS ActiveBans,
              (SELECT COUNT(*) FROM bans WHERE ban_time>=@today) AS TodayNewBans,
              (SELECT COUNT(*) FROM bans) AS TotalBans
            """, new { today });
    }

    /// <summary>最近 hours 小时内按小时聚合的登录次数（含空桶）。</summary>
    public List<HourBucket> GetHourly(int hours = 24)
    {
        var nowHour = Ceil(TimeUtil.Now(), 3600);
        var start = nowHour - hours * 3600L;
        using var c = Open();
        var rows = c.Query<HourBucket>("""
            SELECT (time/3600)*3600 AS Hour,
                   SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS Failures,
                   SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS Successes
            FROM login_events WHERE time>=@start GROUP BY time/3600
            """, new { start }).ToDictionary(r => r.Hour);
        var list = new List<HourBucket>(hours);
        for (var h = start; h < nowHour; h += 3600)
            list.Add(rows.TryGetValue(h, out var b) ? b : new HourBucket { Hour = h });
        return list;

        static long Ceil(long v, long step) => (v / step + 1) * step;
    }

    public List<AttackerStat> GetTopAttackers(long since, int limit)
    {
        using var c = Open();
        return c.Query<AttackerStat>("""
            SELECT e.ip AS Ip, MAX(e.country) AS Country, COUNT(*) AS Count, MAX(e.time) AS LastTime,
                   EXISTS(SELECT 1 FROM bans b WHERE b.ip=e.ip AND b.active=1) AS Banned
            FROM login_events e WHERE e.success=0 AND e.time>=@since
            GROUP BY e.ip ORDER BY Count DESC LIMIT @limit
            """, new { since, limit }).AsList();
    }

    // ───────────────────────── bans ─────────────────────────

    public List<BanRecord> GetActiveBans()
    {
        using var c = Open();
        return c.Query<BanRecord>("SELECT * FROM bans WHERE active=1 ORDER BY id").AsList();
    }

    public BanRecord? GetActiveBan(string ip)
    {
        using var c = Open();
        return c.QueryFirstOrDefault<BanRecord>("SELECT * FROM bans WHERE active=1 AND ip=@ip", new { ip });
    }

    public List<BanRecord> QueryBans(bool activeOnly, string? search, int limit)
    {
        using var c = Open();
        var where = new List<string> { "1=1" };
        if (activeOnly) where.Add("active=1");
        if (!string.IsNullOrWhiteSpace(search)) where.Add("(ip LIKE @like OR country LIKE @like OR note LIKE @like)");
        return c.Query<BanRecord>($"SELECT * FROM bans WHERE {string.Join(" AND ", where)} ORDER BY active DESC, ban_time DESC LIMIT @limit",
            new { like = $"%{search?.Trim()}%", limit }).AsList();
    }

    public List<BanRecord> GetRecentBans(int limit)
    {
        using var c = Open();
        return c.Query<BanRecord>("SELECT * FROM bans ORDER BY id DESC LIMIT @limit", new { limit }).AsList();
    }

    public long InsertBan(BanRecord b)
    {
        using var c = Open();
        return c.ExecuteScalar<long>("""
            INSERT INTO bans(ip,country,ban_time,expire_at,reason,note,active)
            VALUES(@Ip,@Country,@BanTime,@ExpireAt,@Reason,@Note,1);
            SELECT last_insert_rowid();
            """, b);
    }

    public int DeactivateBan(string ip, string unbanReason)
    {
        using var c = Open();
        return c.Execute("UPDATE bans SET active=0, unban_time=@now, unban_reason=@unbanReason WHERE active=1 AND ip=@ip",
            new { ip, unbanReason, now = TimeUtil.Now() });
    }

    public List<string> GetExpiredBanIps(long now)
    {
        using var c = Open();
        return c.Query<string>("SELECT ip FROM bans WHERE active=1 AND expire_at IS NOT NULL AND expire_at<=@now", new { now }).AsList();
    }

    public int CountPreviousBans(string ip)
    {
        using var c = Open();
        return c.ExecuteScalar<int>("SELECT COUNT(*) FROM bans WHERE ip=@ip", new { ip });
    }

    public long MaxBanId()
    {
        using var c = Open();
        return c.ExecuteScalar<long>("SELECT IFNULL(MAX(id),0) FROM bans");
    }

    public List<BanRecord> GetBansAfter(long id)
    {
        using var c = Open();
        return c.Query<BanRecord>("SELECT * FROM bans WHERE id>@id ORDER BY id", new { id }).AsList();
    }

    // ───────────────────────── black / white lists ─────────────────────────

    public List<ListEntry> GetList(string kind)
    {
        using var c = Open();
        return c.Query<ListEntry>("SELECT * FROM ip_lists WHERE kind=@kind ORDER BY id DESC", new { kind }).AsList();
    }

    public bool AddListEntry(ListEntry e)
    {
        using var c = Open();
        return c.Execute("INSERT OR IGNORE INTO ip_lists(kind,ip,country,note,created) VALUES(@Kind,@Ip,@Country,@Note,@Created)", e) > 0;
    }

    public int RemoveListEntry(string kind, string ip)
    {
        using var c = Open();
        return c.Execute("DELETE FROM ip_lists WHERE kind=@kind AND ip=@ip", new { kind, ip });
    }

    // ───────────────────────── operation logs ─────────────────────────

    public void Log(string level, string message)
    {
        try
        {
            using var c = Open();
            c.Execute("INSERT INTO op_logs(time,level,message) VALUES(@time,@level,@message)",
                new { time = TimeUtil.Now(), level, message });
        }
        catch
        {
            // 日志写入失败不应影响主流程
        }
    }

    public List<OpLog> QueryLogs(string? level, string? search, int limit)
    {
        using var c = Open();
        var where = new List<string> { "1=1" };
        if (!string.IsNullOrEmpty(level)) where.Add("level=@level");
        if (!string.IsNullOrWhiteSpace(search)) where.Add("message LIKE @like");
        return c.Query<OpLog>($"SELECT * FROM op_logs WHERE {string.Join(" AND ", where)} ORDER BY id DESC LIMIT @limit",
            new { level, like = $"%{search?.Trim()}%", limit }).AsList();
    }
}
