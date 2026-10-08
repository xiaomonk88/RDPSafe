using RDPSafe.Core;
using RDPSafe.Core.Data;
using RDPSafe.Core.Engine;
using RDPSafe.Core.Firewall;
using RDPSafe.Core.Net;
using RDPSafe.Core.Platform;

void Check(bool ok, string what) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {what}"); if (!ok) Environment.ExitCode = 1; }

// Geo
var geo = new GeoLookup(Paths.GeoDatabase);
Check(geo.Available, "geo loaded");
foreach (var ip in new[] { "45.59.101.106", "194.165.16.151", "193.24.211.151", "114.114.114.114", "8.8.8.8", "192.168.1.5", "143.203.52.136" })
    Console.WriteLine($"      {ip,-16} -> {geo.Lookup(ip)}");

// IP utils
Check(IpUtil.Normalize("::ffff:1.2.3.4") == "1.2.3.4", "normalize mapped v6");
Check(IpUtil.Normalize("-") == null, "normalize dash");
Check(IpUtil.TryParseEntry("10.1.2.3/24", out var cidr) && cidr == "10.1.2.0/24", $"cidr normalize ({cidr})");
Check(!IpUtil.TryParseEntry("1.0.0.0/4", out _), "reject huge cidr");
var m = new IpMatcher(new[] { "10.1.2.0/24", "8.8.8.8" });
Check(m.Contains("10.1.2.200") && m.Contains("8.8.8.8") && !m.Contains("10.1.3.1"), "matcher");

// Correlator
var t0 = DateTime.UtcNow.AddSeconds(-30);
var cor = new EventCorrelator();
var outp = cor.Process(new[] {
    new RawEvent(RawKind.Failure4625, t0, null, "admin", 3, 1),                 // NLA 无 IP
    new RawEvent(RawKind.Failure140, t0.AddMilliseconds(200), "5.5.5.5", null, 3, 100),
    new RawEvent(RawKind.Failure4625, t0.AddSeconds(10), "6.6.6.6", "root", 3, 2),  // 有 IP
    new RawEvent(RawKind.Failure140, t0.AddSeconds(10.5), "6.6.6.6", null, 3, 101), // 重复
    new RawEvent(RawKind.Failure140, t0.AddSeconds(20), "7.7.7.7", null, 3, 102),   // 单独 140
    new RawEvent(RawKind.Success4624, t0.AddSeconds(21), "8.8.4.4", "bob", 10, 3),
}, DateTime.UtcNow);
Console.WriteLine("      " + string.Join(" | ", outp.Select(e => $"{e.Ip}/{e.Username}/{e.Source}/{(e.Success ? "ok" : "fail")}")));
Check(outp.Count == 4 && outp[0].Ip == "5.5.5.5" && outp[0].Username == "admin" && outp.Count(e => e.Ip == "6.6.6.6") == 1 && outp.Any(e => e.Ip == "7.7.7.7"), "correlator merge/dedup");

// Store
var dbPath = Path.Combine(Path.GetTempPath(), $"rdpsafe-test-{Guid.NewGuid():N}.db");
var store = new Store(dbPath);
store.Init();
using (var c = store.Open()) using (var tx = c.BeginTransaction()) { foreach (var e in outp) e.Country = geo.Lookup(e.Ip); store.InsertEvents(c, tx, outp); store.InsertEvents(c, tx, outp); tx.Commit(); }
Check(store.CountEvents() == 4, "insert + dedup by record id");
var q = store.QueryEvents(null, false, 100);
Check(q.Count == 3 && q.All(e => !e.Success), "query failures (bool mapping)");
var bans = new BanService(store, geo);
Check(bans.AddBan("9.9.9.9", BanReasons.Auto, null, "test") != null, "add ban");
Check(bans.AddBan("9.9.9.9", BanReasons.Auto, null, "test") == null, "no duplicate active ban");
var ab = store.GetActiveBans();
Check(ab.Count == 1 && ab[0].Active && ab[0].ExpireAt == null, "active ban mapping");
var d = store.GetDashboard();
Console.WriteLine($"      dashboard fail={d.TodayFailures} succ={d.TodaySuccesses} ips={d.TodayAttackIps} active={d.ActiveBans}");
Check(store.GetHourly().Count == 24, "hourly buckets");
Check(store.GetTopAttackers(0, 5).Count == 3, "top attackers");
var s = new AppSettings { MaxFailures = 5, InstantBanUsers = "admin, test，root" };
store.SaveSettings(s);
var s2 = store.LoadSettings();
Check(s2.MaxFailures == 5 && s2.InstantBanUsers == "admin,test,root", "settings roundtrip");

// Audit / sessions
Console.WriteLine($"      audit logon enabled = {AuditPolicy.IsLogonAuditEnabled()}");
Console.WriteLine($"      rdp peers = {string.Join(",", RdpSessions.GetConnectedClientIps())}; remote session = {RdpSessions.IsRemoteSession()}; rdp port = {RdpSessions.GetRdpPort()}");
Console.WriteLine($"      service state = {EngineService.GetState()}");

// Firewall aggregated rule (TEST-NET-3, not routable)
var test = Enumerable.Range(1, 1500).Select(i => $"203.0.113.{i % 250 + 1}").Distinct().Append("203.0.113.0/28").ToList();
var many = Enumerable.Range(0, 1200).Select(i => $"198.51.{i / 250}.{i % 250 + 1}").ToList(); // TEST-NET-2 区域附近
BlockRules.Sync(many, force: true);
var managed = FirewallApi.ListRules(FwDirection.In).Where(r => r.IsManaged).ToList();
Check(managed.Count == 2 && managed.All(r => r.Action == FwAction.Block && r.Enabled), $"aggregated rules created ({managed.Count})");
BlockRules.Sync(many.Take(10).ToList());
Check(FirewallApi.ListRules(FwDirection.In).Count(r => r.IsManaged) == 1, "shrink to 1 rule");
BlockRules.RemoveAll();
Check(FirewallApi.ListRules(FwDirection.In).Count(r => r.IsManaged) == 0, "remove all managed rules");

// Generic rule CRUD
var rule = new FwRule { Name = "RDPSafe Probe Test", Action = FwAction.Allow, Protocol = FwProtocols.Tcp, LocalPorts = "50555", RemoteAddresses = "203.0.113.7", Enabled = false };
FirewallApi.Add(rule);
var got = FirewallApi.ListRules(FwDirection.In).Single(r => r.Name == rule.Name);
FirewallApi.Update(got, got with { Protocol = FwProtocols.Udp, LocalPorts = "50556" });
got = FirewallApi.ListRules(FwDirection.In).Single(r => r.Name == rule.Name);
Check(got.Protocol == FwProtocols.Udp && got.LocalPorts == "50556", $"update rule ({got.ProtocolText} {got.LocalPorts} {got.RemoteAddresses})");
FirewallApi.Delete(got);
Check(!FirewallApi.ListRules(FwDirection.In).Any(r => r.Name == rule.Name), "delete rule");

var rh = store.ResetHistory();
Check(store.CountEvents() == 0 && store.GetActiveBans().Count == 1 && store.QueryLogs(null, null, 10).Count == 0, $"reset history keeps active bans ({rh})");
Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
File.Delete(dbPath);
