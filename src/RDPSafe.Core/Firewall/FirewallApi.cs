using System.Collections;

namespace RDPSafe.Core.Firewall;

public enum FwAction { Block = 0, Allow = 1 }
public enum FwDirection { In = 1, Out = 2 }

public static class FwProtocols
{
    public const int Any = 256;
    public const int Tcp = 6;
    public const int Udp = 17;
    public const int Icmpv4 = 1;
    public const int Icmpv6 = 58;

    public static string Display(int p) => p switch
    {
        Any => "任意",
        Tcp => "TCP",
        Udp => "UDP",
        Icmpv4 => "ICMPv4",
        Icmpv6 => "ICMPv6",
        _ => p.ToString(),
    };
}

/// <summary>防火墙规则的快照。由于规则名称可重复，修改/删除时按快照匹配定位具体规则。</summary>
public sealed record FwRule
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string Grouping { get; init; } = "";
    public bool Enabled { get; init; } = true;
    public FwDirection Direction { get; init; } = FwDirection.In;
    public FwAction Action { get; init; } = FwAction.Allow;
    public int Protocol { get; init; } = FwProtocols.Any;
    public string LocalPorts { get; init; } = "";
    public string RemotePorts { get; init; } = "";
    public string RemoteAddresses { get; init; } = "*";
    public string ApplicationName { get; init; } = "";
    public int Profiles { get; init; } = FirewallApi.AllProfiles;

    public bool IsManaged => Grouping == BlockRules.Group || Name.StartsWith(BlockRules.Prefix, StringComparison.Ordinal);
    public string ProtocolText => FwProtocols.Display(Protocol);
    public string LocalPortsText => string.IsNullOrEmpty(LocalPorts) || LocalPorts == "*" ? "任意" : LocalPorts;
    public string RemoteAddressesText => string.IsNullOrEmpty(RemoteAddresses) || RemoteAddresses == "*" ? "任意" : RemoteAddresses;
    public string ApplicationText => string.IsNullOrEmpty(ApplicationName) ? "" : Path.GetFileName(ApplicationName);
}

/// <summary>Windows 防火墙（INetFwPolicy2）操作封装。</summary>
public static class FirewallApi
{
    public const int AllProfiles = 0x7FFFFFFF;

    internal static dynamic Policy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return Activator.CreateInstance(type)!;
    }

    internal static IEnumerable<dynamic> EnumerateRules(dynamic policy)
    {
        foreach (dynamic r in (IEnumerable)policy.Rules) yield return r;
    }

    private static readonly (int Bit, string Name)[] ProfileNames = { (1, "域"), (2, "专用"), (4, "公用") };

    /// <summary>当前生效的网络配置文件中，防火墙处于关闭状态的配置文件名称；全部开启时为空。</summary>
    public static List<string> GetDisabledActiveProfiles()
    {
        var p = Policy();
        int current = p.CurrentProfileTypes;
        var off = new List<string>();
        foreach (var (bit, name) in ProfileNames)
        {
            if ((current & bit) != 0 && !(bool)p.FirewallEnabled[bit]) off.Add(name);
        }
        return off;
    }

    /// <summary>
    /// 为当前网络开启 Windows 防火墙。开启前先确保远程桌面端口有入站放行规则，避免管理员被锁在外面。
    /// </summary>
    public static void EnableForActiveProfiles(int rdpPort)
    {
        var existing = ListRules(FwDirection.In);
        foreach (var proto in new[] { FwProtocols.Tcp, FwProtocols.Udp })
        {
            var name = $"RDPSafe 允许远程桌面 ({FwProtocols.Display(proto)} {rdpPort})";
            var rule = existing.FirstOrDefault(r => r.Name == name);
            var wanted = new FwRule
            {
                Name = name,
                Description = "由 RDPSafe 在开启防火墙前创建，确保远程桌面可以连接。被封禁的 IP 仍会被阻止规则拦截。",
                Direction = FwDirection.In,
                Action = FwAction.Allow,
                Protocol = proto,
                LocalPorts = rdpPort.ToString(),
                Enabled = true,
            };
            if (rule == null) Add(wanted);
            else if (!rule.Enabled || rule.Action != FwAction.Allow) Update(rule, wanted);
        }

        var p = Policy();
        int current = p.CurrentProfileTypes;
        foreach (var (bit, _) in ProfileNames)
        {
            if ((current & bit) != 0) p.FirewallEnabled[bit] = true;
        }
    }

    public static List<FwRule> ListRules(FwDirection? direction = null)
    {
        var list = new List<FwRule>();
        foreach (var r in EnumerateRules(Policy()))
        {
            FwRule rule = Snapshot(r);
            if (direction == null || rule.Direction == direction) list.Add(rule);
        }
        return list;
    }

    public static void Add(FwRule rule)
    {
        var policy = Policy();
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        dynamic r = Activator.CreateInstance(type)!;
        Apply(r, rule, isNew: true);
        policy.Rules.Add(r);
    }

    public static void Update(FwRule original, FwRule updated)
    {
        var r = Find(Policy(), original) ?? throw new InvalidOperationException("未找到该规则，可能已被修改或删除，请刷新后重试。");
        Apply(r, updated, isNew: false);
    }

    public static void SetEnabled(FwRule original, bool enabled)
    {
        var r = Find(Policy(), original) ?? throw new InvalidOperationException("未找到该规则，请刷新后重试。");
        r.Enabled = enabled;
    }

    public static void Delete(FwRule original)
    {
        var policy = Policy();
        var r = Find(policy, original) ?? throw new InvalidOperationException("未找到该规则，请刷新后重试。");
        // 规则名称可能重复，先改为唯一名称再按名称删除，确保只删除这一条
        var tmp = "RDPSafe-delete-" + Guid.NewGuid().ToString("N");
        r.Name = tmp;
        policy.Rules.Remove(tmp);
    }

    private static dynamic? Find(dynamic policy, FwRule target)
    {
        foreach (var r in EnumerateRules(policy))
        {
            if ((string)(r.Name ?? "") != target.Name) continue;
            FwRule snap = Snapshot(r);
            if (snap == target) return r;
        }
        return null;
    }

    internal static FwRule Snapshot(dynamic r) => new()
    {
        Name = (string)(r.Name ?? ""),
        Description = (string)(r.Description ?? ""),
        Grouping = (string)(r.Grouping ?? ""),
        Enabled = (bool)r.Enabled,
        Direction = (FwDirection)(int)r.Direction,
        Action = (FwAction)(int)r.Action,
        Protocol = (int)r.Protocol,
        LocalPorts = (string)(r.LocalPorts ?? ""),
        RemotePorts = (string)(r.RemotePorts ?? ""),
        RemoteAddresses = (string)(r.RemoteAddresses ?? ""),
        ApplicationName = (string)(r.ApplicationName ?? ""),
        Profiles = (int)r.Profiles,
    };

    private static void Apply(dynamic r, FwRule rule, bool isNew)
    {
        r.Name = rule.Name;
        r.Description = rule.Description ?? "";
        if (isNew)
        {
            r.Direction = (int)rule.Direction;
            if (!string.IsNullOrEmpty(rule.Grouping)) r.Grouping = rule.Grouping;
        }
        r.Action = (int)rule.Action;

        // 协议变化时必须先清空端口，否则 COM 会拒绝设置
        var portable = rule.Protocol is FwProtocols.Tcp or FwProtocols.Udp;
        if ((int)r.Protocol != rule.Protocol)
        {
            if ((int)r.Protocol is FwProtocols.Tcp or FwProtocols.Udp)
            {
                r.LocalPorts = "*";
                r.RemotePorts = "*";
            }
            r.Protocol = rule.Protocol;
        }
        if (portable)
        {
            r.LocalPorts = Blank(rule.LocalPorts);
            r.RemotePorts = Blank(rule.RemotePorts);
        }
        r.RemoteAddresses = Blank(rule.RemoteAddresses);
        // COM 不接受 null，程序路径为空时保持“所有程序”
        if (!string.IsNullOrWhiteSpace(rule.ApplicationName)) r.ApplicationName = rule.ApplicationName.Trim();
        r.Profiles = rule.Profiles;
        r.Enabled = rule.Enabled;

        static string Blank(string? s) => string.IsNullOrWhiteSpace(s) || s.Trim() == "任意" ? "*" : s.Trim();
    }
}
