using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace RDPSafe.Core.Firewall;

/// <summary>
/// 聚合封禁规则：所有被封 IP 分组写入少量入站阻止规则（每条最多 <see cref="ChunkSize"/> 个地址），
/// 避免一 IP 一规则导致防火墙规则膨胀。
/// </summary>
public static class BlockRules
{
    public const string Group = "RDPSafe";
    public const string Prefix = "RDPSafe_Block_";
    public const int ChunkSize = 1000;

    private static readonly object _lock = new();
    private static readonly Dictionary<string, string> _written = new();

    /// <summary>将封禁地址集合同步到防火墙。force=true 时无视缓存全部重写（用于对账）。</summary>
    /// <returns>本次写入/删除的规则数</returns>
    public static int Sync(IReadOnlyCollection<string> addresses, bool force = false)
    {
        lock (_lock)
        {
            var policy = FirewallApi.Policy();
            var existing = new Dictionary<string, dynamic>();
            var duplicates = new List<dynamic>();
            foreach (var r in FirewallApi.EnumerateRules(policy))
            {
                string name = r.Name ?? "";
                if (!name.StartsWith(Prefix, StringComparison.Ordinal)) continue;
                if (!existing.TryAdd(name, r)) duplicates.Add(r);
            }

            var changes = 0;
            var chunks = addresses.Distinct().Chunk(ChunkSize).ToList();
            var wanted = new HashSet<string>();
            for (var i = 0; i < chunks.Count; i++)
            {
                var name = $"{Prefix}{i + 1:000}";
                wanted.Add(name);
                var joined = string.Join(",", chunks[i]);
                if (existing.TryGetValue(name, out var rule))
                {
                    var intact = (bool)rule.Enabled && (int)rule.Action == (int)FwAction.Block && (int)rule.Direction == (int)FwDirection.In;
                    if (!force && intact && _written.TryGetValue(name, out var last) && last == joined) continue;
                    rule.RemoteAddresses = joined;
                    rule.Action = (int)FwAction.Block;
                    rule.Enabled = true;
                }
                else
                {
                    FirewallApi.Add(new FwRule
                    {
                        Name = name,
                        Description = $"RDPSafe 自动管理的封禁规则（第 {i + 1} 组），请勿手动修改。",
                        Grouping = Group,
                        Direction = FwDirection.In,
                        Action = FwAction.Block,
                        Protocol = FwProtocols.Any,
                        RemoteAddresses = joined,
                        Enabled = true,
                    });
                }
                _written[name] = joined;
                changes++;
            }

            // 删除多余的分组规则及重名规则
            foreach (var (name, rule) in existing)
            {
                if (wanted.Contains(name)) continue;
                duplicates.Add(rule);
                _written.Remove(name);
            }
            foreach (var r in duplicates)
            {
                var tmp = "RDPSafe-delete-" + Guid.NewGuid().ToString("N");
                r.Name = tmp;
                policy.Rules.Remove(tmp);
                changes++;
            }
            return changes;
        }
    }

    /// <summary>删除所有 RDPSafe 管理的规则（卸载时使用）。</summary>
    public static int RemoveAll() => Sync(Array.Empty<string>(), force: true);
}

/// <summary>断开指定 IP 已建立的 IPv4 TCP 连接。</summary>
public static class TcpKiller
{
    private const int MIB_TCP_STATE_DELETE_TCB = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll")]
    private static extern int SetTcpEntry(ref MIB_TCPROW pTcpRow);

    public static int Kill(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork) return 0;
        var target = BitConverter.ToUInt32(addr.GetAddressBytes(), 0);

        var size = 0;
        GetTcpTable(IntPtr.Zero, ref size, false);
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetTcpTable(buf, ref size, false) != 0) return 0;
            var count = Marshal.ReadInt32(buf);
            var rowSize = Marshal.SizeOf<MIB_TCPROW>();
            var killed = 0;
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW>(buf + 4 + i * rowSize);
                if (row.dwRemoteAddr != target || row.dwState == MIB_TCP_STATE_DELETE_TCB) continue;
                row.dwState = MIB_TCP_STATE_DELETE_TCB;
                if (SetTcpEntry(ref row) == 0) killed++;
            }
            return killed;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}
