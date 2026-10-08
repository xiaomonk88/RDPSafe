using System.Net;
using System.Net.Sockets;

namespace RDPSafe.Core.Net;

public static class IpUtil
{
    /// <summary>规范化事件中的 IP 字符串；无效、"-"、未指定地址返回 null。</summary>
    public static string? Normalize(string? s)
    {
        s = s?.Trim();
        if (string.IsNullOrEmpty(s) || s == "-") return null;
        if (!IPAddress.TryParse(s, out var ip)) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6) ip.ScopeId = 0;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None)) return null;
        return ip.ToString();
    }

    public static bool IsLoopback(string ip) => IPAddress.TryParse(ip, out var a) && IPAddress.IsLoopback(a);

    public static bool IsPrivate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return false;
        if (IPAddress.IsLoopback(a)) return true;
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }
        return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6UniqueLocal;
    }

    /// <summary>解析用户输入的单个 IP 或 CIDR，返回规范化形式。</summary>
    public static bool TryParseEntry(string? input, out string normalized)
    {
        normalized = "";
        input = input?.Trim();
        if (string.IsNullOrEmpty(input)) return false;
        var slash = input.IndexOf('/');
        if (slash < 0)
        {
            var n = Normalize(input);
            if (n == null) return false;
            normalized = n;
            return true;
        }
        if (!IPAddress.TryParse(input[..slash], out var ip) || !int.TryParse(input[(slash + 1)..], out var prefix)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > max) return false;
        if (prefix == max)
        {
            normalized = ip.ToString();
            return true;
        }
        if (prefix < (max == 32 ? 8 : 16)) return false; // 防止误封过大的网段
        normalized = $"{new IPAddress(Mask(ip.GetAddressBytes(), prefix))}/{prefix}";
        return true;
    }

    internal static byte[] Mask(byte[] bytes, int prefix)
    {
        var r = (byte[])bytes.Clone();
        for (var i = 0; i < r.Length; i++)
        {
            var bits = Math.Clamp(prefix - i * 8, 0, 8);
            r[i] &= (byte)(0xFF << (8 - bits));
        }
        return r;
    }
}

/// <summary>IP 与 CIDR 混合匹配器。</summary>
public sealed class IpMatcher
{
    private readonly HashSet<string> _exact = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(byte[] Net, int Prefix)> _cidrs = new();

    public IpMatcher(IEnumerable<string> entries)
    {
        foreach (var e in entries)
        {
            if (!IpUtil.TryParseEntry(e, out var n)) continue;
            var slash = n.IndexOf('/');
            if (slash < 0) _exact.Add(n);
            else _cidrs.Add((IPAddress.Parse(n[..slash]).GetAddressBytes(), int.Parse(n[(slash + 1)..])));
        }
    }

    public int Count => _exact.Count + _cidrs.Count;

    public bool Contains(string ip)
    {
        if (_exact.Contains(ip)) return true;
        if (_cidrs.Count == 0 || !IPAddress.TryParse(ip, out var a)) return false;
        var bytes = a.GetAddressBytes();
        foreach (var (net, prefix) in _cidrs)
        {
            if (net.Length == bytes.Length && IpUtil.Mask(bytes, prefix).AsSpan().SequenceEqual(net)) return true;
        }
        return false;
    }
}
