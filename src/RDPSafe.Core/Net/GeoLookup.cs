using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RDPSafe.Core.Net;

/// <summary>
/// ip2region xdb（v3 格式，IPv4）离线归属地查询。整库载入内存，单次查询为微秒级。
/// </summary>
public sealed class GeoLookup
{
    private const int HeaderSize = 256;
    private const int VectorCols = 256;
    private const int VectorEntrySize = 8;
    private const int SegmentSize = 4 * 2 + 6;

    public const string ResourceName = "ip2region_v4.xdb";

    private static readonly Lazy<GeoLookup> _shared = new(() => new GeoLookup(Paths.GeoDatabase));
    public static GeoLookup Shared => _shared.Value;

    private readonly byte[]? _data;
    private readonly ConcurrentDictionary<string, string> _cache = new();

    public bool Available => _data != null;

    /// <param name="path">外部 xdb 文件；不存在时使用程序内嵌的数据。</param>
    public GeoLookup(string path)
    {
        try
        {
            var data = File.Exists(path) ? File.ReadAllBytes(path) : ReadEmbedded();
            if (data == null || data.Length < HeaderSize) return;
            var ipVersion = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(16, 2));
            // v2 格式头部该字段为 0，同样是 IPv4 布局
            if (ipVersion is 0 or 4) _data = data;
        }
        catch
        {
            _data = null;
        }
    }

    private static byte[]? ReadEmbedded()
    {
        using var s = typeof(GeoLookup).Assembly.GetManifestResourceStream(ResourceName);
        if (s == null) return null;
        var buf = new byte[s.Length];
        s.ReadExactly(buf);
        return buf;
    }

    public string Lookup(string? ipText)
    {
        if (string.IsNullOrEmpty(ipText)) return "未知";
        if (_cache.TryGetValue(ipText, out var hit)) return hit;

        var result = Resolve(ipText);
        if (_cache.Count > 50_000) _cache.Clear();
        _cache[ipText] = result;
        return result;
    }

    private string Resolve(string ipText)
    {
        var slash = ipText.IndexOf('/');
        if (slash > 0) ipText = ipText[..slash];
        if (!IPAddress.TryParse(ipText, out var ip)) return "未知";
        if (IPAddress.IsLoopback(ip)) return "本机";
        if (IpUtil.IsPrivate(ip.ToString())) return "局域网";
        if (ip.AddressFamily != AddressFamily.InterNetwork || _data == null) return "未知";

        var region = Search(ip.GetAddressBytes());
        return Format(region);
    }

    private string? Search(byte[] ip)
    {
        var data = _data!;
        var idx = HeaderSize + ip[0] * VectorCols * VectorEntrySize + ip[1] * VectorEntrySize;
        var sPtr = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(idx, 4));
        var ePtr = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(idx + 4, 4));
        if (sPtr == 0 || ePtr == 0) return null;

        var value = BinaryPrimitives.ReadUInt32BigEndian(ip);
        long l = 0, h = (ePtr - sPtr) / SegmentSize;
        while (l <= h)
        {
            var m = (l + h) >> 1;
            var p = (int)(sPtr + m * SegmentSize);
            var start = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p, 4));
            var end = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 4, 4));
            if (value < start) h = m - 1;
            else if (value > end) l = m + 1;
            else
            {
                var len = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(p + 8, 2));
                var ptr = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 10, 4));
                return Encoding.UTF8.GetString(data, (int)ptr, len);
            }
        }
        return null;
    }

    /// <summary>
    /// 将 "国家|省份|城市|运营商|ISO代码" 格式化为 "国家 省份"（国内到城市）。
    /// 国外国家名为英文，借助 ISO 代码转换为中文。
    /// </summary>
    internal static string Format(string? region)
    {
        if (string.IsNullOrEmpty(region)) return "未知";
        var parts = region.Split('|');
        if (parts[0] is "Reserved" or "保留") return "保留地址";

        var country = parts.Length >= 5 ? CountryNames.Get(parts[4]) ?? parts[0] : parts[0];
        var isChina = parts.Length >= 5 ? parts[4] == "CN" : parts[0] == "中国";
        var picked = new List<string>(3);
        if (!string.IsNullOrWhiteSpace(country) && country != "0") picked.Add(country);
        foreach (var part in parts.Skip(1).Take(isChina ? 2 : 1))
        {
            if (string.IsNullOrWhiteSpace(part) || part == "0") continue;
            if (picked.Count > 0 && (picked[^1] == part || part.StartsWith(picked[^1]))) continue;
            picked.Add(part);
        }
        return picked.Count == 0 ? "未知" : string.Join(" ", picked);
    }
}
