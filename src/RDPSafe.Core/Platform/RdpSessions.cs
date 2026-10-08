using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace RDPSafe.Core.Platform;

/// <summary>
/// 查询远程桌面连接的真实来源 IP。
/// 注意：不能使用 WTSQuerySessionInformation(WTSClientAddress)，那是客户端自报的本机地址（常为内网 IP），
/// 而非服务器看到的 TCP 对端地址。这里改为读取 TCP 连接表中远程桌面端口上已建立连接的对端。
/// </summary>
public static class RdpSessions
{
    private const int SM_REMOTESESSION = 0x1000;
    private const uint MIB_TCP_STATE_ESTAB = 5;
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public fixed byte RemoteAddr[16];
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    /// <summary>远程桌面监听端口（注册表 RDP-Tcp\PortNumber，默认 3389）。</summary>
    public static int GetRdpPort()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            return key?.GetValue("PortNumber") is int p and > 0 and < 65536 ? p : 3389;
        }
        catch
        {
            return 3389;
        }
    }

    /// <summary>当前所有已建立的远程桌面连接的对端 IP（服务器实际看到的来源地址）。</summary>
    public static HashSet<string> GetConnectedClientIps()
    {
        var port = GetRdpPort();
        var result = new HashSet<string>();
        try
        {
            foreach (var ip in ReadTable(AF_INET, port)) result.Add(ip);
            foreach (var ip in ReadTable(AF_INET6, port)) result.Add(ip);
        }
        catch
        {
            // 读取失败时返回空集合
        }
        return result;
    }

    /// <summary>当前进程是否运行在远程桌面会话中。</summary>
    public static bool IsRemoteSession() => GetSystemMetrics(SM_REMOTESESSION) != 0;

    private static unsafe List<string> ReadTable(int af, int rdpPort)
    {
        var list = new List<string>();
        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        if (size == 0) return list;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != 0) return list;
            var count = Marshal.ReadInt32(buf);
            if (af == AF_INET)
            {
                var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                    if (row.State != MIB_TCP_STATE_ESTAB || NetPort(row.LocalPort) != rdpPort) continue;
                    AddIp(list, new IPAddress(row.RemoteAddr));
                }
            }
            else
            {
                var rowSize = sizeof(MIB_TCP6ROW_OWNER_PID);
                for (var i = 0; i < count; i++)
                {
                    var row = *(MIB_TCP6ROW_OWNER_PID*)(buf + 4 + i * rowSize);
                    if (row.State != MIB_TCP_STATE_ESTAB || NetPort(row.LocalPort) != rdpPort) continue;
                    AddIp(list, new IPAddress(new ReadOnlySpan<byte>(row.RemoteAddr, 16)));
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return list;

        static void AddIp(List<string> list, IPAddress ip)
        {
            var n = Net.IpUtil.Normalize(ip.ToString());
            if (n != null && !Net.IpUtil.IsLoopback(n)) list.Add(n);
        }
    }

    /// <summary>端口以网络字节序存放在 DWORD 低 16 位。</summary>
    private static int NetPort(uint p) => (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));
}
