using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RDPSafe.Core.Platform;

/// <summary>“审核登录”子类别策略。未开启时 Security 日志不会产生 4624/4625 事件。</summary>
public static class AuditPolicy
{
    private static readonly Guid LogonSubcategory = new("0CCE9215-69AE-11D9-BED3-505054503030");
    private const uint POLICY_AUDIT_EVENT_SUCCESS = 1;
    private const uint POLICY_AUDIT_EVENT_FAILURE = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditSetSystemPolicy([In] AUDIT_POLICY_INFORMATION[] pAuditPolicy, uint dwPolicyCount);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    /// <summary>返回登录失败与成功审核是否均已开启；无法查询时返回 null。</summary>
    public static bool? IsLogonAuditEnabled()
    {
        try
        {
            Privileges.Enable("SeSecurityPrivilege");
            if (!AuditQuerySystemPolicy(new[] { LogonSubcategory }, 1, out var ptr)) return null;
            try
            {
                var info = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(ptr);
                const uint both = POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE;
                return (info.AuditingInformation & both) == both;
            }
            finally
            {
                AuditFree(ptr);
            }
        }
        catch
        {
            return null;
        }
    }

    public static void EnableLogonAudit()
    {
        Privileges.Enable("SeSecurityPrivilege");
        var policy = new[]
        {
            new AUDIT_POLICY_INFORMATION
            {
                AuditSubCategoryGuid = LogonSubcategory,
                AuditingInformation = POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE,
            },
        };
        if (!AuditSetSystemPolicy(policy, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}

internal static class Privileges
{
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    private const uint TOKEN_QUERY = 0x8;
    private const uint SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static void Enable(string privilege)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) return;
        try
        {
            if (!LookupPrivilegeValue(null, privilege, out var luid)) return;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
