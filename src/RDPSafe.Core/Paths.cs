using System.Security.AccessControl;
using System.Security.Principal;

namespace RDPSafe.Core;

public static class Paths
{
    public static string DataDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppInfo.Name);

    public static string Database => Path.Combine(DataDir, "rdpsafe.db");

    public static string GeoDatabase => Path.Combine(AppContext.BaseDirectory, "ip2region_v4.xdb");

    /// <summary>创建数据目录，并限制为仅 SYSTEM 与 Administrators 可访问。</summary>
    public static void EnsureDataDir()
    {
        var dir = new DirectoryInfo(DataDir);
        if (dir.Exists) return;
        dir.Create();
        try
        {
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            {
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                    FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            }
            dir.SetAccessControl(sec);
        }
        catch
        {
            // ACL 设置失败不影响功能
        }
    }
}
