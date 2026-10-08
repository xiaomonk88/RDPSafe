namespace RDPSafe.App;

/// <summary>Segoe Fluent Icons / Segoe MDL2 Assets 字形（以码点定义，避免源码中出现私有区字符）。</summary>
public static class Glyphs
{
    private static string G(int code) => ((char)code).ToString();

    public static readonly string Home = G(0xE80F);
    public static readonly string History = G(0xE81C);
    public static readonly string Lock = G(0xE72E);
    public static readonly string List = G(0xEA37);
    public static readonly string Shield = G(0xEA18);
    public static readonly string Document = G(0xE8A5);
    public static readonly string Settings = G(0xE713);
    public static readonly string Warning = G(0xE7BA);
    public static readonly string Info = G(0xE946);
    public static readonly string Error = G(0xE783);
    public static readonly string Completed = G(0xE930);
    public static readonly string Maximize = G(0xE922);
    public static readonly string Restore = G(0xE923);
}
