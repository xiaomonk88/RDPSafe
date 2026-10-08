using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using RDPSafe.Core.Engine;

namespace RDPSafe.Core.Ipc;

public static class PipeCommands
{
    public const string Status = "status";
    public const string Ban = "ban";
    public const string Unban = "unban";
    public const string AddList = "addList";
    public const string RemoveList = "removeList";
    public const string SaveSettings = "saveSettings";
    public const string ClearLogins = "clearLogins";
    public const string ResetData = "resetData";
}

public sealed class PipeRequest
{
    public string Cmd { get; set; } = "";
    public string? Ip { get; set; }
    public string[]? Ips { get; set; }
    public string? Kind { get; set; }
    public string? Note { get; set; }
    public int? Hours { get; set; }
    public AppSettings? Settings { get; set; }
}

public sealed class PipeResponse
{
    public bool Ok { get; set; }
    public string Message { get; set; } = "";
    public EngineStatus? Status { get; set; }

    public static PipeResponse From(OpResult r) => new() { Ok = r.Ok, Message = r.Message };
}

internal static class PipeJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
    public static readonly UTF8Encoding Utf8 = new(false);
}

/// <summary>引擎命名管道服务端，仅允许 SYSTEM 与 Administrators 连接。</summary>
public sealed class PipeServer
{
    private readonly Func<PipeRequest, PipeResponse> _handler;

    public PipeServer(Func<PipeRequest, PipeResponse> handler) => _handler = handler;

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(AppInfo.PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    0, 0, CreateSecurity());
            }
            catch (IOException)
            {
                await Task.Delay(1000, ct);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct);
            }
            catch
            {
                await pipe.DisposeAsync();
                if (ct.IsCancellationRequested) break;
                continue;
            }
            _ = Task.Run(() => HandleAsync(pipe, ct), ct);
        }
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, PipeJson.Utf8, false, 4096, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, PipeJson.Utf8, 4096, leaveOpen: true) { AutoFlush = true };
                var line = await reader.ReadLineAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
                if (string.IsNullOrEmpty(line)) return;

                PipeResponse resp;
                try
                {
                    var req = JsonSerializer.Deserialize<PipeRequest>(line, PipeJson.Options) ?? new PipeRequest();
                    resp = _handler(req);
                }
                catch (Exception ex)
                {
                    resp = new PipeResponse { Ok = false, Message = ex.Message };
                }
                await writer.WriteLineAsync(JsonSerializer.Serialize(resp, PipeJson.Options));
            }
            catch
            {
                // 客户端断开等情况忽略
            }
        }
    }

    private static PipeSecurity CreateSecurity()
    {
        var sec = new PipeSecurity();
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return sec;
    }
}

public static class PipeClient
{
    /// <summary>发送请求；引擎不可达时返回 null。</summary>
    public static async Task<PipeResponse?> SendAsync(PipeRequest req, int connectTimeoutMs = 800, int replyTimeoutMs = 30_000)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(".", AppInfo.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(connectTimeoutMs);
            using var reader = new StreamReader(pipe, PipeJson.Utf8, false, 4096, leaveOpen: true);
            await using var writer = new StreamWriter(pipe, PipeJson.Utf8, 4096, leaveOpen: true) { AutoFlush = true };
            await writer.WriteLineAsync(JsonSerializer.Serialize(req, PipeJson.Options));
            var line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromMilliseconds(replyTimeoutMs));
            return line == null ? null : JsonSerializer.Deserialize<PipeResponse>(line, PipeJson.Options);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
