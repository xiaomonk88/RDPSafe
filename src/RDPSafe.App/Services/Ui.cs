using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.Core;

namespace RDPSafe.App.Services;

/// <summary>窗口内的确认对话框。</summary>
public sealed partial class DialogModel : ObservableObject
{
    private readonly TaskCompletionSource<bool> _tcs = new();

    public string Title { get; init; } = "";
    public string Message { get; init; } = "";
    public string ConfirmText { get; init; } = "确定";
    public string CancelText { get; init; } = "取消";
    public bool IsDanger { get; init; }
    public bool ShowCancel { get; init; } = true;
    public string Glyph => IsDanger ? Glyphs.Warning : Glyphs.Info;

    public Task<bool> Result => _tcs.Task;

    [RelayCommand]
    private void Confirm() => _tcs.TrySetResult(true);

    [RelayCommand]
    private void Cancel() => _tcs.TrySetResult(false);
}

/// <summary>底部轻提示。</summary>
public sealed partial class ToastModel : ObservableObject
{
    public string Message { get; init; } = "";
    public bool IsError { get; init; }
    public string Glyph => IsError ? Glyphs.Error : Glyphs.Completed;
}

/// <summary>界面反馈服务：轻提示与确认框。</summary>
public sealed partial class Ui : ObservableObject
{
    public static Ui Instance { get; } = new();

    [ObservableProperty]
    private DialogModel? _dialog;

    [ObservableProperty]
    private ToastModel? _toast;

    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(3.2) };

    private Ui()
    {
        _toastTimer.Tick += (_, _) =>
        {
            _toastTimer.Stop();
            Toast = null;
        };
    }

    public static void Show(string message, bool error = false)
    {
        var ui = Instance;
        ui._toastTimer.Stop();
        ui.Toast = new ToastModel { Message = message, IsError = error };
        ui._toastTimer.Interval = TimeSpan.FromSeconds(error ? 5 : 3.2);
        ui._toastTimer.Start();
    }

    public static void Show(OpResult r) => Show(r.Message, !r.Ok);

    public static async Task<bool> ConfirmAsync(string title, string message, string confirmText = "确定", bool danger = false)
    {
        var d = new DialogModel { Title = title, Message = message, ConfirmText = confirmText, IsDanger = danger };
        Instance.Dialog = d;
        try
        {
            return await d.Result;
        }
        finally
        {
            if (Instance.Dialog == d) Instance.Dialog = null;
        }
    }

    public static Task AlertAsync(string title, string message) =>
        ConfirmAndClose(new DialogModel { Title = title, Message = message, ShowCancel = false, ConfirmText = "知道了" });

    private static async Task ConfirmAndClose(DialogModel d)
    {
        Instance.Dialog = d;
        await d.Result;
        if (Instance.Dialog == d) Instance.Dialog = null;
    }

    public static void CopyText(string text)
    {
        try
        {
            Clipboard.SetText(text);
            Show($"已复制：{(text.Length > 40 ? text[..40] + "…" : text)}");
        }
        catch
        {
            Show("复制失败，剪贴板被占用", true);
        }
    }
}
