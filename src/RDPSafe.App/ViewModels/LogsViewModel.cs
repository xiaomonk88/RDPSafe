using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RDPSafe.App.Services;
using RDPSafe.Core;

namespace RDPSafe.App.ViewModels;

public sealed partial class LogsViewModel : PageViewModel
{
    public override string Title => "操作日志";
    public override string Subtitle => "封禁、解封、配置变更与引擎运行记录";
    public override string Glyph => Glyphs.Document;

    public ObservableCollection<OpLog> Items { get; } = new();

    /// <summary>空字符串表示全部级别</summary>
    [ObservableProperty]
    private string _level = "";

    [ObservableProperty]
    private string _search = "";

    partial void OnLevelChanged(string value) => _ = RefreshAsync();

    public override async Task RefreshAsync()
    {
        var level = Level;
        var search = Search;
        var rows = await Engine.QueryAsync(s => s.QueryLogs(string.IsNullOrEmpty(level) ? null : level, search, 2000));
        if (Items.Count > 0 && rows.Count > 0 && rows[0].Id == Items[0].Id && rows.Count == Items.Count) return;
        Items.Clear();
        foreach (var r in rows) Items.Add(r);
    }

    public override Task OnTickAsync(int tick) => tick % 2 == 0 ? RefreshAsync() : Task.CompletedTask;

    [RelayCommand]
    private Task Query() => RefreshAsync();

    [RelayCommand]
    private void Copy(OpLog? log)
    {
        if (log != null) Ui.CopyText($"[{log.LocalTime:yyyy-MM-dd HH:mm:ss}] {log.Message}");
    }
}
