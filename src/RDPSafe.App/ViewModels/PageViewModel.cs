using CommunityToolkit.Mvvm.ComponentModel;
using RDPSafe.App.Services;

namespace RDPSafe.App.ViewModels;

public abstract partial class PageViewModel : ObservableObject
{
    public abstract string Title { get; }
    public abstract string Subtitle { get; }
    /// <summary>Segoe Fluent/MDL2 图标字形</summary>
    public abstract string Glyph { get; }

    [ObservableProperty]
    private bool _isBusy;

    protected static EngineClient Engine => EngineClient.Instance;
    public AppState State => AppState.Instance;

    public virtual Task OnActivatedAsync() => RefreshAsync();

    public abstract Task RefreshAsync();

    /// <summary>页面处于前台时每 3 秒调用一次。</summary>
    public virtual Task OnTickAsync(int tick) => Task.CompletedTask;

    protected async Task RunBusy(Func<Task> action)
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            Ui.Show(ex.Message, true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    protected static List<T> Selected<T>(System.Collections.IList? items) => items?.OfType<T>().ToList() ?? new List<T>();
}
