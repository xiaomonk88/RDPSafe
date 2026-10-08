using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Media;
using RDPSafe.App.Services;
using RDPSafe.App.ViewModels;

namespace RDPSafe.App.Views;

public partial class MainWindow : Window
{
    private bool _forceClose;
    private bool _hintShown;

    private const string PlacementKey = "ui.window";

    public MainWindow()
    {
        InitializeComponent();
        StateChanged += (_, _) => UpdateMaximizedState();
        RestorePlacement();
    }

    public void ForceClose()
    {
        _forceClose = true;
        Close();
    }

    /// <summary>恢复上次的窗口位置；首次启动或原屏幕已断开时居中到主屏。</summary>
    private void RestorePlacement()
    {
        var saved = EngineClient.Instance.Store.GetValue(PlacementKey)?.Split(',');
        if (saved is { Length: 5 }
            && double.TryParse(saved[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var left)
            && double.TryParse(saved[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var top)
            && double.TryParse(saved[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var width)
            && double.TryParse(saved[3], NumberStyles.Float, CultureInfo.InvariantCulture, out var height)
            && IsOnAnyScreen(left, top, width))
        {
            Left = left;
            Top = top;
            Width = Math.Max(MinWidth, width);
            Height = Math.Max(MinHeight, height);
            if (saved[4] == "1") WindowState = WindowState.Maximized;
            return;
        }

        // SystemParameters.WorkArea 始终是主屏工作区
        var area = SystemParameters.WorkArea;
        Width = Math.Min(Width, area.Width);
        Height = Math.Min(Height, area.Height);
        Left = area.Left + (area.Width - Width) / 2;
        Top = area.Top + (area.Height - Height) / 2;
    }

    /// <summary>窗口标题栏区域是否落在某块当前连接的屏幕内。</summary>
    private bool IsOnAnyScreen(double left, double top, double width)
    {
        var dpi = VisualTreeHelper.GetDpi(this);
        var titleBar = new System.Drawing.Rectangle(
            (int)((left + 40) * dpi.DpiScaleX), (int)(top * dpi.DpiScaleY),
            (int)(Math.Max(100, width - 80) * dpi.DpiScaleX), (int)(40 * dpi.DpiScaleY));
        return System.Windows.Forms.Screen.AllScreens.Any(s => s.WorkingArea.IntersectsWith(titleBar));
    }

    private void SavePlacement()
    {
        var b = RestoreBounds.IsEmpty ? new Rect(Left, Top, Width, Height) : RestoreBounds;
        var max = WindowState == WindowState.Maximized ? "1" : "0";
        var value = string.Join(",", new[] { b.Left, b.Top, b.Width, b.Height }.Select(v => v.ToString("0", CultureInfo.InvariantCulture))) + "," + max;
        try
        {
            EngineClient.Instance.Store.SetValue(PlacementKey, value);
        }
        catch
        {
        }
    }

    private void UpdateMaximizedState()
    {
        // WindowChrome 最大化时窗口会超出屏幕边缘，用边距补偿
        var max = WindowState == WindowState.Maximized;
        Root.Margin = max ? new Thickness(7) : new Thickness(0);
        MaxButton.Content = max ? Glyphs.Restore : Glyphs.Maximize;
        MaxButton.ToolTip = max ? "还原" : "最大化";
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        base.OnClosing(e);
        if (IsVisible && !App.DataRemoved) SavePlacement();
        if (_forceClose) return;
        e.Cancel = true;
        var closeToTray = EngineClient.Instance.Store.GetValue(SettingsViewModel.CloseToTrayKey) != "0";
        var app = (App)Application.Current;
        if (closeToTray)
        {
            app.HideToTray(!_hintShown);
            _hintShown = true;
        }
        else
        {
            app.ExitApp();
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
