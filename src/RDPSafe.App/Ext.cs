using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using RDPSafe.Core;

namespace RDPSafe.App;

/// <summary>样式使用的附加属性：图标字形、占位文字。</summary>
public static class Ext
{
    public static readonly DependencyProperty IconProperty =
        DependencyProperty.RegisterAttached("Icon", typeof(string), typeof(Ext), new FrameworkPropertyMetadata(""));

    public static string GetIcon(DependencyObject o) => (string)o.GetValue(IconProperty);
    public static void SetIcon(DependencyObject o, string v) => o.SetValue(IconProperty, v);

    public static readonly DependencyProperty PlaceholderProperty =
        DependencyProperty.RegisterAttached("Placeholder", typeof(string), typeof(Ext), new FrameworkPropertyMetadata(""));

    public static string GetPlaceholder(DependencyObject o) => (string)o.GetValue(PlaceholderProperty);
    public static void SetPlaceholder(DependencyObject o, string v) => o.SetValue(PlaceholderProperty, v);
}

/// <summary>把 DataGrid 的多选结果以 OneWayToSource 方式推送给视图模型。</summary>
public static class GridSelection
{
    public static readonly DependencyProperty SelectedItemsProperty =
        DependencyProperty.RegisterAttached("SelectedItems", typeof(IList), typeof(GridSelection),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault));

    public static IList? GetSelectedItems(DependencyObject o) => (IList?)o.GetValue(SelectedItemsProperty);
    public static void SetSelectedItems(DependencyObject o, IList? v) => o.SetValue(SelectedItemsProperty, v);

    public static readonly DependencyProperty EnabledProperty =
        DependencyProperty.RegisterAttached("Enabled", typeof(bool), typeof(GridSelection), new PropertyMetadata(false, OnEnabled));

    public static bool GetEnabled(DependencyObject o) => (bool)o.GetValue(EnabledProperty);
    public static void SetEnabled(DependencyObject o, bool v) => o.SetValue(EnabledProperty, v);

    private static void OnEnabled(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not MultiSelector grid) return;
        grid.SelectionChanged -= OnSelectionChanged;
        if ((bool)e.NewValue) grid.SelectionChanged += OnSelectionChanged;
    }

    private static void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var grid = (MultiSelector)sender;
        SetSelectedItems(grid, grid.SelectedItems.Cast<object>().ToList());
    }
}

// ───────────────────────── converters ─────────────────────────

public sealed class UnixTimeConverter : IValueConverter
{
    public string Format { get; set; } = "yyyy-MM-dd HH:mm:ss";

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        long l when l > 0 => TimeUtil.ToLocal(l).ToString(parameter as string ?? Format, culture),
        _ => "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class RelativeTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not long l || l <= 0) return "—";
        var d = TimeUtil.Now() - l;
        return d switch
        {
            < 0 => $"{Remaining(-d)}后",
            < 60 => "刚刚",
            < 3600 => $"{d / 60} 分钟前",
            < 86400 => $"{d / 3600} 小时前",
            _ => $"{d / 86400} 天前",
        };
    }

    internal static string Remaining(long s) => s switch
    {
        < 3600 => $"{Math.Max(1, s / 60)} 分钟",
        < 86400 => $"{s / 3600} 小时 {s % 3600 / 60} 分",
        _ => $"{s / 86400} 天 {s % 86400 / 3600} 小时",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>到期时间显示：永久 / 剩余时长。</summary>
public sealed class ExpiryConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not BanRecord b) return "";
        if (!b.Active) return b.UnbanTime is { } u ? TimeUtil.ToLocal(u).ToString("MM-dd HH:mm") + " 已解封" : "已解封";
        if (b.ExpireAt is not { } e) return "永久";
        var left = e - TimeUtil.Now();
        return left <= 0 ? "即将解封" : $"剩余 {RelativeTimeConverter.Remaining(left)}";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class BoolToVisibleConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var b = value switch
        {
            bool v => v,
            null => false,
            string s => !string.IsNullOrEmpty(s),
            int i => i != 0,
            long l => l != 0,
            ICollection c => c.Count > 0,
            _ => true,
        };
        return b ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>枚举/字符串值与单选按钮 IsChecked 的双向转换。</summary>
public sealed class EqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.Ordinal);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not true || parameter == null) return Binding.DoNothing;
        if (targetType.IsEnum) return Enum.Parse(targetType, parameter.ToString()!);
        if (targetType == typeof(int)) return int.Parse(parameter.ToString()!, culture);
        if (targetType == typeof(bool)) return bool.Parse(parameter.ToString()!);
        return parameter;
    }
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}
