using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using RDPSafe.App.ViewModels;
using RDPSafe.Core.Firewall;

namespace RDPSafe.App.Views;

public partial class RuleEditWindow : Window
{
    private readonly RuleEditViewModel _vm;

    public FwRule? Result { get; private set; }

    private RuleEditWindow(FwRule? rule)
    {
        InitializeComponent();
        _vm = new RuleEditViewModel(rule);
        DataContext = _vm;
        Loaded += (_, _) => NameBox.Focus();
    }

    /// <summary>显示编辑对话框；取消返回 null。</summary>
    public static FwRule? Edit(FwRule? rule)
    {
        var w = new RuleEditWindow(rule) { Owner = Application.Current.MainWindow };
        return w.ShowDialog() == true ? w.Result : null;
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var r = _vm.Build();
        if (r == null) return;
        Result = r;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Header_MouseDown(object sender, MouseButtonEventArgs e) => DragMove();

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "程序 (*.exe)|*.exe|所有文件|*.*" };
        if (dlg.ShowDialog(this) == true) _vm.Program = dlg.FileName;
    }
}
