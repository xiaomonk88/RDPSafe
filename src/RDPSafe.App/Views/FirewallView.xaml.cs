using System.Windows.Controls;
using System.Windows.Input;
using RDPSafe.App.ViewModels;
using RDPSafe.Core.Firewall;

namespace RDPSafe.App.Views;

public partial class FirewallView : UserControl
{
    public FirewallView() => InitializeComponent();

    private void Grid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Grid.SelectedItem is FwRule rule && DataContext is FirewallViewModel vm)
            vm.EditRuleCommand.Execute(rule);
    }
}
