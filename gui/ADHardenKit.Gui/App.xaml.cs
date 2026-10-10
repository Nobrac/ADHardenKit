using System.Windows;
using System.Windows.Threading;

namespace ADHardenKit.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandled;
        base.OnStartup(e);
    }

    static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // A front end that vanishes mid-deployment is worse than one that says what went wrong:
        // the engine runs in its own process and keeps its own log either way.
        MessageBox.Show(e.Exception.Message, "ADHardenKit", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
