using Microsoft.UI.Xaml;

namespace TracertIP.Desktop;

public partial class App : Application
{
    private Window? window;

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var address = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault();
        window = new MainWindow(address);
        window.Activate();
    }
}
