using System.Configuration;
using System.Data;
using System.Windows;

namespace Aetheris.App;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (s, ex) => 
        {
            MessageBox.Show($"Unhandled Domain Exception: {ex.ExceptionObject}", "Aetheris Fatal Error", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        DispatcherUnhandledException += (s, ex) => 
        {
            MessageBox.Show($"Unhandled Dispatcher Exception: {ex.Exception.Message}\n\n{ex.Exception.StackTrace}", "Aetheris UI Error", MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;
        };

        base.OnStartup(e);
    }
}

