using System.Windows;
using System.Windows.Threading;
using HacDbgGui.Interop;

namespace HacDbgGui;

public partial class App : Application
{
    public static bool StartWithoutCore { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        StartWithoutCore = e.Args.Any(argument =>
            string.Equals(argument, "--no-connect", StringComparison.OrdinalIgnoreCase));

        if (e.Args.Any(argument => string.Equals(argument, "--abi-check", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                Environment.Exit(HacDbgCore.ValidateAbi() && HacDbgTraceNative.ValidateAbi() ? 0 : 1);
            }
            catch
            {
                Environment.Exit(2);
            }

            return;
        }

        GuiDiagnostics.Initialize();
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += AppDomain_UnhandledException;
        TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
        GuiTheme.Apply(GuiTheme.ReadSavedIsLight());
        base.OnStartup(e);
    }

    private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        GuiDiagnostics.WriteException("dispatcher", e.Exception);

        if (MainWindow is HacDbgGui.MainWindow mainWindow)
        {
            try
            {
                mainWindow.ReportUnhandledException(e.Exception);
            }
            catch (Exception reportError)
            {
                GuiDiagnostics.WriteException("dispatcher report", reportError);
            }

            e.Handled = true;
        }
    }

    private static void AppDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception error)
        {
            GuiDiagnostics.WriteException("appdomain", error);
        }
        else
        {
            GuiDiagnostics.Write("appdomain", "unhandled non-exception failure");
        }
    }

    private static void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        GuiDiagnostics.WriteException("unobserved task", e.Exception);
        e.SetObserved();
    }
}
