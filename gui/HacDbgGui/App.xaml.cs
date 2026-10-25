using System.Runtime.InteropServices;
using System.Windows;
using HacDbgGui.Interop;
using Wpf.Ui.Appearance;

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
                bool valid = HacDbgCore.ApiVersion == 1 &&
                             HacDbgCore.StateSize == (uint)Marshal.SizeOf<HacDbgCoreState>();
                Environment.Exit(valid ? 0 : 1);
            }
            catch
            {
                Environment.Exit(2);
            }

            return;
        }

        ApplicationThemeManager.Apply(ApplicationTheme.Dark);
        base.OnStartup(e);
    }
}
