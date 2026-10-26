using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace HacDbgGui;

public partial class MainWindow
{
    //
    // Ctrl+1 through Ctrl+4 and the trace renderer document actions use this
    // order. The command tab is a peer in the tab strip, but it is not one of
    // these slots. Registers, breakpoints, memory and the call stack are panes
    // inside the disassembly tab.
    //
    private static readonly (string ContentId, string Title)[] DefaultDockDocuments =
    {
        ("disassembly", "反汇编"),
        ("modules", "模块"),
        ("processes", "进程 / 线程"),
        ("trace", "实时 trace")
    };

    private static readonly JsonSerializerOptions SettingsJsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly List<(DataGridColumn Column, DataGridLength Width)> _defaultColumnWidths = new();
    private bool _guiStateRestored;

    private static string SettingsDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HacDbg");

    private static string GuiSettingsPath => Path.Combine(SettingsDirectory, "gui-settings.json");

    private void InitializeViewLayout()
    {
        CaptureDefaultColumnWidths();
        ViewTabs.SelectionChanged += ViewTabs_SelectionChanged;
    }

    private void RestoreGuiState()
    {
        if (_guiStateRestored)
        {
            return;
        }

        _guiStateRestored = true;
        GuiSettings settings = LoadGuiSettings();

        GuiTheme.Apply(GuiTheme.IsLightName(settings.Theme));
        ApplyWindowSettings(settings);
        ApplyTraceSampleRate(settings.TraceSampleRate);
        FollowRipCheck.IsChecked = settings.FollowRip;

        string activeDocument = NormalizeDocumentId(settings.ActiveDocument);

        if (ActivateDocument(activeDocument) == false)
        {
            ActivateDocument("disassembly");
        }
    }

    private void SaveGuiState()
    {
        SaveGuiSettings();
    }

    private bool ActivateDocument(string contentId)
    {
        foreach (object item in ViewTabs.Items)
        {
            if (item is TabItem tab &&
                tab.Tag is string tag &&
                string.Equals(tag, contentId, StringComparison.Ordinal))
            {
                ViewTabs.SelectedItem = tab;
                return true;
            }
        }

        return false;
    }

    private void CycleDocument(int direction)
    {
        int count = ViewTabs.Items.Count;

        if (count == 0)
        {
            return;
        }

        int current = ViewTabs.SelectedIndex;

        if (current < 0)
        {
            current = 0;
        }

        ViewTabs.SelectedIndex = (current + direction + count) % count;
    }

    private string ActiveDocumentId()
    {
        if (ViewTabs.SelectedItem is TabItem tab &&
            tab.Tag is string tag &&
            string.IsNullOrEmpty(tag) == false)
        {
            return tag;
        }

        return "disassembly";
    }

    private static string NormalizeDocumentId(string? contentId)
    {
        //
        // Older settings named the panes that now live inside disassembly.
        //
        if (contentId is null or "" or "status" or "stack" or "memory")
        {
            return "disassembly";
        }

        return contentId;
    }

    private static bool TryDocumentShortcut(Key key, out int index)
    {
        if (key >= Key.D1 && key <= Key.D9)
        {
            index = (int)key - (int)Key.D1;
        }
        else if (key >= Key.NumPad1 && key <= Key.NumPad9)
        {
            index = (int)key - (int)Key.NumPad1;
        }
        else
        {
            index = -1;
            return false;
        }

        return index < DefaultDockDocuments.Length;
    }

    private void ViewTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ReferenceEquals(e.Source, ViewTabs) == false)
        {
            return;
        }

        if (ActiveDocumentId() != "command")
        {
            CloseCompletion();
            return;
        }

        if (_outputNearEnd == false || CommandSearchBar.Visibility == Visibility.Visible)
        {
            return;
        }

        Dispatcher.BeginInvoke(new Action(ScrollCommandOutputToEnd), DispatcherPriority.Loaded);
    }

    private void ScrollCommandOutputToEnd()
    {
        if (ActiveDocumentId() == "command" && _outputNearEnd && CommandOutput.IsVisible)
        {
            CommandOutput.ScrollToEnd();
        }
    }

    private void ResetViewLayout()
    {
        ActivateDocument("disassembly");
        RestoreDefaultPaneSizes();
        SaveGuiSettings();
        AppendInfo("layout reset to defaults");
    }

    private void CaptureDefaultColumnWidths()
    {
        if (_defaultColumnWidths.Count != 0)
        {
            return;
        }

        DataGrid[] grids =
        {
            RegisterGrid, BreakpointGrid, ModuleGrid, ProcessGrid,
            ThreadGrid, StackGrid, MemoryGrid, DisassemblyGrid
        };

        foreach (DataGrid grid in grids)
        {
            foreach (DataGridColumn column in grid.Columns)
            {
                _defaultColumnWidths.Add((column, column.Width));
            }
        }
    }

    private void RestoreDefaultPaneSizes()
    {
        CpuTopRow.Height = new GridLength(3, GridUnitType.Star);
        CpuBottomRow.Height = new GridLength(2, GridUnitType.Star);
        CpuDisasmColumn.Width = new GridLength(5, GridUnitType.Star);
        CpuRegisterColumn.Width = new GridLength(2, GridUnitType.Star);
        CpuMemoryColumn.Width = new GridLength(3, GridUnitType.Star);
        CpuStackColumn.Width = new GridLength(2, GridUnitType.Star);
        StatusRegisterRow.Height = new GridLength(4, GridUnitType.Star);
        StatusBreakpointRow.Height = new GridLength(2, GridUnitType.Star);
        ProcessListRow.Height = new GridLength(3, GridUnitType.Star);
        ThreadListRow.Height = new GridLength(2, GridUnitType.Star);

        foreach ((DataGridColumn column, DataGridLength width) in _defaultColumnWidths)
        {
            column.Width = width;
        }
    }

    private GuiSettings LoadGuiSettings()
    {
        if (File.Exists(GuiSettingsPath) == false)
        {
            return new GuiSettings();
        }

        try
        {
            using FileStream stream = File.OpenRead(GuiSettingsPath);
            GuiSettings settings =
                JsonSerializer.Deserialize<GuiSettings>(stream, SettingsJsonOptions) ?? new GuiSettings();

            if (settings.SchemaVersion != 1)
            {
                AppendWarning($"GUI 设置版本 {settings.SchemaVersion} 不受支持，已使用默认值。");
                GuiDiagnostics.Write("GUI settings load", $"unsupported schema {settings.SchemaVersion}");
                return new GuiSettings();
            }

            return settings;
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("GUI settings load", error);
            AppendWarning($"GUI 设置读取失败，已使用默认值：{error.Message}");
            return new GuiSettings();
        }
    }

    private void SaveGuiSettings()
    {
        try
        {
            Directory.CreateDirectory(SettingsDirectory);

            Rect bounds = WindowState == WindowState.Normal
                ? new Rect(Left, Top, Width, Height)
                : RestoreBounds;
            GuiSettings settings = new()
            {
                SchemaVersion = 1,
                Left = double.IsFinite(bounds.Left) ? bounds.Left : null,
                Top = double.IsFinite(bounds.Top) ? bounds.Top : null,
                Width = double.IsFinite(bounds.Width) ? bounds.Width : null,
                Height = double.IsFinite(bounds.Height) ? bounds.Height : null,
                WindowState = WindowState.ToString(),
                ActiveDocument = ActiveDocumentId(),
                TraceSampleRate = SelectedTraceSampleRate(),
                FollowRip = FollowRipCheck.IsChecked == true,
                Theme = GuiTheme.CurrentName
            };

            string temporaryPath = GuiSettingsPath + ".tmp";

            using (FileStream stream = new(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, settings, SettingsJsonOptions);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, GuiSettingsPath, overwrite: true);
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("GUI settings save", error);
        }
    }

    private void ApplyWindowSettings(GuiSettings settings)
    {
        if (settings.Width is double width && double.IsFinite(width) && width >= MinWidth)
        {
            Width = width;
        }

        if (settings.Height is double height && double.IsFinite(height) && height >= MinHeight)
        {
            Height = height;
        }

        Rect virtualScreen = new(
            SystemParameters.VirtualScreenLeft,
            SystemParameters.VirtualScreenTop,
            SystemParameters.VirtualScreenWidth,
            SystemParameters.VirtualScreenHeight);

        if (settings.Left is double left &&
            settings.Top is double top &&
            double.IsFinite(left) &&
            double.IsFinite(top))
        {
            Rect requested = new(left, top, Width, Height);
            Rect visible = Rect.Intersect(requested, virtualScreen);

            if (visible.Width >= 200 && visible.Height >= 120)
            {
                WindowStartupLocation = WindowStartupLocation.Manual;
                Left = left;
                Top = top;
            }
        }

        if (Enum.TryParse(settings.WindowState, ignoreCase: true, out WindowState windowState) &&
            windowState is WindowState.Normal or WindowState.Maximized)
        {
            WindowState = windowState;
        }
    }

    private void ApplyTraceSampleRate(uint sampleRate)
    {
        foreach (object item in TraceSampleBox.Items)
        {
            if (item is ComboBoxItem comboItem &&
                comboItem.Tag is string text &&
                uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint candidate) &&
                candidate == sampleRate)
            {
                TraceSampleBox.SelectedItem = comboItem;
                return;
            }
        }
    }

    private sealed class GuiSettings
    {
        public int SchemaVersion { get; set; } = 1;
        public double? Left { get; set; }
        public double? Top { get; set; }
        public double? Width { get; set; } = 1600;
        public double? Height { get; set; } = 900;
        public string WindowState { get; set; } = "Normal";
        public string ActiveDocument { get; set; } = "disassembly";
        public uint TraceSampleRate { get; set; } = 64;
        public bool FollowRip { get; set; }
        public string Theme { get; set; } = GuiTheme.DarkName;
    }
}
