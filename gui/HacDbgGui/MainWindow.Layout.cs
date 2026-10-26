using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using AvalonDock.Layout;
using AvalonDock.Serializer.Xml;

namespace HacDbgGui;

public partial class MainWindow
{
    private static readonly (string ContentId, string Title)[] DefaultDockDocuments =
    {
        ("status", "状态"),
        ("modules", "模块"),
        ("processes", "进程 / 线程"),
        ("stack", "调用栈"),
        ("memory", "内存"),
        ("disassembly", "反汇编"),
        ("trace", "实时 trace")
    };

    private static readonly JsonSerializerOptions SettingsJsonOptions = new()
    {
        WriteIndented = true
    };

    private const double DefaultDocumentPaneWidth = 640;

    private readonly Dictionary<string, object> _dockContentById = new(StringComparer.Ordinal);
    private readonly List<(DataGridColumn Column, DataGridLength Width)> _defaultColumnWidths = new();
    private bool _guiStateRestored;

    private static string SettingsDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HacDbg");

    private static string DockLayoutPath => Path.Combine(SettingsDirectory, "layout.xml");

    private static string GuiSettingsPath => Path.Combine(SettingsDirectory, "gui-settings.json");

    private void InitializeDockLayout()
    {
        foreach (LayoutDocument document in EnumerateDockDocuments())
        {
            if (string.IsNullOrEmpty(document.ContentId) || document.Content is null)
            {
                continue;
            }

            _dockContentById.TryAdd(document.ContentId, document.Content);
        }

        CaptureDefaultColumnWidths();
        ApplyDockDocumentPolicy();
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
        ApplyCommandPaneWidth(settings);
        ApplyTraceSampleRate(settings.TraceSampleRate);
        FollowRipCheck.IsChecked = settings.FollowRip;
        LoadDockLayout();

        string activeDocument = settings.ActiveDocument ?? "status";

        if (ActivateDocument(activeDocument) == false)
        {
            ActivateDocument("status");
        }
    }

    private void SaveGuiState()
    {
        SaveDockLayout();
        SaveGuiSettings();
    }

    private bool ActivateDocument(string contentId)
    {
        LayoutDocument? document = FindDockDocument(contentId);

        if (document is null)
        {
            return false;
        }

        if (document.Parent is LayoutDocumentPane pane)
        {
            int index = pane.Children.IndexOf(document);

            if (index >= 0)
            {
                pane.SelectedContentIndex = index;
            }
        }

        document.IsSelected = true;
        document.IsActive = true;

        if (document.Content is not null)
        {
            DockManager.ActiveContent = document.Content;
        }

        return true;
    }

    private void CycleDocument(int direction)
    {
        List<LayoutDocument> documents = EnumerateDockDocuments().ToList();

        if (documents.Count == 0)
        {
            return;
        }

        int current = documents.FindIndex(document => document.IsActive);

        if (current < 0)
        {
            current = 0;
        }

        int next = (current + direction + documents.Count) % documents.Count;
        string? contentId = documents[next].ContentId;

        if (string.IsNullOrEmpty(contentId) == false)
        {
            ActivateDocument(contentId);
        }
    }

    private LayoutDocument? FindDockDocument(string contentId)
    {
        return EnumerateDockDocuments().FirstOrDefault(
            document => string.Equals(document.ContentId, contentId, StringComparison.Ordinal));
    }

    private IEnumerable<LayoutDocument> EnumerateDockDocuments()
    {
        LayoutRoot? layout = DockManager.Layout;

        return layout is null
            ? Array.Empty<LayoutDocument>()
            : layout.Descendents().OfType<LayoutDocument>();
    }

    private string ActiveDocumentId()
    {
        LayoutContent? active = DockManager.Layout?.Descendents()
            .OfType<LayoutContent>()
            .FirstOrDefault(document => document.IsActive);

        if (active?.ContentId is { Length: > 0 } activeId)
        {
            return activeId;
        }

        object? activeContent = DockManager.ActiveContent;

        if (activeContent is not null)
        {
            foreach ((string contentId, object content) in _dockContentById)
            {
                if (ReferenceEquals(content, activeContent))
                {
                    return contentId;
                }
            }
        }

        return "status";
    }

    private void LoadDockLayout()
    {
        if (File.Exists(DockLayoutPath) == false)
        {
            return;
        }

        try
        {
            DetachDockContents();

            HashSet<string> restored = new(StringComparer.Ordinal);
            XmlLayoutSerializer serializer = new(DockManager);
            serializer.LayoutSerializationCallback += (_, args) =>
            {
                string? contentId = args.Model.ContentId;

                if (contentId is not null &&
                    restored.Add(contentId) &&
                    _dockContentById.TryGetValue(contentId, out object? content))
                {
                    args.Content = content;
                    return;
                }

                args.Cancel = true;
            };

            using FileStream stream = File.OpenRead(DockLayoutPath);
            serializer.Deserialize(stream);
            EnsureDockDocuments();
            ApplyDockDocumentPolicy();
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("dock layout load", error);
            AppendWarning($"布局文件读取失败，已恢复默认布局：{error.Message}");
            BuildDefaultDockLayout();
        }
    }

    private void SaveDockLayout()
    {
        try
        {
            Directory.CreateDirectory(SettingsDirectory);

            string temporaryPath = DockLayoutPath + ".tmp";
            XmlLayoutSerializer serializer = new(DockManager);

            using (FileStream stream = new(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                serializer.Serialize(stream);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, DockLayoutPath, overwrite: true);
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("dock layout save", error);
        }
    }

    private void ResetDockLayout()
    {
        BuildDefaultDockLayout();
        RestoreDefaultPaneSizes();
        SaveDockLayout();
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
        RightPanelColumn.Width = new GridLength(DefaultDocumentPaneWidth);
        StatusRegisterRow.Height = new GridLength(4, GridUnitType.Star);
        StatusBreakpointRow.Height = new GridLength(2, GridUnitType.Star);
        ProcessListRow.Height = new GridLength(3, GridUnitType.Star);
        ThreadListRow.Height = new GridLength(2, GridUnitType.Star);

        foreach ((DataGridColumn column, DataGridLength width) in _defaultColumnWidths)
        {
            column.Width = width;
        }
    }

    private void BuildDefaultDockLayout()
    {
        DetachDockContents();

        LayoutRoot root = new();
        LayoutPanel panel = new()
        {
            Orientation = Orientation.Horizontal
        };
        LayoutDocumentPane pane = new();

        panel.Children.Add(pane);
        root.RootPanel = panel;

        foreach ((string contentId, string title) in DefaultDockDocuments)
        {
            if (_dockContentById.TryGetValue(contentId, out object? content) == false)
            {
                continue;
            }

            LayoutDocument document = new()
            {
                Title = title,
                ContentId = contentId,
                Content = content
            };

            pane.Children.Add(document);
        }

        DockManager.Layout = root;
        ApplyDockDocumentPolicy();
        ActivateDocument("status");
    }

    private void EnsureDockDocuments()
    {
        LayoutDocumentPane? firstPane = DockManager.Layout?.Descendents()
            .OfType<LayoutDocumentPane>()
            .FirstOrDefault();

        if (firstPane is null)
        {
            throw new InvalidDataException("layout has no document pane");
        }

        HashSet<string> existing = EnumerateDockDocuments()
            .Select(document => document.ContentId)
            .Where(contentId => string.IsNullOrEmpty(contentId) == false)
            .Cast<string>()
            .ToHashSet(StringComparer.Ordinal);

        foreach ((string contentId, string title) in DefaultDockDocuments)
        {
            if (existing.Contains(contentId) || _dockContentById.TryGetValue(contentId, out object? content) == false)
            {
                continue;
            }

            firstPane.Children.Add(new LayoutDocument
            {
                Title = title,
                ContentId = contentId,
                Content = content
            });
        }

        foreach (LayoutDocument document in EnumerateDockDocuments())
        {
            string? contentId = document.ContentId;

            if (contentId is not null)
            {
                document.Title = TitleForDocument(contentId) ?? document.Title;
            }
        }
    }

    private void DetachDockContents()
    {
        LayoutRoot? layout = DockManager.Layout;

        if (layout is null)
        {
            return;
        }

        foreach (LayoutDocument document in layout.Descendents().OfType<LayoutDocument>())
        {
            document.Content = null;
        }
    }

    private void ApplyDockDocumentPolicy()
    {
        // A floating HwndHost would render above WPF popups, so trace stays docked only.
        DockManager.AllowFloatingWindows = false;
        DockManager.ShowNavigator = false;
        DockManager.DockAllFloatingWindows();

        foreach (LayoutDocument document in EnumerateDockDocuments())
        {
            document.CanClose = false;
            document.CanFloat = false;
            document.CanMove = true;
        }
    }

    private static string? TitleForDocument(string contentId)
    {
        foreach ((string id, string title) in DefaultDockDocuments)
        {
            if (string.Equals(id, contentId, StringComparison.Ordinal))
            {
                return title;
            }
        }

        return null;
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
                DockPanelWidth = RightPanelColumn.Width.IsAbsolute ? RightPanelColumn.Width.Value : 640,
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

    private void ApplyCommandPaneWidth(GuiSettings settings)
    {
        if (settings.DockPanelWidth is double width && double.IsFinite(width))
        {
            RightPanelColumn.Width = new GridLength(
                Math.Clamp(width, 360, 2000),
                GridUnitType.Pixel);
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
        public double? DockPanelWidth { get; set; } = DefaultDocumentPaneWidth;
        public string ActiveDocument { get; set; } = "status";
        public uint TraceSampleRate { get; set; } = 64;
        public bool FollowRip { get; set; }
        public string Theme { get; set; } = GuiTheme.DarkName;
    }
}
