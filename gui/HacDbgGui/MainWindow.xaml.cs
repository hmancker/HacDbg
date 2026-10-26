using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using HacDbgGui.Interop;
using Wpf.Ui.Controls;

namespace HacDbgGui;

public partial class MainWindow : FluentWindow
{
    private static readonly string[] RegisterNames =
    {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "rflags", "cr3"
    };

    private static readonly (string Name, int Bit)[] Flags =
    {
        ("ZF", 6), ("PF", 2), ("AF", 4),
        ("OF", 11), ("SF", 7), ("DF", 10),
        ("CF", 0), ("TF", 8), ("IF", 9)
    };

    private readonly ConcurrentQueue<OutputRecord> _pendingOutput = new();
    private readonly ObservableCollection<RegisterRow> _registers = new();
    private readonly ObservableCollection<FlagRow> _flags = new();
    private readonly ObservableCollection<BreakpointRow> _breakpoints = new();
    private readonly List<string> _history = new();
    private readonly Brush _errorBrush;
    private readonly Brush _warningBrush;
    private readonly Brush _mutedBrush;

    private HacDbgCore? _core;
    private DispatcherTimer? _timer;
    private bool _started;
    private bool _startInProgress;
    private bool _closePending;
    private int _historyIndex;
    private string _breakpointSignature = string.Empty;
    private readonly ulong[] _lastRegisterValues = new ulong[RegisterNames.Length];
    private readonly bool[] _lastRegisterKnown = new bool[RegisterNames.Length];
    private bool _lastRegistersPaused;
    private bool _lastRegisterSnapshotKnown;
    private bool _versionWarningReported;

    public MainWindow()
    {
        InitializeComponent();

        _errorBrush = TryFindResource("ErrorBrush") as SolidColorBrush ??
                      new SolidColorBrush(Color.FromRgb(0xFF, 0x7B, 0x72));
        _warningBrush = TryFindResource("WarningBrush") as SolidColorBrush ??
                        new SolidColorBrush(Color.FromRgb(0xE3, 0xB3, 0x41));
        _mutedBrush = TryFindResource("MutedBrush") as SolidColorBrush ??
                      new SolidColorBrush(Color.FromRgb(0x8B, 0x98, 0xA5));
        CommandOutput.TextArea.TextView.LineTransformers.Add(
            new CommandOutputColorizer(_errorBrush, _warningBrush));

        foreach (string name in RegisterNames)
        {
            _registers.Add(new RegisterRow(name));
        }

        foreach ((string name, int _) in Flags)
        {
            _flags.Add(new FlagRow(name));
        }

        RegisterGrid.ItemsSource = _registers;
        FlagsGrid.ItemsSource = _flags;
        BreakpointGrid.ItemsSource = _breakpoints;
        InitializeDockLayout();
        InitializeStructuredViews();
        InitializeTrace();
        InitializeCommandChrome();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        if (_timer is not null)
        {
            return;
        }

        RestoreGuiState();

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _timer.Tick += Timer_Tick;
        _timer.Start();
        StartTracePolling();

        if (App.StartWithoutCore)
        {
            StatusText.Text = "UI only";
            GuiDiagnostics.Write("startup", "started with --no-connect");
            Focus();
            return;
        }

        GuiDiagnostics.Write("startup", "connecting to HacDbgCore");
        await StartCoreAsync();
    }

    private async Task StartCoreAsync()
    {
        _startInProgress = true;
        StatusText.Text = "正在连接...";

        try
        {
            if (IsAdministrator() == false)
            {
                AppendError("GUI 未以管理员身份运行，无法连接驱动。请从 UAC 提示中允许提权后重试。");
                GuiDiagnostics.Write("core start", "process is not elevated");
                StatusText.Text = "未连接";
                return;
            }

            if (HacDbgCore.ValidateAbi() == false)
            {
                AppendError("HacDbgCore.dll 的核心 ABI 或结构布局与 GUI 不匹配，请使用同一版本重新构建。");
                GuiDiagnostics.Write("core start", "core ABI mismatch");
                StatusText.Text = "未连接";
                return;
            }

            try
            {
                if (HacDbgTraceNative.ValidateAbi() == false)
                {
                    _traceDeviceError = true;
                    SetTraceError("HacDbgTrace.dll ABI 不匹配，实时 trace 已禁用。");
                    GuiDiagnostics.Write("trace start", "trace ABI mismatch");
                }
            }
            catch (Exception error)
            {
                _traceDeviceError = true;
                SetTraceError($"HacDbgTrace.dll 无法加载: {error.Message}");
                GuiDiagnostics.WriteException("trace start", error);
            }

            HacDbgCore core = new(OnCoreOutput);
            _core = core;

            uint status = await Task.Run(core.Start);

            if (status != 0)
            {
                AppendError(DescribeCoreStartFailure(status));
                GuiDiagnostics.Write("core start", $"status {status}");
                StatusText.Text = "未连接";
                return;
            }

            _started = true;
            StatusText.Text = "已连接";
            CommandInput.IsEnabled = true;
            CommandInput.Focus();
            RequestModules();
            RequestProcesses();
            GuiDiagnostics.Write("core start", "connected");
        }
        catch (DllNotFoundException)
        {
            AppendError("缺少 HacDbgCore.dll；请把完整的发布目录一起复制。");
            GuiDiagnostics.Write("core start", "HacDbgCore.dll not found");
            StatusText.Text = "未连接";
        }
        catch (BadImageFormatException)
        {
            AppendError("HacDbgCore.dll 的体系结构不匹配或文件无效；GUI 必须是 x64。");
            GuiDiagnostics.Write("core start", "HacDbgCore.dll has an invalid image format");
            StatusText.Text = "未连接";
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("core start exception", error);
            AppendError($"连接失败：{error.Message}");
            StatusText.Text = "未连接";
        }
        finally
        {
            _startInProgress = false;

            if (_closePending)
            {
                Close();
            }
        }
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        DrainOutput();
        PollCompletions();

        if (_started == false || _core is null)
        {
            return;
        }

        if (_core.GetState(out HacDbgCoreState state) == 0)
        {
            UpdateState(state);
            PollStructuredViews();
        }
    }

    private void OnCoreOutput(uint kind, string text)
    {
        _pendingOutput.Enqueue(new OutputRecord(kind, text));
    }

    private void DrainOutput()
    {
        StringBuilder builder = new();
        bool closeRequested = false;
        int processed = 0;

        while (processed < 500 && _pendingOutput.TryDequeue(out OutputRecord record))
        {
            processed++;

            switch (record.Kind)
            {
                case 0:
                    builder.Append(record.Text);
                    break;

                case 1:
                    AppendLine(builder, record.Text);
                    break;

                case 2:
                    builder.Append("warn, ");
                    AppendLine(builder, record.Text);
                    break;

                case 3:
                    if (record.Text.StartsWith("err,", StringComparison.OrdinalIgnoreCase) == false)
                    {
                        builder.Append("err, ");
                    }

                    AppendLine(builder, record.Text);
                    break;

                case 4:
                    builder.Append(record.Text);
                    break;

                case 5:
                    builder.Clear();
                    CommandOutput.Clear();
                    break;

                case 6:
                    closeRequested = true;
                    break;
            }
        }

        if (builder.Length != 0)
        {
            CommandOutput.AppendText(builder.ToString());
            CommandOutput.ScrollToEnd();
            TrimLog();
        }

        if (closeRequested)
        {
            Close();
        }
    }

    private static void AppendLine(StringBuilder builder, string text)
    {
        builder.Append(text);

        if (text.EndsWith('\n') == false)
        {
            builder.Append('\n');
        }
    }

    private void TrimLog()
    {
        const int maximumLines = 20000;

        if (CommandOutput.Document.LineCount <= maximumLines)
        {
            return;
        }

        int removeThrough = CommandOutput.Document.GetLineByNumber(
            CommandOutput.Document.LineCount - maximumLines).Offset;
        CommandOutput.Document.Remove(0, removeThrough);
    }

    private void UpdateState(HacDbgCoreState state)
    {
        bool running = state.Running != 0;
        bool paused = state.Paused != 0;

        StatusText.Text = state.Initialized == 0 ? "未连接" : (running ? "已连接" : "已停止");
        PausedText.Text = state.Initialized == 0 ? "—" : (paused ? "已暂停" : "运行中");

        string userVersion = DecodeVersion(state.UserVersion);
        string driverVersion = DecodeVersion(state.DriverVersion);
        VersionText.Text = driverVersion.Length == 0
            ? $"usermode {userVersion} / hypervisor —"
            : $"usermode {userVersion} / hypervisor {driverVersion}";
        UpdateVersionWarning(state, userVersion, driverVersion);

        Cr3Text.Text = paused ? $"CR3 {state.Registers.Cr3:X16}" : "CR3 —";

        UpdateRegisters(state, paused);
        UpdateBreakpoints(state);
        UpdateStructuredState(state, paused);

        CommandInput.IsEnabled = running;
        ContinueButton.IsEnabled = running;
        StepIntoButton.IsEnabled = running;
        StepOverButton.IsEnabled = running;
        CancelButton.IsEnabled = running;
    }

    private void UpdateVersionWarning(HacDbgCoreState state, string userVersion, string driverVersion)
    {
        bool versionMismatch = userVersion.Length != 0 &&
                               driverVersion.Length != 0 &&
                               string.Equals(userVersion, driverVersion, StringComparison.Ordinal) == false;
        bool hypercallMismatch = state.Initialized != 0 &&
                                 state.HypercallAbiVersion != HacDbgCore.ExpectedHypercallAbiVersion;

        if (versionMismatch || hypercallMismatch)
        {
            VersionText.Foreground = _warningBrush;

            if (_versionWarningReported == false)
            {
                _versionWarningReported = true;

                if (versionMismatch)
                {
                    AppendWarning(
                        $"usermode {userVersion} 与 hypervisor {driverVersion} 版本不一致，" +
                        "部分功能可能不可用；请使用同一次构建的程序和驱动。");
                    GuiDiagnostics.Write("version", $"usermode {userVersion}, hypervisor {driverVersion}");
                }

                if (hypercallMismatch)
                {
                    AppendWarning(
                        $"hypercall ABI {state.HypercallAbiVersion} 与 GUI 期望的 " +
                        $"{HacDbgCore.ExpectedHypercallAbiVersion} 不一致。");
                    GuiDiagnostics.Write("version", $"hypercall ABI {state.HypercallAbiVersion}");
                }
            }

            return;
        }

        VersionText.Foreground = _mutedBrush;
    }

    private void UpdateRegisters(HacDbgCoreState state, bool paused)
    {
        ulong[] values =
        {
            state.Registers.Rax, state.Registers.Rcx, state.Registers.Rdx, state.Registers.Rbx,
            state.Registers.Rsp, state.Registers.Rbp, state.Registers.Rsi, state.Registers.Rdi,
            state.Registers.R8, state.Registers.R9, state.Registers.R10, state.Registers.R11,
            state.Registers.R12, state.Registers.R13, state.Registers.R14, state.Registers.R15,
            state.Registers.Rip, state.Registers.Rflags, state.Registers.Cr3
        };

        bool rflagsKnown = paused && state.Registers.RflagsKnown != 0;
        bool[] known = new bool[values.Length];

        for (int index = 0; index < known.Length; index++)
        {
            known[index] = index == 17 ? rflagsKnown : paused;
        }

        bool snapshotChanged = false;

        if (paused == true)
        {
            if (_lastRegisterSnapshotKnown == false)
            {
                snapshotChanged = true;
            }
            else
            {
                for (int index = 0; index < values.Length; index++)
                {
                    if (known[index] != _lastRegisterKnown[index] ||
                        (known[index] == true && values[index] != _lastRegisterValues[index]))
                    {
                        snapshotChanged = true;
                        break;
                    }
                }
            }
        }

        bool markChanges = paused && _lastRegistersPaused && _lastRegisterSnapshotKnown && snapshotChanged;

        for (int index = 0; index < _registers.Count; index++)
        {
            _registers[index].Value = known[index] == true ? $"0x{values[index]:X16}" : "—";

            if (paused == false)
            {
                _registers[index].Changed = false;
            }
            else if (snapshotChanged == true)
            {
                _registers[index].Changed = markChanges && known[index] && _lastRegisterKnown[index] &&
                                           values[index] != _lastRegisterValues[index];
            }
        }

        ulong previousRflags = _lastRegisterValues[17];
        bool previousRflagsKnown = _lastRegisterKnown[17];

        for (int index = 0; index < Flags.Length; index++)
        {
            FlagRow flag = _flags[index];
            int bit = Flags[index].Bit;

            if (paused == false)
            {
                flag.Value = "—";
                flag.Changed = false;
                continue;
            }

            if (rflagsKnown == false)
            {
                flag.Value = "—";

                if (snapshotChanged == true)
                {
                    flag.Changed = false;
                }

                continue;
            }

            ulong value = (state.Registers.Rflags >> bit) & 1;
            flag.Value = value.ToString(CultureInfo.InvariantCulture);

            if (snapshotChanged == true)
            {
                flag.Changed = markChanges && previousRflagsKnown &&
                               ((previousRflags >> bit) & 1) != value;
            }
        }

        if (paused == true)
        {
            Array.Copy(values, _lastRegisterValues, values.Length);
            Array.Copy(known, _lastRegisterKnown, known.Length);
            _lastRegisterSnapshotKnown = true;
        }
        else
        {
            Array.Clear(_lastRegisterValues);
            Array.Clear(_lastRegisterKnown);
            _lastRegisterSnapshotKnown = false;
        }

        _lastRegistersPaused = paused;
    }

    private void ClearRegisterChangeMarks()
    {
        for (int index = 0; index < _registers.Count; index++)
        {
            _registers[index].Changed = false;
        }

        for (int index = 0; index < _flags.Count; index++)
        {
            _flags[index].Changed = false;
        }
    }

    private void UpdateBreakpoints(HacDbgCoreState state)
    {
        StringBuilder signature = new();

        for (int index = 0; index < state.BreakpointCount && index < state.Breakpoints.Length; index++)
        {
            HacDbgCoreBreakpoint breakpoint = state.Breakpoints[index];
            signature.Append(breakpoint.Id).Append(':')
                .Append(breakpoint.Address).Append(':')
                .Append(breakpoint.Cr3).Append(':')
                .Append(breakpoint.Enabled).Append(':')
                .Append(breakpoint.PausesThread).Append('|');
        }

        string nextSignature = signature.ToString();

        if (nextSignature == _breakpointSignature)
        {
            return;
        }

        _breakpointSignature = nextSignature;
        _breakpoints.Clear();

        for (int index = 0; index < state.BreakpointCount && index < state.Breakpoints.Length; index++)
        {
            HacDbgCoreBreakpoint breakpoint = state.Breakpoints[index];
            _breakpoints.Add(new BreakpointRow(
                breakpoint.Id.ToString(),
                $"0x{breakpoint.Address:X16}",
                breakpoint.Enabled != 0 ? "e" : "d",
                breakpoint.PausesThread != 0 ? "pause" : ""));
        }
    }

    private static string DecodeVersion(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
        {
            return string.Empty;
        }

        int length = Array.IndexOf(bytes, (byte)0);

        if (length < 0)
        {
            length = bytes.Length;
        }

        return Encoding.ASCII.GetString(bytes, 0, length);
    }

    private void ExecuteCommand(string commandText)
    {
        if (_core is null || _started == false)
        {
            AppendError("debugger is not connected");
            return;
        }

        string command = commandText.Trim();

        if (command.Length == 0)
        {
            return;
        }

        CommandOutput.AppendText($"kd> {command}\n");
        CommandOutput.ScrollToEnd();

        _history.Add(command);
        _historyIndex = _history.Count;

        uint status = _core.Execute(command);

        if (status != 0)
        {
            AppendError($"execute failed (status {status})");
            return;
        }

        ClearRegisterChangeMarks();
    }

    private void AppendError(string message)
    {
        CommandOutput.AppendText($"err, {message}\n");
        CommandOutput.ScrollToEnd();
    }

    private void AppendWarning(string message)
    {
        CommandOutput.AppendText($"warn, {message}\n");
        CommandOutput.ScrollToEnd();
    }

    private void AppendInfo(string message)
    {
        CommandOutput.AppendText($"{message}\n");
        CommandOutput.ScrollToEnd();
    }

    internal void ReportUnhandledException(Exception error)
    {
        AppendError($"界面发生未处理异常：{error.Message}。详细日志：{GuiDiagnostics.LogPath}");
    }

    private void CommandInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        e.Handled = true;
        string command = CommandInput.Text;
        CommandInput.Clear();
        ExecuteCommand(command);
    }

    private void CommandInput_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        HandleCommandInputKey(e);
    }

    private void ContinueButton_Click(object sender, RoutedEventArgs e)
    {
        ExecuteCommand("g");
    }

    private void StepIntoButton_Click(object sender, RoutedEventArgs e)
    {
        ExecuteCommand("t");
    }

    private void StepOverButton_Click(object sender, RoutedEventArgs e)
    {
        ExecuteCommand("p");
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _core?.Cancel();
    }

    private void MainWindow_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        Key key = e.Key == Key.System ? e.SystemKey : e.Key;
        ModifierKeys modifiers = Keyboard.Modifiers;
        bool control = (modifiers & ModifierKeys.Control) != 0;
        bool shift = (modifiers & ModifierKeys.Shift) != 0;

        if (HandleSearchShortcut(key, control, shift))
        {
            e.Handled = true;
            return;
        }

        if (control && key == Key.L)
        {
            e.Handled = true;
            CloseCompletion();
            CommandOutput.Clear();
            return;
        }

        if (control && key == Key.Tab)
        {
            e.Handled = true;
            CloseCompletion();
            CycleDocument(shift ? -1 : 1);
            return;
        }

        if (control && key >= Key.D1 && key <= Key.D7)
        {
            int index = (int)key - (int)Key.D1;

            if (index >= 0 && index < DefaultDockDocuments.Length)
            {
                e.Handled = true;
                CloseCompletion();
                ActivateDocument(DefaultDockDocuments[index].ContentId);
            }

            return;
        }

        if (control && key >= Key.NumPad1 && key <= Key.NumPad7)
        {
            int index = (int)key - (int)Key.NumPad1;

            if (index >= 0 && index < DefaultDockDocuments.Length)
            {
                e.Handled = true;
                CloseCompletion();
                ActivateDocument(DefaultDockDocuments[index].ContentId);
            }

            return;
        }

        if (key == Key.Escape && CommandInput.IsKeyboardFocusWithin == false)
        {
            e.Handled = true;
            FocusCommandInput();
            return;
        }

        switch (key)
        {
            case Key.F5:
                e.Handled = true;
                CloseCompletion();
                ExecuteCommand("g");
                break;

            case Key.F10:
                e.Handled = true;
                CloseCompletion();
                ExecuteCommand("p");
                break;

            case Key.F11:
                e.Handled = true;
                CloseCompletion();
                ExecuteCommand("t");
                break;
        }
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        CommandOutput.Clear();
    }

    private void ResetLayoutButton_Click(object sender, RoutedEventArgs e)
    {
        ResetDockLayout();
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_startInProgress)
        {
            e.Cancel = true;
            _closePending = true;
            return;
        }

        ReleaseCommandChrome();
        SaveGuiState();
        _timer?.Stop();
        _timer = null;
        StopTracePolling();
        TraceViewHost.Detach();
        _core?.Dispose();
        _core = null;
        _started = false;
    }

    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string DescribeCoreStartFailure(uint status)
    {
        return status switch
        {
            HacDbgCore.StatusArgument => "核心启动参数无效。请使用完整发布目录重新运行。",
            HacDbgCore.StatusState => "核心处于无效状态，无法启动调试会话。",
            HacDbgCore.StatusDriver =>
                "未连接到 HacDbg 驱动。请先加载与 GUI 同版本的驱动，并确认进程具有管理员权限。",
            HacDbgCore.StatusException => "核心启动时发生内部异常。请查看 GUI 日志和驱动调试输出。",
            _ => $"核心启动失败 (status {status})。"
        };
    }

    private readonly record struct OutputRecord(uint Kind, string Text);
}

internal sealed class RegisterRow : INotifyPropertyChanged
{
    private string _value = "—";
    private bool _changed;

    public RegisterRow(string name)
    {
        Name = name;
    }

    public string Name { get; }

    public string Value
    {
        get => _value;
        set
        {
            if (_value == value)
            {
                return;
            }

            _value = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Value)));
        }
    }

    public bool Changed
    {
        get => _changed;
        set
        {
            if (_changed == value)
            {
                return;
            }

            _changed = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Changed)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

internal sealed class FlagRow : INotifyPropertyChanged
{
    private string _value = "—";
    private bool _changed;

    public FlagRow(string name)
    {
        Name = name;
    }

    public string Name { get; }

    public string Value
    {
        get => _value;
        set
        {
            if (_value == value)
            {
                return;
            }

            _value = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Value)));
        }
    }

    public bool Changed
    {
        get => _changed;
        set
        {
            if (_changed == value)
            {
                return;
            }

            _changed = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Changed)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

internal sealed class BreakpointRow
{
    public BreakpointRow(string id, string address, string enabled, string pause)
    {
        Id = id;
        Address = address;
        Enabled = enabled;
        Pause = pause;
    }

    public string Id { get; }
    public string Address { get; }
    public string Enabled { get; }
    public string Pause { get; }
}
