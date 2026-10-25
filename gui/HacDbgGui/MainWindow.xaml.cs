using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
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

    public MainWindow()
    {
        InitializeComponent();

        SolidColorBrush errorBrush = TryFindResource("ErrorBrush") as SolidColorBrush ??
                                     new SolidColorBrush(Color.FromRgb(0xFF, 0x7B, 0x72));
        SolidColorBrush warningBrush = TryFindResource("WarningBrush") as SolidColorBrush ??
                                       new SolidColorBrush(Color.FromRgb(0xE3, 0xB3, 0x41));
        CommandOutput.TextArea.TextView.LineTransformers.Add(
            new CommandOutputColorizer(errorBrush, warningBrush));

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
        InitializeStructuredViews();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        if (_timer is not null)
        {
            return;
        }

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _timer.Tick += Timer_Tick;
        _timer.Start();

        if (App.StartWithoutCore)
        {
            StatusText.Text = "UI only";
            Focus();
            return;
        }

        await StartCoreAsync();
    }

    private async Task StartCoreAsync()
    {
        _startInProgress = true;
        StatusText.Text = "正在连接...";

        try
        {
            if (HacDbgCore.ValidateAbi() == false)
            {
                AppendError("core API or structure layout mismatch");
                return;
            }

            HacDbgCore core = new(OnCoreOutput);
            _core = core;

            uint status = await Task.Run(core.Start);

            if (status != 0)
            {
                AppendError($"core start failed (status {status})");
                StatusText.Text = "未连接";
                return;
            }

            _started = true;
            StatusText.Text = "已连接";
            CommandInput.IsEnabled = true;
            CommandInput.Focus();
            RequestModules();
            RequestProcesses();
        }
        catch (DllNotFoundException)
        {
            AppendError("HacDbgCore.dll is missing from the application directory");
            StatusText.Text = "未连接";
        }
        catch (BadImageFormatException)
        {
            AppendError("HacDbgCore.dll has the wrong architecture or is not a valid DLL");
            StatusText.Text = "未连接";
        }
        catch (Exception error)
        {
            AppendError(error.Message);
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
        if (e.Key != Key.Up && e.Key != Key.Down)
        {
            return;
        }

        if (_history.Count == 0)
        {
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Up)
        {
            if (_historyIndex > 0)
            {
                _historyIndex--;
            }

            CommandInput.Text = _history[_historyIndex];
        }
        else
        {
            if (_historyIndex < _history.Count)
            {
                _historyIndex++;
            }

            CommandInput.Text = _historyIndex == _history.Count ? string.Empty : _history[_historyIndex];
        }

        CommandInput.CaretIndex = CommandInput.Text.Length;
        e.Handled = true;
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

        switch (key)
        {
            case Key.F5:
                e.Handled = true;
                ExecuteCommand("g");
                break;

            case Key.F10:
                e.Handled = true;
                ExecuteCommand("p");
                break;

            case Key.F11:
                e.Handled = true;
                ExecuteCommand("t");
                break;
        }
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        CommandOutput.Clear();
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_startInProgress)
        {
            e.Cancel = true;
            _closePending = true;
            return;
        }

        _timer?.Stop();
        _timer = null;
        _core?.Dispose();
        _core = null;
        _started = false;
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
