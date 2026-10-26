using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using HacDbgGui.Controls;
using HacDbgGui.Interop;
using Microsoft.Win32;

namespace HacDbgGui;

public partial class MainWindow
{
    private DispatcherTimer? _traceTimer;
    private ulong _lastTraceSequence;
    private bool _tracePollFaulted;
    private bool _traceDeviceError;
    private bool _traceSupported;
    private uint _traceAttachmentGeneration;

    private void InitializeTrace()
    {
        TraceViewHost.InitializationFailed += TraceViewHost_InitializationFailed;
        TraceViewHost.ActionRequested += TraceViewHost_ActionRequested;
        TraceStatusText.Text = "实时 trace 未连接";
    }

    private void StartTracePolling()
    {
        if (_traceTimer is not null)
        {
            return;
        }

        _traceTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(33)
        };
        _traceTimer.Tick += TraceTimer_Tick;
        _traceTimer.Start();
    }

    private void StopTracePolling()
    {
        _traceTimer?.Stop();
        _traceTimer = null;
    }

    private void TraceTimer_Tick(object? sender, EventArgs e)
    {
        if (_core is null || _started == false)
        {
            if (_traceSupported)
            {
                _traceSupported = false;
                UpdateTraceControls(null);
                TraceStatusText.Text = "实时 trace 未连接";
            }

            return;
        }

        try
        {
            if (_core.GetTraceStatus(out HacDbgCoreTraceStatus status) != 0)
            {
                return;
            }

            UpdateTraceState(status);

            if (TraceViewHost.AttachmentGeneration != _traceAttachmentGeneration)
            {
                _traceAttachmentGeneration = TraceViewHost.AttachmentGeneration;
                _lastTraceSequence = 0;
            }

            if (status.Supported != 0 && status.Capturing != 0)
            {
                _core.RequestTraceRead();
            }

            if (status.Supported != 0 &&
                status.SnapshotSequence != 0 &&
                status.SnapshotSequence != _lastTraceSequence &&
                TraceViewHost.IsAttached &&
                TraceViewHost.IsVisible &&
                TraceViewHost.SnapshotBuffer != IntPtr.Zero)
            {
                if (_core.CopyTraceSnapshot(TraceViewHost.SnapshotBuffer) == 0)
                {
                    TraceViewHost.PublishSnapshot();
                    _lastTraceSequence = status.SnapshotSequence;
                }
            }

            _tracePollFaulted = false;
        }
        catch (Exception error)
        {
            if (_tracePollFaulted == false)
            {
                _tracePollFaulted = true;
                GuiDiagnostics.WriteException("trace polling", error);
                SetTraceError($"实时 trace 状态读取失败: {error.Message}");
            }
        }
    }

    private void UpdateTraceState(HacDbgCoreTraceStatus status)
    {
        bool supported = status.Supported != 0;

        if (supported == false)
        {
            const string unsupportedText = "当前驱动不支持实时 trace；GUI 其余功能不受影响。";

            if (TraceStatusText.Text != unsupportedText)
            {
                TraceStatusText.Text = unsupportedText;
            }

            SetTraceError("当前驱动不支持实时 trace。加载带 trace 数据面的 1.1.0 或更新驱动后再试。");
            UpdateTraceControls(status);
            _traceSupported = false;
            return;
        }

        _traceSupported = true;

        if (_traceDeviceError == false)
        {
            if (status.LastError == HacDbgCore.TraceErrorControlFailed)
            {
                SetTraceError("trace_control 调用失败。查看驱动调试输出和加载日志。");
            }
            else if (status.LastError == HacDbgCore.TraceErrorReadFailed)
            {
                SetTraceError("trace_read 调用失败。停止捕获后检查驱动和设备状态。");
            }
            else
            {
                ClearTraceError();
            }
        }

        string mode = status.Capturing == 0
            ? "已停止"
            : status.EventsEnabled != 0
                ? "事件模式"
                : "计数模式";

        string statusText =
            $"{mode} · 采样 {status.SampleRate} · CPU {status.CpuCount} · " +
            $"退出 {status.TotalExits:N0} · 丢弃 {status.DroppedEvents:N0} · " +
            $"事件 {status.SnapshotEventCount} · TSC 0x{status.CapturedTsc:X16} · " +
            $"快照 #{status.SnapshotSequence} · 33 ms 轮询 / 60 fps 渲染";

        if (TraceStatusText.Text != statusText)
        {
            TraceStatusText.Text = statusText;
        }

        UpdateTraceControls(status);
    }

    private void UpdateTraceControls(HacDbgCoreTraceStatus? status)
    {
        bool supported = status is { Supported: not 0 } && _started;
        bool canControl = supported && _traceDeviceError == false;
        bool capturing = supported && status is { Capturing: not 0 };
        bool hasSnapshot = canControl && status is { SnapshotSequence: not 0 } && _lastTraceSequence != 0;

        TraceCountersButton.IsEnabled = canControl;
        TraceEventsButton.IsEnabled = canControl;
        TraceStopButton.IsEnabled = capturing;
        TraceResetButton.IsEnabled = canControl;
        TraceExportButton.IsEnabled = hasSnapshot;
        TraceSampleBox.IsEnabled = canControl;
    }

    private void TraceCountersButton_Click(object sender, RoutedEventArgs e)
    {
        ApplyTraceControl(
            HacDbgCore.TraceControlEnableCounters |
            HacDbgCore.TraceControlSetSampleRate,
            resetSequence: false);
    }

    private void TraceEventsButton_Click(object sender, RoutedEventArgs e)
    {
        ApplyTraceControl(
            HacDbgCore.TraceControlEnableCounters |
            HacDbgCore.TraceControlEnableEvents |
            HacDbgCore.TraceControlSetSampleRate |
            HacDbgCore.TraceControlSetEventMask,
            resetSequence: false);
    }

    private void TraceStopButton_Click(object sender, RoutedEventArgs e)
    {
        ApplyTraceControl(HacDbgCore.TraceControlDisable, resetSequence: false);
    }

    private void TraceResetButton_Click(object sender, RoutedEventArgs e)
    {
        ApplyTraceControl(
            HacDbgCore.TraceControlReset |
            HacDbgCore.TraceControlSetSampleRate,
            resetSequence: true);
    }

    private void TraceExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (TraceViewHost.IsAttached == false || _traceSupported == false)
        {
            SetTraceError("实时 trace 尚未就绪，无法导出。");
            return;
        }

        SaveFileDialog dialog = new()
        {
            Filter = "CSV 文件 (*.csv)|*.csv|所有文件 (*.*)|*.*",
            DefaultExt = ".csv",
            FileName = $"HacDbg-trace-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
            AddExtension = true,
            OverwritePrompt = true
        };

        if (dialog.ShowDialog(Window.GetWindow(this)) != true)
        {
            return;
        }

        uint result = TraceViewHost.ExportCsv(dialog.FileName);

        if (result != 0)
        {
            SetTraceError($"trace CSV 导出失败 (0x{result:X8})。");
            return;
        }

        CommandOutput.AppendText($"trace: exported snapshot to {dialog.FileName}\n");
        CommandOutput.ScrollToEnd();
    }

    private void ApplyTraceControl(uint flags, bool resetSequence)
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            SetTraceError("调试器尚未连接。");
            return;
        }

        uint sampleRate = SelectedTraceSampleRate();
        uint eventMask = (flags & HacDbgCore.TraceControlEnableEvents) != 0
            ? HacDbgCore.TraceEventMaskAll
            : 0;
        uint result = core.TraceControl(flags, sampleRate, eventMask);

        if (result != 0)
        {
            SetTraceError($"trace_control 排队失败 (status {result})。");
            return;
        }

        if (resetSequence)
        {
            _lastTraceSequence = 0;
        }

        ClearTraceError();
    }

    private uint SelectedTraceSampleRate()
    {
        if (TraceSampleBox.SelectedItem is System.Windows.Controls.ComboBoxItem item &&
            item.Tag is string text &&
            uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint sampleRate) &&
            sampleRate != 0)
        {
            return sampleRate;
        }

        return 64;
    }

    private void TraceReturnFocusButton_Click(object sender, RoutedEventArgs e)
    {
        FocusCommandInput();
    }

    private void FocusCommandInput()
    {
        Activate();
        FocusManager.SetFocusedElement(this, CommandInput);
        CommandInput.Focus();
        Keyboard.Focus(CommandInput);
    }

    private void TraceViewHost_ActionRequested(object? sender, TraceActionEventArgs e)
    {
        if (e.Action >= HacDbgTraceNative.ActionDocument1 &&
            e.Action < HacDbgTraceNative.ActionDocument1 + DefaultDockDocuments.Length)
        {
            int index = (int)(e.Action - HacDbgTraceNative.ActionDocument1);
            ActivateDocument(DefaultDockDocuments[index].ContentId);
            return;
        }

        switch (e.Action)
        {
            case HacDbgTraceNative.ActionContinue:
                ExecuteCommand("g");
                break;

            case HacDbgTraceNative.ActionStepInto:
                ExecuteCommand("t");
                break;

            case HacDbgTraceNative.ActionStepOver:
                ExecuteCommand("p");
                break;

            case HacDbgTraceNative.ActionFocusCommand:
                FocusCommandInput();
                break;

            case HacDbgTraceNative.ActionNextDocument:
                CycleDocument(1);
                break;

            case HacDbgTraceNative.ActionPreviousDocument:
                CycleDocument(-1);
                break;

            case HacDbgTraceNative.ActionClearOutput:
                CommandOutput.Clear();
                break;

            case HacDbgTraceNative.ActionDeviceError:
                _traceDeviceError = true;
                GuiDiagnostics.Write(
                    "trace renderer",
                    $"device error 0x{HacDbgTraceNative.LastError:X8}");
                SetTraceError(
                    $"trace 渲染器已停止 (0x{HacDbgTraceNative.LastError:X8})。" +
                    "重新打开 GUI 可重建 D3D11 设备。");
                TraceViewHost.Visibility = Visibility.Collapsed;
                break;
        }
    }

    private void TraceViewHost_InitializationFailed(string message)
    {
        _traceDeviceError = true;
        GuiDiagnostics.Write("trace renderer", message);
        SetTraceError(message);
        TraceViewHost.Visibility = Visibility.Collapsed;
    }

    private void SetTraceError(string message)
    {
        if (TraceErrorText.Text != message)
        {
            TraceErrorText.Text = message;
        }

        if (TraceErrorText.Visibility != Visibility.Visible)
        {
            TraceErrorText.Visibility = Visibility.Visible;
        }
    }

    private void ClearTraceError()
    {
        if (_traceDeviceError)
        {
            return;
        }

        if (TraceErrorText.Text.Length != 0)
        {
            TraceErrorText.Text = string.Empty;
        }

        if (TraceErrorText.Visibility != Visibility.Collapsed)
        {
            TraceErrorText.Visibility = Visibility.Collapsed;
        }
    }
}
