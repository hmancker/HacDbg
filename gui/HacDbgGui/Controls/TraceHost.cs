using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using HacDbgGui.Interop;

namespace HacDbgGui.Controls;

public sealed class TraceActionEventArgs(uint action) : EventArgs
{
    public uint Action { get; } = action;
}

public sealed class TraceHost : HwndHost
{
    private const int WsChild = 0x40000000;
    private const int WsVisible = 0x10000000;
    private const int WsClipSiblings = 0x04000000;
    private const int WsClipChildren = 0x02000000;

    private readonly HacDbgTraceNative.ActionCallback _actionCallback;
    private IntPtr _trace;
    private IntPtr _hostWindow;
    private IntPtr _snapshotBuffer;
    private GCHandle _actionContext;
    private uint _lastDpi;
    private uint _lastWidth;
    private uint _lastHeight;
    private bool _actionHooked;
    private bool _disposed;
    private bool _detaching;
    private bool _destroyingHost;

    public TraceHost()
    {
        _actionCallback = HandleNativeAction;
        IsVisibleChanged += TraceHost_IsVisibleChanged;
    }

    public event EventHandler<TraceActionEventArgs>? ActionRequested;

    public event Action<string>? InitializationFailed;

    public bool IsAttached => _trace != IntPtr.Zero;

    public uint AttachmentGeneration { get; private set; }

    public IntPtr SnapshotBuffer => _snapshotBuffer;

    public void ApplyTheme()
    {
        if (_trace == IntPtr.Zero)
        {
            return;
        }

        HacDbgTraceTheme theme = CreateTheme();
        HacDbgTraceNative.SetTheme(_trace, ref theme);
    }

    public void PublishSnapshot()
    {
        if (_trace != IntPtr.Zero && _snapshotBuffer != IntPtr.Zero)
        {
            HacDbgTraceNative.PublishSnapshot(_trace, _snapshotBuffer);
        }
    }

    public uint ExportCsv(string path)
    {
        return _trace == IntPtr.Zero ? 0x80004005u : HacDbgTraceNative.ExportCsv(_trace, path);
    }

    public void Detach()
    {
        if (_disposed)
        {
            return;
        }

        if (Dispatcher.CheckAccess() == false)
        {
            Dispatcher.Invoke(Detach);
            return;
        }

        DetachCore();
    }

    protected override HandleRef BuildWindowCore(HandleRef hwndParent)
    {
        if (_hostWindow != IntPtr.Zero)
        {
            return new HandleRef(this, _hostWindow);
        }

        DpiScale dpi = VisualTreeHelper.GetDpi(this);
        uint width = Math.Max(Scale(ActualWidth, dpi.DpiScaleX), 1);
        uint height = Math.Max(Scale(ActualHeight, dpi.DpiScaleY), 1);

        _hostWindow = CreateWindowExW(
            0,
            "static",
            string.Empty,
            WsChild | WsVisible | WsClipSiblings | WsClipChildren,
            0,
            0,
            (int)width,
            (int)height,
            hwndParent.Handle,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero);

        if (_hostWindow == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                $"CreateWindowEx failed ({Marshal.GetLastWin32Error()})");
        }

        try
        {
            AttachTrace();
        }
        catch (Exception error)
        {
            DetachCore();
            PublishFailure($"trace renderer failed to initialize: {error.Message}");
        }

        return new HandleRef(this, _hostWindow);
    }

    protected override void DestroyWindowCore(HandleRef hwnd)
    {
        if (_destroyingHost)
        {
            return;
        }

        _destroyingHost = true;

        try
        {
            DetachCore();

            if (_hostWindow != IntPtr.Zero)
            {
                DestroyWindow(_hostWindow);
                _hostWindow = IntPtr.Zero;
            }
        }
        finally
        {
            _destroyingHost = false;
        }
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo sizeInfo)
    {
        base.OnRenderSizeChanged(sizeInfo);
        UpdateNativeGeometry();
    }

    protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
    {
        base.OnDpiChanged(oldDpi, newDpi);
        UpdateNativeGeometry();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Detach();
            _disposed = true;
        }

        base.Dispose(disposing);
    }

    private void AttachTrace()
    {
        if (HacDbgTraceNative.ValidateAbi() == false)
        {
            throw new InvalidOperationException("HacDbgTrace.dll ABI mismatch");
        }

        HacDbgTraceTheme theme = CreateTheme();
        _trace = HacDbgTraceNative.Attach(_hostWindow, GetModuleHandleW(null), ref theme);

        if (_trace == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                $"HacDbgTraceAttach failed (0x{HacDbgTraceNative.LastError:X8})");
        }

        AttachmentGeneration += 1;
        _snapshotBuffer = Marshal.AllocHGlobal(HacDbgCore.TraceSnapshotSize);

        _actionHooked = true;
        _actionContext = GCHandle.Alloc(this);
        HacDbgTraceNative.SetActionCallback(_trace, _actionCallback, GCHandle.ToIntPtr(_actionContext));
        HacDbgTraceNative.SetTheme(_trace, ref theme);
        UpdateNativeGeometry(forceDpi: true);
        HacDbgTraceNative.SetVisible(_trace, IsVisible);
    }

    private void DetachCore()
    {
        if (_detaching)
        {
            return;
        }

        _detaching = true;

        try
        {
            if (_trace != IntPtr.Zero)
            {
                if (_actionHooked)
                {
                    HacDbgTraceNative.SetActionCallback(_trace, null, IntPtr.Zero);
                    _actionHooked = false;
                }

                IntPtr trace = _trace;
                _trace = IntPtr.Zero;

                Task detachTask = Task.Run(() => HacDbgTraceNative.Detach(trace));
                WaitForNativeDetach(detachTask);
            }

            if (_actionContext.IsAllocated)
            {
                _actionContext.Free();
            }

            if (_snapshotBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_snapshotBuffer);
                _snapshotBuffer = IntPtr.Zero;
            }

            _lastDpi = 0;
            _lastWidth = 0;
            _lastHeight = 0;
        }
        finally
        {
            _detaching = false;
        }
    }

    private static void WaitForNativeDetach(Task detachTask)
    {
        // The native render thread destroys its child HWND while exiting.
        // Blocking the WPF thread on Join would prevent those parent-window
        // messages from being handled, so keep a DispatcherFrame alive until
        // the background detach returns.
        Dispatcher dispatcher = Dispatcher.CurrentDispatcher;

        while (detachTask.IsCompleted == false &&
               dispatcher.CheckAccess() &&
               dispatcher.HasShutdownStarted == false)
        {
            DispatcherFrame frame = new();
            DispatcherTimer timer = new()
            {
                Interval = TimeSpan.FromMilliseconds(5)
            };
            EventHandler onTick = (_, _) =>
            {
                timer.Stop();
                frame.Continue = false;
            };

            timer.Tick += onTick;
            timer.Start();

            try
            {
                Dispatcher.PushFrame(frame);
            }
            catch (InvalidOperationException)
            {
                break;
            }
            finally
            {
                timer.Stop();
                timer.Tick -= onTick;
            }
        }

        detachTask.GetAwaiter().GetResult();
    }

    private void UpdateNativeGeometry(bool forceDpi = false)
    {
        if (_trace == IntPtr.Zero)
        {
            return;
        }

        DpiScale dpi = VisualTreeHelper.GetDpi(this);
        uint dpiValue = (uint)Math.Max(Math.Round(dpi.PixelsPerInchX), 48);

        if (forceDpi || dpiValue != _lastDpi)
        {
            _lastDpi = dpiValue;
            HacDbgTraceNative.SetDpi(_trace, dpiValue);
        }

        uint width = Math.Max(Scale(ActualWidth, dpi.DpiScaleX), 1);
        uint height = Math.Max(Scale(ActualHeight, dpi.DpiScaleY), 1);

        if (width != _lastWidth || height != _lastHeight)
        {
            _lastWidth = width;
            _lastHeight = height;
            HacDbgTraceNative.Resize(_trace, width, height);
        }
    }

    private void TraceHost_IsVisibleChanged(object? sender, DependencyPropertyChangedEventArgs e)
    {
        if (_trace != IntPtr.Zero)
        {
            HacDbgTraceNative.SetVisible(_trace, IsVisible);
        }
    }

    private void HandleNativeAction(uint action, IntPtr context)
    {
        try
        {
            Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() =>
            {
                if (_disposed == false)
                {
                    ActionRequested?.Invoke(this, new TraceActionEventArgs(action));
                }
            }));
        }
        catch (InvalidOperationException)
        {
        }
    }

    private void PublishFailure(string message)
    {
        try
        {
            Dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(() =>
            {
                if (_disposed == false)
                {
                    InitializationFailed?.Invoke(message);
                }
            }));
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static uint Scale(double value, double scale = 1.0)
    {
        if (double.IsFinite(value) == false || value <= 0.0)
        {
            return 1;
        }

        return (uint)Math.Clamp(Math.Round(value * scale), 1.0, 16384.0);
    }

    private static HacDbgTraceTheme CreateTheme()
    {
        return new HacDbgTraceTheme
        {
            Size = HacDbgTraceNative.ThemeSizeValue,
            Version = HacDbgTraceNative.ThemeVersion,
            Background = ReadColor("WindowBackgroundColor", 0xFF111418),
            Surface = ReadColor("SurfaceColor", 0xFF181D23),
            SurfaceRaised = ReadColor("SurfaceRaisedColor", 0xFF20262E),
            Border = ReadColor("BorderColor", 0xFF303842),
            Text = ReadColor("ForegroundColor", 0xFFE6EDF3),
            Muted = ReadColor("MutedColor", 0xFF8B98A5),
            Accent = ReadColor("AccentColor", 0xFF4CC2FF),
            Warning = ReadColor("WarningColor", 0xFFE3B341),
            Error = ReadColor("ErrorColor", 0xFFFF7B72)
        };
    }

    private static uint ReadColor(string resource, uint fallback)
    {
        if (Application.Current?.TryFindResource(resource) is not Color color)
        {
            return fallback;
        }

        return ((uint)color.A << 24) |
               ((uint)color.R << 16) |
               ((uint)color.G << 8) |
               color.B;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr CreateWindowExW(
        int exStyle,
        string className,
        string windowName,
        int style,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr parameter);

    [DllImport("user32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr window);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandleW(string? moduleName);
}
