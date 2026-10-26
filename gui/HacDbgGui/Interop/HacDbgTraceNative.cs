using System.Runtime.InteropServices;

namespace HacDbgGui.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgTraceTheme
{
    public uint Size;
    public uint Version;
    public uint Background;
    public uint Surface;
    public uint SurfaceRaised;
    public uint Border;
    public uint Text;
    public uint Muted;
    public uint Accent;
    public uint Warning;
    public uint Error;
    public uint Reserved;
}

internal static class HacDbgTraceNative
{
    public const uint ApiVersionValue = 1;
    public const uint ThemeVersion = 1;
    public const uint ThemeSizeValue = 48;

    public const uint ActionContinue = 1;
    public const uint ActionStepInto = 2;
    public const uint ActionStepOver = 3;
    public const uint ActionFocusCommand = 4;
    public const uint ActionDeviceError = 5;
    public const uint ActionNextDocument = 6;
    public const uint ActionPreviousDocument = 7;
    public const uint ActionClearOutput = 8;
    public const uint ActionDocument1 = 9;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void ActionCallback(uint action, IntPtr context);

    public static bool ValidateAbi()
    {
        return NativeMethods.HacDbgTraceApiVersion() == ApiVersionValue &&
               NativeMethods.HacDbgTraceThemeSize() == ThemeSizeValue &&
               Marshal.SizeOf<HacDbgTraceTheme>() == ThemeSizeValue;
    }

    public static uint LastError => NativeMethods.HacDbgTraceLastError();

    public static IntPtr Attach(IntPtr host, IntPtr instance, ref HacDbgTraceTheme theme) =>
        NativeMethods.HacDbgTraceAttach(host, instance, ref theme);

    public static void PublishSnapshot(IntPtr trace, IntPtr snapshot) =>
        NativeMethods.HacDbgTracePublishSnapshot(trace, snapshot);

    public static void SetTheme(IntPtr trace, ref HacDbgTraceTheme theme) =>
        NativeMethods.HacDbgTraceSetTheme(trace, ref theme);

    public static void SetDpi(IntPtr trace, uint dpi) =>
        NativeMethods.HacDbgTraceSetDpi(trace, dpi);

    public static void SetVisible(IntPtr trace, bool visible) =>
        NativeMethods.HacDbgTraceSetVisible(trace, visible ? 1u : 0u);

    public static void Resize(IntPtr trace, uint width, uint height) =>
        NativeMethods.HacDbgTraceResize(trace, width, height);

    public static void SetActionCallback(IntPtr trace, ActionCallback? callback, IntPtr context) =>
        NativeMethods.HacDbgTraceSetActionCallback(trace, callback, context);

    public static uint ExportCsv(IntPtr trace, string path) =>
        NativeMethods.HacDbgTraceExportCsv(trace, path);

    public static void Detach(IntPtr trace) =>
        NativeMethods.HacDbgTraceDetach(trace);

    private static class NativeMethods
    {
        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgTraceApiVersion();

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgTraceThemeSize();

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgTraceLastError();

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern IntPtr HacDbgTraceAttach(IntPtr host, IntPtr instance,
                                                        ref HacDbgTraceTheme theme);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTracePublishSnapshot(IntPtr trace, IntPtr snapshot);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTraceSetTheme(IntPtr trace, ref HacDbgTraceTheme theme);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTraceSetDpi(IntPtr trace, uint dpi);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTraceSetVisible(IntPtr trace, uint visible);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTraceResize(IntPtr trace, uint width, uint height);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTraceSetActionCallback(IntPtr trace, ActionCallback? callback,
                                                                  IntPtr context);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode,
                   ExactSpelling = true)]
        internal static extern uint HacDbgTraceExportCsv(IntPtr trace, [MarshalAs(UnmanagedType.LPWStr)] string path);

        [DllImport("HacDbgTrace.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgTraceDetach(IntPtr trace);
    }
}
