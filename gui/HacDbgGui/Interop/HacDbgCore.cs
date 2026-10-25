using System.Runtime.InteropServices;

namespace HacDbgGui.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreRegisters
{
    public ulong Rax;
    public ulong Rcx;
    public ulong Rdx;
    public ulong Rbx;
    public ulong Rsp;
    public ulong Rbp;
    public ulong Rsi;
    public ulong Rdi;
    public ulong R8;
    public ulong R9;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;
    public ulong Rip;
    public ulong Rflags;
    public ulong Cr3;
    public uint RflagsKnown;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreBreakpoint
{
    public ulong Id;
    public ulong Address;
    public ulong Cr3;
    public uint Enabled;
    public uint PausesThread;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreState
{
    public uint Initialized;
    public uint Running;
    public uint Paused;
    public uint BreakpointCount;
    public uint HypercallAbiVersion;
    public uint Reserved;
    public HacDbgCoreRegisters Registers;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public HacDbgCoreBreakpoint[] Breakpoints;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] UserVersion;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] DriverVersion;
}

internal sealed class HacDbgCore : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void OutputCallback(uint kind, IntPtr text, uint length, IntPtr context);

    private readonly OutputCallback _callback;
    private readonly Action<uint, string> _output;
    private IntPtr _handle;

    public HacDbgCore(Action<uint, string> output)
    {
        _output = output;
        _callback = OnOutput;
        _handle = NativeMethods.HacDbgCoreCreate(_callback, IntPtr.Zero);

        if (_handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("HacDbgCoreCreate failed");
        }
    }

    public static uint ApiVersion => NativeMethods.HacDbgCoreApiVersion();

    public static uint StateSize => NativeMethods.HacDbgCoreStateSize();

    public uint Start() => NativeMethods.HacDbgCoreStart(_handle);

    public uint Execute(string command) => NativeMethods.HacDbgCoreExecute(_handle, command);

    public void Cancel() => NativeMethods.HacDbgCoreCancel(_handle);

    public uint GetState(out HacDbgCoreState state) => NativeMethods.HacDbgCoreGetState(_handle, out state);

    public void Dispose()
    {
        if (_handle == IntPtr.Zero)
        {
            return;
        }

        NativeMethods.HacDbgCoreStop(_handle);
        NativeMethods.HacDbgCoreDestroy(_handle);
        _handle = IntPtr.Zero;
        GC.KeepAlive(_callback);
    }

    private void OnOutput(uint kind, IntPtr text, uint length, IntPtr context)
    {
        try
        {
            string message = length == 0 ? string.Empty : (Marshal.PtrToStringUTF8(text, (int)length) ?? string.Empty);
            _output(kind, message);
        }
        catch
        {
        }
    }

    private static class NativeMethods
    {
        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreApiVersion();

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreStateSize();

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern IntPtr HacDbgCoreCreate(OutputCallback callback, IntPtr context);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgCoreDestroy(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreStart(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreStop(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreExecute(IntPtr core, [MarshalAs(UnmanagedType.LPUTF8Str)] string command);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void HacDbgCoreCancel(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreGetState(IntPtr core, out HacDbgCoreState state);
    }
}
