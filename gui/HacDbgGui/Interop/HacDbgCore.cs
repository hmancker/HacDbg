using System.Runtime.InteropServices;
using System.Text;

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

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreSymbolProgress
{
    public uint Active;
    public uint Completed;
    public uint Total;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreViewStatus
{
    public ulong RequestId;
    public ulong CompletedRequestId;
    public uint Pending;
    public uint Failed;
    public uint Count;
    public uint Truncated;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 192)]
    public byte[] Message;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreModule
{
    public ulong Base;
    public ulong Size;
    public ulong Cr3;
    public uint Kernel;
    public uint SymbolsLoaded;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public byte[] Name;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)]
    public byte[] SymbolPath;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreProcess
{
    public ulong Eprocess;
    public ulong Pid;
    public ulong ParentPid;
    public ulong Peb;
    public ulong Directory;
    public ulong UserCr3;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public byte[] Image;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreThread
{
    public ulong Ethread;
    public ulong Eprocess;
    public ulong Pid;
    public ulong Tid;
    public ulong Teb;
    public ulong Trap;
    public ulong Win32Start;
    public ulong StackBase;
    public ulong StackLimit;
    public ulong KernelStack;
    public ulong InstructionPointer;
    public ulong Cr3;
    public uint ContextSwitches;
    public uint WaitTime;
    public uint State;
    public uint Priority;
    public uint SuspendCount;
    public uint WaitReason;
    public uint WaitMode;
    public uint SystemThread;
    public uint HasRegisters;
    public uint KernelMode;
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public byte[] Image;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
    public byte[] StateName;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] WaitReasonName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreStackFrame
{
    public ulong ChildSp;
    public ulong ReturnAddress;
    public ulong InstructionPointer;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public ulong[] Args;
    public uint ArgsValidMask;
    public uint HasReturn;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 192)]
    public byte[] Symbol;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreMemory
{
    public ulong Address;
    public ulong Cr3;
    public uint Requested;
    public uint BytesValid;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
    public byte[] Data;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreInstruction
{
    public ulong Address;
    public uint Length;
    public uint Invalid;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] Bytes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
    public byte[] Text;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 192)]
    public byte[] Symbol;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreResolvedAddress
{
    public ulong Address;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 192)]
    public byte[] Symbol;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreTraceStatus
{
    public ulong TotalExits;
    public ulong DroppedEvents;
    public ulong CapturedTsc;
    public ulong SnapshotSequence;
    public uint SnapshotVersion;
    public uint Supported;
    public uint Capturing;
    public uint EventsEnabled;
    public uint SampleRate;
    public uint EventMask;
    public uint CpuCount;
    public uint LastError;
    public uint SnapshotEventCount;
    public uint ControlPending;
    public uint ReadPending;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreCompletion
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] Text;
}

[StructLayout(LayoutKind.Sequential)]
internal struct HacDbgCoreCompletionStatus
{
    public ulong RequestId;
    public ulong CompletedRequestId;
    public uint Pending;
    public uint Failed;
    public uint Count;
    public uint Total;
}

internal sealed class HacDbgCore : IDisposable
{
    public const uint StatusArgument = 1;
    public const uint StatusState = 2;
    public const uint StatusDriver = 3;
    public const uint StatusException = 4;
    public const uint ExpectedHypercallAbiVersion = 1;
    public const uint ViewModules = 0;
    public const uint ViewProcesses = 1;
    public const uint ViewThreads = 2;
    public const uint ViewStack = 3;
    public const uint ViewMemory = 4;
    public const uint ViewDisassembly = 5;
    public const uint ViewResolve = 6;
    public const uint StructureViewStatus = 0;
    public const uint StructureModule = 1;
    public const uint StructureProcess = 2;
    public const uint StructureThread = 3;
    public const uint StructureStackFrame = 4;
    public const uint StructureMemory = 5;
    public const uint StructureInstruction = 6;
    public const uint StructureResolvedAddress = 7;
    public const uint StructureTraceStatus = 8;
    public const uint StructureTraceSnapshot = 9;
    public const uint StructureCompletion = 10;
    public const uint StructureCompletionStatus = 11;
    public const int MaxCompletions = 128;
    public const int CompletionSize = 512;
    public const int MaxModules = 512;
    public const int MaxProcesses = 512;
    public const int MaxThreads = 512;
    public const int MaxStackFrames = 64;
    public const int MaxDisassemblyLines = 128;
    public const int MaxMemoryBytes = 4096;
    public const int TraceSnapshotSize = 53288;
    public const uint TraceControlEnableCounters = 1u << 0;
    public const uint TraceControlEnableEvents = 1u << 1;
    public const uint TraceControlReset = 1u << 2;
    public const uint TraceControlSetSampleRate = 1u << 3;
    public const uint TraceControlSetEventMask = 1u << 4;
    public const uint TraceControlDisable = 1u << 5;
    public const uint TraceEventMaskAll = (1u << 16) - 1u;
    public const uint TraceErrorNone = 0;
    public const uint TraceErrorUnsupported = 1;
    public const uint TraceErrorControlFailed = 2;
    public const uint TraceErrorReadFailed = 3;

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

    public static uint GetStructureSize(uint structure) => NativeMethods.HacDbgCoreStructureSize(structure);

    public static bool ValidateAbi()
    {
        static bool Matches<T>(uint structure) where T : struct =>
            GetStructureSize(structure) == (uint)Marshal.SizeOf<T>();

        return ApiVersion == 4 &&
               StateSize == (uint)Marshal.SizeOf<HacDbgCoreState>() &&
               Matches<HacDbgCoreViewStatus>(StructureViewStatus) &&
               Matches<HacDbgCoreModule>(StructureModule) &&
               Matches<HacDbgCoreProcess>(StructureProcess) &&
               Matches<HacDbgCoreThread>(StructureThread) &&
               Matches<HacDbgCoreStackFrame>(StructureStackFrame) &&
               Matches<HacDbgCoreMemory>(StructureMemory) &&
               Matches<HacDbgCoreInstruction>(StructureInstruction) &&
               Matches<HacDbgCoreResolvedAddress>(StructureResolvedAddress) &&
               Matches<HacDbgCoreTraceStatus>(StructureTraceStatus) &&
               GetStructureSize(StructureTraceSnapshot) == TraceSnapshotSize &&
               Matches<HacDbgCoreCompletion>(StructureCompletion) &&
               Matches<HacDbgCoreCompletionStatus>(StructureCompletionStatus);
    }

    public uint Start() => NativeMethods.HacDbgCoreStart(_handle);

    public uint Execute(string command) => NativeMethods.HacDbgCoreExecute(_handle, command);

    public void Cancel() => NativeMethods.HacDbgCoreCancel(_handle);

    public uint GetState(out HacDbgCoreState state) => NativeMethods.HacDbgCoreGetState(_handle, out state);

    public uint GetSymbolProgress(out HacDbgCoreSymbolProgress progress) =>
        NativeMethods.HacDbgCoreGetSymbolProgress(_handle, out progress);

    public ulong RequestModules() => NativeMethods.HacDbgCoreRequestModules(_handle);

    public ulong RequestProcesses() => NativeMethods.HacDbgCoreRequestProcesses(_handle);

    public ulong RequestThreads(ulong eprocess) => NativeMethods.HacDbgCoreRequestThreads(_handle, eprocess);

    public ulong RequestStack(uint frameCount) => NativeMethods.HacDbgCoreRequestStack(_handle, frameCount);

    public ulong RequestMemory(ulong address, ulong cr3, uint size) =>
        NativeMethods.HacDbgCoreRequestMemory(_handle, address, cr3, size);

    public ulong RequestDisassembly(ulong address, ulong cr3, uint instructionCount) =>
        NativeMethods.HacDbgCoreRequestDisassembly(_handle, address, cr3, instructionCount);

    public ulong RequestResolve(string text) => NativeMethods.HacDbgCoreRequestResolve(_handle, text);

    public uint GetViewStatus(uint view, out HacDbgCoreViewStatus status) =>
        NativeMethods.HacDbgCoreGetViewStatus(_handle, view, out status);

    public uint CopyModules([Out] HacDbgCoreModule[] modules, uint capacity, out uint count) =>
        NativeMethods.HacDbgCoreCopyModules(_handle, modules, capacity, out count);

    public uint CopyProcesses([Out] HacDbgCoreProcess[] processes, uint capacity, out uint count) =>
        NativeMethods.HacDbgCoreCopyProcesses(_handle, processes, capacity, out count);

    public uint CopyThreads([Out] HacDbgCoreThread[] threads, uint capacity, out uint count) =>
        NativeMethods.HacDbgCoreCopyThreads(_handle, threads, capacity, out count);

    public uint CopyStack([Out] HacDbgCoreStackFrame[] frames, uint capacity, out uint count) =>
        NativeMethods.HacDbgCoreCopyStack(_handle, frames, capacity, out count);

    public uint CopyMemory(out HacDbgCoreMemory memory) =>
        NativeMethods.HacDbgCoreCopyMemory(_handle, out memory);

    public uint CopyDisassembly([Out] HacDbgCoreInstruction[] instructions, uint capacity, out uint count) =>
        NativeMethods.HacDbgCoreCopyDisassembly(_handle, instructions, capacity, out count);

    public uint CopyResolvedAddress(out HacDbgCoreResolvedAddress address) =>
        NativeMethods.HacDbgCoreCopyResolvedAddress(_handle, out address);

    public uint TraceControl(uint flags, uint sampleRate, uint eventMask) =>
        NativeMethods.HacDbgCoreTraceControl(_handle, flags, sampleRate, eventMask);

    public uint RequestTraceRead() => NativeMethods.HacDbgCoreRequestTraceRead(_handle);

    public uint GetTraceStatus(out HacDbgCoreTraceStatus status) =>
        NativeMethods.HacDbgCoreGetTraceStatus(_handle, out status);

    public uint CopyTraceSnapshot(IntPtr snapshot) =>
        NativeMethods.HacDbgCoreCopyTraceSnapshot(_handle, snapshot);

    public static uint CompleteCommands(string token, out string[] matches)
    {
        matches = Array.Empty<string>();
        HacDbgCoreCompletion[] items = NewCompletionBuffer(MaxCompletions);
        uint status = NativeMethods.HacDbgCoreCompleteCommands(token, items, (uint)items.Length, out uint count);

        if (status == 0)
        {
            matches = DecodeCompletions(items, count);
        }

        return status;
    }

    public ulong RequestCompletions(string token) => NativeMethods.HacDbgCoreRequestCompletions(_handle, token);

    public uint GetCompletionStatus(out HacDbgCoreCompletionStatus status) =>
        NativeMethods.HacDbgCoreGetCompletionStatus(_handle, out status);

    public uint CopyCompletions(ulong requestId, uint count, out string[] matches)
    {
        matches = Array.Empty<string>();

        if (count == 0)
        {
            return 0;
        }

        uint capacity = Math.Min(count, (uint)MaxCompletions);
        HacDbgCoreCompletion[] items = NewCompletionBuffer(capacity);
        uint status = NativeMethods.HacDbgCoreCopyCompletions(_handle, requestId, items, capacity, out uint copied);

        if (status == 0)
        {
            matches = DecodeCompletions(items, copied);
        }

        return status;
    }

    private static HacDbgCoreCompletion[] NewCompletionBuffer(uint capacity)
    {
        HacDbgCoreCompletion[] items = new HacDbgCoreCompletion[capacity];

        for (int index = 0; index < items.Length; index++)
        {
            items[index].Text = new byte[CompletionSize];
        }

        return items;
    }

    private static string[] DecodeCompletions(HacDbgCoreCompletion[] items, uint count)
    {
        int length = (int)Math.Min(count, (uint)items.Length);
        string[] matches = new string[length];

        for (int index = 0; index < length; index++)
        {
            byte[] bytes = items[index].Text ?? Array.Empty<byte>();
            int textLength = Array.IndexOf(bytes, (byte)0);

            if (textLength < 0)
            {
                textLength = bytes.Length;
            }

            matches[index] = Encoding.UTF8.GetString(bytes, 0, textLength);
        }

        return matches;
    }

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
        internal static extern uint HacDbgCoreStructureSize(uint structure);

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

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreGetSymbolProgress(IntPtr core, out HacDbgCoreSymbolProgress progress);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestModules(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestProcesses(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestThreads(IntPtr core, ulong eprocess);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestStack(IntPtr core, uint frameCount);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestMemory(IntPtr core, ulong address, ulong cr3, uint size);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestDisassembly(IntPtr core, ulong address, ulong cr3,
                                                                  uint instructionCount);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestResolve(IntPtr core,
                                                              [MarshalAs(UnmanagedType.LPUTF8Str)] string text);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreGetViewStatus(IntPtr core, uint view,
                                                            out HacDbgCoreViewStatus status);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyModules(IntPtr core, [Out] HacDbgCoreModule[] modules,
                                                          uint capacity, out uint count);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyProcesses(IntPtr core, [Out] HacDbgCoreProcess[] processes,
                                                            uint capacity, out uint count);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyThreads(IntPtr core, [Out] HacDbgCoreThread[] threads,
                                                          uint capacity, out uint count);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyStack(IntPtr core, [Out] HacDbgCoreStackFrame[] frames,
                                                        uint capacity, out uint count);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyMemory(IntPtr core, out HacDbgCoreMemory memory);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyDisassembly(IntPtr core,
                                                              [Out] HacDbgCoreInstruction[] instructions,
                                                              uint capacity, out uint count);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyResolvedAddress(IntPtr core,
                                                                  out HacDbgCoreResolvedAddress address);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreTraceControl(IntPtr core, uint flags, uint sampleRate,
                                                           uint eventMask);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreRequestTraceRead(IntPtr core);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreGetTraceStatus(IntPtr core,
                                                             out HacDbgCoreTraceStatus status);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyTraceSnapshot(IntPtr core, IntPtr snapshot);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCompleteCommands(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string token,
            [Out] HacDbgCoreCompletion[] items,
            uint capacity,
            out uint count);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern ulong HacDbgCoreRequestCompletions(
            IntPtr core,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string token);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreGetCompletionStatus(IntPtr core, out HacDbgCoreCompletionStatus status);

        [DllImport("HacDbgCore.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern uint HacDbgCoreCopyCompletions(
            IntPtr core,
            ulong requestId,
            [Out] HacDbgCoreCompletion[] items,
            uint capacity,
            out uint count);
    }
}
