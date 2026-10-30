#pragma once

/**
 * @file hacdbg_core_api.h
 * @brief C ABI between the GUI and the native debugger core.
 *
 * @author HacDbg
 */

#include <stddef.h>
#include <stdint.h>

#include <structures/trace.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define HACDBG_CORE_API_VERSION 7u
#define HACDBG_CORE_MAX_MONITORS 64u
#define HACDBG_CORE_MONITOR_STACK 5u
#define HACDBG_CORE_MAX_BREAKPOINTS 64u
#define HACDBG_CORE_VERSION_STRING_SIZE 32u
#define HACDBG_CORE_MAX_MODULES 512u
#define HACDBG_CORE_MAX_PROCESSES 512u
#define HACDBG_CORE_MAX_THREADS 512u
#define HACDBG_CORE_MAX_STACK_FRAMES 64u
#define HACDBG_CORE_MAX_DISASSEMBLY_LINES 128u
#define HACDBG_CORE_MAX_MEMORY_BYTES 4096u
#define HACDBG_CORE_NAME_SIZE 128u
#define HACDBG_CORE_PATH_SIZE 260u
#define HACDBG_CORE_SYMBOL_SIZE 192u
#define HACDBG_CORE_MESSAGE_SIZE 192u
#define HACDBG_CORE_STATE_NAME_SIZE 48u
#define HACDBG_CORE_WAIT_REASON_SIZE 64u
#define HACDBG_CORE_MAX_COMPLETIONS 128u
#define HACDBG_CORE_COMPLETION_SIZE 512u

/**
 * @brief Status returned by the GUI core ABI.
 */
typedef enum _HACDBG_CORE_STATUS
{
    HacDbgCoreStatusOk = 0,
    HacDbgCoreStatusArgument = 1,
    HacDbgCoreStatusState = 2,
    HacDbgCoreStatusDriver = 3,
    HacDbgCoreStatusException = 4
} HACDBG_CORE_STATUS;

/**
 * @brief Output event kinds delivered on the core callback thread.
 */
typedef enum _HACDBG_OUTPUT_KIND
{
    HacDbgOutputText = 0,
    HacDbgOutputInfo = 1,
    HacDbgOutputWarning = 2,
    HacDbgOutputError = 3,
    HacDbgOutputProgress = 4,
    HacDbgOutputClear = 5,
    HacDbgOutputQuit = 6
} HACDBG_OUTPUT_KIND;

/**
 * @brief Structured snapshots copied by the core.
 */
typedef enum _HACDBG_CORE_VIEW
{
    HacDbgViewModules = 0,
    HacDbgViewProcesses = 1,
    HacDbgViewThreads = 2,
    HacDbgViewStack = 3,
    HacDbgViewMemory = 4,
    HacDbgViewDisassembly = 5,
    HacDbgViewResolve = 6,
    HacDbgViewCount = 7
} HACDBG_CORE_VIEW;

/**
 * @brief Structures whose size is validated by the managed frontend.
 */
typedef enum _HACDBG_CORE_STRUCTURE
{
    HacDbgStructureViewStatus = 0,
    HacDbgStructureModule = 1,
    HacDbgStructureProcess = 2,
    HacDbgStructureThread = 3,
    HacDbgStructureStackFrame = 4,
    HacDbgStructureMemory = 5,
    HacDbgStructureInstruction = 6,
    HacDbgStructureResolvedAddress = 7,
    HacDbgStructureTraceStatus = 8,
    HacDbgStructureTraceSnapshot = 9,
    HacDbgStructureCompletion = 10,
    HacDbgStructureCompletionStatus = 11,
    HacDbgStructureMonitor = 12,
    HacDbgStructureMonitorHit = 13,
    HacDbgStructureStackWindow = 14
} HACDBG_CORE_STRUCTURE;

/**
 * @brief Trace status copied without entering the driver.
 */
typedef struct _HACDBG_CORE_TRACE_STATUS
{
    uint64_t TotalExits;
    uint64_t DroppedEvents;
    uint64_t CapturedTsc;
    uint64_t SnapshotSequence;
    uint32_t SnapshotVersion;
    uint32_t Supported;
    uint32_t Capturing;
    uint32_t EventsEnabled;
    uint32_t SampleRate;
    uint32_t EventMask;
    uint32_t CpuCount;
    uint32_t LastError;
    uint32_t SnapshotEventCount;
    uint32_t ControlPending;
    uint32_t ReadPending;
    uint32_t Reserved;
} HACDBG_CORE_TRACE_STATUS;

#define HACDBG_CORE_TRACE_ERROR_NONE           0u
#define HACDBG_CORE_TRACE_ERROR_UNSUPPORTED    1u
#define HACDBG_CORE_TRACE_ERROR_CONTROL_FAILED 2u
#define HACDBG_CORE_TRACE_ERROR_READ_FAILED    3u

/**
 * @brief Guest register snapshot captured while a breakpoint paused a thread.
 */
typedef struct _HACDBG_CORE_REGISTERS
{
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    uint64_t Rflags;
    uint64_t Cr3;
    uint32_t RflagsKnown;
    uint32_t Reserved;
} HACDBG_CORE_REGISTERS;

/**
 * @brief One execution breakpoint.
 */
typedef struct _HACDBG_CORE_BREAKPOINT
{
    uint64_t Id;
    uint64_t Address;
    uint64_t Cr3;
    uint32_t Enabled;
    uint32_t PausesThread;
} HACDBG_CORE_BREAKPOINT;

/**
 * @brief Immutable state snapshot copied by HacDbgCoreGetState.
 */
typedef struct _HACDBG_CORE_STATE
{
    uint32_t Initialized;
    uint32_t Running;
    uint32_t Paused;
    uint32_t BreakpointCount;
    uint32_t HypercallAbiVersion;
    uint32_t CommandSequence;
    HACDBG_CORE_REGISTERS Registers;
    HACDBG_CORE_BREAKPOINT Breakpoints[HACDBG_CORE_MAX_BREAKPOINTS];
    char UserVersion[HACDBG_CORE_VERSION_STRING_SIZE];
    char DriverVersion[HACDBG_CORE_VERSION_STRING_SIZE];
} HACDBG_CORE_STATE;

typedef struct _HACDBG_CORE_SYMBOL_PROGRESS
{
    uint32_t Active;
    uint32_t Completed;
    uint32_t Total;
} HACDBG_CORE_SYMBOL_PROGRESS;

/**
 * @brief Status of one asynchronous structured view request.
 */
typedef struct _HACDBG_CORE_VIEW_STATUS
{
    uint64_t RequestId;
    uint64_t CompletedRequestId;
    uint32_t Pending;
    uint32_t Failed;
    uint32_t Count;
    uint32_t Truncated;
    char Message[HACDBG_CORE_MESSAGE_SIZE];
} HACDBG_CORE_VIEW_STATUS;

typedef struct _HACDBG_CORE_MODULE
{
    uint64_t Base;
    uint64_t Size;
    uint64_t Cr3;
    uint32_t Kernel;
    uint32_t SymbolsLoaded;
    char Name[HACDBG_CORE_NAME_SIZE];
    char SymbolPath[HACDBG_CORE_PATH_SIZE];
} HACDBG_CORE_MODULE;

typedef struct _HACDBG_CORE_PROCESS
{
    uint64_t Eprocess;
    uint64_t Pid;
    uint64_t ParentPid;
    uint64_t Peb;
    uint64_t Directory;
    uint64_t UserCr3;
    char Image[HACDBG_CORE_NAME_SIZE];
} HACDBG_CORE_PROCESS;

typedef struct _HACDBG_CORE_THREAD
{
    uint64_t Ethread;
    uint64_t Eprocess;
    uint64_t Pid;
    uint64_t Tid;
    uint64_t Teb;
    uint64_t Trap;
    uint64_t Win32Start;
    uint64_t StackBase;
    uint64_t StackLimit;
    uint64_t KernelStack;
    uint64_t InstructionPointer;
    uint64_t Cr3;
    uint32_t ContextSwitches;
    uint32_t WaitTime;
    uint32_t State;
    uint32_t Priority;
    uint32_t SuspendCount;
    uint32_t WaitReason;
    uint32_t WaitMode;
    uint32_t SystemThread;
    uint32_t HasRegisters;
    uint32_t KernelMode;
    uint32_t Reserved;
    char Image[HACDBG_CORE_NAME_SIZE];
    char StateName[HACDBG_CORE_STATE_NAME_SIZE];
    char WaitReasonName[HACDBG_CORE_WAIT_REASON_SIZE];
} HACDBG_CORE_THREAD;

typedef struct _HACDBG_CORE_STACK_FRAME
{
    uint64_t ChildSp;
    uint64_t ReturnAddress;
    uint64_t InstructionPointer;
    uint64_t Args[4];
    uint32_t ArgsValidMask;
    uint32_t HasReturn;
    char Symbol[HACDBG_CORE_SYMBOL_SIZE];
} HACDBG_CORE_STACK_FRAME;

/**
 * @brief Qwords on the paused thread's stack, read from an aligned RSP.
 *
 * @details Address is 8-byte aligned and is the first byte of Data. Rsp is the
 * paused stack pointer. BytesValid is the number of readable bytes in Data.
 */
typedef struct _HACDBG_CORE_STACK_WINDOW
{
    uint64_t Address;
    uint64_t Rsp;
    uint32_t BytesValid;
    uint32_t Reserved;
    uint8_t Data[HACDBG_CORE_MAX_MEMORY_BYTES];
} HACDBG_CORE_STACK_WINDOW;

typedef struct _HACDBG_CORE_MEMORY
{
    uint64_t Address;
    uint64_t Cr3;
    uint32_t Requested;
    uint32_t BytesValid;
    uint8_t Data[HACDBG_CORE_MAX_MEMORY_BYTES];
} HACDBG_CORE_MEMORY;

typedef struct _HACDBG_CORE_INSTRUCTION
{
    uint64_t Address;
    uint32_t Length;
    uint32_t Invalid;
    char Bytes[32];
    char Text[160];
    char Symbol[HACDBG_CORE_SYMBOL_SIZE];
} HACDBG_CORE_INSTRUCTION;

typedef struct _HACDBG_CORE_RESOLVED_ADDRESS
{
    uint64_t Address;
    char Symbol[HACDBG_CORE_SYMBOL_SIZE];
} HACDBG_CORE_RESOLVED_ADDRESS;

typedef struct HACDBG_CORE HACDBG_CORE;

/**
 * @brief Receives UTF-8 output from the core thread. The text is valid only
 * during the callback and must be copied before returning.
 */
typedef void (__cdecl *HACDBG_OUTPUT_CALLBACK)(uint32_t Kind, const char* Text, uint32_t Length, void* Context);

/**
 * @brief Returns HACDBG_CORE_API_VERSION.
 */
uint32_t HacDbgCoreApiVersion(void);

/**
 * @brief Returns sizeof(HACDBG_CORE_STATE) for the loaded DLL.
 */
uint32_t HacDbgCoreStateSize(void);

/**
 * @brief Returns sizeof() for one HACDBG_CORE_STRUCTURE, or zero when unknown.
 */
uint32_t HacDbgCoreStructureSize(uint32_t Structure);

/**
 * @brief Creates a core session. The callback may be null.
 */
HACDBG_CORE* HacDbgCoreCreate(HACDBG_OUTPUT_CALLBACK OutputCallback, void* Context);

/**
 * @brief Stops and frees a core session.
 */
void HacDbgCoreDestroy(HACDBG_CORE* Core);

/**
 * @brief Connects to the running driver and starts the core worker.
 * @return HacDbgCoreStatusOk on success; otherwise a HACDBG_CORE_STATUS.
 */
uint32_t HacDbgCoreStart(HACDBG_CORE* Core);

/**
 * @brief Stops the worker and releases debugger-side state.
 */
uint32_t HacDbgCoreStop(HACDBG_CORE* Core);

/**
 * @brief Queues one UTF-8 command line for the core thread.
 */
uint32_t HacDbgCoreExecute(HACDBG_CORE* Core, const char* Utf8Command);

/**
 * @brief Requests cancellation of the current long-running command.
 */
void HacDbgCoreCancel(HACDBG_CORE* Core);

/**
 * @brief Copies the latest state snapshot without entering the driver.
 */
uint32_t HacDbgCoreGetState(HACDBG_CORE* Core, HACDBG_CORE_STATE* StateOut);

/**
 * @brief Returns live symbol loading progress without entering the driver.
 */
uint32_t HacDbgCoreGetSymbolProgress(HACDBG_CORE* Core, HACDBG_CORE_SYMBOL_PROGRESS* ProgressOut);

/**
 * @brief Queues structured snapshot requests on the core worker.
 *
 * Each request returns a nonzero request id. A newer request of the same kind
 * replaces an older pending request. The data is copied only after
 * HacDbgCoreGetViewStatus reports the completed request id.
 */
uint64_t HacDbgCoreRequestModules(HACDBG_CORE* Core);
uint64_t HacDbgCoreRequestProcesses(HACDBG_CORE* Core);
uint64_t HacDbgCoreRequestThreads(HACDBG_CORE* Core, uint64_t Eprocess);
uint64_t HacDbgCoreRequestStack(HACDBG_CORE* Core, uint32_t FrameCount);
uint64_t HacDbgCoreRequestMemory(HACDBG_CORE* Core, uint64_t Address, uint64_t Cr3, uint32_t Size);
uint64_t HacDbgCoreRequestDisassembly(HACDBG_CORE* Core, uint64_t Address, uint64_t Cr3, uint32_t InstructionCount);
uint64_t HacDbgCoreRequestResolve(HACDBG_CORE* Core, const char* Utf8Text);

uint32_t HacDbgCoreGetViewStatus(HACDBG_CORE* Core, uint32_t View, HACDBG_CORE_VIEW_STATUS* StatusOut);
uint32_t HacDbgCoreCopyModules(HACDBG_CORE* Core, HACDBG_CORE_MODULE* Modules, uint32_t Capacity,
                               uint32_t* CountOut);
uint32_t HacDbgCoreCopyProcesses(HACDBG_CORE* Core, HACDBG_CORE_PROCESS* Processes, uint32_t Capacity,
                                 uint32_t* CountOut);
uint32_t HacDbgCoreCopyThreads(HACDBG_CORE* Core, HACDBG_CORE_THREAD* Threads, uint32_t Capacity,
                               uint32_t* CountOut);
uint32_t HacDbgCoreCopyStack(HACDBG_CORE* Core, HACDBG_CORE_STACK_FRAME* Frames, uint32_t Capacity,
                             uint32_t* CountOut);
uint32_t HacDbgCoreCopyStackWindow(HACDBG_CORE* Core, HACDBG_CORE_STACK_WINDOW* WindowOut);
uint32_t HacDbgCoreCopyMemory(HACDBG_CORE* Core, HACDBG_CORE_MEMORY* MemoryOut);
uint32_t HacDbgCoreCopyDisassembly(HACDBG_CORE* Core, HACDBG_CORE_INSTRUCTION* Instructions,
                                   uint32_t Capacity, uint32_t* CountOut);
uint32_t HacDbgCoreCopyResolvedAddress(HACDBG_CORE* Core, HACDBG_CORE_RESOLVED_ADDRESS* AddressOut);

/**
 * @brief Queues a trace_control request for the core worker.
 *
 * @details Flags use HACDBG_TRACE_CONTROL_*. The request is coalesced with any
 * pending trace control request. It is not a debugger command.
 */
uint32_t HacDbgCoreTraceControl(HACDBG_CORE* Core, uint32_t Flags, uint32_t SampleRate, uint32_t EventMask);

/**
 * @brief Requests a fresh trace_read snapshot on the core worker.
 */
uint32_t HacDbgCoreRequestTraceRead(HACDBG_CORE* Core);

/**
 * @brief Copies the latest trace status without entering the driver.
 */
uint32_t HacDbgCoreGetTraceStatus(HACDBG_CORE* Core, HACDBG_CORE_TRACE_STATUS* StatusOut);

/**
 * @brief Copies the latest complete trace snapshot without entering the driver.
 */
uint32_t HacDbgCoreCopyTraceSnapshot(HACDBG_CORE* Core, HACDBG_TRACE_SNAPSHOT* SnapshotOut);

/**
 * @brief One completion candidate. Text is a NUL-terminated UTF-8 string.
 */
typedef struct _HACDBG_CORE_COMPLETION
{
    char Text[HACDBG_CORE_COMPLETION_SIZE];
} HACDBG_CORE_COMPLETION;

/**
 * @brief Status of the latest completion request.
 *
 * @details Count is the number of candidates stored for copying. Total includes
 * candidates that were not stored because the buffer or text size was exceeded.
 */
typedef struct _HACDBG_CORE_COMPLETION_STATUS
{
    uint64_t RequestId;
    uint64_t CompletedRequestId;
    uint32_t Pending;
    uint32_t Failed;
    uint32_t Count;
    uint32_t Total;
} HACDBG_CORE_COMPLETION_STATUS;

/**
 * @brief Fills command-name completions for a token that does not contain '!'.
 *
 * @details Safe to call from any thread. It reads only the static command table
 * and does not enter the driver. A token containing '!' is rejected so symbol
 * lookup stays on the core worker.
 *
 * @param Utf8Token The current command token. An empty token returns every command name.
 * @param Items Caller-owned array of at least Capacity entries.
 * @param Capacity Number of entries in Items.
 * @param CountOut Receives the number of entries written.
 * @return HacDbgCoreStatusOk, or an error status. CountOut is unchanged on error.
 */
uint32_t HacDbgCoreCompleteCommands(const char* Utf8Token, HACDBG_CORE_COMPLETION* Items,
                                    uint32_t Capacity, uint32_t* CountOut);

/**
 * @brief Queues symbol or command completion for one token on the core worker.
 *
 * @details A newer request replaces an older pending request. The caller copies
 * the result only after HacDbgCoreGetCompletionStatus reports that request id
 * as completed. Symbol lookup may use the symbol parser and must not run on
 * the UI thread; this function only enqueues.
 *
 * @return Nonzero request id, or zero when the arguments or core state are invalid.
 */
uint64_t HacDbgCoreRequestCompletions(HACDBG_CORE* Core, const char* Utf8Token);

/**
 * @brief Copies the completion request status without entering the driver.
 */
uint32_t HacDbgCoreGetCompletionStatus(HACDBG_CORE* Core, HACDBG_CORE_COMPLETION_STATUS* StatusOut);

/**
 * @brief Copies candidates for a completed request id.
 *
 * @details Returns HacDbgCoreStatusState when RequestId is not the completed
 * id, or when a newer request is still pending. Names that do not fit in
 * HACDBG_CORE_COMPLETION_SIZE are omitted from the copy and remain in Total.
 */
uint32_t HacDbgCoreCopyCompletions(HACDBG_CORE* Core, uint64_t RequestId,
                                   HACDBG_CORE_COMPLETION* Items, uint32_t Capacity,
                                   uint32_t* CountOut);

/**
 * @brief One akh --monitor hook. Address is the hooked function. Hits is the
 * number of mailbox records matched since the hook was installed.
 */
typedef struct _HACDBG_CORE_MONITOR
{
    uint64_t Address;
    uint64_t Hits;
} HACDBG_CORE_MONITOR;

/**
 * @brief One monitor hit copied from the log mailbox. Rip is the address the
 * stub asked the driver to record, which is the function passed to akh.
 * Address is that same function. Stack is the five qwords that were on the
 * guest stack before the stub's pushes.
 */
typedef struct _HACDBG_CORE_MONITOR_HIT
{
    uint64_t Address;
    uint64_t Rip;
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Cr3;
    uint64_t Stack[HACDBG_CORE_MONITOR_STACK];
    uint64_t Sequence;
} HACDBG_CORE_MONITOR_HIT;

/**
 * @brief Copies the current akh --monitor hooks. Does not enter the driver.
 */
uint32_t HacDbgCoreCopyMonitors(HACDBG_CORE* Core, HACDBG_CORE_MONITOR* Items, uint32_t Capacity,
                                uint32_t* CountOut);

/**
 * @brief Copies and removes the oldest monitor hits waiting for the GUI.
 *
 * @details The monitor thread reads the log mailbox. Hits stay here until this
 * copy. The queue keeps the newest 8192 hits and reuses those slots. Sequence
 * is the capture count for that hit, starting at 1. NewestSequence receives
 * the highest sequence assigned so far, including hits the queue has already
 * overwritten, or 0 when none have been captured.
 */
uint32_t HacDbgCoreCopyMonitorHits(HACDBG_CORE* Core, HACDBG_CORE_MONITOR_HIT* Items, uint32_t Capacity,
                                   uint32_t* CountOut, uint64_t* NewestSequence);

#ifdef __cplusplus
}

static_assert(sizeof(HACDBG_CORE_TRACE_STATUS) == 80, "core trace status ABI changed");
static_assert(sizeof(HACDBG_CORE_COMPLETION) == 512, "core completion ABI changed");
static_assert(sizeof(HACDBG_CORE_COMPLETION_STATUS) == 32, "core completion status ABI changed");
static_assert(sizeof(HACDBG_CORE_MONITOR) == 16, "core monitor ABI changed");
static_assert(sizeof(HACDBG_CORE_MONITOR_HIT) == 200, "core monitor hit ABI changed");
static_assert(HACDBG_CORE_MONITOR_STACK == 5, "core monitor stack ABI changed");
#endif
