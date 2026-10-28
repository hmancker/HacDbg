/**
 * @file Hypercall.c
 * @brief CPUID hypercall and guest memory operations.
 *
 * @author HacDbg
 */

#include "Hypercall.h"
#include "Debug.h"
#include "Logs.h"
#include "PhysicalMemory.h"
#include "Trace.h"
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#include "Vmx.h"
#define HacDbgSlatAddHook EptAddHook
#define HacDbgSlatRemoveHook EptRemoveHook
#define HacDbgSlatHidePage EptHidePage
#define HacDbgSlatFreePages EptFreeTableCount
#define HacDbgSlatFlush VmxFlushAllProcessors
#define HacDbgSlatContainsShadow EptContainsShadowPage
#define HacDbgSlatContainsHookTarget EptContainsHookTarget
#define HacDbgSlatContainsHidden EptContainsHiddenPage
#else
#include "Npt.h"
#include "Svm.h"
#define HacDbgSlatAddHook NptAddHook
#define HacDbgSlatRemoveHook NptRemoveHook
#define HacDbgSlatHidePage NptHidePage
#define HacDbgSlatFreePages NptFreeTableCount
#define HacDbgSlatFlush SvmFlushAllProcessors
#define HacDbgSlatContainsShadow NptContainsShadowPage
#define HacDbgSlatContainsHookTarget NptContainsHookTarget
#define HacDbgSlatContainsHidden NptContainsHiddenPage
#endif

#include "../shared/hypercall/hypercall_def.h"

#define HACDBG_CR3_MASK         0xFFFFFFFFFFFFF000ull
#define HACDBG_LOG_POPPED_FIVE  5
#define HACDBG_LOG_POPPED_THREE 3
#define HACDBG_LOG_POPPED_ONE   1
#define HACDBG_COPY_FAILURE_LOG_LIMIT 64

C_ASSERT(sizeof(hypercall_info_t) == sizeof(UINT64));
C_ASSERT(sizeof(trap_frame_log_t) == 0xb8);
C_ASSERT(sizeof(HACDBG_HYPERCALL_REQUEST) == 0x40);

typedef struct _SVM_CPUID_REGISTERS
{
    UINT32 Eax;
    UINT32 Ebx;
    UINT32 Ecx;
    UINT32 Edx;
} SVM_CPUID_REGISTERS;

static BOOLEAN g_BreakpointPauseActive;
static BOOLEAN g_BreakpointGoRequested;
static UINT64 g_BreakpointOwnerRsp;
static UINT64 g_BreakpointOwnerCr3;
static UINT64 g_BreakpointLatchPa;
static volatile LONG g_BreakpointLatchLogs;
static HACDBG_SPIN_LOCK g_BreakpointLock;
static UINT64 g_KernelCr3;
static volatile LONG g_VirtualCopyFailureLogCount;

//
// 记录内核页表根。三环 CPUID 退出时的客户 CR3 在 KPTI 下是用户目录，
// 不能用来翻译内核地址。系统进程目录也没有会话空间，所以每个不同的
// CPL 0 目录都留一份，供 win32k 这类地址改用。
//
VOID
HypercallNoteKernelCr3(
    _In_ UINT64 Cr3
    )
{
    UINT64 directory = Cr3 & HACDBG_CR3_MASK;

    if (directory == 0 || directory == g_KernelCr3)
    {
        return;
    }

    //
    // VM-exit does not load host CR8, so this runs at the guest IRQL. The
    // image-slot read uses the temporary map, which stops above
    // DISPATCH_LEVEL. Skip the directory until an exit at DISPATCH_LEVEL or
    // below can check it. Do not log: the virtualization IPI exits at
    // HIGH_LEVEL and would otherwise report every new kernel CR3.
    //
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
        return;
    }

    //
    // INVARIANT: directory is a guest CR3 page. The kernel image slot is
    // read through the temporary RAM map and is not a guest-visible host page.
    //
    if (PhysicalMemoryMapsKernelImage(directory) == FALSE)
    {
        return;
    }

    g_KernelCr3 = directory;
    PhysicalMemoryRememberKernelDirectory(directory);
}

static VOID
HypercallFillVersion(
    _Out_ HACDBG_VERSION_INFO* Info
    )
{
    RtlZeroMemory(Info, sizeof(*Info));
    Info->Major = HACDBG_VERSION_MAJOR;
    Info->Minor = HACDBG_VERSION_MINOR;
    Info->Patch = HACDBG_VERSION_PATCH;
    Info->HypercallAbiVersion = HACDBG_HYPERCALL_REQUEST_VERSION;
    RtlCopyMemory(Info->VersionString, HACDBG_VERSION_STRING, sizeof(HACDBG_VERSION_STRING));
}

// 复位断点暂停状态。
VOID
HypercallInitialize(
    VOID
    )
{
    g_BreakpointPauseActive = FALSE;
    g_BreakpointGoRequested = FALSE;
    g_BreakpointOwnerRsp = 0;
    g_BreakpointOwnerCr3 = 0;
    g_BreakpointLatchPa = 0;
    g_BreakpointLatchLogs = 0;
    HacDbgSpinLockInitialize(&g_BreakpointLock);
}

// 追加一条断点日志，并按需从客户栈补回被 pop 的寄存器。
static VOID
HypercallCopyStack(
    _In_ HACDBG_GUEST_VIEW* GuestContext,
    _Inout_ trap_frame_log_t* Log,
    _In_ UINT64 PoppedCount
    )
{
    UINT64 values[trap_frame_log_stack_data_count + 5] = { 0 };
    UINT64 index;
    UINT64 total = trap_frame_log_stack_data_count + PoppedCount;

    if (PoppedCount > 5 || Log->rsp == 0)
    {
        return;
    }

    GuestVirtualRead(Log->cr3, HacDbgGuestVirtualAddress(Log->rsp), values, total * sizeof(UINT64));

    for (index = 0; index < trap_frame_log_stack_data_count; index++)
    {
        Log->stack_data[index] = values[index + PoppedCount];
    }

    if (PoppedCount == 5)
    {
        Log->r11 = values[0];
        Log->r8 = values[1];
        Log->rdx = values[2];
        Log->rcx = values[3];
        Log->rax = values[4];
    }
    else if (PoppedCount == 3)
    {
        Log->r8 = values[0];
        Log->rdx = values[1];
        Log->rcx = values[2];
    }
    else if (PoppedCount == 1)
    {
        Log->rcx = values[0];
    }

    Log->rsp += PoppedCount * sizeof(UINT64);
    Log->cr3 = GuestContext->Cr3;
}

// 记录一份完整的陷阱帧。
static VOID
HypercallLogState(
    _In_ HACDBG_GUEST_VIEW* GuestContext,
    _In_ UINT64 PoppedCount,
    _In_ UINT64 LogRip,
    _In_ UINT64 Cr3Filter
    )
{
    trap_frame_log_t log;
    HACDBG_GUEST_REGISTERS* registers = GuestContext->Registers;
    UINT64 guestCr3 = GuestContext->Cr3;

    if (Cr3Filter != 0 && (guestCr3 & HACDBG_CR3_MASK) != (Cr3Filter & HACDBG_CR3_MASK))
    {
        return;
    }

    RtlZeroMemory(&log, sizeof(log));
    log.rax = registers->Rax;
    log.rcx = registers->Rcx;
    log.rdx = registers->Rdx;
    log.rbx = registers->Rbx;
    log.rsp = registers->Rsp;
    log.rbp = registers->Rbp;
    log.rsi = registers->Rsi;
    log.rdi = registers->Rdi;
    log.r8 = registers->R8;
    log.r9 = registers->R9;
    log.r10 = registers->R10;
    log.r11 = registers->R11;
    log.r12 = registers->R12;
    log.r13 = registers->R13;
    log.r14 = registers->R14;
    log.r15 = registers->R15;
    log.rip = LogRip;
    log.cr3 = guestCr3;

    HypercallCopyStack(GuestContext, &log, PoppedCount);
    LogsAdd(&log);
}

// 暂停闩要么在活动钩子影子页里，要么紧跟 HACLATCH 且该页不是钩子目标。
static BOOLEAN
HypercallLatchIsAccepted(
    _In_ UINT64 LatchPa
    )
{
    UINT64 offset = LatchPa & (PAGE_SIZE - 1);
    UINT64 page = LatchPa & ~(PAGE_SIZE - 1);
    UINT64 signature = 0;

    if (LatchPa == 0 || offset > PAGE_SIZE - sizeof(UINT64))
    {
        return FALSE;
    }

    if (HacDbgSlatContainsShadow(page) != FALSE)
    {
        return TRUE;
    }

    if (offset < sizeof(UINT64) || HacDbgSlatContainsHookTarget(page) != FALSE ||
        HacDbgSlatContainsHidden(page) != FALSE)
    {
        return FALSE;
    }

    //
    // INVARIANT: LatchPa - 8 and LatchPa are in the same locked RAM page.
    // The page is not an execute-hook target, so the main SLAT root maps it
    // identity and the parked guest reads this signature.
    //
    if (PhysicalMemoryRead(HacDbgGuestPhysicalAddress(LatchPa - sizeof(UINT64)), &signature,
                           sizeof(signature)) != sizeof(signature))
    {
        return FALSE;
    }

    return signature == pause_latch_signature;
}

static VOID
HypercallRememberLatch(
    _In_ UINT64 LatchPa
    )
{
    if (HypercallLatchIsAccepted(LatchPa) == FALSE)
    {
        g_BreakpointLatchPa = 0;

        if (InterlockedIncrement(&g_BreakpointLatchLogs) <= 4)
        {
            HACDBG_LOG("HacDbg: Err, breakpoint latch was rejected pa=0x%I64x.\n", LatchPa);
        }

        return;
    }

    g_BreakpointLatchPa = LatchPa;
}

// 置放行位，并把暂停闩写成 1。调用方持有 g_BreakpointLock。
static VOID
HypercallPublishLatch(
    VOID
    )
{
    UINT64 latchPa = g_BreakpointLatchPa;
    UINT64 value = 1;

    g_BreakpointGoRequested = TRUE;

    if (HypercallLatchIsAccepted(latchPa) == FALSE)
    {
        if (InterlockedIncrement(&g_BreakpointLatchLogs) <= 4)
        {
            HACDBG_LOG("HacDbg: Err, breakpoint latch was rejected pa=0x%I64x.\n", latchPa);
        }

        return;
    }

    //
    // INVARIANT: latchPa is an 8-byte pause latch in locked host RAM. It is
    // either an active hook shadow or the qword after HACLATCH on a page the
    // main SLAT root maps identity. The parked guest reads that same qword.
    //
    if (PhysicalMemoryWrite(HacDbgGuestPhysicalAddress(latchPa), &value, sizeof(value)) != sizeof(value) &&
        InterlockedIncrement(&g_BreakpointLatchLogs) <= 4)
    {
        HACDBG_LOG("HacDbg: Err, breakpoint latch write failed pa=0x%I64x.\n", latchPa);
    }
}

// 断点 stub 轮询：首次命中挂起，收到放行后返回 1。
static UINT64
HypercallBreakpointPausePoll(
    _Inout_ HACDBG_GUEST_VIEW* GuestContext
    )
{
    UINT64 cr3Filter = GuestContext->Registers->Rdx;
    UINT64 breakpointRip = GuestContext->Registers->R8;
    UINT64 guestCr3 = GuestContext->Cr3;
    UINT64 guestRsp = GuestContext->Registers->Rsp;
    BOOLEAN owner;

    if (cr3Filter != 0 && (guestCr3 & HACDBG_CR3_MASK) != (cr3Filter & HACDBG_CR3_MASK))
    {
        return 1;
    }

    HacDbgSpinLockAcquire(&g_BreakpointLock);

    owner = g_BreakpointPauseActive != FALSE && guestRsp == g_BreakpointOwnerRsp &&
            (guestCr3 & HACDBG_CR3_MASK) == (g_BreakpointOwnerCr3 & HACDBG_CR3_MASK);

    if (g_BreakpointPauseActive == FALSE)
    {
        g_BreakpointPauseActive = TRUE;
        g_BreakpointGoRequested = FALSE;
        g_BreakpointOwnerRsp = guestRsp;
        g_BreakpointOwnerCr3 = guestCr3;
        HypercallRememberLatch(GuestContext->Registers->R9);
        HacDbgSpinLockRelease(&g_BreakpointLock);
        HypercallLogState(GuestContext, HACDBG_LOG_POPPED_FIVE, breakpointRip, 0);
        return 0;
    }

    if (owner == FALSE)
    {
        HacDbgSpinLockRelease(&g_BreakpointLock);
        return 1;
    }

    if (g_BreakpointGoRequested != FALSE)
    {
        g_BreakpointPauseActive = FALSE;
        g_BreakpointGoRequested = FALSE;
        g_BreakpointOwnerRsp = 0;
        g_BreakpointOwnerCr3 = 0;
        g_BreakpointLatchPa = 0;
        HacDbgSpinLockRelease(&g_BreakpointLock);
        return 1;
    }

    HypercallRememberLatch(GuestContext->Registers->R9);
    HacDbgSpinLockRelease(&g_BreakpointLock);
    return 0;
}

// 按客户物理地址复制，客户缓冲区用给定 CR3 翻译。
static UINT64
HypercallCopyPhysical(
    _In_ UINT64 CurrentCr3,
    _In_ UINT64 Operation,
    _In_ UINT64 GuestPhysical,
    _In_ UINT64 GuestVirtual,
    _In_ UINT64 Size
    )
{
    UINT64 limit = min(Size, hypercall_memory_chunk_size);
    UINT64 copied = 0;

    while (copied < limit)
    {
        if (GuestPhysical + copied < GuestPhysical || GuestVirtual + copied < GuestVirtual)
        {
            break;
        }

        GUEST_PHYSICAL_ADDRESS bufferPhysical;
        GUEST_PHYSICAL_ADDRESS guestPhysical = HacDbgGuestPhysicalAddress(GuestPhysical + copied);
        GUEST_VIRTUAL_ADDRESS guestVirtual = HacDbgGuestVirtualAddress(GuestVirtual + copied);
        UINT64 chunk;

        BOOLEAN bufferAbsent = FALSE;

        if (GuestVirtualToPhysical(CurrentCr3, guestVirtual, &bufferPhysical, &bufferAbsent) == FALSE)
        {
            if (bufferAbsent == FALSE)
            {
                HACDBG_LOG("HacDbg: Err, physical copy buffer translation failed cr3=0x%I64x va=0x%I64x\n",
                         CurrentCr3, guestVirtual.Value);
            }

            break;
        }

        chunk = min(limit - copied, PAGE_SIZE - (guestVirtual.Value & (PAGE_SIZE - 1)));
        chunk = min(chunk, PAGE_SIZE - (guestPhysical.Value & (PAGE_SIZE - 1)));
        chunk = min(chunk, PAGE_SIZE - (bufferPhysical.Value & (PAGE_SIZE - 1)));

        {
            UCHAR bounce[PAGE_SIZE];
            GUEST_PHYSICAL_ADDRESS from;
            GUEST_PHYSICAL_ADDRESS to;
            SIZE_T got;
            SIZE_T put;

            if (Operation == memory_operation_t_READ)
            {
                from = guestPhysical;
                to = bufferPhysical;
            }
            else
            {
                from = bufferPhysical;
                to = guestPhysical;
            }

            got = PhysicalMemoryRead(from, bounce, (SIZE_T)chunk);
            if (got == 0)
            {
                HACDBG_LOG("HacDbg: Err, physical copy read failed pa=0x%I64x size=0x%I64x\n",
                         from.Value, chunk);
                break;
            }

            put = PhysicalMemoryWrite(to, bounce, got);
            if (put == 0)
            {
                HACDBG_LOG("HacDbg: Err, physical copy write failed pa=0x%I64x size=0x%I64x\n",
                         to.Value, (UINT64)got);
                break;
            }

            copied += put;
            if (put != chunk)
            {
                break;
            }
        }
    }

    return copied;
}

// 按客户页表翻译两侧虚拟地址。调用发生在 CPUID 退出里。
static UINT64
HypercallCopyVirtual(
    _In_ UINT64 CurrentCr3,
    _In_ UINT64 Operation,
    _In_ UINT64 DestinationOrSourceCr3,
    _In_ UINT64 First,
    _In_ UINT64 Second,
    _In_ UINT64 Size
    )
{
    UINT64 copied = 0;
    UINT64 limit = min(Size, hypercall_memory_chunk_size);

    while (copied < limit)
    {
        if (First + copied < First || Second + copied < Second)
        {
            break;
        }

        UINT64 destinationCr3 = Operation == memory_operation_t_READ ? CurrentCr3 : DestinationOrSourceCr3;
        UINT64 sourceCr3 = Operation == memory_operation_t_READ ? DestinationOrSourceCr3 : CurrentCr3;
        UINT64 destinationVa = Operation == memory_operation_t_READ ? First : Second;
        UINT64 sourceVa = Operation == memory_operation_t_READ ? Second : First;
        GUEST_PHYSICAL_ADDRESS destinationPhysical;
        GUEST_PHYSICAL_ADDRESS sourcePhysical;
        UINT64 virtualPageLeft;
        UINT64 chunk;

        BOOLEAN destinationAbsent = FALSE;
        BOOLEAN sourceAbsent = FALSE;

        if (GuestVirtualToPhysical(destinationCr3, HacDbgGuestVirtualAddress(destinationVa + copied),
                                   &destinationPhysical, &destinationAbsent) == FALSE ||
            GuestVirtualToPhysical(sourceCr3, HacDbgGuestVirtualAddress(sourceVa + copied),
                                   &sourcePhysical, &sourceAbsent) == FALSE)
        {
            if (destinationAbsent == FALSE && sourceAbsent == FALSE &&
                InterlockedIncrement(&g_VirtualCopyFailureLogCount) <= HACDBG_COPY_FAILURE_LOG_LIMIT)
            {
                HACDBG_LOG("HacDbg: Err, virtual copy translation failed dest_cr3=0x%I64x dest_va=0x%I64x "
                         "src_cr3=0x%I64x src_va=0x%I64x\n",
                         destinationCr3, destinationVa + copied, sourceCr3, sourceVa + copied);
            }

            break;
        }

        virtualPageLeft = PAGE_SIZE - ((destinationVa + copied) & (PAGE_SIZE - 1));
        chunk = min(limit - copied, virtualPageLeft);
        virtualPageLeft = PAGE_SIZE - ((sourceVa + copied) & (PAGE_SIZE - 1));
        chunk = min(chunk, virtualPageLeft);
        chunk = min(chunk, PAGE_SIZE - (destinationPhysical.Value & (PAGE_SIZE - 1)));
        chunk = min(chunk, PAGE_SIZE - (sourcePhysical.Value & (PAGE_SIZE - 1)));

        {
            UCHAR bounce[PAGE_SIZE];
            SIZE_T got;
            SIZE_T put;

            got = PhysicalMemoryRead(sourcePhysical, bounce, (SIZE_T)chunk);
            if (got == 0)
            {
                HACDBG_LOG("HacDbg: Err, virtual copy read failed pa=0x%I64x size=0x%I64x\n",
                         sourcePhysical.Value, chunk);
                break;
            }

            put = PhysicalMemoryWrite(destinationPhysical, bounce, got);
            if (put == 0)
            {
                HACDBG_LOG("HacDbg: Err, virtual copy write failed pa=0x%I64x size=0x%I64x\n",
                         destinationPhysical.Value, (UINT64)got);
                break;
            }

            copied += put;
            if (put != chunk)
            {
                break;
            }
        }
    }

    return copied;
}

// CPUID 退出里的 hypercall 分发表。
static VOID
HypercallExecute(
    _Inout_ HACDBG_GUEST_VIEW* GuestContext,
    _In_ UINT64 CurrentCr3,
    _In_ const hypercall_info_t* Information
    )
{
    HACDBG_GUEST_REGISTERS* registers = GuestContext->Registers;
    UINT64 result = 0;

    switch (Information->call_type)
    {
    case guest_physical_memory_operation:
        result = HypercallCopyPhysical(CurrentCr3, Information->call_reserved_data, registers->Rdx,
                                       registers->R8, registers->R9);
        break;

    case guest_virtual_memory_operation:
    {
        UINT64 operation = Information->call_reserved_data & 1;
        UINT64 cr3 = ((Information->call_reserved_data >> 1) & 0xFFFFFFFFFull) << PAGE_SHIFT;
        result = HypercallCopyVirtual(CurrentCr3, operation, cr3,
                                      registers->Rdx, registers->R8,
                                      registers->R9);
        break;
    }

    case translate_guest_virtual_address:
    {
        GUEST_PHYSICAL_ADDRESS physical = { 0 };
        if (GuestVirtualToPhysical(registers->R8, HacDbgGuestVirtualAddress(registers->Rdx), &physical,
                                   NULL) != FALSE)
        {
            result = physical.Value;
        }
        break;
    }

    case read_guest_cr3:
    {
        UINT64 selected = PhysicalMemorySelectLiveKernelDirectory(g_KernelCr3);

        if (selected != g_KernelCr3)
        {
            g_KernelCr3 = selected;
        }

        if (g_KernelCr3 == 0)
        {
            HACDBG_LOG("HacDbg: Err, read_guest_cr3 has no kernel directory current=0x%I64x.\n",
                     CurrentCr3);
        }

        result = g_KernelCr3;
        break;
    }

    case add_slat_code_hook:
        result = HacDbgSlatAddHook(HacDbgGuestPhysicalAddress(registers->Rdx),
                                   HacDbgGuestPhysicalAddress(registers->R8)) != FALSE;
        if (result != 0)
        {
            HacDbgSlatFlush();
        }
        break;

    case remove_slat_code_hook:
        result = HacDbgSlatRemoveHook(HacDbgGuestPhysicalAddress(registers->Rdx)) != FALSE;
        if (result != 0)
        {
            HacDbgSlatFlush();
        }
        break;

    case hide_guest_physical_page:
        result = HacDbgSlatHidePage(HacDbgGuestPhysicalAddress(registers->Rdx)) != FALSE;
        if (result != 0)
        {
            HacDbgSlatFlush();
        }
        break;

    case log_current_state:
    {
        UINT64 logRip = 0;

        if (GuestContext->InGuest == FALSE)
        {
            break;
        }

        if ((Information->call_reserved_data & hypercall_log_breakpoint_flag) != 0)
        {
            logRip = registers->R8;
            HypercallLogState(GuestContext, HACDBG_LOG_POPPED_THREE, logRip, registers->Rdx);
        }
        else
        {
            logRip = GuestContext->Rip;
            HypercallLogState(GuestContext, HACDBG_LOG_POPPED_ONE, logRip, 0);
        }

        HACDBG_LOG("HacDbg: monitor rip=0x%I64x cr3=0x%I64x.\n", logRip, GuestContext->Cr3);

        break;
    }

    case flush_logs:
        if (Information->call_reserved_data == flush_logs_register_mailbox)
        {
            result = LogsRegisterMailbox(CurrentCr3, registers->Rdx);
        }
        else if (Information->call_reserved_data == flush_logs_unregister_mailbox)
        {
            result = LogsUnregisterMailbox();
        }
        else if (Information->call_reserved_data == 0)
        {
            result = LogsFlush(CurrentCr3, HacDbgGuestVirtualAddress(registers->Rdx), registers->R8);
        }

        break;

    case get_heap_free_page_count:
        result = HacDbgSlatFreePages();
        break;

    case flush_slat_cache:
        HacDbgSlatFlush();
        result = 1;
        break;

    case query_hypervisor_version:
    {
        HACDBG_VERSION_INFO info;

        if (registers->R8 < sizeof(info) || registers->Rdx == 0)
        {
            break;
        }

        HypercallFillVersion(&info);
        result = GuestVirtualWrite(CurrentCr3, HacDbgGuestVirtualAddress(registers->Rdx),
                                   &info, sizeof(info));
        break;
    }

    case breakpoint_pause_poll:
        result = GuestContext->InGuest == FALSE ? 0 : HypercallBreakpointPausePoll(GuestContext);
        break;

    case breakpoint_resume:
    {
        HacDbgSpinLockAcquire(&g_BreakpointLock);

        if (Information->call_reserved_data == breakpoint_resume_abandon)
        {
            //
            // The owner thread is gone. Publishing the latch would wait forever
            // for a confirmation CPUID that never comes, and every later hit
            // would be treated as a non-owner and would not pause.
            //
            g_BreakpointPauseActive = FALSE;
            g_BreakpointGoRequested = FALSE;
            g_BreakpointOwnerRsp = 0;
            g_BreakpointOwnerCr3 = 0;
            g_BreakpointLatchPa = 0;
            result = 1;
        }
        else if (g_BreakpointPauseActive != FALSE)
        {
            HypercallPublishLatch();
            result = 1;
        }

        HacDbgSpinLockRelease(&g_BreakpointLock);
        break;
    }

    case trace_control:
        result = TraceControl(registers->Rdx, registers->R8, registers->R9);
        break;

    case trace_read:
        result = TraceRead(CurrentCr3, HacDbgGuestVirtualAddress(registers->Rdx),
                           registers->R8, registers->R9);
        break;

    default:
        break;
    }

    registers->Rax = result;
}

// CPUID 入口：命中调用描述则分派，否则透传真实 CPUID。
VOID
HypercallHandleCpuid(
    _Inout_ HACDBG_GUEST_VIEW* GuestContext
    )
{
    hypercall_info_t information = { 0 };
    SVM_CPUID_REGISTERS registers;
    UINT32 subLeaf = (UINT32)GuestContext->Registers->Rcx;
    UINT32 leaf = (UINT32)GuestContext->Registers->Rax;

    information.value = GuestContext->Registers->Rcx;

    if (information.primary_key == hypercall_primary_key &&
        information.secondary_key == hypercall_secondary_key)
    {
        HypercallExecute(GuestContext, GuestContext->Cr3, &information);
    }
    else
    {
        __cpuidex((int*)&registers, (int)leaf, (int)subLeaf);
        GuestContext->Registers->Rax = registers.Eax;
        GuestContext->Registers->Rbx = registers.Ebx;
        GuestContext->Registers->Rcx = registers.Ecx;
        GuestContext->Registers->Rdx = registers.Edx;
#if HACDBG_BACKEND_INTEL
        VmxConcealCpuid(leaf, GuestContext->Registers);
#else
        SvmConcealCpuid(leaf, GuestContext->Registers);
#endif
    }
}

