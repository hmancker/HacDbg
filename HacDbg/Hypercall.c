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
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#include "Vmx.h"
#define HacDbgSlatAddHook EptAddHook
#define HacDbgSlatRemoveHook EptRemoveHook
#define HacDbgSlatHidePage EptHidePage
#define HacDbgSlatFreePages EptFreeTableCount
#define HacDbgSlatFlush VmxFlushAllProcessors
#else
#include "Npt.h"
#include "Svm.h"
#define HacDbgSlatAddHook NptAddHook
#define HacDbgSlatRemoveHook NptRemoveHook
#define HacDbgSlatHidePage NptHidePage
#define HacDbgSlatFreePages NptFreeTableCount
#define HacDbgSlatFlush SvmFlushAllProcessors
#endif

#include "../shared/hypercall/hypercall_def.h"

#define HACDBG_CR3_MASK         0xFFFFFFFFFFFFF000ull
#define HACDBG_LOG_POPPED_FIVE  5
#define HACDBG_LOG_POPPED_THREE 3
#define HACDBG_LOG_POPPED_ONE   1

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
static HACDBG_SPIN_LOCK g_BreakpointLock;
static UINT64 g_KernelCr3;

//
// 记录内核页表根。三环 CPUID 退出时的客户 CR3 在 KPTI 下是用户目录，
// 不能用来翻译内核地址。
//
VOID
HypercallNoteKernelCr3(
    _In_ UINT64 Cr3
    )
{
    UINT64 directory = Cr3 & HACDBG_CR3_MASK;

    if (directory != 0)
    {
        g_KernelCr3 = directory;
    }
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
        HacDbgSpinLockRelease(&g_BreakpointLock);
        return 1;
    }

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

        if (GuestVirtualToPhysical(CurrentCr3, guestVirtual, &bufferPhysical) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, physical copy buffer translation failed cr3=0x%I64x va=0x%I64x\n",
                     CurrentCr3, guestVirtual.Value);
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

        if (GuestVirtualToPhysical(destinationCr3, HacDbgGuestVirtualAddress(destinationVa + copied),
                                   &destinationPhysical) == FALSE ||
            GuestVirtualToPhysical(sourceCr3, HacDbgGuestVirtualAddress(sourceVa + copied),
                                   &sourcePhysical) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, virtual copy translation failed dest_cr3=0x%I64x dest_va=0x%I64x "
                     "src_cr3=0x%I64x src_va=0x%I64x\n",
                     destinationCr3, destinationVa + copied, sourceCr3, sourceVa + copied);
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
        if (GuestVirtualToPhysical(registers->R8, HacDbgGuestVirtualAddress(registers->Rdx), &physical) != FALSE)
        {
            result = physical.Value;
        }
        break;
    }

    case read_guest_cr3:
        result = g_KernelCr3;
        break;

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
        if (GuestContext->InGuest == FALSE)
        {
            break;
        }

        if ((Information->call_reserved_data & hypercall_log_breakpoint_flag) != 0)
        {
            HypercallLogState(GuestContext, HACDBG_LOG_POPPED_THREE, registers->R8, registers->Rdx);
        }
        else
        {
            HypercallLogState(GuestContext, HACDBG_LOG_POPPED_ONE, GuestContext->Rip, 0);
        }
        break;

    case flush_logs:
        result = LogsFlush(CurrentCr3, HacDbgGuestVirtualAddress(registers->Rdx), registers->R8);
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
        if (g_BreakpointPauseActive != FALSE)
        {
            g_BreakpointGoRequested = TRUE;
        }
        HacDbgSpinLockRelease(&g_BreakpointLock);
        break;
    }

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
#endif
    }
}

