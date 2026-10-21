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

#include <intrin.h>

#define HACDBG_CR3_MASK         0xFFFFFFFFFFFFF000ull
#define HACDBG_LOG_POPPED_FIVE  5
#define HACDBG_LOG_POPPED_THREE 3
#define HACDBG_LOG_POPPED_ONE   1
#define HACDBG_RESERVED_MASK    0x1FFFFFFFFFull
#define HACDBG_KERNEL_VA_START  0xFFFF800000000000ull
#define HACDBG_SAFE_COPY_TAG    'ScaH'

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
static volatile LONG g_SafeCopyFailureLogCount;

// 只允许三环通过 IOCTL 发起的调用类型。
static BOOLEAN
HypercallIsIoctlAllowed(
    _In_ hypercall_type_t CallType
    )
{
    switch (CallType)
    {
    case guest_physical_memory_operation:
    case guest_virtual_memory_operation:
    case translate_guest_virtual_address:
    case read_guest_cr3:
    case add_slat_code_hook:
    case remove_slat_code_hook:
    case hide_guest_physical_page:
    case flush_logs:
    case get_heap_free_page_count:
    case flush_slat_cache:
    case breakpoint_resume:
        return TRUE;

    default:
        return FALSE;
    }
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
        SIZE_T bufferMappedSize = 0;
        SIZE_T guestMappedSize = 0;
        PUCHAR guestMapped;
        PUCHAR bufferMapped;
        PUCHAR destination;
        PUCHAR source;

        if (GuestVirtualToPhysical(CurrentCr3, guestVirtual, &bufferPhysical) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, physical copy buffer translation failed cr3=0x%I64x va=0x%I64x\n",
                     CurrentCr3, guestVirtual.Value);
            break;
        }

        chunk = min(limit - copied, PAGE_SIZE - (guestVirtual.Value & (PAGE_SIZE - 1)));
        chunk = min(chunk, PAGE_SIZE - (guestPhysical.Value & (PAGE_SIZE - 1)));
        chunk = min(chunk, PAGE_SIZE - (bufferPhysical.Value & (PAGE_SIZE - 1)));

        guestMapped = (PUCHAR)PhysicalMemoryMapTemporary(guestPhysical, (SIZE_T)chunk,
                                                         &guestMappedSize);
        if (guestMapped == NULL)
        {
            HACDBG_LOG("HacDbg: Err, physical copy source map failed pa=0x%I64x size=0x%I64x\n",
                     guestPhysical.Value, chunk);
            break;
        }

        bufferMapped = (PUCHAR)PhysicalMemoryMapTemporary(bufferPhysical, (SIZE_T)chunk,
                                                          &bufferMappedSize);
        if (bufferMapped == NULL)
        {
            HACDBG_LOG("HacDbg: Err, physical copy buffer map failed pa=0x%I64x size=0x%I64x\n",
                     bufferPhysical.Value, chunk);
            PhysicalMemoryUnmapTemporary(guestMapped, guestMappedSize);
            break;
        }

        chunk = min(chunk, (UINT64)guestMappedSize);
        chunk = min(chunk, (UINT64)bufferMappedSize);

        if (chunk == 0)
        {
            PhysicalMemoryUnmapTemporary(bufferMapped, bufferMappedSize);
            PhysicalMemoryUnmapTemporary(guestMapped, guestMappedSize);
            break;
        }

        if (Operation == memory_operation_t_READ)
        {
            destination = bufferMapped;
            source = guestMapped;
        }
        else
        {
            destination = guestMapped;
            source = bufferMapped;
        }

        RtlMoveMemory(destination, source, (SIZE_T)chunk);
        PhysicalMemoryUnmapTemporary(bufferMapped, bufferMappedSize);
        PhysicalMemoryUnmapTemporary(guestMapped, guestMappedSize);
        copied += chunk;
    }

    return copied;
}

// 在调用方上下文用 MmCopyMemory 读内核虚拟地址，避免手工遍历缺页。
static UINT64
HypercallCopyVirtualSafe(
    _In_ UINT64 DestinationVa,
    _In_ UINT64 SourceVa,
    _In_ UINT64 Size
    )
{
    SIZE_T allocationSize;
    PVOID temporary;
    UINT64 copied = 0;

    if (Size == 0 || KeGetCurrentIrql() > APC_LEVEL)
    {
        return 0;
    }

    allocationSize = (SIZE_T)min(Size, hypercall_memory_chunk_size);
    temporary = ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationSize, HACDBG_SAFE_COPY_TAG);
    if (temporary == NULL)
    {
        HACDBG_LOG("HacDbg: Err, safe virtual copy allocation failed size=0x%I64x.\n",
                 (UINT64)allocationSize);
        return 0;
    }

    while (copied < Size)
    {
        MM_COPY_ADDRESS source = { 0 };
        SIZE_T transferred = 0;
        SIZE_T chunk = (SIZE_T)min(Size - copied, (UINT64)allocationSize);
        NTSTATUS status;

        source.VirtualAddress = (PVOID)(ULONG_PTR)(SourceVa + copied);
        status = MmCopyMemory(temporary, source, chunk, MM_COPY_MEMORY_VIRTUAL, &transferred);
        if (!NT_SUCCESS(status) || transferred == 0)
        {
#if !HACDBG_DISABLE_DEBUG_LOG
            if (InterlockedIncrement(&g_SafeCopyFailureLogCount) <= 64)
            {
                HACDBG_LOG("HacDbg: Err, safe virtual read failed va=0x%I64x size=0x%I64x "
                         "status=0x%08x transferred=0x%I64x.\n",
                         SourceVa + copied, (UINT64)chunk, status, (UINT64)transferred);
            }
#endif
            break;
        }

        __try
        {
            ProbeForWrite((PVOID)(ULONG_PTR)(DestinationVa + copied), transferred, sizeof(UCHAR));
            RtlCopyMemory((PVOID)(ULONG_PTR)(DestinationVa + copied), temporary, transferred);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
#if !HACDBG_DISABLE_DEBUG_LOG
            if (InterlockedIncrement(&g_SafeCopyFailureLogCount) <= 64)
            {
                HACDBG_LOG("HacDbg: Err, safe virtual copy to user failed dest=0x%I64x size=0x%I64x.\n",
                         DestinationVa + copied, (UINT64)transferred);
            }
#endif
            break;
        }

        copied += transferred;
        if (transferred != chunk)
        {
            break;
        }
    }

    ExFreePoolWithTag(temporary, HACDBG_SAFE_COPY_TAG);

    return copied;
}

// 通用虚拟地址复制；当前 CR3 的内核读走安全路径，其余按页翻译。
static UINT64
HypercallCopyVirtual(
    _In_ UINT64 CurrentCr3,
    _In_ BOOLEAN SafeVirtualRead,
    _In_ UINT64 Operation,
    _In_ UINT64 DestinationOrSourceCr3,
    _In_ UINT64 First,
    _In_ UINT64 Second,
    _In_ UINT64 Size
    )
{
    UINT64 copied = 0;
    UINT64 limit = min(Size, hypercall_memory_chunk_size);

    if (Operation == memory_operation_t_READ && SafeVirtualRead != FALSE &&
        (CurrentCr3 & HACDBG_CR3_MASK) == (DestinationOrSourceCr3 & HACDBG_CR3_MASK) &&
        Second >= HACDBG_KERNEL_VA_START)
    {
        return HypercallCopyVirtualSafe(First, Second, limit);
    }

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
        SIZE_T destinationMappedSize = 0;
        SIZE_T sourceMappedSize = 0;
        PUCHAR source;
        PUCHAR destination;

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

        source = (PUCHAR)PhysicalMemoryMapTemporary(sourcePhysical, (SIZE_T)chunk,
                                                    &sourceMappedSize);
        if (source == NULL)
        {
            HACDBG_LOG("HacDbg: Err, virtual copy source map failed pa=0x%I64x size=0x%I64x\n",
                     sourcePhysical.Value, chunk);
            break;
        }

        destination = (PUCHAR)PhysicalMemoryMapTemporary(destinationPhysical, (SIZE_T)chunk,
                                                         &destinationMappedSize);
        if (destination == NULL)
        {
            HACDBG_LOG("HacDbg: Err, virtual copy destination map failed pa=0x%I64x size=0x%I64x\n",
                     destinationPhysical.Value, chunk);
            PhysicalMemoryUnmapTemporary(source, sourceMappedSize);
            break;
        }

        chunk = min(chunk, (UINT64)sourceMappedSize);
        chunk = min(chunk, (UINT64)destinationMappedSize);

        if (chunk == 0)
        {
            PhysicalMemoryUnmapTemporary(destination, destinationMappedSize);
            PhysicalMemoryUnmapTemporary(source, sourceMappedSize);
            break;
        }

        RtlMoveMemory(destination, source, (SIZE_T)chunk);
        PhysicalMemoryUnmapTemporary(destination, destinationMappedSize);
        PhysicalMemoryUnmapTemporary(source, sourceMappedSize);
        copied += chunk;
    }

    return copied;
}

// hypercall 分发表，CPUID 和 IOCTL 两条路径共用。
static VOID
HypercallExecute(
    _Inout_ HACDBG_GUEST_VIEW* GuestContext,
    _In_ UINT64 CurrentCr3,
    _In_ BOOLEAN SafeVirtualRead,
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
        result = HypercallCopyVirtual(CurrentCr3, SafeVirtualRead, operation, cr3,
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
        result = CurrentCr3;
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
        break;

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
        HypercallExecute(GuestContext, GuestContext->Cr3, FALSE, &information);
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

// IOCTL 入口：校验版本和类型后，用调用方 CR3 构造上下文执行。
NTSTATUS
HypercallHandleIoctl(
    _Inout_ HACDBG_HYPERCALL_REQUEST* Request
    )
{
    HACDBG_GUEST_REGISTERS registers = { 0 };
    HACDBG_GUEST_VIEW context = { 0 };
    hypercall_info_t information = { 0 };
    hypercall_type_t callType;

    if (Request == NULL || Request->Version != HACDBG_HYPERCALL_REQUEST_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }

    if (Request->CallType > 0xF || Request->Reserved > HACDBG_RESERVED_MASK)
    {
        return STATUS_INVALID_PARAMETER;
    }

    callType = (hypercall_type_t)Request->CallType;
    if (HypercallIsIoctlAllowed(callType) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, IOCTL hypercall type 0x%I64x is not allowed.\n", Request->CallType);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    information.call_type = callType;
    information.call_reserved_data = Request->Reserved;

    UINT64 currentCr3 = Request->ProcessCr3 != 0 ? Request->ProcessCr3 : __readcr3();

    registers.Rdx = Request->Rdx;
    registers.R8 = Request->R8;
    registers.R9 = Request->R9;
    context.Registers = &registers;

    //
    // The driver is both the control path and the SVM host, so this dispatch
    // costs no second VM exit. The synthetic context carries the caller's CR3
    // so buffer virtual addresses resolve like the CPUID path.
    //
    HypercallExecute(&context, currentCr3, TRUE, &information);

    Request->Result = registers.Rax;
    Request->Status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

