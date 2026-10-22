/**
 * @file Svm.c
 * @brief SVM setup, VMEXIT handling, and processor state.
 *
 * @author HacDbg
 */

#include "Svm.h"
#include "Debug.h"
#include "Hypercall.h"
#include "Npt.h"
#include "PhysicalMemory.h"

#include <intrin.h>

#define HACDBG_SVM_TAG              'VcaH'
#define HACDBG_HOST_STACK_SIZE      0x8000
#define HACDBG_MAX_PROCESSORS       256
#define HACDBG_MSR_EFER             0xc0000080ull
#define HACDBG_MSR_PAT              0x277ull
#define HACDBG_EFER_LME             (1ull << 8)
#define HACDBG_EFER_LMA             (1ull << 10)
#define HACDBG_EFER_NXE             (1ull << 11)
#define HACDBG_EFER_SVME            (1ull << 12)

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER;
#pragma pack(pop)

C_ASSERT(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10);

static SVM_PROCESSOR_CONTEXT* g_Processors[HACDBG_MAX_PROCESSORS];
static HACDBG_SPIN_LOCK g_ProcessorLock;
static BOOLEAN g_ProcessorTableReady;
static PVOID g_MsrpmAllocation;
static PVOID g_Msrpm;
static UINT64 g_MsrpmPa;
static ULONG g_SharedFailureDetail;

EXTERN_C VOID
SvmLaunchVm(
    _In_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ PVOID HostStackTop
    );

C_ASSERT(sizeof(SVM_GUEST_REGISTERS) == sizeof(HACDBG_GUEST_REGISTERS));
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rax) == FIELD_OFFSET(HACDBG_GUEST_REGISTERS, Rax));
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R15) == FIELD_OFFSET(HACDBG_GUEST_REGISTERS, R15));
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rax) == 0x00);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rcx) == 0x08);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rdx) == 0x10);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rbx) == 0x18);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rsp) == 0x20);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rbp) == 0x28);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rsi) == 0x30);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, Rdi) == 0x38);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R8) == 0x40);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R9) == 0x48);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R10) == 0x50);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R11) == 0x58);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R12) == 0x60);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R13) == 0x68);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R14) == 0x70);
C_ASSERT(FIELD_OFFSET(SVM_GUEST_REGISTERS, R15) == 0x78);
C_ASSERT(sizeof(SVM_GUEST_REGISTERS) == 0x80);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, GuestVmcbPa) == 0x40);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, HostVmcbPa) == 0x48);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, Virtualized) == 0x50);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, StopRequested) == 0x51);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, LaunchCompleted) == 0x52);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, Registers) == 0x58);
C_ASSERT(FIELD_OFFSET(SVM_PROCESSOR_CONTEXT, TlbFlushRequested) == 0xD8);
C_ASSERT(sizeof(SVM_PROCESSOR_CONTEXT) == 0xE0);

// 分配非分页内存并返回 4 KiB 对齐的首地址，原指针写入 AllocationBase。
static PVOID
SvmAllocateAligned(
    _In_ SIZE_T Size,
    _Out_ PVOID* AllocationBase
    )
{
    PVOID allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size + PAGE_SIZE, HACDBG_SVM_TAG);
    PVOID aligned;

    if (allocation == NULL)
    {
        *AllocationBase = NULL;
        return NULL;
    }

    aligned = (PVOID)(((ULONG_PTR)allocation + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    RtlZeroMemory(aligned, Size);
    *AllocationBase = allocation;
    return aligned;
}

// 从 GDT 描述符取出段属性字段。
static UINT16
SvmSegmentAttributes(
    _In_ UINT16 Selector,
    _In_ UINT64 GdtBase
    )
{
    UINT64 descriptor;

    if ((Selector & 0xfff8u) == 0)
    {
        return 0;
    }

    descriptor = *(UINT64*)(ULONG_PTR)(GdtBase + (Selector & 0xfff8u));
    return (UINT16)(((descriptor >> 40) & 0xffu) | (((descriptor >> 52) & 0xfu) << 8));
}

// 从 GDT 描述符取出段界限，展开粒度位。
static UINT32
SvmSegmentLimit(
    _In_ UINT16 Selector,
    _In_ UINT64 GdtBase
    )
{
    UINT64 descriptor;
    UINT32 limit;

    if ((Selector & 0xfff8u) == 0)
    {
        return 0;
    }

    descriptor = *(UINT64*)(ULONG_PTR)(GdtBase + (Selector & 0xfff8u));
    limit = (UINT32)(descriptor & 0xffffu);
    limit |= (UINT32)((descriptor >> 48) & 0xfu) << 16;

    if ((descriptor & (1ull << 55)) != 0)
    {
        limit = (limit << 12) | 0xfffu;
    }

    return limit;
}

// 检查 CPUID 中的 SVM/NPT 支持位和 VM_CR.SVMDIS。
NTSTATUS
SvmCheckSupport(
    VOID
    )
{
    int registers[4];
    UINT64 vmCr;

    __cpuid(registers, 0);
    if (registers[1] != 'htuA' || registers[3] != 'itne' || registers[2] != 'DMAc')
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    __cpuid(registers, 0x80000001);
    if ((registers[2] & (1 << 2)) == 0 || (registers[3] & (1 << 20)) == 0)
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    __cpuid(registers, 0x8000000a);
    if ((registers[3] & (1 << 0)) == 0)
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    vmCr = __readmsr(SVM_MSR_VM_CR);
    if ((vmCr & SVM_VM_CR_SVMDIS) != 0)
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    return STATUS_SUCCESS;
}

// 分配 8 KiB 连续内存作 MSRPM，并隐藏其两张页表页。
NTSTATUS
SvmInitializeShared(
    VOID
    )
{
    PHYSICAL_ADDRESS low;
    PHYSICAL_ADDRESS high;
    PHYSICAL_ADDRESS boundary;
    PHYSICAL_ADDRESS physical;
    PVOID allocation;

    g_SharedFailureDetail = 0;

    if (g_Msrpm != NULL)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    low.QuadPart = 0;
    high.QuadPart = (1ull << 40) - 1;
    boundary.QuadPart = 0;

    allocation = MmAllocateContiguousMemorySpecifyCache(0x3000, low, high, boundary, MmCached);
    if (allocation == NULL)
    {
        g_SharedFailureDetail = 1;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_MsrpmAllocation = allocation;
    g_Msrpm = (PVOID)(((ULONG_PTR)allocation + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    RtlZeroMemory(g_Msrpm, 0x2000);

    //
    // The second MSR permission region starts at byte 0x800. EFER is at
    // 0xC0000080, and each MSR has a read bit followed by a write bit.
    //
    ((UINT8*)g_Msrpm)[0x800 + (((HACDBG_MSR_EFER - 0xc0000000ull) * 2ull) / 8ull)] = 0x03;

    physical = MmGetPhysicalAddress(g_Msrpm);
    g_MsrpmPa = (UINT64)physical.QuadPart;

    if ((g_MsrpmPa & (PAGE_SIZE - 1)) != 0)
    {
        HACDBG_LOG("HacDbg: Err, MSRPM physical address is not page-aligned: 0x%I64x.\n",
                 g_MsrpmPa);
        g_SharedFailureDetail = 2;
        SvmCleanupShared();
        return STATUS_UNSUCCESSFUL;
    }

    if (NptHidePage(HacDbgGuestPhysicalAddress(g_MsrpmPa)) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, hiding the first MSRPM page failed: 0x%I64x.\n", g_MsrpmPa);
        g_SharedFailureDetail = 3;
        SvmCleanupShared();
        return STATUS_UNSUCCESSFUL;
    }

    if (NptHidePage(HacDbgGuestPhysicalAddress(g_MsrpmPa + PAGE_SIZE)) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, hiding the second MSRPM page failed: 0x%I64x.\n",
                 g_MsrpmPa + PAGE_SIZE);
        g_SharedFailureDetail = 4;
        SvmCleanupShared();
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

// 释放 MSRPM 连续内存。
VOID
SvmCleanupShared(
    VOID
    )
{
    if (g_MsrpmAllocation != NULL)
    {
        MmFreeContiguousMemory(g_MsrpmAllocation);
    }

    g_MsrpmAllocation = NULL;
    g_Msrpm = NULL;
    g_MsrpmPa = 0;
}

// 返回 MSRPM 初始化的细分失败码。
ULONG
SvmGetSharedFailureDetail(
    VOID
    )
{
    return g_SharedFailureDetail;
}

// 置位 EFER.SVME 和 NXE，允许执行 SVM 指令。
VOID
SvmEnable(
    VOID
    )
{
    __writemsr(HACDBG_MSR_EFER, __readmsr(HACDBG_MSR_EFER) | HACDBG_EFER_SVME | HACDBG_EFER_NXE);
}

// 清除 EFER.SVME 并复位 VM_HSAVE_PA。
VOID
SvmDisable(
    VOID
    )
{
    __writemsr(HACDBG_MSR_EFER, __readmsr(HACDBG_MSR_EFER) & ~HACDBG_EFER_SVME);
    __writemsr(SVM_MSR_VM_HSAVE_PA, 0);
}

// 把当前处理器上下文登记到全局数组，供跨处理器刷新使用。
static VOID
SvmRegisterProcessor(
    _In_ SVM_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    PROCESSOR_NUMBER processorNumber;
    ULONG index;

    KeGetCurrentProcessorNumberEx(&processorNumber);
    index = KeGetProcessorIndexFromNumber(&processorNumber);

    HacDbgSpinLockAcquire(&g_ProcessorLock);
    if (index < HACDBG_MAX_PROCESSORS)
    {
        g_Processors[index] = ProcessorContext;
    }
    HacDbgSpinLockRelease(&g_ProcessorLock);
}

// 分配本处理器的 VMCB、宿主保存区和宿主栈，并在 NPT 中隐藏它们。
NTSTATUS
SvmInitialize(
    _Out_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT64 NptRootPa,
    _In_ UINT64 GuestAsid
    )
{
    PHYSICAL_ADDRESS physical;

    if (g_ProcessorTableReady == FALSE)
    {
        RtlZeroMemory(g_Processors, sizeof(g_Processors));
        HacDbgSpinLockInitialize(&g_ProcessorLock);
        g_ProcessorTableReady = TRUE;
    }

    RtlZeroMemory(ProcessorContext, sizeof(*ProcessorContext));

    ProcessorContext->GuestVmcb = (VMCB*)SvmAllocateAligned(sizeof(VMCB),
                                                             &ProcessorContext->GuestVmcbAllocation);
    ProcessorContext->HostVmcb = (VMCB*)SvmAllocateAligned(sizeof(VMCB),
                                                            &ProcessorContext->HostVmcbAllocation);
    ProcessorContext->HostSaveArea = SvmAllocateAligned(PAGE_SIZE,
                                                        &ProcessorContext->HostSaveAreaAllocation);
    ProcessorContext->HostStack = SvmAllocateAligned(HACDBG_HOST_STACK_SIZE,
                                                     &ProcessorContext->HostStackAllocation);

    if (ProcessorContext->GuestVmcb == NULL || ProcessorContext->HostVmcb == NULL ||
        ProcessorContext->HostSaveArea == NULL || ProcessorContext->HostStack == NULL)
    {
        HACDBG_LOG("HacDbg: Err, processor allocation failed: guest=%p host=%p save=%p stack=%p.\n",
                 ProcessorContext->GuestVmcb, ProcessorContext->HostVmcb,
                 ProcessorContext->HostSaveArea, ProcessorContext->HostStack);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (g_MsrpmPa == 0)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    physical = MmGetPhysicalAddress(ProcessorContext->GuestVmcb);
    ProcessorContext->GuestVmcbPa = (UINT64)physical.QuadPart;
    physical = MmGetPhysicalAddress(ProcessorContext->HostVmcb);
    ProcessorContext->HostVmcbPa = (UINT64)physical.QuadPart;
    physical = MmGetPhysicalAddress(ProcessorContext->HostSaveArea);
    {
        UINT64 hostSaveAreaPa = (UINT64)physical.QuadPart;

        if ((ProcessorContext->GuestVmcbPa & (PAGE_SIZE - 1)) != 0 ||
            (ProcessorContext->HostVmcbPa & (PAGE_SIZE - 1)) != 0 ||
            (hostSaveAreaPa & (PAGE_SIZE - 1)) != 0)
        {
            return STATUS_UNSUCCESSFUL;
        }

        ProcessorContext->GuestVmcb->ControlArea.InterceptMisc1 =
            SVM_INTERCEPT_MISC1_CPUID | SVM_INTERCEPT_MISC1_MSR_PROT;
        ProcessorContext->GuestVmcb->ControlArea.InterceptMisc2 =
            SVM_INTERCEPT_MISC2_VMRUN;
        ProcessorContext->GuestVmcb->ControlArea.MsrpmBasePa = g_MsrpmPa;
        ProcessorContext->GuestVmcb->ControlArea.GuestAsid = (UINT32)GuestAsid;
        ProcessorContext->GuestVmcb->ControlArea.NpEnable = SVM_NP_ENABLE;
        ProcessorContext->GuestVmcb->ControlArea.NCr3 = NptRootPa;

        if (NptHidePage(HacDbgGuestPhysicalAddress(ProcessorContext->GuestVmcbPa)) == FALSE ||
            NptHidePage(HacDbgGuestPhysicalAddress(ProcessorContext->HostVmcbPa)) == FALSE ||
            NptHidePage(HacDbgGuestPhysicalAddress(hostSaveAreaPa)) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, hiding processor state failed: guest_vmcb=0x%I64x "
                     "host_vmcb=0x%I64x host_save=0x%I64x.\n",
                     ProcessorContext->GuestVmcbPa, ProcessorContext->HostVmcbPa,
                     hostSaveAreaPa);
            return STATUS_UNSUCCESSFUL;
        }

        ProcessorContext->GuestVmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;

        SvmRegisterProcessor(ProcessorContext);
        SvmFlushAllProcessors();
        return STATUS_SUCCESS;
    }
}

// 用当前上下文填充客户 VMCB，并设置 VM_HSAVE_PA。
VOID
SvmPrepareLaunch(
    _Inout_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ const CONTEXT* Context
    )
{
    DESCRIPTOR_TABLE_REGISTER gdtr = { 0 };
    DESCRIPTOR_TABLE_REGISTER idtr = { 0 };
    VMCB* vmcb = ProcessorContext->GuestVmcb;
    PHYSICAL_ADDRESS hostSavePhysical;

    _sgdt(&gdtr);
    __sidt(&idtr);

    vmcb->StateSaveArea.GdtrBase = gdtr.Base;
    vmcb->StateSaveArea.GdtrLimit = gdtr.Limit;
    vmcb->StateSaveArea.IdtrBase = idtr.Base;
    vmcb->StateSaveArea.IdtrLimit = idtr.Limit;

    vmcb->StateSaveArea.CsSelector = Context->SegCs;
    vmcb->StateSaveArea.DsSelector = Context->SegDs;
    vmcb->StateSaveArea.EsSelector = Context->SegEs;
    vmcb->StateSaveArea.SsSelector = Context->SegSs;
    vmcb->StateSaveArea.CsAttrib = SvmSegmentAttributes(Context->SegCs, gdtr.Base);
    vmcb->StateSaveArea.DsAttrib = SvmSegmentAttributes(Context->SegDs, gdtr.Base);
    vmcb->StateSaveArea.EsAttrib = SvmSegmentAttributes(Context->SegEs, gdtr.Base);
    vmcb->StateSaveArea.SsAttrib = SvmSegmentAttributes(Context->SegSs, gdtr.Base);
    vmcb->StateSaveArea.CsLimit = SvmSegmentLimit(Context->SegCs, gdtr.Base);
    vmcb->StateSaveArea.DsLimit = SvmSegmentLimit(Context->SegDs, gdtr.Base);
    vmcb->StateSaveArea.EsLimit = SvmSegmentLimit(Context->SegEs, gdtr.Base);
    vmcb->StateSaveArea.SsLimit = SvmSegmentLimit(Context->SegSs, gdtr.Base);

    //
    // VMRUN rejects a guest EFER with SVME clear. The guest-visible value is
    // masked in the EFER read intercept below.
    //
    vmcb->StateSaveArea.Efer = __readmsr(HACDBG_MSR_EFER);
    vmcb->StateSaveArea.Cr0 = __readcr0();
    vmcb->StateSaveArea.Cr2 = __readcr2();
    vmcb->StateSaveArea.Cr3 = __readcr3();
    HypercallNoteKernelCr3(vmcb->StateSaveArea.Cr3);
    vmcb->StateSaveArea.Cr4 = __readcr4();
    vmcb->StateSaveArea.GPat = __readmsr(HACDBG_MSR_PAT);
    vmcb->StateSaveArea.Rflags = Context->EFlags;
    vmcb->StateSaveArea.Rsp = Context->Rsp;
    vmcb->StateSaveArea.Rip = Context->Rip;
    vmcb->StateSaveArea.Rax = Context->Rax;
    vmcb->ControlArea.VmcbClean = 0;
    vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;

    ProcessorContext->Registers.Rax = Context->Rax;
    ProcessorContext->Registers.Rcx = Context->Rcx;
    ProcessorContext->Registers.Rdx = Context->Rdx;
    ProcessorContext->Registers.Rbx = Context->Rbx;
    ProcessorContext->Registers.Rsp = Context->Rsp;
    ProcessorContext->Registers.Rbp = Context->Rbp;
    ProcessorContext->Registers.Rsi = Context->Rsi;
    ProcessorContext->Registers.Rdi = Context->Rdi;
    ProcessorContext->Registers.R8 = Context->R8;
    ProcessorContext->Registers.R9 = Context->R9;
    ProcessorContext->Registers.R10 = Context->R10;
    ProcessorContext->Registers.R11 = Context->R11;
    ProcessorContext->Registers.R12 = Context->R12;
    ProcessorContext->Registers.R13 = Context->R13;
    ProcessorContext->Registers.R14 = Context->R14;
    ProcessorContext->Registers.R15 = Context->R15;

    //
    // INVARIANT: Both VMCB pages are 4 KiB-aligned nonpaged allocations, the
    // guest VMCB is not reachable through either nested page table, and this
    // processor is not currently executing VMRUN.
    //
    __svm_vmsave(ProcessorContext->GuestVmcbPa);
    __svm_vmsave(ProcessorContext->HostVmcbPa);

    hostSavePhysical = MmGetPhysicalAddress(ProcessorContext->HostSaveArea);
    //
    // INVARIANT: HostSaveArea is a 4 KiB-aligned host page that is not
    // reachable through the guest nested page tables.
    //
    __writemsr(SVM_MSR_VM_HSAVE_PA, (UINT64)hostSavePhysical.QuadPart);
}

// 把宿主状态写回，关闭 SVM，恢复客户控制寄存器后退出 VMRUN 循环。
static VOID
SvmStopCurrentProcessor(
    _Inout_ SVM_GUEST_CONTEXT* GuestContext
    )
{
    SVM_PROCESSOR_CONTEXT* processor = GuestContext->ProcessorContext;

    GuestContext->Vmcb->StateSaveArea.Rax = GuestContext->Registers->Rax;
    //
    // INVARIANT: The processor is handling a VMEXIT with GIF clear, the guest
    // VMCB belongs to this processor, and SVM is still enabled.
    //
    __svm_vmload(processor->GuestVmcbPa);

    processor->StopRequested = FALSE;
    processor->Virtualized = FALSE;
    processor->LaunchCompleted = TRUE;
    _disable();
    //
    // INVARIANT: Interrupts are masked, the guest VMCB has been loaded, and
    // this processor is about to leave the VMRUN loop.
    //
    __svm_stgi();
    SvmDisable();
    //
    // VMLOAD restores only the hidden segment/MSR subset. The control
    // registers were replaced by the host values on #VMEXIT, so restore the
    // guest values before returning to the original instruction stream.
    //
    __writecr0(GuestContext->Vmcb->StateSaveArea.Cr0);
    __writecr4(GuestContext->Vmcb->StateSaveArea.Cr4);
    __writemsr(HACDBG_MSR_EFER,
               GuestContext->Vmcb->StateSaveArea.Efer & ~HACDBG_EFER_SVME);
    __writemsr(HACDBG_MSR_PAT, GuestContext->Vmcb->StateSaveArea.GPat);
    __writecr3(GuestContext->Vmcb->StateSaveArea.Cr3);

}

// 处理 EFER 的 MSR 拦截，其余 MSR 透传。
static VOID
SvmHandleMsrAccess(
    _Inout_ SVM_GUEST_CONTEXT* GuestContext
    )
{
    VMCB* vmcb = GuestContext->Vmcb;
    SVM_GUEST_REGISTERS* registers = GuestContext->Registers;
    UINT32 msr = (UINT32)registers->Rcx;
    BOOLEAN writeAccess = (vmcb->ControlArea.ExitInfo1 & 1ull) != 0;
    UINT64 value = ((UINT64)registers->Rdx << 32) | (UINT32)registers->Rax;

    if (msr == HACDBG_MSR_EFER)
    {
        if (writeAccess != FALSE)
        {
            UINT64 current = __readmsr(HACDBG_MSR_EFER);
            UINT64 guestEfer = value & ~(HACDBG_EFER_SVME | HACDBG_EFER_LME | HACDBG_EFER_LMA);

            guestEfer |= current & (HACDBG_EFER_LME | HACDBG_EFER_LMA);
            guestEfer |= HACDBG_EFER_SVME;
            vmcb->StateSaveArea.Efer = guestEfer;
            vmcb->ControlArea.VmcbClean = 0;
            __writemsr(HACDBG_MSR_EFER,
                       (guestEfer & ~HACDBG_EFER_SVME) | HACDBG_EFER_SVME | HACDBG_EFER_NXE);
        }
        else
        {
            value = vmcb->StateSaveArea.Efer & ~HACDBG_EFER_SVME;
            registers->Rax = (UINT32)value;
            registers->Rdx = value >> 32;
        }
    }
    else if (writeAccess != FALSE)
    {
        __writemsr(msr, value);
    }
    else
    {
        value = __readmsr(msr);
        registers->Rax = (UINT32)value;
        registers->Rdx = value >> 32;
    }

    if (vmcb->ControlArea.NRip != 0)
    {
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
    }
    else
    {
        vmcb->StateSaveArea.Rip += 2;
    }
}

// VMEXIT 总入口：恢复宿主状态，按退出码分派，返回 TRUE 表示离开 VMRUN。
BOOLEAN
SvmHandleVmExit(
    _Inout_ SVM_GUEST_CONTEXT* GuestContext
    )
{
    VMCB* vmcb = GuestContext->Vmcb;
    SVM_PROCESSOR_CONTEXT* processor = GuestContext->ProcessorContext;

    __svm_vmload(processor->HostVmcbPa);
    GuestContext->Registers->Rax = vmcb->StateSaveArea.Rax;

    if (vmcb->StateSaveArea.Cpl == 0)
    {
        HypercallNoteKernelCr3(vmcb->StateSaveArea.Cr3);
    }
    vmcb->ControlArea.TlbControl =
        InterlockedExchange(&processor->TlbFlushRequested, 0) != 0 ? SVM_TLB_CONTROL_FLUSH_GUEST : 0;

    if (processor->StopRequested != FALSE)
    {
        if (vmcb->ControlArea.ExitCode == SVM_EXIT_CPUID && vmcb->ControlArea.NRip != 0)
        {
            vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        }

        SvmStopCurrentProcessor(GuestContext);
        return TRUE;
    }

    if (vmcb->ControlArea.ExitCode == SVM_EXIT_CPUID &&
        vmcb->StateSaveArea.Cpl == 0 &&
        vmcb->StateSaveArea.Rax == HACDBG_FLUSH_CPUID_LEAF &&
        (UINT32)GuestContext->Registers->Rcx == HACDBG_FLUSH_CPUID_SUBLEAF)
    {
        GuestContext->Registers->Rax = 1;
        vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        vmcb->ControlArea.VmcbClean &= ~(1ull << 4);

        if (vmcb->ControlArea.NRip != 0)
        {
            vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        }
        else
        {
            vmcb->StateSaveArea.Rip += 2;
        }

        vmcb->StateSaveArea.Rax = GuestContext->Registers->Rax;
        return FALSE;
    }

    if (vmcb->ControlArea.ExitCode == SVM_EXIT_CPUID &&
        vmcb->StateSaveArea.Cpl == 0 &&
        vmcb->StateSaveArea.Rax == HACDBG_STOP_CPUID_LEAF &&
        (UINT32)GuestContext->Registers->Rcx == HACDBG_STOP_CPUID_SUBLEAF)
    {
        GuestContext->Registers->Rax = 0x48444301ull;
        if (vmcb->ControlArea.NRip != 0)
        {
            vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        }
        else
        {
            vmcb->StateSaveArea.Rip += 2;
        }
        processor->StopRequested = TRUE;
        SvmStopCurrentProcessor(GuestContext);
        return TRUE;
    }

    switch (vmcb->ControlArea.ExitCode)
    {
    case SVM_EXIT_CPUID:
        {
            HACDBG_GUEST_VIEW view;

            view.Registers = (HACDBG_GUEST_REGISTERS*)GuestContext->Registers;
            view.Cr3 = vmcb->StateSaveArea.Cr3;
            view.Rip = vmcb->StateSaveArea.Rip;
            view.InGuest = TRUE;
            HypercallHandleCpuid(&view);
            vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip != 0
                                          ? vmcb->ControlArea.NRip
                                          : vmcb->StateSaveArea.Rip + 2;
        }
        break;

    case SVM_EXIT_MSR:
        SvmHandleMsrAccess(GuestContext);
        break;

    case SVM_EXIT_NPF:
        if (NptHandleNestedPageFault(vmcb) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, unhandled NPF exit=%u info1=0x%I64x info2=0x%I64x "
                     "ncr3=0x%I64x rip=0x%I64x.\n",
                     (UINT32)vmcb->ControlArea.ExitCode, vmcb->ControlArea.ExitInfo1,
                     vmcb->ControlArea.ExitInfo2, vmcb->ControlArea.NCr3,
                     vmcb->StateSaveArea.Rip);
            SvmStopCurrentProcessor(GuestContext);
            return TRUE;
        }
        break;

    default:
        HACDBG_LOG("HacDbg: Err, unhandled VMEXIT code=0x%I64x info1=0x%I64x info2=0x%I64x "
                 "rip=0x%I64x cr3=0x%I64x.\n",
                 vmcb->ControlArea.ExitCode, vmcb->ControlArea.ExitInfo1,
                 vmcb->ControlArea.ExitInfo2, vmcb->StateSaveArea.Rip,
                 vmcb->StateSaveArea.Cr3);
        SvmStopCurrentProcessor(GuestContext);
        return TRUE;
    }

    vmcb->StateSaveArea.Rax = GuestContext->Registers->Rax;
    return FALSE;
}

// 给所有已注册处理器打 TLB 刷新标记。
VOID
SvmFlushAllProcessors(
    VOID
    )
{
    ULONG index;

    HacDbgSpinLockAcquire(&g_ProcessorLock);

    for (index = 0; index < HACDBG_MAX_PROCESSORS; index++)
    {
        SVM_PROCESSOR_CONTEXT* processor = g_Processors[index];

        if (processor != NULL)
        {
            InterlockedExchange(&processor->TlbFlushRequested, 1);
            processor->GuestVmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        }
    }

    HacDbgSpinLockRelease(&g_ProcessorLock);
}
