/**
 * @file Vmx.c
 * @brief VT-x setup, VM-exit handling, and processor state.
 *
 * @author HacDbg
 */

#include <ntifs.h>

#include "Vmx.h"
#include "Debug.h"
#include "Ept.h"
#include "Hypercall.h"
#include "PhysicalMemory.h"
#include "Svm.h"

#include <intrin.h>

#define HACDBG_VMX_TAG            'XcaH'
#define HACDBG_HOST_STACK_SIZE    0x8000
#define HACDBG_MAX_PROCESSORS     256
#define HACDBG_MSR_EFER           0xC0000080ull
#define HACDBG_MSR_PAT            0x277ull
#define HACDBG_MSR_DEBUGCTL       0x1D9ull
#define HACDBG_MSR_FS_BASE        0xC0000100ull
#define HACDBG_MSR_GS_BASE        0xC0000101ull
#define HACDBG_MSR_SYSENTER_CS    0x174ull
#define HACDBG_MSR_SYSENTER_ESP   0x175ull
#define HACDBG_MSR_SYSENTER_EIP   0x176ull
#define VMX_MSR_BITMAP_READ_LOW   0u
#define VMX_MSR_BITMAP_WRITE_LOW  2048u
#define VMX_CPUID_VMX_BIT         (1u << 5)
#define VMX_CPUID_HYPERVISOR_PRESENT (1u << 31)
#define VMX_ACCESS_UNUSABLE       (1u << 16)
#define VMX_CR0_NW                (1ull << 29)
#define VMX_CR0_CD                (1ull << 30)
#define VMX_CR4_PCIDE             (1ull << 17)

//
// MSR indexes 40000000H-400001FFH sit outside both MSR-bitmap windows,
// so RDMSR/WRMSR of them always VM-exits. A hypervisor guest uses this
// range for synthetic MSRs. CPUID.1 ECX[31] is the only check; leaf
// 40000000H is not queried here because that CPUID runs before the VMX
// capability MSRs are read.
//
#define VMX_MSR_SYNTHETIC_FIRST   0x40000000u
#define VMX_MSR_SYNTHETIC_LAST    0x400001FFu
#define VMX_MSR_HV_VP_RUNTIME     0x40000010u
#define VMX_MSR_HV_TIME_REF_COUNT 0x40000020u
#define VMX_MSR_HV_REFERENCE_TSC  0x40000021u
#define VMX_MSR_HV_TSC_FREQUENCY  0x40000022u
#define VMX_MSR_HV_APIC_FREQUENCY 0x40000023u
#define VMX_MSR_HV_GUEST_IDLE     0x400000F0u
#define VMX_HV_100NS_PER_SECOND   10000000ull

C_ASSERT(sizeof(HACDBG_GUEST_REGISTERS) == 0x80);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, Registers) == 0x00);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, GuestCr3) == 0x80);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, GuestRip) == 0x88);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, GuestRsp) == 0x90);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, GuestRflags) == 0x98);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, TscAtExit) == 0x128);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, TscOffset) == 0x130);
C_ASSERT(FIELD_OFFSET(VMX_PROCESSOR_CONTEXT, TscOffsetting) == 0x158);



#pragma pack(push, 1)
typedef struct _VMX_TABLE_REGISTER
{
    UINT16 Limit;
    UINT64 Base;
} VMX_TABLE_REGISTER;
#pragma pack(pop)

static VMX_PROCESSOR_CONTEXT* g_Processors[HACDBG_MAX_PROCESSORS];
static ULONG g_ProcessorCount;
static HACDBG_SPIN_LOCK g_ProcessorLock;
static UINT64 g_Cr0Fixed0;
static UINT64 g_Cr0Fixed1;
static UINT64 g_Cr4Fixed0;
static UINT64 g_Cr4Fixed1;
static UINT32 g_PinControls;
static UINT32 g_PreemptionTimerShift;
static BOOLEAN g_PreemptionTimerAvailable;
static BOOLEAN g_PreemptionTimerSticky;
static volatile LONG g_PreemptionTimerLogged;
static UINT32 g_ProcControls;
static UINT32 g_ProcControls2;
static UINT32 g_ExitControls;
static UINT32 g_EntryControls;
static UINT64 g_InveptType;
static BOOLEAN g_ControlsReady;
static volatile LONG g_SyntheticMsrPassthrough;
static volatile LONG g_UnexpectedMsrLogs;
static volatile LONG g_GuestIdleIgnored;
static volatile LONG g_HvTimeReady;
static BOOLEAN g_PmcFreeze;
#if HACDBG_HIDE_VIRTUALIZATION
static BOOLEAN g_TscAdjustPresent;
static BOOLEAN g_TscDeadlinePresent;
#endif

#define VMX_CPUID_TSC_ADJUST    (1u << 1)
#define VMX_CPUID_TSC_DEADLINE  (1u << 24)

static UINT64 g_HvRefTsc;
static UINT64 g_HvRefTime;
static UINT64 g_HvTscFrequency;
static UINT64 g_HvApicFrequency;
static volatile UINT64 g_HvReferenceTscMsr;

static BOOLEAN
VmxWrite(
    _In_ UINT64 Field,
    _In_ UINT64 Value
    )
{
    return __vmx_vmwrite((size_t)Field, (size_t)Value) == 0;
}

static BOOLEAN
VmxRead(
    _In_ UINT64 Field,
    _Out_ UINT64* Value
    )
{
    size_t read = 0;
    BOOLEAN ok = __vmx_vmread((size_t)Field, &read) == 0;

    *Value = (UINT64)read;
    return ok;
}

static UINT32
VmxAdjust(
    _In_ UINT32 Desired,
    _In_ UINT32 MsrIndex
    )
{
    UINT64 msr = __readmsr(MsrIndex);

    Desired |= (UINT32)msr;
    Desired &= (UINT32)(msr >> 32);
    return Desired;
}

static VOID*
VmxAllocateAligned(
    _In_ SIZE_T Size,
    _Out_ PVOID* Allocation
    )
{
    PVOID block = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size + PAGE_SIZE, HACDBG_VMX_TAG);

    *Allocation = block;
    if (block == NULL)
    {
        return NULL;
    }

    return (PVOID)(((ULONG_PTR)block + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
}

static VOID
VmxBitmapSet(
    _Inout_ PUCHAR Bitmap,
    _In_ UINT32 Msr,
    _In_ UINT32 Base
    )
{
    UINT32 byteIndex = Base + (Msr / 8);

    if (Msr > 0x1FFF || byteIndex >= PAGE_SIZE)
    {
        return;
    }

    Bitmap[byteIndex] |= (UINT8)(1u << (Msr & 7));
}

static UINT64
VmxDescriptorBase(
    _In_ UINT64 GdtBase,
    _In_ UINT16 Selector
    )
{
    UINT64 first;
    UINT64 base;
    UINT32 access;

    if ((Selector & 0xFFF8u) == 0)
    {
        return 0;
    }

    first = *(UINT64*)(ULONG_PTR)(GdtBase + (Selector & 0xFFF8u));
    base = ((first >> 16) & 0xFFFFFFull) | (((first >> 56) & 0xFFull) << 24);
    access = (UINT32)((first >> 40) & 0xFFu);

    if ((access & 0x10u) == 0)
    {
        UINT64 second = *(UINT64*)(ULONG_PTR)(GdtBase + (Selector & 0xFFF8u) + 8);

        base |= second << 32;
    }

    return base;
}

static UINT32
VmxDescriptorLimit(
    _In_ UINT64 GdtBase,
    _In_ UINT16 Selector
    )
{
    UINT64 first;
    UINT32 limit;

    if ((Selector & 0xFFF8u) == 0)
    {
        return 0;
    }

    first = *(UINT64*)(ULONG_PTR)(GdtBase + (Selector & 0xFFF8u));
    limit = (UINT32)(first & 0xFFFFu);
    limit |= (UINT32)((first >> 48) & 0xFu) << 16;

    if ((first & (1ull << 55)) != 0)
    {
        limit = (limit << 12) | 0xFFFu;
    }

    return limit;
}

static UINT32
VmxDescriptorRights(
    _In_ UINT64 GdtBase,
    _In_ UINT16 Selector,
    _In_ BOOLEAN AllowUnusable
    )
{
    UINT64 first;
    UINT32 access;
    UINT32 flags;
    UINT32 rights;

    if ((Selector & 0xFFF8u) == 0)
    {
        return AllowUnusable ? VMX_ACCESS_UNUSABLE : 0;
    }

    first = *(UINT64*)(ULONG_PTR)(GdtBase + (Selector & 0xFFF8u));
    access = (UINT32)((first >> 40) & 0xFFu);
    flags = (UINT32)((first >> 52) & 0xFu);
    rights = access | (flags << 12);

    if ((access & 0x80u) == 0 && AllowUnusable != FALSE)
    {
        rights |= VMX_ACCESS_UNUSABLE;
    }

    return rights;
}

static BOOLEAN
VmxWriteSegment(
    _In_ UINT16 Selector,
    _In_ UINT64 GdtBase,
    _In_ UINT64 SelectorField,
    _In_ UINT64 LimitField,
    _In_ UINT64 AccessField,
    _In_ UINT64 BaseField,
    _In_ UINT64 Base,
    _In_ BOOLEAN AllowUnusable,
    _In_ BOOLEAN ForceBusyTss
    )
{
    UINT32 rights = VmxDescriptorRights(GdtBase, Selector, AllowUnusable);

    if (ForceBusyTss != FALSE && (rights & VMX_ACCESS_UNUSABLE) == 0)
    {
        rights = (rights & ~0xFu) | 11u;
    }

    return VmxWrite(SelectorField, Selector) &&
           VmxWrite(LimitField, VmxDescriptorLimit(GdtBase, Selector)) &&
           VmxWrite(AccessField, rights) &&
           VmxWrite(BaseField, Base);
}

static BOOLEAN
VmxAdvanceRip(
    VOID
    )
{
    UINT64 rip;
    UINT64 length;

    if (VmxRead(VMCS_GUEST_RIP, &rip) == FALSE ||
        VmxRead(VMCS_EXIT_INSTRUCTION_LENGTH, &length) == FALSE)
    {
        return FALSE;
    }

    return VmxWrite(VMCS_GUEST_RIP, rip + length);
}

static VOID
VmxInjectHardwareException(
    _In_ UINT32 Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ UINT32 ErrorCode
    )
{
    UINT64 information = Vector | VMX_INTERRUPTION_HARDWARE | VMX_INTERRUPTION_VALID;

    if (DeliverErrorCode != FALSE)
    {
        information |= VMX_INTERRUPTION_ERROR_CODE;
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, ErrorCode);
    }

    VmxWrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 0);
    VmxWrite(VMCS_CTRL_VMENTRY_INTERRUPTION, information);
}

static UINT32
VmxGuestCpl(
    VOID
    )
{
    UINT64 rights;

    if (VmxRead(VMCS_GUEST_CS_ACCESS, &rights) == FALSE)
    {
        return 0;
    }

    return (UINT32)((rights >> 5) & 3u);
}

static VOID
VmxExitVmxRoot(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    VMX_TABLE_REGISTER gdtr;
    VMX_TABLE_REGISTER idtr;

    //
    // INVARIANT: This processor is in VMX root operation on its own VMCS.
    // VMXOFF is not executed from SMM.
    //
    HacDbgVmxOff();
    __writecr4(__readcr4() & ~VMX_CR4_VMXE);

    if (ProcessorContext->DescriptorTablesSaved == FALSE)
    {
        return;
    }

    gdtr.Limit = ProcessorContext->SavedGdtrLimit;
    gdtr.Base = ProcessorContext->SavedGdtrBase;
    idtr.Limit = ProcessorContext->SavedIdtrLimit;
    idtr.Base = ProcessorContext->SavedIdtrBase;

    //
    // INVARIANT: Saved bases and limits were read with SGDT and SIDT before
    // this processor's first VM-exit. VM-exit forces both limits to FFFFH
    // and VMXOFF leaves them there. Both tables are the kernel tables.
    //
    VmxWriteGdtr(&gdtr);
    VmxWriteIdtr(&idtr);
}

static BOOLEAN
VmxLeaveVmx(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    if (VmxRead(VMCS_GUEST_RIP, &ProcessorContext->GuestRip) == FALSE ||
        VmxRead(VMCS_GUEST_RSP, &ProcessorContext->GuestRsp) == FALSE ||
        VmxRead(VMCS_GUEST_RFLAGS, &ProcessorContext->GuestRflags) == FALSE ||
        VmxRead(VMCS_GUEST_CR3, &ProcessorContext->GuestCr3) == FALSE)
    {
        ProcessorContext->GuestRip = 0;
        ProcessorContext->GuestRsp = 0;
        ProcessorContext->GuestRflags = 2;
        ProcessorContext->GuestCr3 = __readcr3();
    }

    VmxExitVmxRoot(ProcessorContext);
    ProcessorContext->Virtualized = FALSE;
    ProcessorContext->StopRequested = FALSE;
    ProcessorContext->LaunchCompleted = TRUE;
    return TRUE;
}

static VOID
VmxInvalidateEpt(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    if (ProcessorContext->EptEnabled == FALSE || g_InveptType == 0)
    {
        return;
    }

    if (g_InveptType == VMX_INVEPT_ALL_CONTEXT)
    {
        VmxInvept(VMX_INVEPT_ALL_CONTEXT, 0);
        return;
    }

    VmxInvept(VMX_INVEPT_SINGLE_CONTEXT, EptMainEptp());
    VmxInvept(VMX_INVEPT_SINGLE_CONTEXT, EptHookEptp());
}

static BOOLEAN
VmxHandleCpuid(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    HACDBG_GUEST_VIEW view;
    UINT64 rip;

    if (VmxRead(VMCS_GUEST_RIP, &rip) == FALSE)
    {
        return FALSE;
    }

    view.Registers = &ProcessorContext->Registers;
    if (VmxRead(VMCS_GUEST_CR3, &view.Cr3) == FALSE)
    {
        return FALSE;
    }

    view.Rip = rip;
    view.InGuest = TRUE;
    ProcessorContext->GuestCr3 = view.Cr3;

    if (VmxGuestCpl() == 0 &&
        ProcessorContext->Registers.Rax == HACDBG_FLUSH_CPUID_LEAF &&
        (UINT32)ProcessorContext->Registers.Rcx == HACDBG_FLUSH_CPUID_SUBLEAF)
    {
        ProcessorContext->Registers.Rax = 1;
        VmxInvalidateEpt(ProcessorContext);
        InterlockedExchange(&ProcessorContext->InveptRequested, 0);
        return VmxAdvanceRip();
    }

    HypercallHandleCpuid(&view);
    return VmxAdvanceRip();
}

//
// Guest CR4.VMXE stays set in the VMCS. The read shadow includes that bit
// only when virtualization is left visible.
//
static UINT64
VmxCr4ReadShadow(
    _In_ UINT64 GuestCr4
    )
{
#if HACDBG_HIDE_VIRTUALIZATION
    return GuestCr4 & ~VMX_CR4_VMXE;
#else
    return GuestCr4;
#endif
}

static BOOLEAN
VmxHandleCrAccess(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    UINT64 qualification;
    UINT32 cr;
    UINT32 access;
    UINT32 reg;
    UINT64 source;
    UINT64 newCr4;

    if (VmxRead(VMCS_EXIT_QUALIFICATION, &qualification) == FALSE)
    {
        return FALSE;
    }

    cr = (UINT32)(qualification & 0xF);
    access = (UINT32)((qualification >> 4) & 3u);
    reg = (UINT32)((qualification >> 8) & 0xF);

    if (cr != 4 || access != 0 || reg > 15)
    {
        HACDBG_LOG("HacDbg: Err, unhandled CR access qual=0x%I64x.\n", qualification);
        return FALSE;
    }

    source = ((UINT64*)&ProcessorContext->Registers)[reg];
    newCr4 = (source | g_Cr4Fixed0) & g_Cr4Fixed1;
    newCr4 |= VMX_CR4_VMXE;

    if (VmxWrite(VMCS_GUEST_CR4, newCr4) == FALSE ||
        VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, VmxCr4ReadShadow(newCr4)) == FALSE)
    {
        return FALSE;
    }

    return VmxAdvanceRip();
}

static BOOLEAN
VmxAccessMsr(
    _In_ UINT32 Msr,
    _In_ BOOLEAN Write,
    _Inout_ UINT64* Value
    )
{
    __try
    {
        if (Write != FALSE)
        {
            //
            // INVARIANT: Msr is outside both MSR-bitmap windows. Passthrough
            // is enabled only when an outer hypervisor implements this
            // synthetic range. The instruction runs in VMX root and does not
            // modify this processor's VMCS.
            //
            __writemsr(Msr, *Value);
        }
        else
        {
            //
            // INVARIANT: Same as the WRMSR above. A #GP here means the outer
            // hypervisor rejected the index; it must not leave VMX.
            //
            *Value = __readmsr(Msr);
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static BOOLEAN
VmxReadSyntheticMsr(
    _In_ UINT32 Msr,
    _Out_ UINT64* Value
    )
{
    __try
    {
        //
        // INVARIANT: Called before VMXON, while this processor still uses
        // the outer hypervisor's guest time domain.
        //
        *Value = __readmsr(Msr);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static BOOLEAN
VmxSnapshotGuestClock(
    VOID
    )
{
    UINT64 tsc;
    UINT64 refTime;
    UINT64 frequency;
    UINT64 apicFrequency;
    UINT64 referenceTsc;

    //
    // INVARIANT: VMX capability MSRs are already cached. These synthetic
    // indexes are read before VMXON, so the values belong to the guest
    // clock rather than the outer host clock.
    //
    tsc = __rdtsc();
    if (VmxReadSyntheticMsr(VMX_MSR_HV_TIME_REF_COUNT, &refTime) == FALSE ||
        VmxReadSyntheticMsr(VMX_MSR_HV_TSC_FREQUENCY, &frequency) == FALSE ||
        VmxReadSyntheticMsr(VMX_MSR_HV_APIC_FREQUENCY, &apicFrequency) == FALSE ||
        VmxReadSyntheticMsr(VMX_MSR_HV_REFERENCE_TSC, &referenceTsc) == FALSE ||
        frequency == 0)
    {
        return FALSE;
    }

    g_HvRefTsc = tsc;
    g_HvRefTime = refTime;
    g_HvTscFrequency = frequency;
    g_HvApicFrequency = apicFrequency;
    g_HvReferenceTscMsr = referenceTsc;
    InterlockedExchange(&g_HvTimeReady, 1);
    HACDBG_LOG("HacDbg: Synthetic time MSRs use the guest clock.\n");
    return TRUE;
}

static UINT64
VmxCyclesSinceTimeSnapshot(
    _In_ const VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    UINT64 rootNow = __rdtsc();

    //
    // TscAfterVmxon and rootNow are both read in VMX root. TscBeforeVmxon
    // and g_HvRefTsc were both read before VMXON. Adding the two deltas
    // keeps the result on the pre-VMXON guest TSC even when root RDTSC
    // uses a different offset.
    //
    return (rootNow - ProcessorContext->TscAfterVmxon) +
           (ProcessorContext->TscBeforeVmxon - g_HvRefTsc);
}

static UINT64
VmxCyclesToHundredNs(
    _In_ UINT64 Cycles
    )
{
    UINT64 frequency = g_HvTscFrequency;
    UINT64 whole;
    UINT64 part;

    if (frequency == 0)
    {
        return 0;
    }

    whole = Cycles / frequency;
    part = Cycles % frequency;
    return whole * VMX_HV_100NS_PER_SECOND + (part * VMX_HV_100NS_PER_SECOND) / frequency;
}

static BOOLEAN
VmxFinishMsrRead(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT64 Value
    )
{
    ProcessorContext->Registers.Rax = (UINT32)Value;
    ProcessorContext->Registers.Rdx = Value >> 32;
    return VmxAdvanceRip();
}

static BOOLEAN
VmxHandleSyntheticTime(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT32 Msr,
    _In_ BOOLEAN Write,
    _Out_ BOOLEAN* Handled
    )
{
    UINT64 value;
    UINT64 elapsed;

    *Handled = FALSE;
    if (g_HvTimeReady == 0 ||
        (Msr != VMX_MSR_HV_VP_RUNTIME && Msr != VMX_MSR_HV_TIME_REF_COUNT &&
         Msr != VMX_MSR_HV_REFERENCE_TSC && Msr != VMX_MSR_HV_TSC_FREQUENCY &&
         Msr != VMX_MSR_HV_APIC_FREQUENCY))
    {
        return TRUE;
    }

    *Handled = TRUE;
    if (Msr == VMX_MSR_HV_REFERENCE_TSC)
    {
        if (Write != FALSE)
        {
            //
            // Executing this WRMSR in VMX root makes the outer hypervisor
            // rebuild the reference-TSC page from its own clock. Windows
            // then adds that delta to the interrupt time. Keep the page
            // that was programmed before VMXON and only remember the value
            // the guest stored.
            //
            value = (ProcessorContext->Registers.Rdx << 32) |
                    (UINT32)ProcessorContext->Registers.Rax;
            InterlockedExchange64((volatile LONG64*)&g_HvReferenceTscMsr, (LONG64)value);
            return VmxAdvanceRip();
        }

        return VmxFinishMsrRead(ProcessorContext, g_HvReferenceTscMsr);
    }

    if (Write != FALSE)
    {
        VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
        return TRUE;
    }

    elapsed = VmxCyclesToHundredNs(VmxCyclesSinceTimeSnapshot(ProcessorContext));
    if (Msr == VMX_MSR_HV_VP_RUNTIME)
    {
        value = ProcessorContext->VpRuntime + elapsed;
    }
    else if (Msr == VMX_MSR_HV_TIME_REF_COUNT)
    {
        value = g_HvRefTime + elapsed;
    }
    else if (Msr == VMX_MSR_HV_TSC_FREQUENCY)
    {
        value = g_HvTscFrequency;
    }
    else
    {
        value = g_HvApicFrequency;
    }

    return VmxFinishMsrRead(ProcessorContext, value);
}

#if HACDBG_HIDE_VIRTUALIZATION
static BOOLEAN
VmxMsrPresent(
    _In_ ULONG Index
    )
{
    __try
    {
        (void)__readmsr(Index);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

//
// Writes the same deadline just read. A failed probe means this processor
// cannot publish IA32_TSC_DEADLINE, so TSC offsetting must not be paired
// with a guest that programs the APIC timer from RDTSC.
//
static BOOLEAN
VmxProbeTscDeadline(
    VOID
    )
{
    UINT64 current;

    __try
    {
        current = __readmsr(VMX_MSR_TSC_DEADLINE);
        //
        // INVARIANT: Still before VMXON. The value just read is the OS deadline.
        // Writing it back does not select a new target.
        //
        __writemsr(VMX_MSR_TSC_DEADLINE, current);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static BOOLEAN
VmxWriteTscDeadline(
    _In_ UINT64 HostDeadline
    )
{
    __try
    {
        //
        // INVARIANT: This processor is in VMX root, or still before VMXON.
        // HostDeadline is an absolute TSC in the same domain as RDTSC here,
        // which is not the guest-visible TSC while TSC offsetting is on.
        //
        __writemsr(VMX_MSR_TSC_DEADLINE, HostDeadline);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static BOOLEAN
VmxReadTscDeadline(
    _Out_ UINT64* Deadline
    )
{
    __try
    {
        //
        // INVARIANT: This processor is in VMX root, or still before VMXON.
        // The value is the host-domain IA32_TSC_DEADLINE. The local APIC
        // compares it with the time-stamp counter itself.
        //
        *Deadline = __readmsr(VMX_MSR_TSC_DEADLINE);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

//
// SDM 13.5.4.1: the timer fires when the TSC reaches a non-zero deadline,
// then the hardware clears the MSR. A zero readback of an already-due
// deadline is the published state.
//
static BOOLEAN
VmxDeadlineIsPublished(
    _In_ UINT64 HostDeadline,
    _In_ UINT64 Seen
    )
{
    if (Seen == HostDeadline)
    {
        return TRUE;
    }

    if (Seen == 0 && HostDeadline != 0 && HostDeadline <= __rdtsc())
    {
        return TRUE;
    }

    return FALSE;
}

//
// SDM 13.5.4.1: writing zero disarms the timer and does not generate the
// interrupt. A later non-zero write arms it. Overwriting an already armed
// deadline is also allowed, but a matching readback of that overwrite is
// not treated as proof that the comparator was armed. The publish path
// therefore disarms first. Postponing can still deliver the old deadline
// and clear the MSR, so a future deadline is written again when the
// readback is zero.
//
static BOOLEAN
VmxPublishTscDeadline(
    _In_ UINT64 HostDeadline
    )
{
    UINT64 seen;
    UINT32 attempt;

    if (HostDeadline == 0)
    {
        return FALSE;
    }

    //
    // INVARIANT: Same domain as VmxWriteTscDeadline. Reads and writes of
    // IA32_TSC_DEADLINE occur in program order, so the readback observes
    // the write without a serializing instruction.
    //
    for (attempt = 0; attempt < 2; attempt++)
    {
        if (VmxWriteTscDeadline(0) == FALSE ||
            VmxWriteTscDeadline(HostDeadline) == FALSE ||
            VmxReadTscDeadline(&seen) == FALSE)
        {
            return FALSE;
        }

        if (VmxDeadlineIsPublished(HostDeadline, seen) != FALSE)
        {
            return TRUE;
        }

        if (seen != 0)
        {
            return FALSE;
        }
    }

    return FALSE;
}

//
// SDM 13.5.4.1: the local APIC compares IA32_TSC_DEADLINE with the
// time-stamp counter itself, then clears the MSR. RDTSC in non-root returns
// that counter plus the TSC offset. The host deadline is the guest deadline
// minus the current VMCS offset. A stealth bias of at most 10000 cycles
// moves that offset, so a stale host deadline would fire early or late.
// The MSR is rewritten only when the converted deadline or the readback
// differs. Publishing still disarms before arming, because postponing can
// deliver the old deadline and clear the MSR.
//
static VOID
VmxSyncTscDeadline(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    UINT64 now;
    UINT64 guestNow;
    UINT64 hostDeadline;
    UINT64 seen;

    if (ProcessorContext->TscDeadlineArmed == FALSE)
    {
        return;
    }

    now = __rdtsc();
    guestNow = now + ProcessorContext->TscOffset;
    if (guestNow >= ProcessorContext->GuestTscDeadline)
    {
        //
        // Writing zero disarms the local APIC without an interrupt. A
        // non-zero deadline at or behind the TSC makes the timer fire.
        //
        if (now == 0)
        {
            now = 1;
        }

        if (VmxPublishTscDeadline(now) == FALSE)
        {
            ProcessorContext->HostDeadlineValid = FALSE;
            return;
        }

        ProcessorContext->TscDeadlineArmed = FALSE;
        ProcessorContext->HostDeadlineValid = FALSE;
        ProcessorContext->GuestTscDeadline = 0;
        ProcessorContext->HostTscDeadline = 0;
        return;
    }

    hostDeadline = ProcessorContext->GuestTscDeadline - ProcessorContext->TscOffset;
    if (ProcessorContext->HostDeadlineValid != FALSE &&
        ProcessorContext->HostTscDeadline == hostDeadline &&
        VmxReadTscDeadline(&seen) != FALSE &&
        seen == hostDeadline)
    {
        return;
    }

    if (VmxPublishTscDeadline(hostDeadline) == FALSE)
    {
        ProcessorContext->HostDeadlineValid = FALSE;
        return;
    }

    ProcessorContext->HostTscDeadline = hostDeadline;
    ProcessorContext->HostDeadlineValid = TRUE;
}
#endif

static BOOLEAN
VmxHandleMsr(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ BOOLEAN Write
    )
{
    UINT32 msr = (UINT32)ProcessorContext->Registers.Rcx;
    UINT64 value;
    BOOLEAN timeHandled = FALSE;

#if HACDBG_HIDE_VIRTUALIZATION
    if (g_TscDeadlinePresent != FALSE && msr == (UINT32)VMX_MSR_TSC_DEADLINE)
    {
        UINT64 deadline;

        if (VmxGuestCpl() != 0)
        {
            VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
            return TRUE;
        }

        if (Write != FALSE)
        {
            deadline = (ProcessorContext->Registers.Rdx << 32) |
                       (UINT32)ProcessorContext->Registers.Rax;
            if (deadline == 0)
            {
                (void)VmxWriteTscDeadline(0);
                ProcessorContext->TscDeadlineArmed = FALSE;
                ProcessorContext->HostDeadlineValid = FALSE;
                ProcessorContext->GuestTscDeadline = 0;
                ProcessorContext->HostTscDeadline = 0;
            }
            else
            {
                ProcessorContext->GuestTscDeadline = deadline;
                ProcessorContext->TscDeadlineArmed = TRUE;
                ProcessorContext->HostDeadlineValid = FALSE;
                ProcessorContext->HostTscDeadline = 0;
            }
        }
        else
        {
            deadline = 0;
            if (ProcessorContext->TscDeadlineArmed != FALSE &&
                __rdtsc() + ProcessorContext->TscOffset < ProcessorContext->GuestTscDeadline)
            {
                deadline = ProcessorContext->GuestTscDeadline;
            }

            ProcessorContext->Registers.Rax = (UINT32)deadline;
            ProcessorContext->Registers.Rdx = deadline >> 32;
        }

        return VmxAdvanceRip();
    }

    if (msr == (UINT32)VMX_MSR_TIME_STAMP_COUNTER)
    {
        UINT64 now;
        UINT64 desired;

        if (Write == FALSE || VmxGuestCpl() != 0)
        {
            VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
            return TRUE;
        }

        desired = (ProcessorContext->Registers.Rdx << 32) |
                  (UINT32)ProcessorContext->Registers.Rax;
        now = __rdtsc();
        ProcessorContext->GuestTscOffset = desired - now;
        ProcessorContext->TscBias = 0;
        ProcessorContext->TscOffset = ProcessorContext->GuestTscOffset;
        ProcessorContext->LastGuestTsc = desired;
        return VmxAdvanceRip();
    }

    if (g_TscAdjustPresent != FALSE && msr == (UINT32)VMX_MSR_TSC_ADJUST)
    {
        UINT64 adjust;

        if (VmxGuestCpl() != 0)
        {
            VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
            return TRUE;
        }

        if (Write != FALSE)
        {
            UINT64 delta;

            adjust = (ProcessorContext->Registers.Rdx << 32) |
                     (UINT32)ProcessorContext->Registers.Rax;
            delta = adjust - ProcessorContext->GuestTscAdjust;
            ProcessorContext->GuestTscAdjust = adjust;
            ProcessorContext->GuestTscOffset += delta;
            ProcessorContext->TscOffset += delta;
            ProcessorContext->LastGuestTsc += delta;
        }
        else
        {
            adjust = ProcessorContext->GuestTscAdjust;
            ProcessorContext->Registers.Rax = (UINT32)adjust;
            ProcessorContext->Registers.Rdx = adjust >> 32;
        }

        return VmxAdvanceRip();
    }

    if (msr == VMX_MSR_FEATURE_CONTROL)
    {
        if (Write != FALSE)
        {
            VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
            return TRUE;
        }

        value = __readmsr(VMX_MSR_FEATURE_CONTROL);
        value |= VMX_FEATURE_CONTROL_LOCK;
        value &= ~(1ull << 1);
        value &= ~VMX_FEATURE_CONTROL_OUTSIDE_SMX;
        ProcessorContext->Registers.Rax = (UINT32)value;
        ProcessorContext->Registers.Rdx = value >> 32;
        return VmxAdvanceRip();
    }

    if (msr >= VMX_MSR_BASIC && msr <= VMX_MSR_VMX_LAST)
    {
        VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
        return TRUE;
    }
#endif

    if (g_SyntheticMsrPassthrough != 0 &&
        msr >= VMX_MSR_SYNTHETIC_FIRST &&
        msr <= VMX_MSR_SYNTHETIC_LAST)
    {
        if (msr == VMX_MSR_HV_GUEST_IDLE)
        {
            UINT64 rflags;
            UINT64 interruptibility;

            //
            // nt!PpmIdleGuestExecute reads MSR 400000F0H instead of HLT.
            // The read must not complete until an interrupt is deliverable.
            // Executing it from VMX root waits where the guest interrupt is
            // not delivered. Returning immediately makes the idle loop exit
            // on every iteration. Enter the guest in the HLT activity state
            // with RFLAGS.IF set, which is the same sequence as
            // nt!HalProcessorIdle.
            //
            if (Write == FALSE)
            {
                ProcessorContext->Registers.Rax = 0;
                ProcessorContext->Registers.Rdx = 0;
            }

            if (VmxAdvanceRip() == FALSE ||
                VmxRead(VMCS_GUEST_RFLAGS, &rflags) == FALSE ||
                VmxRead(VMCS_GUEST_INTERRUPTIBILITY, &interruptibility) == FALSE)
            {
                return FALSE;
            }

            rflags |= (1ull << 9);
            interruptibility &= ~3ull;
            if (VmxWrite(VMCS_GUEST_RFLAGS, rflags) == FALSE ||
                VmxWrite(VMCS_GUEST_INTERRUPTIBILITY, interruptibility) == FALSE ||
                VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 1) == FALSE)
            {
                return FALSE;
            }

            if (InterlockedCompareExchange(&g_GuestIdleIgnored, 1, 0) == 0)
            {
                HACDBG_LOG("HacDbg: Synthetic guest-idle MSR resumes as HLT.\n");
            }

            return TRUE;
        }

        if (VmxHandleSyntheticTime(ProcessorContext, msr, Write, &timeHandled) == FALSE)
        {
            return FALSE;
        }

        if (timeHandled != FALSE)
        {
            return TRUE;
        }

        value = (ProcessorContext->Registers.Rdx << 32) |
                (UINT32)ProcessorContext->Registers.Rax;
        if (VmxAccessMsr(msr, Write, &value) == FALSE)
        {
            VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
            return TRUE;
        }

        if (Write == FALSE)
        {
            ProcessorContext->Registers.Rax = (UINT32)value;
            ProcessorContext->Registers.Rdx = value >> 32;
        }

        return VmxAdvanceRip();
    }

    if (InterlockedIncrement(&g_UnexpectedMsrLogs) <= 8)
    {
        HACDBG_LOG("HacDbg: Err, MSR exit injected #GP msr=0x%x write=%u.\n", msr, Write);
    }

    VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
    return TRUE;
}

static BOOLEAN
VmxHandleXsetbv(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    int cpuInfo[4];
    UINT64 value;
    UINT64 allowed;

    if (VmxGuestCpl() != 0 || (UINT32)ProcessorContext->Registers.Rcx != 0)
    {
        VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
        return TRUE;
    }

    value = (ProcessorContext->Registers.Rdx << 32) |
            (UINT32)ProcessorContext->Registers.Rax;
    __cpuidex(cpuInfo, 0x0D, 0);
    allowed = (UINT64)(UINT32)cpuInfo[0] | ((UINT64)(UINT32)cpuInfo[1] << 32);

    if ((value & 1ull) == 0 ||
        (value & ~allowed) != 0 ||
        ((value & 4ull) != 0 && (value & 2ull) == 0))
    {
        VmxInjectHardwareException(VMX_VECTOR_GP, TRUE, 0);
        return TRUE;
    }

    _xsetbv(0, value);
    return VmxAdvanceRip();
}

static BOOLEAN
VmxHandleEptViolation(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    UINT64 qualification;
    UINT64 guestPhysical;
    UINT64 currentEptp;
    UINT64 nextEptp;
    BOOLEAN invalidateEpt;

    if (VmxRead(VMCS_EXIT_QUALIFICATION, &qualification) == FALSE ||
        VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS, &guestPhysical) == FALSE ||
        VmxRead(VMCS_CTRL_EPT_POINTER, &currentEptp) == FALSE)
    {
        return FALSE;
    }

    if (EptHandleViolation(qualification, guestPhysical, ProcessorContext->GuestCr3,
                           ProcessorContext->GuestRip, currentEptp, &nextEptp,
                           &invalidateEpt) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, unhandled EPT violation qual=0x%I64x gpa=0x%I64x rip=0x%I64x.\n",
                 qualification, guestPhysical, ProcessorContext->GuestRip);
        return FALSE;
    }

    if (nextEptp != currentEptp && VmxWrite(VMCS_CTRL_EPT_POINTER, nextEptp) == FALSE)
    {
        return FALSE;
    }

    if (invalidateEpt != FALSE)
    {
        VmxFlushAllProcessors();
    }

    return TRUE;
}

static BOOLEAN
VmxDispatch(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT32 Reason
    )
{
    if (ProcessorContext->StopRequested != FALSE)
    {
        if (Reason == VMX_EXIT_CPUID)
        {
            VmxAdvanceRip();
        }

        return VmxLeaveVmx(ProcessorContext);
    }

    switch (Reason)
    {
    case VMX_EXIT_CPUID:
        return VmxHandleCpuid(ProcessorContext) ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_CR_ACCESS:
        return VmxHandleCrAccess(ProcessorContext) ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_RDMSR:
        return VmxHandleMsr(ProcessorContext, FALSE) ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_WRMSR:
        return VmxHandleMsr(ProcessorContext, TRUE) ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_INVD:
        __wbinvd();
        return VmxAdvanceRip() ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_XSETBV:
        return VmxHandleXsetbv(ProcessorContext) ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_EPT_VIOLATION:
        return VmxHandleEptViolation(ProcessorContext) ? FALSE : VmxLeaveVmx(ProcessorContext);

    case VMX_EXIT_PREEMPTION_TIMER:
        return FALSE;

    case VMX_EXIT_GETSEC:
    case VMX_EXIT_VMCALL:
    case VMX_EXIT_VMCLEAR:
    case VMX_EXIT_VMLAUNCH:
    case VMX_EXIT_VMPTRLD:
    case VMX_EXIT_VMPTRST:
    case VMX_EXIT_VMREAD:
    case VMX_EXIT_VMRESUME:
    case VMX_EXIT_VMWRITE:
    case VMX_EXIT_VMXOFF:
    case VMX_EXIT_VMXON:
    case VMX_EXIT_INVEPT:
    case VMX_EXIT_INVVPID:
        VmxInjectHardwareException(VMX_VECTOR_UD, FALSE, 0);
        return FALSE;

    default:
        HACDBG_LOG("HacDbg: Err, unhandled VM-exit reason=%u rip=0x%I64x cr3=0x%I64x.\n",
                 Reason, ProcessorContext->GuestRip, ProcessorContext->GuestCr3);
        return VmxLeaveVmx(ProcessorContext);
    }
}

#define VMX_TSC_BIAS_LIMIT    10000ull
#define VMX_TSC_SAMPLE_COUNT  32u

//
// SDM 28.5.1: the VMX-preemption timer counts only in non-root operation
// and exits when it reaches zero. The value loaded on VM-entry is the
// VMCS field. An expiration exit saves zero when the save control is on.
// Entering again with zero exits before the guest runs, so this function
// never writes zero. IA32_VMX_MISC bits 4:0 select which TSC bit advances
// the count.
//
static BOOLEAN
VmxProgramPreemptionTimer(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ BOOLEAN Arm
    )
{
    UINT32 pin = g_PinControls;
    UINT32 ticks = 0xFFFFFFFFu;

    if (g_PreemptionTimerAvailable == FALSE && g_PreemptionTimerSticky == FALSE)
    {
        ProcessorContext->PreemptionTimerArmed = FALSE;
        return Arm == FALSE;
    }

    if (Arm != FALSE)
    {
        ticks = (UINT32)(VMX_TSC_BIAS_LIMIT >> g_PreemptionTimerShift);
        if (ticks < 2)
        {
            ticks = 2;
        }

        pin |= VMX_PIN_PREEMPTION_TIMER;
    }
    else if (g_PreemptionTimerSticky != FALSE)
    {
        pin |= VMX_PIN_PREEMPTION_TIMER;
    }

    //
    // INVARIANT: The current VMCS belongs to this processor. The timer
    // value is non-zero. Pin controls stay within the allowed-1 mask
    // captured at load, with the preemption-timer bit added only when
    // that bit may be 1.
    //
    if (VmxWrite(VMCS_GUEST_PREEMPTION_TIMER, ticks) == FALSE ||
        VmxWrite(VMCS_CTRL_PIN_BASED, pin) == FALSE)
    {
        return FALSE;
    }

    ProcessorContext->PreemptionTimerArmed = (UINT8)(Arm != FALSE);
    return TRUE;
}

static VOID
VmxNotePreemptionTimerFailure(
    VOID
    )
{
    if (InterlockedExchange(&g_PreemptionTimerLogged, 1) == 0)
    {
        HACDBG_LOG("HacDbg: Err, VMX-preemption timer could not be programmed.\n");
    }
}

#if HACDBG_HIDE_VIRTUALIZATION
// 进入客户前采 32 次 CPUID，取中位数当作客户自己执行这条指令的开销。
static UINT64
VmxMedianCpuidCost(
    VOID
    )
{
    UINT64 samples[VMX_TSC_SAMPLE_COUNT];
    UINT32 index;
    UINT32 cursor;

    for (index = 0; index < VMX_TSC_SAMPLE_COUNT; index++)
    {
        int registers[4];
        UINT64 start;
        UINT64 end;

        _mm_lfence();
        start = __rdtsc();
        __cpuid(registers, 0);
        end = __rdtsc();
        _mm_lfence();
        samples[index] = end - start;
    }

    for (index = 1; index < VMX_TSC_SAMPLE_COUNT; index++)
    {
        UINT64 value = samples[index];

        cursor = index;
        while (cursor > 0 && samples[cursor - 1] > value)
        {
            samples[cursor] = samples[cursor - 1];
            cursor--;
        }

        samples[cursor] = value;
    }

    return samples[VMX_TSC_SAMPLE_COUNT / 2];
}
#endif

static VOID
VmxAccountExit(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT32 Reason
    )
{
    if (Reason == VMX_EXIT_PREEMPTION_TIMER && ProcessorContext->TscOffsetting == FALSE)
    {
        if (VmxProgramPreemptionTimer(ProcessorContext, FALSE) == FALSE)
        {
            VmxNotePreemptionTimerFailure();
        }

        return;
    }

    if (ProcessorContext->TscOffsetting == FALSE)
    {
        return;
    }

#if HACDBG_HIDE_VIRTUALIZATION
    UINT64 now;
    UINT64 elapsed;
    UINT64 bias;
    UINT64 guestOffset;
    UINT64 bareGuest;
    UINT64 room;

    now = __rdtsc();
    if (ProcessorContext->TscAtExit != 0 && now >= ProcessorContext->TscAtExit)
    {
        elapsed = now - ProcessorContext->TscAtExit;
    }
    else
    {
        elapsed = VMX_TSC_BIAS_LIMIT + 1;
    }

    if (elapsed > ~ProcessorContext->HardwareTransition)
    {
        elapsed = ~0ull;
    }
    else
    {
        elapsed += ProcessorContext->HardwareTransition;
    }

    bias = ProcessorContext->TscBias;
    if (bias > VMX_TSC_BIAS_LIMIT)
    {
        bias = VMX_TSC_BIAS_LIMIT;
    }

    //
    // A long exit, including a hypercall that copies memory, must not be
    // charged. Charging it pulls this processor's guest TSC away from the
    // others and Windows schedules a high-resolution timer past interrupt
    // time. The preemption-timer exit exists only to retire the bias.
    //
    if (Reason == VMX_EXIT_PREEMPTION_TIMER || elapsed > VMX_TSC_BIAS_LIMIT)
    {
        bias = 0;
    }
    else
    {
        UINT64 charge = 0;

        if (elapsed > ProcessorContext->NativeCpuidCost)
        {
            charge = elapsed - ProcessorContext->NativeCpuidCost;
        }

        if (charge <= VMX_TSC_BIAS_LIMIT - bias)
        {
            bias += charge;
        }
    }

    guestOffset = ProcessorContext->GuestTscOffset;
    bareGuest = now + guestOffset;
    if (bareGuest < ProcessorContext->LastGuestTsc)
    {
        guestOffset = ProcessorContext->LastGuestTsc - now;
        bias = 0;
    }
    else
    {
        room = bareGuest - ProcessorContext->LastGuestTsc;
        if (bias > room)
        {
            bias = room;
        }
    }

    if (bias != 0 && g_PreemptionTimerAvailable != FALSE &&
        VmxProgramPreemptionTimer(ProcessorContext, TRUE) == FALSE)
    {
        VmxNotePreemptionTimerFailure();
        bias = 0;
        if (VmxProgramPreemptionTimer(ProcessorContext, FALSE) == FALSE)
        {
            VmxNotePreemptionTimerFailure();
        }
    }
    else if (bias == 0 &&
             (ProcessorContext->PreemptionTimerArmed != FALSE ||
              Reason == VMX_EXIT_PREEMPTION_TIMER))
    {
        if (VmxProgramPreemptionTimer(ProcessorContext, FALSE) == FALSE)
        {
            VmxNotePreemptionTimerFailure();
        }
    }

    ProcessorContext->GuestTscOffset = guestOffset;
    ProcessorContext->TscBias = bias;
    ProcessorContext->TscOffset = guestOffset - bias;
    ProcessorContext->LastGuestTsc = now + ProcessorContext->TscOffset;
    VmxSyncTscDeadline(ProcessorContext);
#else
    UNREFERENCED_PARAMETER(ProcessorContext);
    UNREFERENCED_PARAMETER(Reason);
#endif
}

BOOLEAN
VmxHandleVmExit(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    UINT64 reasonFull;
    UINT32 reason;
    BOOLEAN stopGuest;
    BOOLEAN entryFailure;

    VmxWrite(VMCS_CTRL_VMENTRY_INTERRUPTION, 0);

    if (VmxRead(VMCS_GUEST_RSP, &ProcessorContext->Registers.Rsp) == FALSE ||
        VmxRead(VMCS_EXIT_REASON, &reasonFull) == FALSE)
    {
        return VmxLeaveVmx(ProcessorContext);
    }

    reason = (UINT32)(reasonFull & VMX_EXIT_REASON_MASK);
    entryFailure = (reasonFull & VMX_EXIT_ENTRY_FAILURE) != 0;
    VmxRead(VMCS_GUEST_RIP, &ProcessorContext->GuestRip);
    VmxRead(VMCS_GUEST_CR3, &ProcessorContext->GuestCr3);

    if (entryFailure == FALSE)
    {
        UINT64 rights = 0;

        if (VmxRead(VMCS_GUEST_CS_ACCESS, &rights) != FALSE && ((rights >> 5) & 3u) == 0)
        {
            HypercallNoteKernelCr3(ProcessorContext->GuestCr3);
        }
    }

    if (entryFailure != FALSE)
    {
        UINT64 qualification = 0;
        UINT64 cr0 = 0;
        UINT64 cr4 = 0;
        UINT64 debugCtl = 0;
        UINT64 efer = 0;
        UINT64 cs = 0;
        UINT64 rflags = 0;
        UINT64 entry = 0;

        VmxRead(VMCS_EXIT_QUALIFICATION, &qualification);
        VmxRead(VMCS_GUEST_CR0, &cr0);
        VmxRead(VMCS_GUEST_CR4, &cr4);
        VmxRead(VMCS_GUEST_DEBUGCTL, &debugCtl);
        VmxRead(VMCS_GUEST_EFER, &efer);
        VmxRead(VMCS_GUEST_CS_ACCESS, &cs);
        VmxRead(VMCS_GUEST_RFLAGS, &rflags);
        VmxRead(VMCS_CTRL_VMENTRY, &entry);
        HACDBG_LOG("HacDbg: Err, VM-entry failed reason=%u qual=0x%I64x cr0=0x%I64x cr3=0x%I64x "
                   "cr4=0x%I64x efer=0x%I64x dbg=0x%I64x cs=0x%I64x rflags=0x%I64x rip=0x%I64x "
                   "entry=0x%I64x.\n",
                   reason, qualification, cr0, ProcessorContext->GuestCr3, cr4, efer, debugCtl, cs,
                   rflags, ProcessorContext->GuestRip, entry);
        stopGuest = VmxLeaveVmx(ProcessorContext);
    }
    else
    {
        stopGuest = VmxDispatch(ProcessorContext, reason);
    }

    if (stopGuest == FALSE)
    {
        if (InterlockedExchange(&ProcessorContext->InveptRequested, 0) != 0)
        {
            VmxInvalidateEpt(ProcessorContext);
        }

        VmxAccountExit(ProcessorContext, reason);
    }

    return stopGuest;
}

VMX_PROCESSOR_CONTEXT*
VmxAbortToGuest(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    UINT64 error = 0;

    VmxRead(VMCS_VM_INSTRUCTION_ERROR, &error);
    HACDBG_LOG("HacDbg: Err, VMRESUME failed error=%u.\n", (UINT32)error);
    ProcessorContext->InstructionError = (UINT32)error;
    VmxLeaveVmx(ProcessorContext);
    return ProcessorContext;
}

static BOOLEAN
VmxHideHostPage(
    _In_ UINT64 PhysicalAddress
    )
{
    if (EptIsEnabled() == FALSE)
    {
        return TRUE;
    }

    return EptHidePage(HacDbgGuestPhysicalAddress(PhysicalAddress & ~0xFFFull));
}

static BOOLEAN
VmxHideHostRange(
    _In_ PVOID Page,
    _In_ SIZE_T Bytes
    )
{
    ULONG_PTR address = (ULONG_PTR)Page;
    SIZE_T offset;

    for (offset = 0; offset < Bytes; offset += PAGE_SIZE)
    {
        PHYSICAL_ADDRESS physical = MmGetPhysicalAddress((PVOID)(address + offset));

        if (VmxHideHostPage((UINT64)physical.QuadPart) == FALSE)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
VmxLoadControls(
    VOID
    )
{
    int cpuInfo[4];
    UINT64 basic;
    BOOLEAN trueControls;
    UINT32 pinMsr;
    UINT32 procMsr;
    UINT32 exitMsr;
    UINT32 entryMsr;
    UINT32 desired2;
    UINT64 eptCap;

    if (g_ControlsReady != FALSE)
    {
        return TRUE;
    }

    basic = __readmsr(VMX_MSR_BASIC);
    if (((basic >> VMX_BASIC_MEMORY_TYPE_SHIFT) & 0xF) != VMX_BASIC_MEMORY_TYPE_WB)
    {
        HACDBG_LOG("HacDbg: Err, VMCS memory type is not write-back.\n");
        return FALSE;
    }

    trueControls = (basic & VMX_BASIC_TRUE_CONTROLS) != 0;
    pinMsr = trueControls ? VMX_MSR_TRUE_PINBASED_CTLS : VMX_MSR_PINBASED_CTLS;
    procMsr = trueControls ? VMX_MSR_TRUE_PROCBASED_CTLS : VMX_MSR_PROCBASED_CTLS;
    exitMsr = trueControls ? VMX_MSR_TRUE_EXIT_CTLS : VMX_MSR_EXIT_CTLS;
    entryMsr = trueControls ? VMX_MSR_TRUE_ENTRY_CTLS : VMX_MSR_ENTRY_CTLS;

    g_Cr0Fixed0 = __readmsr(VMX_MSR_CR0_FIXED0);
    g_Cr0Fixed1 = __readmsr(VMX_MSR_CR0_FIXED1);
    g_Cr4Fixed0 = __readmsr(VMX_MSR_CR4_FIXED0);
    g_Cr4Fixed1 = __readmsr(VMX_MSR_CR4_FIXED1);

    {
        UINT64 pinCap = __readmsr(pinMsr);

        g_PinControls = VmxAdjust(0, pinMsr);
        g_PreemptionTimerSticky = ((UINT32)pinCap & VMX_PIN_PREEMPTION_TIMER) != 0;
        g_PreemptionTimerAvailable = ((UINT32)(pinCap >> 32) & VMX_PIN_PREEMPTION_TIMER) != 0;
        g_PreemptionTimerShift = 0;
        if (g_PreemptionTimerAvailable != FALSE)
        {
            //
            // INVARIANT: IA32_VMX_MISC is readable before VMXON. Bits 4:0
            // are the VMX-preemption timer's TSC relationship.
            //
            g_PreemptionTimerShift = (UINT32)(__readmsr(VMX_MSR_MISC) & 0x1Fu);
        }
    }
    {
        UINT32 desiredProc = VMX_PROC_USE_MSR_BITMAPS | VMX_PROC_ACTIVATE_SECONDARY;

#if HACDBG_HIDE_VIRTUALIZATION
        //
        // An outer hypervisor already owns the TSC domain used by the guest
        // APIC timer. Subtracting exit cost from that domain makes every
        // TSC-deadline interrupt fire immediately.
        //
        if (g_SyntheticMsrPassthrough == 0)
        {
            desiredProc |= VMX_PROC_USE_TSC_OFFSETTING;
        }
#endif
        g_ProcControls = VmxAdjust(desiredProc, procMsr);
    }
#if HACDBG_HIDE_VIRTUALIZATION
    if (g_SyntheticMsrPassthrough == 0 &&
        (g_ProcControls & VMX_PROC_USE_TSC_OFFSETTING) == 0)
    {
        HACDBG_LOG("HacDbg: Err, TSC offsetting cannot be enabled.\n");
        return FALSE;
    }

    if (g_SyntheticMsrPassthrough == 0)
    {
        int leaf1[4];

        __cpuidex(cpuInfo, 7, 0);
        g_TscAdjustPresent = ((UINT32)cpuInfo[1] & VMX_CPUID_TSC_ADJUST) != 0 &&
                             VmxMsrPresent((ULONG)VMX_MSR_TSC_ADJUST) != FALSE;
        __cpuid(leaf1, 1);
        g_TscDeadlinePresent = ((UINT32)leaf1[2] & VMX_CPUID_TSC_DEADLINE) != 0 &&
                               VmxProbeTscDeadline() != FALSE;
    }
#endif
    desired2 = VMX_PROC2_ENABLE_EPT;
#if HACDBG_HIDE_VIRTUALIZATION
    if (g_SyntheticMsrPassthrough == 0)
    {
        desired2 |= VMX_PROC2_CONCEAL_VMX_FROM_PT;
    }
#endif
    __cpuidex(cpuInfo, 0x80000001, 0);
    if ((cpuInfo[3] & (1 << 27)) != 0)
    {
        desired2 |= VMX_PROC2_ENABLE_RDTSCP;
    }

    __cpuidex(cpuInfo, 7, 0);
    if ((cpuInfo[1] & (1 << 10)) != 0)
    {
        desired2 |= VMX_PROC2_ENABLE_INVPCID;
    }

    __cpuidex(cpuInfo, 0x0D, 1);
    if ((cpuInfo[0] & (1 << 3)) != 0)
    {
        desired2 |= VMX_PROC2_ENABLE_XSAVES;
    }

    eptCap = __readmsr(VMX_MSR_EPT_VPID_CAP);
    if ((eptCap & (VMX_EPT_CAP_WALK4 | VMX_EPT_CAP_WB | VMX_EPT_CAP_2MB | VMX_EPT_CAP_INVEPT)) !=
        (VMX_EPT_CAP_WALK4 | VMX_EPT_CAP_WB | VMX_EPT_CAP_2MB | VMX_EPT_CAP_INVEPT))
    {
        HACDBG_LOG("HacDbg: Err, EPT capabilities are missing: 0x%I64x.\n", eptCap);
        return FALSE;
    }

    g_InveptType = (eptCap & VMX_EPT_CAP_INVEPT_SINGLE) != 0
                       ? VMX_INVEPT_SINGLE_CONTEXT
                       : VMX_INVEPT_ALL_CONTEXT;
    if ((__readmsr(VMX_MSR_PROCBASED_CTLS2) >> 32) & VMX_PROC2_ENABLE_VPID)
    {
        desired2 |= VMX_PROC2_ENABLE_VPID;
    }

    g_ProcControls2 = VmxAdjust(desired2, VMX_MSR_PROCBASED_CTLS2);
    {
        UINT32 exitRequested = VMX_EXIT_HOST_ADDR_SPACE_SIZE | VMX_EXIT_SAVE_DEBUG;
        UINT32 entryRequested = VMX_ENTRY_IA32E_MODE_GUEST | VMX_ENTRY_LOAD_DEBUG;

#if HACDBG_HIDE_VIRTUALIZATION
        if (g_SyntheticMsrPassthrough == 0)
        {
            UINT32 exitWithPmc;
            UINT32 entryWithPmc;

            exitRequested |= VMX_EXIT_CONCEAL_VMX_FROM_PT;
            entryRequested |= VMX_ENTRY_CONCEAL_VMX_FROM_PT;
            exitWithPmc = exitRequested | VMX_EXIT_LOAD_PERF_GLOBAL | VMX_EXIT_SAVE_PERF_GLOBAL;
            entryWithPmc = entryRequested | VMX_ENTRY_LOAD_PERF_GLOBAL;
            g_ExitControls = VmxAdjust(exitWithPmc, exitMsr);
            g_EntryControls = VmxAdjust(entryWithPmc, entryMsr);
            g_PmcFreeze = (g_ExitControls & (VMX_EXIT_LOAD_PERF_GLOBAL | VMX_EXIT_SAVE_PERF_GLOBAL)) ==
                              (VMX_EXIT_LOAD_PERF_GLOBAL | VMX_EXIT_SAVE_PERF_GLOBAL) &&
                          (g_EntryControls & VMX_ENTRY_LOAD_PERF_GLOBAL) != 0;
            if (g_PmcFreeze == FALSE)
            {
                g_ExitControls = VmxAdjust(exitRequested, exitMsr);
                g_EntryControls = VmxAdjust(entryRequested, entryMsr);
                if ((g_ExitControls & VMX_EXIT_LOAD_PERF_GLOBAL) != 0 ||
                    (g_EntryControls & VMX_ENTRY_LOAD_PERF_GLOBAL) != 0)
                {
                    HACDBG_LOG("HacDbg: Err, IA32_PERF_GLOBAL_CTRL controls cannot be paired.\n");
                    return FALSE;
                }
            }
        }
        else
        {
            g_PmcFreeze = FALSE;
            g_ExitControls = VmxAdjust(exitRequested, exitMsr);
            g_EntryControls = VmxAdjust(entryRequested, entryMsr);
        }
#else
        g_PmcFreeze = FALSE;
        g_ExitControls = VmxAdjust(exitRequested, exitMsr);
        g_EntryControls = VmxAdjust(entryRequested, entryMsr);
#endif
    }

    if ((g_PinControls & (VMX_PIN_EXTERNAL_INT_EXITING | VMX_PIN_NMI_EXITING)) != 0 ||
        (g_ProcControls & (VMX_PROC_HLT_EXITING | VMX_PROC_INVLPG_EXITING |
                           VMX_PROC_RDTSC_EXITING | VMX_PROC_CR3_LOAD_EXITING |
                           VMX_PROC_CR3_STORE_EXITING | VMX_PROC_IO_EXITING |
                           VMX_PROC_USE_IO_BITMAPS | VMX_PROC_MONITOR_TRAP_FLAG)) != 0 ||
        (g_ProcControls & (VMX_PROC_USE_MSR_BITMAPS | VMX_PROC_ACTIVATE_SECONDARY)) !=
            (VMX_PROC_USE_MSR_BITMAPS | VMX_PROC_ACTIVATE_SECONDARY) ||
        (g_ExitControls & VMX_EXIT_LOAD_CET) != 0 ||
        (g_EntryControls & VMX_ENTRY_LOAD_CET) != 0 ||
        (g_ExitControls & VMX_EXIT_HOST_ADDR_SPACE_SIZE) == 0 ||
        (g_EntryControls & VMX_ENTRY_IA32E_MODE_GUEST) == 0)
    {
        HACDBG_LOG("HacDbg: Err, VMX controls pin=0x%x proc=0x%x proc2=0x%x exit=0x%x entry=0x%x.\n",
                 g_PinControls, g_ProcControls, g_ProcControls2, g_ExitControls, g_EntryControls);
        return FALSE;
    }

    if ((g_ProcControls2 & VMX_PROC2_ENABLE_EPT) == 0)
    {
        HACDBG_LOG("HacDbg: Err, EPT cannot be enabled.\n");
        return FALSE;
    }

    if ((desired2 & VMX_PROC2_ENABLE_RDTSCP) != 0 &&
        (g_ProcControls2 & VMX_PROC2_ENABLE_RDTSCP) == 0)
    {
        HACDBG_LOG("HacDbg: Err, RDTSCP cannot be kept enabled in VMX non-root.\n");
        return FALSE;
    }

    if ((desired2 & VMX_PROC2_ENABLE_INVPCID) != 0 &&
        (g_ProcControls2 & VMX_PROC2_ENABLE_INVPCID) == 0)
    {
        HACDBG_LOG("HacDbg: Err, INVPCID cannot be kept enabled in VMX non-root.\n");
        return FALSE;
    }

    if ((desired2 & VMX_PROC2_ENABLE_XSAVES) != 0 &&
        (g_ProcControls2 & VMX_PROC2_ENABLE_XSAVES) == 0)
    {
        HACDBG_LOG("HacDbg: Err, XSAVES cannot be kept enabled in VMX non-root.\n");
        return FALSE;
    }

    g_ControlsReady = TRUE;
    return TRUE;
}

NTSTATUS
VmxCheckSupport(
    VOID
    )
{
    int cpuInfo[4];
    UINT64 featureControl;

    __cpuid(cpuInfo, 0);
    if (cpuInfo[1] != 0x756E6547 || cpuInfo[3] != 0x49656E69 || cpuInfo[2] != 0x6C65746E)
    {
        return STATUS_NOT_SUPPORTED;
    }

    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & VMX_CPUID_VMX_BIT) == 0)
    {
        return STATUS_NOT_SUPPORTED;
    }

    if ((cpuInfo[2] & VMX_CPUID_HYPERVISOR_PRESENT) != 0)
    {
        InterlockedExchange(&g_SyntheticMsrPassthrough, 1);
        HACDBG_LOG("HacDbg: Synthetic MSRs 0x%x-0x%x are passed through.\n",
                   VMX_MSR_SYNTHETIC_FIRST, VMX_MSR_SYNTHETIC_LAST);
#if HACDBG_HIDE_VIRTUALIZATION
        HACDBG_LOG("HacDbg: Outer hypervisor present. TSC offsetting stays off.\n");
#endif
    }

    featureControl = __readmsr(VMX_MSR_FEATURE_CONTROL);
    if ((featureControl & VMX_FEATURE_CONTROL_LOCK) == 0 ||
        (featureControl & VMX_FEATURE_CONTROL_OUTSIDE_SMX) == 0)
    {
        HACDBG_LOG("HacDbg: Err, IA32_FEATURE_CONTROL does not allow VMX: 0x%I64x.\n",
                 featureControl);
        return STATUS_NOT_SUPPORTED;
    }

    if (VmxLoadControls() == FALSE)
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (g_SyntheticMsrPassthrough != 0 && VmxSnapshotGuestClock() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, synthetic time MSR snapshot failed.\n");
    }

    return STATUS_SUCCESS;
}

NTSTATUS
VmxInitializeShared(
    VOID
    )
{
    HacDbgSpinLockInitialize(&g_ProcessorLock);
    return STATUS_SUCCESS;
}

VOID
VmxCleanupShared(
    VOID
    )
{
    g_ControlsReady = FALSE;
    InterlockedExchange(&g_SyntheticMsrPassthrough, 0);
    InterlockedExchange(&g_UnexpectedMsrLogs, 0);
    InterlockedExchange(&g_GuestIdleIgnored, 0);
    InterlockedExchange(&g_HvTimeReady, 0);
}

ULONG
VmxGetSharedFailureDetail(
    VOID
    )
{
    return 0;
}

VOID
VmxConcealCpuid(
    _In_ UINT32 Leaf,
    _Inout_ HACDBG_GUEST_REGISTERS* Registers
    )
{
#if HACDBG_HIDE_VIRTUALIZATION
    if (Leaf == 1)
    {
        Registers->Rcx &= ~VMX_CPUID_VMX_BIT;
    }
#else
    UNREFERENCED_PARAMETER(Leaf);
    UNREFERENCED_PARAMETER(Registers);
#endif
}

static NTSTATUS
VmxPrepareProcessor(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT16 Vpid
    )
{
    UINT64 basic = __readmsr(VMX_MSR_BASIC);
    UINT32 revision = (UINT32)(basic & 0x7FFFFFFFu);
    ULONG_PTR hostTop;
    PHYSICAL_ADDRESS physical;

    ProcessorContext->Vmxon = VmxAllocateAligned(PAGE_SIZE, &ProcessorContext->VmxonAllocation);
    ProcessorContext->Vmcs = VmxAllocateAligned(PAGE_SIZE, &ProcessorContext->VmcsAllocation);
    ProcessorContext->MsrBitmap = VmxAllocateAligned(PAGE_SIZE, &ProcessorContext->MsrBitmapAllocation);
    ProcessorContext->HostStack = VmxAllocateAligned(HACDBG_HOST_STACK_SIZE,
                                                     &ProcessorContext->HostStackAllocation);

    if (ProcessorContext->Vmxon == NULL || ProcessorContext->Vmcs == NULL ||
        ProcessorContext->MsrBitmap == NULL || ProcessorContext->HostStack == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *(UINT32*)ProcessorContext->Vmxon = revision;
    *(UINT32*)ProcessorContext->Vmcs = revision;
    RtlZeroMemory(ProcessorContext->MsrBitmap, PAGE_SIZE);

#if HACDBG_HIDE_VIRTUALIZATION
    {
        UINT32 msr;

        VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_FEATURE_CONTROL, VMX_MSR_BITMAP_READ_LOW);
        VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_FEATURE_CONTROL, VMX_MSR_BITMAP_WRITE_LOW);
        for (msr = (UINT32)VMX_MSR_BASIC; msr <= (UINT32)VMX_MSR_VMX_LAST; msr++)
        {
            VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, msr, VMX_MSR_BITMAP_READ_LOW);
            VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, msr, VMX_MSR_BITMAP_WRITE_LOW);
        }

        if (g_SyntheticMsrPassthrough == 0)
        {
            VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_TIME_STAMP_COUNTER,
                         VMX_MSR_BITMAP_WRITE_LOW);
            if (g_TscAdjustPresent != FALSE)
            {
                VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_TSC_ADJUST,
                             VMX_MSR_BITMAP_READ_LOW);
                VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_TSC_ADJUST,
                             VMX_MSR_BITMAP_WRITE_LOW);
            }

            if (g_TscDeadlinePresent != FALSE)
            {
                VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_TSC_DEADLINE,
                             VMX_MSR_BITMAP_READ_LOW);
                VmxBitmapSet((PUCHAR)ProcessorContext->MsrBitmap, (UINT32)VMX_MSR_TSC_DEADLINE,
                             VMX_MSR_BITMAP_WRITE_LOW);
            }
        }
    }
#endif

    physical = MmGetPhysicalAddress(ProcessorContext->Vmxon);
    ProcessorContext->VmxonPa = (UINT64)physical.QuadPart;
    physical = MmGetPhysicalAddress(ProcessorContext->Vmcs);
    ProcessorContext->VmcsPa = (UINT64)physical.QuadPart;
    physical = MmGetPhysicalAddress(ProcessorContext->MsrBitmap);
    ProcessorContext->MsrBitmapPa = (UINT64)physical.QuadPart;

    if ((ProcessorContext->VmxonPa | ProcessorContext->VmcsPa | ProcessorContext->MsrBitmapPa) &
        (PAGE_SIZE - 1))
    {
        return STATUS_UNSUCCESSFUL;
    }

    hostTop = ((ULONG_PTR)ProcessorContext->HostStack + HACDBG_HOST_STACK_SIZE) & ~(ULONG_PTR)0xF;
    hostTop -= 8;
    *(VMX_PROCESSOR_CONTEXT**)hostTop = ProcessorContext;
    ProcessorContext->HostRsp = hostTop;
    ProcessorContext->Vpid = Vpid;
    ProcessorContext->EptEnabled = EptIsEnabled();

    if (VmxHideHostRange(ProcessorContext->Vmxon, PAGE_SIZE) == FALSE ||
        VmxHideHostRange(ProcessorContext->Vmcs, PAGE_SIZE) == FALSE ||
        VmxHideHostRange(ProcessorContext->MsrBitmap, PAGE_SIZE) == FALSE ||
        VmxHideHostRange(ProcessorContext->HostStack, HACDBG_HOST_STACK_SIZE) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, hiding VMX host pages failed.\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static BOOLEAN
VmxFillVmcs(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ const CONTEXT* Context
    )
{
    VMX_TABLE_REGISTER gdtr = { 0 };
    VMX_TABLE_REGISTER idtr = { 0 };
    UINT16 tr = VmxReadTr();
    UINT16 ldtr = VmxReadLdtr();
    UINT64 cr0 = (__readcr0() | g_Cr0Fixed0) & g_Cr0Fixed1;
    UINT64 cr3 = __readcr3();
    UINT64 cr4 = (__readcr4() | g_Cr4Fixed0) & g_Cr4Fixed1;
    UINT64 guestCr4 = cr4;

    //
    // VM-entry rejects CR0.NW set while CR0.CD is clear, and rejects CR3
    // bits 11:0 when CR4.PCIDE is 0. CR4.VMXE may be set only when
    // IA32_VMX_CR4_FIXED1 allows it.
    //
    if ((cr0 & VMX_CR0_CD) == 0)
    {
        cr0 &= ~VMX_CR0_NW;
    }

    if ((g_Cr4Fixed1 & VMX_CR4_VMXE) != 0)
    {
        guestCr4 |= VMX_CR4_VMXE;
    }

    if ((guestCr4 & VMX_CR4_PCIDE) == 0)
    {
        cr3 &= ~0xFFFull;
    }
    else
    {
        cr3 &= ~(1ull << 63);
    }

    HypercallNoteKernelCr3(cr3);
    UINT64 efer = __readmsr(HACDBG_MSR_EFER);
    UINT64 pat = __readmsr(HACDBG_MSR_PAT);
    UINT16 hostCs = (UINT16)(Context->SegCs & 0xF8u);

    _sgdt(&gdtr);
    __sidt(&idtr);
    ProcessorContext->SavedGdtrLimit = gdtr.Limit;
    ProcessorContext->SavedGdtrBase = gdtr.Base;
    ProcessorContext->SavedIdtrLimit = idtr.Limit;
    ProcessorContext->SavedIdtrBase = idtr.Base;
    ProcessorContext->DescriptorTablesSaved = TRUE;
    cr4 |= VMX_CR4_VMXE;
    __writecr0(cr0);
    if ((cr4 & VMX_CR4_PCIDE) == 0)
    {
        //
        // INVARIANT: CR3 is the current kernel page-table root. Clearing
        // CR4.PCIDE while bits 11:0 of CR3 are nonzero raises #GP.
        //
        __writecr3(__readcr3() & ~0xFFFull);
    }
    __writecr4(cr4);

    if (VmxWrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ull) == FALSE ||
        VmxWrite(VMCS_CTRL_PIN_BASED, g_PinControls) == FALSE ||
        VmxWrite(VMCS_CTRL_PROCESSOR_BASED, g_ProcControls) == FALSE ||
        VmxWrite(VMCS_CTRL_PROCESSOR_BASED2, g_ProcControls2) == FALSE ||
        VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP, 0) == FALSE ||
        VmxWrite(VMCS_CTRL_VMEXIT, g_ExitControls) == FALSE ||
        VmxWrite(VMCS_CTRL_VMENTRY, g_EntryControls) == FALSE ||
        VmxWrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0) == FALSE ||
        VmxWrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0) == FALSE ||
        VmxWrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0) == FALSE ||
        VmxWrite(VMCS_CTRL_VMENTRY_INTERRUPTION, 0) == FALSE ||
        VmxWrite(VMCS_CTRL_MSR_BITMAP, ProcessorContext->MsrBitmapPa) == FALSE ||
        VmxWrite(VMCS_CTRL_CR0_MASK, 0) == FALSE ||
        VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, cr0) == FALSE ||
        VmxWrite(VMCS_CTRL_CR4_MASK, VMX_CR4_VMXE) == FALSE ||
        VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, VmxCr4ReadShadow(guestCr4)) == FALSE)
    {
        return FALSE;
    }

    if ((g_PinControls & VMX_PIN_PREEMPTION_TIMER) != 0 &&
        VmxWrite(VMCS_GUEST_PREEMPTION_TIMER, 0xFFFFFFFFull) == FALSE)
    {
        return FALSE;
    }

    if ((g_ProcControls & VMX_PROC_USE_TSC_OFFSETTING) != 0 &&
        VmxWrite(VMCS_CTRL_TSC_OFFSET, ProcessorContext->TscOffset) == FALSE)
    {
        return FALSE;
    }

    if (g_PmcFreeze != FALSE &&
        (VmxWrite(VMCS_GUEST_PERF_GLOBAL_CTRL, __readmsr(VMX_MSR_PERF_GLOBAL_CTRL)) == FALSE ||
         VmxWrite(VMCS_HOST_PERF_GLOBAL_CTRL, 0) == FALSE))
    {
        return FALSE;
    }

    if ((g_ProcControls2 & VMX_PROC2_ENABLE_EPT) != 0 &&
        VmxWrite(VMCS_CTRL_EPT_POINTER, EptMainEptp()) == FALSE)
    {
        return FALSE;
    }

    if ((g_ProcControls2 & VMX_PROC2_ENABLE_VPID) != 0 &&
        VmxWrite(VMCS_CTRL_VPID, ProcessorContext->Vpid) == FALSE)
    {
        return FALSE;
    }

    if (((g_ExitControls & (VMX_EXIT_SAVE_EFER | VMX_EXIT_LOAD_EFER)) != 0 ||
         (g_EntryControls & VMX_ENTRY_LOAD_EFER) != 0) &&
        (VmxWrite(VMCS_GUEST_EFER, efer) == FALSE || VmxWrite(VMCS_HOST_EFER, efer) == FALSE))
    {
        return FALSE;
    }

    if (((g_ExitControls & ((1u << 18) | (1u << 19))) != 0 ||
         (g_EntryControls & (1u << 14)) != 0) &&
        (VmxWrite(VMCS_GUEST_PAT, pat) == FALSE || VmxWrite(VMCS_HOST_PAT, pat) == FALSE))
    {
        return FALSE;
    }

    if ((g_EntryControls & VMX_ENTRY_LOAD_DEBUG) != 0 &&
        (VmxWrite(VMCS_GUEST_DEBUGCTL, __readmsr(HACDBG_MSR_DEBUGCTL)) == FALSE ||
         VmxWrite(VMCS_GUEST_DR7, __readdr(7)) == FALSE))
    {
        return FALSE;
    }

    if (VmxWriteSegment((UINT16)Context->SegEs, gdtr.Base, VMCS_GUEST_ES_SELECTOR,
                        VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_ACCESS, VMCS_GUEST_ES_BASE,
                        VmxDescriptorBase(gdtr.Base, (UINT16)Context->SegEs), TRUE, FALSE) == FALSE ||
        VmxWriteSegment((UINT16)Context->SegCs, gdtr.Base, VMCS_GUEST_CS_SELECTOR,
                        VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_ACCESS, VMCS_GUEST_CS_BASE,
                        VmxDescriptorBase(gdtr.Base, (UINT16)Context->SegCs), FALSE, FALSE) == FALSE ||
        VmxWriteSegment((UINT16)Context->SegSs, gdtr.Base, VMCS_GUEST_SS_SELECTOR,
                        VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_ACCESS, VMCS_GUEST_SS_BASE,
                        VmxDescriptorBase(gdtr.Base, (UINT16)Context->SegSs), FALSE, FALSE) == FALSE ||
        VmxWriteSegment((UINT16)Context->SegDs, gdtr.Base, VMCS_GUEST_DS_SELECTOR,
                        VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_ACCESS, VMCS_GUEST_DS_BASE,
                        VmxDescriptorBase(gdtr.Base, (UINT16)Context->SegDs), TRUE, FALSE) == FALSE ||
        VmxWriteSegment((UINT16)Context->SegFs, gdtr.Base, VMCS_GUEST_FS_SELECTOR,
                        VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_ACCESS, VMCS_GUEST_FS_BASE,
                        __readmsr(HACDBG_MSR_FS_BASE), TRUE, FALSE) == FALSE ||
        VmxWriteSegment((UINT16)Context->SegGs, gdtr.Base, VMCS_GUEST_GS_SELECTOR,
                        VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_ACCESS, VMCS_GUEST_GS_BASE,
                        __readmsr(HACDBG_MSR_GS_BASE), TRUE, FALSE) == FALSE ||
        VmxWriteSegment(ldtr, gdtr.Base, VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_LDTR_LIMIT,
                        VMCS_GUEST_LDTR_ACCESS, VMCS_GUEST_LDTR_BASE,
                        VmxDescriptorBase(gdtr.Base, ldtr), TRUE, FALSE) == FALSE ||
        VmxWriteSegment(tr, gdtr.Base, VMCS_GUEST_TR_SELECTOR, VMCS_GUEST_TR_LIMIT,
                        VMCS_GUEST_TR_ACCESS, VMCS_GUEST_TR_BASE,
                        VmxDescriptorBase(gdtr.Base, tr), FALSE, TRUE) == FALSE)
    {
        return FALSE;
    }

    return VmxWrite(VMCS_GUEST_GDTR_BASE, gdtr.Base) &&
           VmxWrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit) &&
           VmxWrite(VMCS_GUEST_IDTR_BASE, idtr.Base) &&
           VmxWrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit) &&
           VmxWrite(VMCS_GUEST_INTERRUPTIBILITY, 0) &&
           VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0) &&
           VmxWrite(VMCS_GUEST_SYSENTER_CS, __readmsr(HACDBG_MSR_SYSENTER_CS)) &&
           VmxWrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(HACDBG_MSR_SYSENTER_ESP)) &&
           VmxWrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(HACDBG_MSR_SYSENTER_EIP)) &&
           VmxWrite(VMCS_GUEST_CR0, cr0) &&
           VmxWrite(VMCS_GUEST_CR3, cr3) &&
           VmxWrite(VMCS_GUEST_CR4, guestCr4) &&
           VmxWrite(VMCS_GUEST_RSP, Context->Rsp) &&
           VmxWrite(VMCS_GUEST_RIP, Context->Rip) &&
           VmxWrite(VMCS_GUEST_RFLAGS, ((UINT64)Context->EFlags) | 2ull) &&
           VmxWrite(VMCS_HOST_ES_SELECTOR, (UINT16)(Context->SegEs & 0xF8u)) &&
           VmxWrite(VMCS_HOST_CS_SELECTOR, hostCs) &&
           VmxWrite(VMCS_HOST_SS_SELECTOR, (UINT16)(Context->SegSs & 0xF8u)) &&
           VmxWrite(VMCS_HOST_DS_SELECTOR, (UINT16)(Context->SegDs & 0xF8u)) &&
           VmxWrite(VMCS_HOST_FS_SELECTOR, (UINT16)(Context->SegFs & 0xF8u)) &&
           VmxWrite(VMCS_HOST_GS_SELECTOR, (UINT16)(Context->SegGs & 0xF8u)) &&
           VmxWrite(VMCS_HOST_TR_SELECTOR, (UINT16)(tr & 0xF8u)) &&
           VmxWrite(VMCS_HOST_CR0, cr0) &&
           VmxWrite(VMCS_HOST_CR3, __readcr3()) &&
           VmxWrite(VMCS_HOST_CR4, cr4) &&
           VmxWrite(VMCS_HOST_FS_BASE, __readmsr(HACDBG_MSR_FS_BASE)) &&
           VmxWrite(VMCS_HOST_GS_BASE, __readmsr(HACDBG_MSR_GS_BASE)) &&
           VmxWrite(VMCS_HOST_TR_BASE, VmxDescriptorBase(gdtr.Base, tr)) &&
           VmxWrite(VMCS_HOST_GDTR_BASE, gdtr.Base) &&
           VmxWrite(VMCS_HOST_IDTR_BASE, idtr.Base) &&
           VmxWrite(VMCS_HOST_SYSENTER_CS, __readmsr(HACDBG_MSR_SYSENTER_CS)) &&
           VmxWrite(VMCS_HOST_SYSENTER_ESP, __readmsr(HACDBG_MSR_SYSENTER_ESP)) &&
           VmxWrite(VMCS_HOST_SYSENTER_EIP, __readmsr(HACDBG_MSR_SYSENTER_EIP)) &&
           VmxWrite(VMCS_HOST_RSP, ProcessorContext->HostRsp) &&
           VmxWrite(VMCS_HOST_RIP, (UINT64)(ULONG_PTR)VmxExitEntry);
}

static VOID
VmxVirtualizeProcessor(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    CONTEXT context;
    UINT8 status;
    UINT64 tscBefore;
    UINT64 vpRuntime;

    RtlCaptureContext(&context);

    if (ProcessorContext->Virtualized != FALSE || ProcessorContext->LaunchCompleted != FALSE)
    {
        return;
    }

    ProcessorContext->StopRequested = FALSE;
    ProcessorContext->Virtualized = TRUE;
    vpRuntime = 0;
    if (g_SyntheticMsrPassthrough != 0)
    {
        //
        // INVARIANT: Still before VMXON, so this per-processor runtime is
        // the outer guest's value.
        //
        if (VmxReadSyntheticMsr(VMX_MSR_HV_VP_RUNTIME, &vpRuntime) == FALSE)
        {
            vpRuntime = 0;
        }
    }

    ProcessorContext->VpRuntime = vpRuntime;
#if HACDBG_HIDE_VIRTUALIZATION
    if (g_SyntheticMsrPassthrough == 0)
    {
        ProcessorContext->GuestTscOffset = 0;
        ProcessorContext->TscBias = 0;
        ProcessorContext->TscOffset = 0;
        ProcessorContext->NativeCpuidCost = VmxMedianCpuidCost();
        ProcessorContext->HardwareTransition = 0;
        ProcessorContext->PreemptionTimerArmed = FALSE;
        ProcessorContext->TscOffsetting = TRUE;
        if (g_TscAdjustPresent != FALSE)
        {
            __try
            {
                ProcessorContext->GuestTscAdjust = __readmsr(VMX_MSR_TSC_ADJUST);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ProcessorContext->GuestTscAdjust = 0;
            }
        }
    }
#endif
    _disable();

    if (VmxLoadControls() == FALSE)
    {
        ProcessorContext->Virtualized = FALSE;
        ProcessorContext->LaunchCompleted = TRUE;
        _enable();
        return;
    }

    __writecr4(__readcr4() | VMX_CR4_VMXE);
    //
    // INVARIANT: VmxonPa is the 4 KiB-aligned VMXON region for this processor.
    // It is not mapped executable into the guest when EPT is enabled.
    // TscBeforeVmxon is the guest TSC. TscAfterVmxon is the first RDTSC after
    // VMXON and may use a different offset in VMX root.
    //
    tscBefore = __rdtsc();
    status = HacDbgVmxOn(&ProcessorContext->VmxonPa);
    ProcessorContext->TscBeforeVmxon = tscBefore;
    ProcessorContext->TscAfterVmxon = __rdtsc();
    if (status != 0 ||
        VmxClear(&ProcessorContext->VmcsPa) != 0 ||
        VmxPtrld(&ProcessorContext->VmcsPa) != 0 ||
        VmxFillVmcs(ProcessorContext, &context) == FALSE)
    {
        UINT64 error = 0;

        VmxRead(VMCS_VM_INSTRUCTION_ERROR, &error);
        HACDBG_LOG("HacDbg: Err, VMCS setup failed status=%u error=%u.\n", status, (UINT32)error);
        if (status == 0)
        {
            VmxExitVmxRoot(ProcessorContext);
        }
        else
        {
            __writecr4(__readcr4() & ~VMX_CR4_VMXE);
        }
        ProcessorContext->Virtualized = FALSE;
        ProcessorContext->LaunchCompleted = TRUE;
        _enable();
        return;
    }

    //
    // INVARIANT: This processor is in VMX operation, its VMCS is current, and
    // it is not already in VMX non-root operation.
    //
#if HACDBG_HIDE_VIRTUALIZATION
    if (ProcessorContext->TscOffsetting != FALSE)
    {
        UINT64 deadline = 0;

        ProcessorContext->LastGuestTsc = __rdtsc();
        ProcessorContext->TscDeadlineArmed = FALSE;
        ProcessorContext->HostDeadlineValid = FALSE;
        ProcessorContext->GuestTscDeadline = 0;
        ProcessorContext->HostTscDeadline = 0;
        if (g_TscDeadlinePresent != FALSE)
        {
            __try
            {
                //
                // INVARIANT: Still before the first VM-entry. The offset is
                // zero, so the OS deadline is already in the host TSC domain.
                //
                deadline = __readmsr(VMX_MSR_TSC_DEADLINE);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                deadline = 0;
            }
        }

        if (deadline != 0)
        {
            ProcessorContext->GuestTscDeadline = deadline;
            ProcessorContext->HostTscDeadline = deadline;
            ProcessorContext->HostDeadlineValid = TRUE;
            ProcessorContext->TscDeadlineArmed = TRUE;
        }
    }
#endif
    //
    // Leave MmCopyMemory disabled before the first VM-entry. A TLB-shootdown
    // IPI from that API is delivered to processors that are still guests.
    //
    PhysicalMemorySetGuestRunning(TRUE);
    VmxLaunchVm(ProcessorContext, ProcessorContext->HostRsp);
    VmxExitVmxRoot(ProcessorContext);
    ProcessorContext->Virtualized = FALSE;
    ProcessorContext->LaunchCompleted = TRUE;
    _enable();
}

static VOID
VmxStopProcessor(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    int registers[4];

    if (ProcessorContext->Virtualized == FALSE)
    {
        return;
    }

    ProcessorContext->StopRequested = TRUE;
    __cpuidex(registers, HACDBG_STOP_CPUID_LEAF, HACDBG_STOP_CPUID_SUBLEAF);
}

static VOID
VmxFreeProcessor(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    if (ProcessorContext->VmxonAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->VmxonAllocation, HACDBG_VMX_TAG);
    }
    if (ProcessorContext->VmcsAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->VmcsAllocation, HACDBG_VMX_TAG);
    }
    if (ProcessorContext->MsrBitmapAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->MsrBitmapAllocation, HACDBG_VMX_TAG);
    }
    if (ProcessorContext->HostStackAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->HostStackAllocation, HACDBG_VMX_TAG);
    }

    ExFreePoolWithTag(ProcessorContext, HACDBG_VMX_TAG);
}

static BOOLEAN
VmxSelectProcessor(
    _In_ ULONG Index,
    _Out_ GROUP_AFFINITY* Previous
    )
{
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity;

    if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(Index, &processorNumber)))
    {
        return FALSE;
    }

    affinity.Group = processorNumber.Group;
    affinity.Mask = 1ull << processorNumber.Number;
    affinity.Reserved[0] = 0;
    affinity.Reserved[1] = 0;
    affinity.Reserved[2] = 0;
    KeSetSystemGroupAffinityThread(&affinity, Previous);
    return TRUE;
}

NTSTATUS
VmxStartAllProcessors(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index;

    g_ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (g_ProcessorCount > HACDBG_MAX_PROCESSORS)
    {
        return STATUS_NOT_SUPPORTED;
    }

    for (index = 0; index < g_ProcessorCount; index++)
    {
        GROUP_AFFINITY previous;
        VMX_PROCESSOR_CONTEXT* context;

        if (VmxSelectProcessor(index, &previous) == FALSE)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        context = (VMX_PROCESSOR_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                          sizeof(*context),
                                                          HACDBG_VMX_TAG);
        if (context == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            RtlZeroMemory(context, sizeof(*context));
            g_Processors[index] = context;
            status = VmxPrepareProcessor(context, (UINT16)(index + 1));
        }

        KeRevertToUserGroupAffinityThread(&previous);
        if (!NT_SUCCESS(status))
        {
            break;
        }
    }

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (index = 0; index < g_ProcessorCount; index++)
    {
        GROUP_AFFINITY previous;

        if (VmxSelectProcessor(index, &previous) == FALSE)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        VmxVirtualizeProcessor(g_Processors[index]);
        if (g_Processors[index]->Virtualized == FALSE)
        {
            status = STATUS_UNSUCCESSFUL;
        }

        KeRevertToUserGroupAffinityThread(&previous);
        if (!NT_SUCCESS(status))
        {
            break;
        }
    }

    return status;
}

VOID
VmxStopAllProcessors(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < g_ProcessorCount; index++)
    {
        GROUP_AFFINITY previous;

        if (g_Processors[index] == NULL || VmxSelectProcessor(index, &previous) == FALSE)
        {
            continue;
        }

        VmxStopProcessor(g_Processors[index]);
        KeRevertToUserGroupAffinityThread(&previous);
    }

    for (index = 0; index < g_ProcessorCount; index++)
    {
        if (g_Processors[index] != NULL && g_Processors[index]->Virtualized != FALSE)
        {
            return;
        }
    }

    PhysicalMemorySetGuestRunning(FALSE);
}

NTSTATUS
VmxRestartAllProcessors(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < g_ProcessorCount; index++)
    {
        GROUP_AFFINITY previous;

        if (g_Processors[index] == NULL)
        {
            continue;
        }

        if (VmxSelectProcessor(index, &previous) == FALSE)
        {
            VmxStopAllProcessors();
            return STATUS_UNSUCCESSFUL;
        }

        g_Processors[index]->StopRequested = FALSE;
        g_Processors[index]->LaunchCompleted = FALSE;
        g_Processors[index]->Virtualized = FALSE;
        VmxVirtualizeProcessor(g_Processors[index]);

        if (g_Processors[index]->Virtualized == FALSE)
        {
            KeRevertToUserGroupAffinityThread(&previous);
            VmxStopAllProcessors();
            return STATUS_UNSUCCESSFUL;
        }

        KeRevertToUserGroupAffinityThread(&previous);
    }

    return STATUS_SUCCESS;
}

VOID
VmxFreeAllProcessors(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < HACDBG_MAX_PROCESSORS; index++)
    {
        if (g_Processors[index] != NULL)
        {
            if (g_Processors[index]->Virtualized != FALSE)
            {
                KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x48444301ull, index, 0, 0);
            }

            VmxFreeProcessor(g_Processors[index]);
            g_Processors[index] = NULL;
        }
    }

    g_ProcessorCount = 0;
}

VOID
VmxFlushAllProcessors(
    VOID
    )
{
    ULONG index;

    HacDbgSpinLockAcquire(&g_ProcessorLock);

    for (index = 0; index < HACDBG_MAX_PROCESSORS; index++)
    {
        if (g_Processors[index] != NULL)
        {
            InterlockedExchange(&g_Processors[index]->InveptRequested, 1);
        }
    }

    HacDbgSpinLockRelease(&g_ProcessorLock);
}
