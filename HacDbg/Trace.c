/**
 * @file Trace.c
 * @brief Per-processor VM-exit counters and optional event rings.
 *
 * @author HacDbg
 */

#include "Trace.h"
#include "Config.h"
#include "Debug.h"
#include "PhysicalMemory.h"
#include "../shared/hypercall/hypercall_def.h"

#include <intrin.h>

#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#include "Vmx.h"
#define HACDBG_TRACE_BACKEND HACDBG_TRACE_BACKEND_INTEL
#define HACDBG_TRACE_HIDE_PAGE(Page) EptHidePage(HacDbgGuestPhysicalAddress(Page))
#else
#include "Npt.h"
#include "Svm.h"
#define HACDBG_TRACE_BACKEND HACDBG_TRACE_BACKEND_AMD
#define HACDBG_TRACE_HIDE_PAGE(Page) NptHidePage(HacDbgGuestPhysicalAddress(Page))
#endif

#define HACDBG_TRACE_TAG 'TcaH'

typedef struct _HACDBG_TRACE_RING
{
    volatile LONG64 Sequence;
    volatile LONG ValidCount;
    volatile LONG Next;
    HACDBG_TRACE_EVENT Events[HACDBG_TRACE_EVENTS_PER_CPU];
} HACDBG_TRACE_RING;

struct _HACDBG_TRACE_CPU_STATE
{
    HACDBG_TRACE_CPU Counters;
    HACDBG_TRACE_RING Ring;
    UINT32 SampleCountdown;
    UINT32 Reserved;
};

typedef struct _HACDBG_TRACE_STATE
{
    HACDBG_TRACE_CPU_STATE Cpu[HACDBG_TRACE_MAX_CPUS];
    HACDBG_TRACE_SNAPSHOT Snapshot;
} HACDBG_TRACE_STATE;

static HACDBG_TRACE_STATE* g_Trace;
static PVOID g_TraceAllocation;
static UINT32 g_TraceCpuCount;
static HACDBG_SPIN_LOCK g_TraceLock;
static volatile LONG g_TraceCountersEnabled;
static volatile LONG g_TraceEventsEnabled;
static volatile LONG g_TraceSampleRate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
static volatile LONG g_TraceEventMask = HACDBG_TRACE_EVENT_MASK_ALL;
static volatile LONG g_TraceResetInProgress;

static BOOLEAN
TraceHideAllocation(
    _In_ const HACDBG_TRACE_STATE* State
    )
{
    ULONG_PTR first = (ULONG_PTR)State & ~(PAGE_SIZE - 1);
    ULONG_PTR last = ((ULONG_PTR)State + sizeof(*State) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    ULONG_PTR page;

    for (page = first; page < last; page += PAGE_SIZE)
    {
        PHYSICAL_ADDRESS physical = MmGetPhysicalAddress((PVOID)page);

        if (physical.QuadPart == 0 || HACDBG_TRACE_HIDE_PAGE((ULONG_PTR)physical.QuadPart) == FALSE)
        {
            return FALSE;
        }
    }

    return TRUE;
}

NTSTATUS
TraceInitialize(
    VOID
    )
{
    PVOID allocation;
    HACDBG_TRACE_STATE* state;
    ULONG cpuCount;
    ULONG index;

    if (g_Trace != NULL)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpuCount == 0 || cpuCount > HACDBG_TRACE_MAX_CPUS)
    {
        return STATUS_NOT_SUPPORTED;
    }

    allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*state) + PAGE_SIZE,
                                 HACDBG_TRACE_TAG);
    if (allocation == NULL)
    {
        HACDBG_LOG("HacDbg: Err, trace state allocation failed: %Iu bytes.\n", sizeof(*state));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    state = (HACDBG_TRACE_STATE*)(((ULONG_PTR)allocation + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    RtlZeroMemory(state, sizeof(*state));
    for (index = 0; index < cpuCount; index++)
    {
        state->Cpu[index].Counters.CpuIndex = index;
        state->Cpu[index].SampleCountdown = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
    }

    g_Trace = state;
    g_TraceAllocation = allocation;
    g_TraceCpuCount = cpuCount;
    g_TraceCountersEnabled = 0;
    g_TraceEventsEnabled = 0;
    g_TraceSampleRate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
    g_TraceEventMask = HACDBG_TRACE_EVENT_MASK_ALL;
    g_TraceResetInProgress = 0;
    HacDbgSpinLockInitialize(&g_TraceLock);

    //
    // INVARIANT: The trace allocation is nonpaged, not yet visible to a guest,
    // and all of its pages are hidden before any processor executes VMRUN or
    // VMLAUNCH. The allocation remains alive until TraceCleanup after all
    // processors leave the guest.
    //
    if (TraceHideAllocation(state) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, trace pages could not be hidden from the guest.\n");
        g_Trace = NULL;
        g_TraceAllocation = NULL;
        g_TraceCpuCount = 0;
        ExFreePoolWithTag(allocation, HACDBG_TRACE_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    HACDBG_LOG("HacDbg: Trace state ready: cpus=%u bytes=%Iu.\n", cpuCount, sizeof(*state));
    return STATUS_SUCCESS;
}

VOID
TraceCleanup(
    VOID
    )
{
    HACDBG_TRACE_STATE* state = g_Trace;
    PVOID allocation = g_TraceAllocation;

    if (state == NULL)
    {
        return;
    }

    TraceDisable();
    g_Trace = NULL;
    g_TraceAllocation = NULL;
    g_TraceCpuCount = 0;
    ExFreePoolWithTag(allocation, HACDBG_TRACE_TAG);
}

VOID
TraceDisable(
    VOID
    )
{
    InterlockedExchange(&g_TraceCountersEnabled, 0);
    InterlockedExchange(&g_TraceEventsEnabled, 0);
}

BOOLEAN
TraceIsEnabled(
    VOID
    )
{
    return g_TraceCountersEnabled != 0 || g_TraceEventsEnabled != 0;
}

BOOLEAN
TraceEventsEnabled(
    VOID
    )
{
    return g_TraceEventsEnabled != 0;
}

HACDBG_TRACE_CPU_STATE*
TraceCpuState(
    _In_ UINT32 CpuIndex
    )
{
    if (g_Trace == NULL || CpuIndex >= g_TraceCpuCount)
    {
        return NULL;
    }

    return &g_Trace->Cpu[CpuIndex];
}

static UINT32
TraceMapReason(
    _In_ UINT32 RawReason,
    _In_ UINT32 Flags
    )
{
#if HACDBG_BACKEND_INTEL
    if ((Flags & HACDBG_TRACE_EVENT_FLAG_ENTRY_FAILURE) != 0)
    {
        return HACDBG_TRACE_REASON_OTHER;
    }

    switch (RawReason)
    {
    case VMX_EXIT_CPUID:
        return HACDBG_TRACE_REASON_CPUID;
    case VMX_EXIT_RDMSR:
    case VMX_EXIT_WRMSR:
        return HACDBG_TRACE_REASON_MSR;
    case VMX_EXIT_EPT_VIOLATION:
    case VMX_EXIT_EPT_MISCONFIG:
        return HACDBG_TRACE_REASON_NESTED_PAGE_FAULT;
    case VMX_EXIT_PREEMPTION_TIMER:
        return HACDBG_TRACE_REASON_PREEMPTION_TIMER;
    case VMX_EXIT_XSETBV:
        return HACDBG_TRACE_REASON_XSETBV;
    case VMX_EXIT_INVD:
        return HACDBG_TRACE_REASON_INVD;
    case VMX_EXIT_MONITOR_TRAP:
        return HACDBG_TRACE_REASON_MONITOR_TRAP;
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
        return HACDBG_TRACE_REASON_VMX_INSTRUCTION;
    default:
        return HACDBG_TRACE_REASON_OTHER;
    }
#else
    UNREFERENCED_PARAMETER(Flags);

    switch (RawReason)
    {
    case SVM_EXIT_CPUID:
        return HACDBG_TRACE_REASON_CPUID;
    case SVM_EXIT_MSR:
        return HACDBG_TRACE_REASON_MSR;
    case SVM_EXIT_NPF:
        return HACDBG_TRACE_REASON_NESTED_PAGE_FAULT;
    case SVM_EXIT_VMRUN:
    case SVM_EXIT_VMLOAD:
    case SVM_EXIT_VMSAVE:
    case SVM_EXIT_STGI:
    case SVM_EXIT_CLGI:
    case SVM_EXIT_SKINIT:
        return HACDBG_TRACE_REASON_SVM_INSTRUCTION;
    default:
        return HACDBG_TRACE_REASON_OTHER;
    }
#endif
}

static BOOLEAN
TraceIsOwnHypercall(
    _In_ const BOOLEAN IsCpuid,
    _In_ const UINT64 Rcx
    )
{
    hypercall_info_t information = { 0 };

    if (IsCpuid == FALSE)
    {
        return FALSE;
    }

    information.value = Rcx;
    return information.primary_key == hypercall_primary_key &&
           information.secondary_key == hypercall_secondary_key &&
           (information.call_type == trace_control || information.call_type == trace_read);
}

static VOID
TraceAddEvent(
    _Inout_ HACDBG_TRACE_CPU_STATE* Cpu,
    _In_ const HACDBG_TRACE_EVENT* Event
    )
{
    HACDBG_TRACE_RING* ring = &Cpu->Ring;
    UINT32 slot;

    InterlockedIncrement64(&ring->Sequence);
    KeMemoryBarrier();

    slot = (UINT32)ring->Next;
    ring->Events[slot] = *Event;
    ring->Next = (LONG)((slot + 1u) % HACDBG_TRACE_EVENTS_PER_CPU);

    if ((UINT32)ring->ValidCount < HACDBG_TRACE_EVENTS_PER_CPU)
    {
        ring->ValidCount = ring->ValidCount + 1;
    }
    else if (Cpu->Counters.DroppedEvents != 0xFFFFFFFFu)
    {
        Cpu->Counters.DroppedEvents = Cpu->Counters.DroppedEvents + 1;
    }

    KeMemoryBarrier();
    InterlockedIncrement64(&ring->Sequence);
}

VOID
TraceRecordExit(
    _In_ HACDBG_TRACE_CPU_STATE* Cpu,
    _In_ UINT64 Tsc,
    _In_ UINT64 Rip,
    _In_ UINT64 Cr3,
    _In_ UINT32 RawReason,
    _In_ UINT64 ExitInfo1,
    _In_ UINT64 ExitInfo2,
    _In_ UINT32 Flags,
    _In_ BOOLEAN IsCpuid,
    _In_ UINT64 Rcx
    )
{
    UINT32 reason;
    LONG sampleRate;
    LONG eventMask;

    if (Cpu == NULL || TraceIsEnabled() == FALSE || g_TraceResetInProgress != 0 ||
        TraceIsOwnHypercall(IsCpuid, Rcx) != FALSE)
    {
        return;
    }

    reason = TraceMapReason(RawReason, Flags);

    if (g_TraceCountersEnabled != 0)
    {
        Cpu->Counters.TotalExits = Cpu->Counters.TotalExits + 1;
        Cpu->Counters.ReasonCounts[reason] = Cpu->Counters.ReasonCounts[reason] + 1;
    }

    if (g_TraceEventsEnabled == 0)
    {
        return;
    }

    sampleRate = g_TraceSampleRate;
    if (sampleRate <= 0)
    {
        sampleRate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
    }

    if (Cpu->SampleCountdown > 1)
    {
        Cpu->SampleCountdown = Cpu->SampleCountdown - 1;
        return;
    }

    Cpu->SampleCountdown = (UINT32)sampleRate;
    eventMask = g_TraceEventMask;

    if ((eventMask & (1 << reason)) == 0)
    {
        return;
    }

    {
        HACDBG_TRACE_EVENT event = { 0 };

        event.Tsc = Tsc;
        event.Rip = Rip;
        event.Cr3 = Cr3;
        event.ExitInfo1 = ExitInfo1;
        event.ExitInfo2 = ExitInfo2;
        event.CpuIndex = Cpu->Counters.CpuIndex;
        event.Reason = reason;
        event.Backend = HACDBG_TRACE_BACKEND;
        event.Flags = Flags;
        TraceAddEvent(Cpu, &event);
    }
}

static VOID
TraceResetCpuState(
    _Inout_ HACDBG_TRACE_CPU_STATE* Cpu,
    _In_ UINT32 CpuIndex,
    _In_ UINT32 SampleRate
    )
{
    RtlZeroMemory(Cpu, sizeof(*Cpu));
    Cpu->Counters.CpuIndex = CpuIndex;
    Cpu->SampleCountdown = SampleRate;
}

UINT64
TraceControl(
    _In_ const UINT64 Flags,
    _In_ const UINT64 SampleRate,
    _In_ const UINT64 EventMask
    )
{
    UINT32 flags = (UINT32)Flags;
    UINT32 sampleRate = (UINT32)SampleRate;
    UINT32 eventMask = (UINT32)EventMask & HACDBG_TRACE_EVENT_MASK_ALL;
    UINT32 resetSampleRate;
    UINT32 index;

    if (g_Trace == NULL)
    {
        return 0;
    }

    HacDbgSpinLockAcquire(&g_TraceLock);
    resetSampleRate = (flags & HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE) != 0
                          ? (sampleRate == 0 ? HACDBG_TRACE_DEFAULT_SAMPLE_RATE : sampleRate)
                          : (UINT32)g_TraceSampleRate;

    if ((flags & HACDBG_TRACE_CONTROL_RESET) != 0)
    {
        TraceDisable();
        InterlockedExchange(&g_TraceResetInProgress, 1);
        KeMemoryBarrier();

        for (index = 0; index < g_TraceCpuCount; index++)
        {
            TraceResetCpuState(&g_Trace->Cpu[index], index, resetSampleRate);
        }

        KeMemoryBarrier();
        InterlockedExchange(&g_TraceResetInProgress, 0);
    }

    if ((flags & HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE) != 0)
    {
        if (sampleRate == 0)
        {
            sampleRate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
        }

        InterlockedExchange(&g_TraceSampleRate, (LONG)sampleRate);
        for (index = 0; index < g_TraceCpuCount; index++)
        {
            g_Trace->Cpu[index].SampleCountdown = sampleRate;
        }
    }

    if ((flags & HACDBG_TRACE_CONTROL_SET_EVENT_MASK) != 0)
    {
        InterlockedExchange(&g_TraceEventMask, (LONG)eventMask);
    }

    if ((flags & HACDBG_TRACE_CONTROL_DISABLE) != 0)
    {
        TraceDisable();
    }
    else if ((flags & (HACDBG_TRACE_CONTROL_ENABLE_COUNTERS |
                       HACDBG_TRACE_CONTROL_ENABLE_EVENTS)) != 0)
    {
        InterlockedExchange(&g_TraceCountersEnabled, 1);
        InterlockedExchange(&g_TraceEventsEnabled,
                            (flags & HACDBG_TRACE_CONTROL_ENABLE_EVENTS) != 0);

        if ((flags & HACDBG_TRACE_CONTROL_ENABLE_EVENTS) != 0)
        {
            const LONG rate = g_TraceSampleRate;

            for (index = 0; index < g_TraceCpuCount; index++)
            {
                g_Trace->Cpu[index].SampleCountdown = rate > 0
                                                          ? (UINT32)rate
                                                          : HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
            }
        }
    }

    HacDbgSpinLockRelease(&g_TraceLock);
    return 1;
}

static BOOLEAN
TraceCopyRingEvent(
    _In_ const HACDBG_TRACE_RING* Ring,
    _In_ const UINT32 NewestOffset,
    _Out_ HACDBG_TRACE_EVENT* EventOut
    )
{
    UINT32 attempt;

    RtlZeroMemory(EventOut, sizeof(*EventOut));

    for (attempt = 0; attempt < 4; attempt++)
    {
        LONG64 sequence = InterlockedCompareExchange64((volatile LONG64*)&Ring->Sequence, 0, 0);
        LONG next;
        LONG valid;
        UINT32 index;

        if ((sequence & 1) != 0)
        {
            YieldProcessor();
            continue;
        }

        KeMemoryBarrier();
        valid = Ring->ValidCount;
        next = Ring->Next;

        if (NewestOffset >= (UINT32)valid)
        {
            return FALSE;
        }

        index = (UINT32)next + HACDBG_TRACE_EVENTS_PER_CPU - 1u - NewestOffset;
        index %= HACDBG_TRACE_EVENTS_PER_CPU;
        *EventOut = Ring->Events[index];
        KeMemoryBarrier();

        if (InterlockedCompareExchange64((volatile LONG64*)&Ring->Sequence, 0, 0) == sequence)
        {
            return TRUE;
        }
    }

    return FALSE;
}

UINT64
TraceRead(
    _In_ const UINT64 DestinationCr3,
    _In_ const GUEST_VIRTUAL_ADDRESS Destination,
    _In_ const UINT64 Size,
    _In_ const UINT64 CpuFilter
    )
{
    HACDBG_TRACE_SNAPSHOT* snapshot;
    UINT32 firstCpu;
    UINT32 cpuCount;
    UINT32 outputIndex;
    UINT32 round;
    UINT64 written;

    if (g_Trace == NULL || Destination.Value == 0 || Size < sizeof(HACDBG_TRACE_SNAPSHOT))
    {
        return 0;
    }

    if (CpuFilter != HACDBG_TRACE_ALL_CPUS && CpuFilter >= g_TraceCpuCount)
    {
        return 0;
    }

    HacDbgSpinLockAcquire(&g_TraceLock);
    snapshot = &g_Trace->Snapshot;
    RtlZeroMemory(snapshot, sizeof(*snapshot));

    snapshot->Version = HACDBG_TRACE_VERSION;
    snapshot->CapturedTsc = __rdtsc();
    snapshot->Flags =
        (g_TraceCountersEnabled != 0 ? HACDBG_TRACE_FLAG_COUNTERS_ENABLED : 0) |
        (g_TraceEventsEnabled != 0 ? HACDBG_TRACE_FLAG_EVENTS_ENABLED : 0);

    firstCpu = CpuFilter == HACDBG_TRACE_ALL_CPUS ? 0 : (UINT32)CpuFilter;
    cpuCount = CpuFilter == HACDBG_TRACE_ALL_CPUS ? g_TraceCpuCount : 1;
    snapshot->CpuCount = cpuCount;

    for (outputIndex = 0; outputIndex < cpuCount; outputIndex++)
    {
        const UINT32 cpuIndex = firstCpu + outputIndex;
        const HACDBG_TRACE_CPU_STATE* cpu = &g_Trace->Cpu[cpuIndex];

        snapshot->Cpu[outputIndex] = cpu->Counters;
        snapshot->Cpu[outputIndex].CpuIndex = cpuIndex;
        snapshot->TotalExits += cpu->Counters.TotalExits;
        snapshot->DroppedEvents += cpu->Counters.DroppedEvents;
    }

    //
    // Fill the recent-event window fairly across the selected processors:
    // take the newest event from every processor, then the second newest,
    // and so on. The user-mode consumer can sort the bounded result by TSC.
    //
    for (round = 0; round < HACDBG_TRACE_EVENTS_PER_CPU &&
                    snapshot->EventCount < HACDBG_TRACE_MAX_EVENTS;
         round++)
    {
        for (outputIndex = 0; outputIndex < cpuCount &&
                              snapshot->EventCount < HACDBG_TRACE_MAX_EVENTS;
             outputIndex++)
        {
            const UINT32 cpuIndex = firstCpu + outputIndex;
            HACDBG_TRACE_EVENT event;

            if (TraceCopyRingEvent(&g_Trace->Cpu[cpuIndex].Ring, round, &event) != FALSE)
            {
                event.CpuIndex = cpuIndex;
                snapshot->Events[snapshot->EventCount] = event;
                snapshot->EventCount++;
            }
        }
    }

    //
    // INVARIANT: DestinationCr3 belongs to the CPUID caller, Destination points
    // into that process, and the snapshot is a host-only nonpaged buffer hidden
    // from the guest. GuestVirtualWrite performs the page translations.
    //
    written = GuestVirtualWrite(DestinationCr3, Destination, snapshot, sizeof(*snapshot));
    HacDbgSpinLockRelease(&g_TraceLock);

    return written;
}
