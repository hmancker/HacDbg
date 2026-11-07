/**
 * @file Timer.c
 * @brief Enumerate IO timers and per-processor DPC timers.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <intrin.h>

#include "Timer.h"
#include "Debug.h"
#include "Search.h"

#define TIMER_TAG 'mTiH'
#define TIMER_IO_PERIOD_MS 1000u
#define TIMER_TABLE_OFFSET 0x4100u
#define TIMER_ENTRY_OFFSET 0x200u
#define TIMER_ENTRY_STRIDE 0x20u
#define TIMER_ENTRY_COUNT 512u
#define TIMER_LIST_OFFSET 0x08u
#define TIMER_WALK_LIMIT 64u
#define TIMER_DPC_WALK_LIMIT 4096u
#define TIMER_TYPE_NOTIFICATION 8u
#define TIMER_TYPE_SYNCHRONIZATION 9u
#define TIMER_DPC_OBJECT 0x13u
#define TIMER_THREADED_DPC_OBJECT 0x1Au
#define TIMER_IO_OBJECT 9u

typedef struct _TIMER_IO_BLOCK
{
    SHORT Type;
    SHORT TimerFlag;
    ULONG Reserved;
    LIST_ENTRY TimerList;
    PVOID TimerRoutine;
    PVOID Context;
    PDEVICE_OBJECT DeviceObject;
} TIMER_IO_BLOCK;

typedef struct _TIMER_KTIMER_BLOCK
{
    UCHAR Type;
    UCHAR Reserved0[0x1F];
    LIST_ENTRY TimerListEntry;
    PVOID Dpc;
    USHORT Processor;
    USHORT TimerType;
    ULONG Period;
} TIMER_KTIMER_BLOCK;

C_ASSERT(FIELD_OFFSET(TIMER_IO_BLOCK, TimerList) == 0x08);
C_ASSERT(FIELD_OFFSET(TIMER_IO_BLOCK, TimerRoutine) == 0x18);
C_ASSERT(FIELD_OFFSET(TIMER_IO_BLOCK, DeviceObject) == 0x28);
C_ASSERT(FIELD_OFFSET(TIMER_KTIMER_BLOCK, TimerListEntry) == 0x20);
C_ASSERT(FIELD_OFFSET(TIMER_KTIMER_BLOCK, Dpc) == 0x30);
C_ASSERT(FIELD_OFFSET(TIMER_KTIMER_BLOCK, Period) == 0x3C);

static PLIST_ENTRY g_TimerQueueHead = NULL;
static PKSPIN_LOCK g_TimerLock = NULL;
static UINT64* g_TimerWaitNever = NULL;
static UINT64* g_TimerWaitAlways = NULL;

static PVOID
TimerResolveRip(
    _In_ const UCHAR* Code
    )
{
    LONG Displacement;

    Displacement = *(LONG*)(Code + 3);
    return (PVOID)(Code + 7 + Displacement);
}

static BOOLEAN
TimerLocateQueue(
    VOID
    )
{
    UNICODE_STRING Name;
    UCHAR* Code;
    ULONG Index;
    PVOID Head;
    PVOID Lock;

    if (g_TimerQueueHead != NULL && g_TimerLock != NULL)
    {
        return TRUE;
    }

    RtlInitUnicodeString(&Name, L"IoInitializeTimer");
    Code = (UCHAR*)MmGetSystemRoutineAddress(&Name);
    if (Code == NULL)
    {
        HACDBG_LOG("HacDbg: Err, timer IoInitializeTimer was not found.\n");
        return FALSE;
    }

    Head = NULL;
    Lock = NULL;
    for (Index = 0; Index + 7 < 0x100; ++Index)
    {
        if (MmIsAddressValid(Code + Index + 6) == FALSE)
        {
            break;
        }

        if (Code[Index] == 0xC3)
        {
            break;
        }

        if (Code[Index] == 0x4C && Code[Index + 1] == 0x8D && Code[Index + 2] == 0x05)
        {
            Lock = TimerResolveRip(Code + Index);
        }

        if (Code[Index] == 0x48 && Code[Index + 1] == 0x8D && Code[Index + 2] == 0x0D)
        {
            Head = TimerResolveRip(Code + Index);
        }
    }

    if (Head == NULL || Lock == NULL || MmIsAddressValid(Head) == FALSE || MmIsAddressValid(Lock) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, timer queue was not found.\n");
        return FALSE;
    }

    g_TimerQueueHead = (PLIST_ENTRY)Head;
    g_TimerLock = (PKSPIN_LOCK)Lock;
    return TRUE;
}

static BOOLEAN
TimerMatchWaitKeys(
    _In_ UCHAR* Code,
    _In_ ULONG Limit
    )
{
    ULONG Index;

    for (Index = 0; Index + 17 < Limit; ++Index)
    {
        PVOID Never;
        PVOID Always;

        if (MmIsAddressValid(Code + Index + 16) == FALSE)
        {
            break;
        }

        Never = NULL;
        Always = NULL;

        //
        // 26100 KiSetTimerEx loads KiWaitNever into rax, moves the DPC into
        // rbp, then xors KiWaitAlways. 19041 loads KiWaitAlways into rsi
        // after saving the timer in rdi. Both immediates are rip-relative.
        //
        if (Code[Index] == 0x48 && Code[Index + 1] == 0x8B && Code[Index + 2] == 0x05 &&
            Code[Index + 7] == 0x49 && Code[Index + 8] == 0x8B && Code[Index + 9] == 0xEE &&
            Code[Index + 10] == 0x48 && Code[Index + 11] == 0x33 && Code[Index + 12] == 0x2D)
        {
            Never = TimerResolveRip(Code + Index);
            Always = TimerResolveRip(Code + Index + 10);
        }
        else if (Code[Index] == 0x48 && Code[Index + 1] == 0x8B && Code[Index + 2] == 0x05 &&
                 Code[Index + 7] == 0x48 && Code[Index + 8] == 0x8B && Code[Index + 9] == 0xF9 &&
                 Code[Index + 10] == 0x48 && Code[Index + 11] == 0x8B && Code[Index + 12] == 0x35)
        {
            Never = TimerResolveRip(Code + Index);
            Always = TimerResolveRip(Code + Index + 10);
        }

        if (Never == NULL || Always == NULL || ((ULONG_PTR)Never & 7) != 0 || ((ULONG_PTR)Always & 7) != 0 ||
            MmIsAddressValid(Never) == FALSE || MmIsAddressValid(Always) == FALSE)
        {
            continue;
        }

        g_TimerWaitNever = (UINT64*)Never;
        g_TimerWaitAlways = (UINT64*)Always;
        HACDBG_LOG("HacDbg: Timer wait keys %p %p.\n", g_TimerWaitNever, g_TimerWaitAlways);
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
TimerLocateWaitKeys(
    VOID
    )
{
    UNICODE_STRING Name;
    UCHAR* Code;
    UCHAR* Callee;
    ULONG Index;
    LONG Relative;

    if (g_TimerWaitNever != NULL && g_TimerWaitAlways != NULL)
    {
        return TRUE;
    }

    RtlInitUnicodeString(&Name, L"KeSetTimerEx");
    Code = (UCHAR*)MmGetSystemRoutineAddress(&Name);
    if (Code == NULL || MmIsAddressValid(Code) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, timer KeSetTimerEx was not found.\n");
        return FALSE;
    }

    if (Code[0] == 0xE9 && MmIsAddressValid(Code + 4) != FALSE)
    {
        Relative = *(LONG*)(Code + 1);
        Code = Code + 5 + Relative;
        if (MmIsAddressValid(Code) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, timer KeSetTimerEx was not found.\n");
            return FALSE;
        }
    }

    if (TimerMatchWaitKeys(Code, 0x40) != FALSE)
    {
        return TRUE;
    }

    Callee = NULL;
    for (Index = 0; Index + 5 < 0x40; ++Index)
    {
        if (MmIsAddressValid(Code + Index + 4) == FALSE)
        {
            break;
        }

        if (Code[Index] != 0xE8)
        {
            continue;
        }

        Relative = *(LONG*)(Code + Index + 1);
        Callee = Code + Index + 5 + Relative;
        break;
    }

    if (Callee == NULL || MmIsAddressValid(Callee) == FALSE || TimerMatchWaitKeys(Callee, 0x80) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, timer wait keys were not found.\n");
        return FALSE;
    }

    return TRUE;
}

static PVOID
TimerDecodeDpc(
    _In_ TIMER_KTIMER_BLOCK* Timer
    )
{
    UINT64 Never;
    UINT64 Always;
    UINT64 Value;

    //
    // KiSetTimerEx writes
    // rotr64(bswap64(Dpc ^ KiWaitAlways) ^ Timer, KiWaitNever) ^ KiWaitNever
    // at KTIMER+0x30. A timer with no DPC decodes to 0.
    //
    Never = *g_TimerWaitNever;
    Always = *g_TimerWaitAlways;
    Value = (UINT64)(ULONG_PTR)Timer->Dpc ^ Never;
    Value = _rotl64(Value, (UCHAR)Never);
    Value ^= (UINT64)(ULONG_PTR)Timer;
    Value = _byteswap_uint64(Value) ^ Always;
    return (PVOID)Value;
}

static PRTL_PROCESS_MODULES
TimerQueryModules(
    VOID
    )
{
    ULONG Bytes;
    NTSTATUS Status;
    PRTL_PROCESS_MODULES Modules;

    Bytes = 0;
    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, NULL, 0, &Bytes);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || Bytes < sizeof(RTL_PROCESS_MODULES))
    {
        return NULL;
    }

    Bytes += sizeof(RTL_PROCESS_MODULE_INFORMATION);
    Modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, Bytes, TIMER_TAG);
    if (Modules == NULL)
    {
        return NULL;
    }

    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, Modules, Bytes, &Bytes);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Modules, TIMER_TAG);
        return NULL;
    }

    return Modules;
}

static VOID
TimerPathFromAddress(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Address,
    _Out_writes_(HACDBG_TIMER_PATH_CHARS) WCHAR* Path
    )
{
    ULONG Index;

    Path[0] = 0;
    if (Modules == NULL || Address == NULL)
    {
        return;
    }

    for (Index = 0; Index < Modules->NumberOfModules; ++Index)
    {
        UCHAR* Base;
        ULONG Size;
        const UCHAR* Source;
        ULONG Char;

        Base = (UCHAR*)Modules->Modules[Index].ImageBase;
        Size = Modules->Modules[Index].ImageSize;
        if ((UCHAR*)Address < Base || (UCHAR*)Address >= Base + Size)
        {
            continue;
        }

        Source = Modules->Modules[Index].FullPathName;
        for (Char = 0; Char + 1 < HACDBG_TIMER_PATH_CHARS && Source[Char] != 0; ++Char)
        {
            Path[Char] = (WCHAR)Source[Char];
        }

        Path[Char] = 0;
        return;
    }
}

static BOOLEAN
TimerAddRow(
    _Inout_ HACDBG_TIMER_REQUEST* Request,
    _In_ unsigned int Type,
    _In_ unsigned long long Callback,
    _In_ unsigned long long Dpc,
    _In_ unsigned long long Timer,
    _In_ unsigned int Period,
    _In_ unsigned int Running,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID ImageHint
    )
{
    HACDBG_TIMER_ROW* Row;

    if (Request->Count >= HACDBG_TIMER_MAX_ROWS)
    {
        Request->Truncated = 1;
        return FALSE;
    }

    Row = &Request->Rows[Request->Count];
    RtlZeroMemory(Row, sizeof(*Row));
    Row->Callback = Callback;
    Row->Dpc = Dpc;
    Row->Timer = Timer;
    Row->Type = Type;
    Row->Period = Period;
    Row->Running = Running;
    TimerPathFromAddress(Modules, ImageHint, Row->Path);
    Request->Count += 1;
    return TRUE;
}

static VOID
TimerScanIo(
    _Inout_ HACDBG_TIMER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules
    )
{
    KIRQL Irql;
    PLIST_ENTRY Link;
    ULONG Seen;

    if (TimerLocateQueue() == FALSE)
    {
        return;
    }

    //
    // INVARIANT: IopTimerLock is the kernel spinlock that guards
    // IopTimerQueueHead. The walk copies timer fields and drops the lock
    // before returning to the caller.
    //
    Irql = KeAcquireSpinLockRaiseToDpc(g_TimerLock);
    Seen = 0;
    for (Link = g_TimerQueueHead->Flink; Link != g_TimerQueueHead && Seen < TIMER_WALK_LIMIT * 4 && Request->Truncated == 0;
         Link = Link->Flink)
    {
        TIMER_IO_BLOCK* Timer;

        Seen += 1;
        if (MmIsAddressValid(Link) == FALSE || MmIsAddressValid((PUCHAR)Link - 8) == FALSE)
        {
            break;
        }

        Timer = (TIMER_IO_BLOCK*)((PUCHAR)Link - 8);
        if (Timer->Type != TIMER_IO_OBJECT || Timer->TimerRoutine == NULL)
        {
            continue;
        }

        //
        // The routine can live in the port driver while DeviceObject belongs
        // to a miniport. The path follows the routine.
        //
        TimerAddRow(Request, HACDBG_TIMER_IO, (unsigned long long)(ULONG_PTR)Timer->TimerRoutine, 0,
                    (unsigned long long)(ULONG_PTR)Timer, TIMER_IO_PERIOD_MS, Timer->TimerFlag != 0 ? 1u : 0u, Modules,
                    Timer->TimerRoutine);
    }

    KeReleaseSpinLock(g_TimerLock, Irql);
}

PVOID
KeQueryPrcbAddress(
    ULONG Number
    );

static VOID
TimerScanProcessor(
    _Inout_ HACDBG_TIMER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PUCHAR Prcb
    )
{
    PUCHAR Entries;
    ULONG Index;

    if (Prcb == NULL || MmIsAddressValid(Prcb + TIMER_TABLE_OFFSET) == FALSE)
    {
        return;
    }

    Entries = Prcb + TIMER_TABLE_OFFSET + TIMER_ENTRY_OFFSET;
    for (Index = 0; Index < TIMER_ENTRY_COUNT && Request->Truncated == 0; ++Index)
    {
        PUCHAR Entry;
        PLIST_ENTRY Head;
        PLIST_ENTRY Link;
        ULONG Seen;
        KIRQL Irql;

        Entry = Entries + (Index * TIMER_ENTRY_STRIDE);
        if (MmIsAddressValid(Entry) == FALSE)
        {
            break;
        }

        Head = (PLIST_ENTRY)(Entry + TIMER_LIST_OFFSET);
        if (MmIsAddressValid(Head) == FALSE || Head->Flink == Head)
        {
            continue;
        }

        Irql = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)Entry);
        Seen = 0;
        for (Link = Head->Flink; Link != Head && Seen < TIMER_DPC_WALK_LIMIT && Request->Truncated == 0; Link = Link->Flink)
        {
            TIMER_KTIMER_BLOCK* Timer;
            PUCHAR Dpc;
            PVOID Routine;

            Seen += 1;
            if (MmIsAddressValid(Link) == FALSE)
            {
                break;
            }

            Timer = (TIMER_KTIMER_BLOCK*)((PUCHAR)Link - FIELD_OFFSET(TIMER_KTIMER_BLOCK, TimerListEntry));
            if (MmIsAddressValid(Timer) == FALSE)
            {
                break;
            }

            if (Timer->Type != TIMER_TYPE_NOTIFICATION && Timer->Type != TIMER_TYPE_SYNCHRONIZATION)
            {
                continue;
            }

            Dpc = (PUCHAR)TimerDecodeDpc(Timer);
            Routine = NULL;
            if ((ULONG_PTR)Dpc >= 0xFFFF800000000000ull && MmIsAddressValid(Dpc) != FALSE &&
                (Dpc[0] == TIMER_DPC_OBJECT || Dpc[0] == TIMER_THREADED_DPC_OBJECT) &&
                MmIsAddressValid(Dpc + 0x18) != FALSE)
            {
                Routine = *(PVOID*)(Dpc + 0x18);
            }

            if (Routine == NULL || (ULONG_PTR)Routine < 0xFFFF800000000000ull)
            {
                continue;
            }

            TimerAddRow(Request, HACDBG_TIMER_DPC, (unsigned long long)(ULONG_PTR)Routine,
                        (unsigned long long)(ULONG_PTR)Dpc, (unsigned long long)(ULONG_PTR)Timer, Timer->Period, 1, Modules,
                        Routine);
        }

        if (Link != Head && Seen >= TIMER_DPC_WALK_LIMIT)
        {
            Request->Truncated = 1;
        }

        KeReleaseSpinLock((PKSPIN_LOCK)Entry, Irql);
    }
}

static VOID
TimerScanDpc(
    _Inout_ HACDBG_TIMER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules
    )
{
    ULONG Count;
    ULONG Index;

    if (TimerLocateWaitKeys() == FALSE)
    {
        return;
    }

    Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (Index = 0; Index < Count && Request->Truncated == 0; ++Index)
    {
        //
        // INVARIANT: KeQueryPrcbAddress returns KiProcessorBlock[Index], the
        // Windows KPRCB. The WOB path must not read gs, because that base is
        // not the guest processor block.
        //
        TimerScanProcessor(Request, Modules, (PUCHAR)KeQueryPrcbAddress(Index));
    }
}

static NTSTATUS
TimerRemoveIo(
    _In_ ULONG64 Address
    )
{
    KIRQL Irql;
    PLIST_ENTRY Link;
    ULONG Seen;
    BOOLEAN Found;

    if (TimerLocateQueue() == FALSE)
    {
        return STATUS_NOT_FOUND;
    }

    Found = FALSE;
    Irql = KeAcquireSpinLockRaiseToDpc(g_TimerLock);
    Seen = 0;
    for (Link = g_TimerQueueHead->Flink; Link != g_TimerQueueHead && Seen < TIMER_WALK_LIMIT * 4; Link = Link->Flink)
    {
        TIMER_IO_BLOCK* Timer;

        Seen += 1;
        if (MmIsAddressValid(Link) == FALSE)
        {
            break;
        }

        Timer = (TIMER_IO_BLOCK*)((PUCHAR)Link - 8);
        if ((ULONG64)(ULONG_PTR)Timer != Address)
        {
            continue;
        }

        RemoveEntryList(&Timer->TimerList);
        Timer->TimerFlag = 0;
        if (Timer->DeviceObject != NULL && MmIsAddressValid(Timer->DeviceObject) != FALSE &&
            Timer->DeviceObject->Timer == (PIO_TIMER)Timer)
        {
            Timer->DeviceObject->Timer = NULL;
        }

        Found = TRUE;
        break;
    }

    KeReleaseSpinLock(g_TimerLock, Irql);
    HACDBG_LOG("HacDbg: Timer IO %p remove %s.\n", (PVOID)Address, Found != FALSE ? "ok" : "missing");
    return Found != FALSE ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS
TimerRemoveDpc(
    _In_ ULONG64 Address
    )
{
    BOOLEAN Cancelled;

    if (Address < 0xFFFF800000000000ull || MmIsAddressValid((PVOID)Address) == FALSE)
    {
        return STATUS_INVALID_ADDRESS;
    }

    Cancelled = KeCancelTimer((PKTIMER)Address);
    HACDBG_LOG("HacDbg: Timer DPC %p cancel %u.\n", (PVOID)Address, Cancelled);
    return Cancelled != FALSE ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

C_ASSERT(sizeof(HACDBG_TIMER_REQUEST) <= 1024u * 1024u);

NTSTATUS
TimerExecute(
    _Inout_ HACDBG_TIMER_REQUEST* Request
    )
{
    unsigned int Operation;
    unsigned int Type;
    ULONG64 Timer;
    PRTL_PROCESS_MODULES Modules;

    Operation = Request->Reserved;
    Type = Request->Rows[0].Type;
    Timer = Request->Rows[0].Timer;
    Request->Status = 0;
    Request->Count = 0;
    Request->Truncated = 0;
    Request->Reserved = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        Request->Status = STATUS_INVALID_LEVEL;
        return Request->Status;
    }

    if (Operation == HACDBG_TIMER_OP_REMOVE)
    {
        Request->Status = Type == HACDBG_TIMER_IO ? TimerRemoveIo(Timer) : TimerRemoveDpc(Timer);
        return Request->Status;
    }

    Modules = TimerQueryModules();
    TimerScanIo(Request, Modules);
    TimerScanDpc(Request, Modules);
    HACDBG_LOG("HacDbg: Timer scan count=%u truncated=%u.\n", Request->Count, Request->Truncated);
    if (Modules != NULL)
    {
        ExFreePoolWithTag(Modules, TIMER_TAG);
    }

    return Request->Status;
}
