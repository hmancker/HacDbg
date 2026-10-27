/**
 * @file Logs.c
 * @brief Nonpaged trap frame log ring.
 *
 * @author HacDbg
 */

#include "Logs.h"
#include "Debug.h"
#include "PhysicalMemory.h"

#define HACDBG_LOGS_TAG     'GcaH'
#define HACDBG_LOG_CAPACITY 2048

static trap_frame_log_t* g_Logs;
static UINT64 g_LogCount;
static UINT64 g_LogNext;
static UINT64 g_LogSequence;
static UINT64 g_LogNotifyCr3;
static UINT64 g_LogNotifyVa;
static UINT64 g_LogNotifyKey;
static BOOLEAN g_LogNotifyActive;
static LONG g_LogNotifyRejectLogs;
static HACDBG_SPIN_LOCK g_LogLock;

static BOOLEAN
LogsPublishNotify(
    _In_ UINT64 Sequence
    );

// 分配非分页日志环。
NTSTATUS
LogsInitialize(
    VOID
    )
{
    if (g_Logs != NULL)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    g_Logs = (trap_frame_log_t*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                 sizeof(trap_frame_log_t) * HACDBG_LOG_CAPACITY,
                                                 HACDBG_LOGS_TAG);
    if (g_Logs == NULL)
    {
        HACDBG_LOG("HacDbg: Err, log ring allocation failed: %Iu bytes.\n",
                 sizeof(trap_frame_log_t) * HACDBG_LOG_CAPACITY);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_Logs, sizeof(trap_frame_log_t) * HACDBG_LOG_CAPACITY);
    g_LogCount = 0;
    g_LogNext = 0;
    g_LogSequence = 0;
    g_LogNotifyCr3 = 0;
    g_LogNotifyVa = 0;
    g_LogNotifyKey = 0;
    g_LogNotifyActive = FALSE;
    g_LogNotifyRejectLogs = 0;
    HacDbgSpinLockInitialize(&g_LogLock);

    return STATUS_SUCCESS;
}

// 释放日志环。
VOID
LogsCleanup(
    VOID
    )
{
    if (g_Logs == NULL)
    {
        return;
    }

    HacDbgSpinLockAcquire(&g_LogLock);
    g_LogNotifyActive = FALSE;
    g_LogNotifyCr3 = 0;
    g_LogNotifyVa = 0;
    g_LogNotifyKey = 0;
    HacDbgSpinLockRelease(&g_LogLock);

    ExFreePoolWithTag(g_Logs, HACDBG_LOGS_TAG);
    g_Logs = NULL;
    g_LogCount = 0;
    g_LogNext = 0;
    g_LogSequence = 0;
}

// 追加一条日志，写满后覆盖最旧记录。
VOID
LogsAdd(
    _In_ const trap_frame_log_t* Log
    )
{
    HacDbgSpinLockAcquire(&g_LogLock);

    g_Logs[g_LogNext] = *Log;
    g_LogNext = (g_LogNext + 1) % HACDBG_LOG_CAPACITY;

    if (g_LogCount < HACDBG_LOG_CAPACITY)
    {
        g_LogCount++;
    }

    g_LogSequence += 1;
    (VOID)LogsPublishNotify(g_LogSequence);
    HacDbgSpinLockRelease(&g_LogLock);
}

// 把待处理日志写入客户缓冲区并清空；写入失败返回 -1。
UINT64
LogsFlush(
    _In_ UINT64 DestinationCr3,
    _In_ GUEST_VIRTUAL_ADDRESS Destination,
    _In_ UINT64 MaximumCount
    )
{
    UINT64 count;
    UINT64 first;
    UINT64 index;
    HacDbgSpinLockAcquire(&g_LogLock);
    count = g_LogCount;
    first = (g_LogNext + HACDBG_LOG_CAPACITY - count) % HACDBG_LOG_CAPACITY;

    if (count > MaximumCount)
    {
        count = MaximumCount;
    }

    if (count != 0)
    {
        HACDBG_LOG("HacDbg: flushing %I64u log entries cr3=0x%I64x destination=0x%I64x.\n",
                 count, DestinationCr3, Destination.Value);
    }

    for (index = 0; index < count; index++)
    {
        UINT64 sourceIndex = (first + index) % HACDBG_LOG_CAPACITY;
        if (GuestVirtualWrite(DestinationCr3,
                              HacDbgGuestVirtualAddress(Destination.Value + (index * sizeof(trap_frame_log_t))),
                              &g_Logs[sourceIndex],
                              sizeof(trap_frame_log_t)) != sizeof(trap_frame_log_t))
        {
            HACDBG_LOG("HacDbg: Err, log flush write failed index=%I64u cr3=0x%I64x "
                     "destination=0x%I64x.\n",
                     index, DestinationCr3,
                     Destination.Value + (index * sizeof(trap_frame_log_t)));
            HacDbgSpinLockRelease(&g_LogLock);
            return (UINT64)-1;
        }
    }

    g_LogCount = 0;
    g_LogNext = 0;
    HacDbgSpinLockRelease(&g_LogLock);

    return count;
}

UINT64
LogsRegisterNotify(
    _In_ UINT64 Cr3,
    _In_ UINT64 VirtualAddress
    )
{
    UINT64 key;
    UINT64 sequence;
    GUEST_VIRTUAL_ADDRESS address;

    if (g_Logs == NULL || Cr3 == 0 || VirtualAddress == 0 || (VirtualAddress & 7) != 0 ||
        (VirtualAddress & (PAGE_SIZE - 1)) > (PAGE_SIZE - sizeof(HACDBG_LOG_NOTIFY)))
    {
        return 0;
    }

    address = HacDbgGuestVirtualAddress(VirtualAddress);

    //
    // INVARIANT: Cr3 is the registering CPUID's guest page-table root and
    // VirtualAddress is an 8-byte-aligned HACDBG_LOG_NOTIFY that fits in one
    // page of that process. The debugger locks the page before this call.
    //
    if (GuestVirtualRead(Cr3, address, &key, sizeof(key)) != sizeof(key) || key == 0)
    {
        return 0;
    }

    HacDbgSpinLockAcquire(&g_LogLock);
    g_LogNotifyCr3 = Cr3;
    g_LogNotifyVa = VirtualAddress;
    g_LogNotifyKey = key;
    g_LogNotifyActive = TRUE;
    sequence = g_LogSequence;

    if (g_LogCount != 0 && sequence == 0)
    {
        g_LogSequence = 1;
        sequence = 1;
    }

    if (LogsPublishNotify(sequence) == FALSE)
    {
        g_LogNotifyActive = FALSE;
        g_LogNotifyCr3 = 0;
        g_LogNotifyVa = 0;
        g_LogNotifyKey = 0;
        HacDbgSpinLockRelease(&g_LogLock);
        return 0;
    }

    HacDbgSpinLockRelease(&g_LogLock);
    return 1;
}

UINT64
LogsUnregisterNotify(
    VOID
    )
{
    if (g_Logs == NULL)
    {
        return 0;
    }

    HacDbgSpinLockAcquire(&g_LogLock);
    g_LogNotifyActive = FALSE;
    g_LogNotifyCr3 = 0;
    g_LogNotifyVa = 0;
    g_LogNotifyKey = 0;
    HacDbgSpinLockRelease(&g_LogLock);
    return 1;
}

// 把序号写进已注册的通知页。调用方持有 g_LogLock。键不匹配时取消注册。
static BOOLEAN
LogsPublishNotify(
    _In_ UINT64 Sequence
    )
{
    UINT64 key;
    GUEST_VIRTUAL_ADDRESS address;

    if (g_LogNotifyActive == FALSE)
    {
        return TRUE;
    }

    address = HacDbgGuestVirtualAddress(g_LogNotifyVa);

    //
    // INVARIANT: g_LogNotifyVa addresses one locked HACDBG_LOG_NOTIFY in the
    // registering process. g_LogNotifyCr3 is that process's page-table root
    // from the registration CPUID. The page is not a guest of another CR3.
    //
    if (GuestVirtualRead(g_LogNotifyCr3, address, &key, sizeof(key)) != sizeof(key))
    {
        return FALSE;
    }

    if (key != g_LogNotifyKey)
    {
        g_LogNotifyActive = FALSE;
        g_LogNotifyCr3 = 0;
        g_LogNotifyVa = 0;
        g_LogNotifyKey = 0;

        if (InterlockedIncrement(&g_LogNotifyRejectLogs) <= 4)
        {
            HACDBG_LOG("HacDbg: Err, log notify key mismatch va=0x%I64x.\n", address.Value);
        }

        return FALSE;
    }

    address = HacDbgGuestVirtualAddress(g_LogNotifyVa + offsetof(HACDBG_LOG_NOTIFY, sequence));

    if (GuestVirtualWrite(g_LogNotifyCr3, address, &Sequence, sizeof(Sequence)) != sizeof(Sequence))
    {
        return FALSE;
    }

    address = HacDbgGuestVirtualAddress(g_LogNotifyVa + offsetof(HACDBG_LOG_NOTIFY, sequence_copy));

    if (GuestVirtualWrite(g_LogNotifyCr3, address, &Sequence, sizeof(Sequence)) != sizeof(Sequence))
    {
        return FALSE;
    }

    return TRUE;
}
