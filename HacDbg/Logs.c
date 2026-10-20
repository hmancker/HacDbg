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
static HACDBG_SPIN_LOCK g_LogLock;

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

    ExFreePoolWithTag(g_Logs, HACDBG_LOGS_TAG);
    g_Logs = NULL;
    g_LogCount = 0;
    g_LogNext = 0;
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
