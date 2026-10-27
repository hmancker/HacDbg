/**
 * @file Logs.c
 * @brief Nonpaged trap frame log ring and the debugger mailbox.
 *
 * @author HacDbg
 */

#include "Logs.h"
#include "Debug.h"
#include "PhysicalMemory.h"

#define HACDBG_LOGS_TAG     'GcaH'
#define HACDBG_LOG_CAPACITY 2048
#define HACDBG_LOG_MAILBOX_PAGES \
    ((sizeof(HACDBG_LOG_MAILBOX) + PAGE_SIZE - 1) / PAGE_SIZE)

typedef enum _LOG_MAILBOX_STATUS
{
    LogMailboxPublished = 1,
    LogMailboxRejected = 0,
    LogMailboxFailed = -1
} LOG_MAILBOX_STATUS;

typedef struct _LOG_MAILBOX_PAGE
{
    UINT64 PagePhysical;
    UINT64 PtePhysical;
} LOG_MAILBOX_PAGE;

static trap_frame_log_t* g_Logs;
static UINT64 g_LogCount;
static UINT64 g_LogNext;
static LOG_MAILBOX_PAGE g_LogMailboxPages[HACDBG_LOG_MAILBOX_PAGES];
static UINT64 g_LogMailboxVa;
static UINT64 g_LogMailboxKey;
static UINT64 g_LogMailboxProducer;
static BOOLEAN g_LogMailboxActive;
static LONG g_LogMailboxRejectLogs;
static HACDBG_SPIN_LOCK g_LogLock;

static INT
LogsMailboxAccess(
    _In_ UINT64 Offset,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN ToMailbox
    );

static LOG_MAILBOX_STATUS
LogsPublishMailbox(
    _In_ const trap_frame_log_t* Log
    );

static VOID
LogsDisarmMailbox(
    _In_ BOOLEAN ZeroKey
    );

_Static_assert(PAGE_SIZE == 0x1000, "log mailbox page size changed");
_Static_assert(sizeof(trap_frame_log_t) == HACDBG_LOG_MAILBOX_RECORD_BYTES, "log record size changed");
_Static_assert(HACDBG_LOG_MAILBOX_HEADER_BYTES == 32, "log mailbox header changed");

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
    RtlZeroMemory(g_LogMailboxPages, sizeof(g_LogMailboxPages));
    g_LogMailboxVa = 0;
    g_LogMailboxKey = 0;
    g_LogMailboxProducer = 0;
    g_LogMailboxActive = FALSE;
    g_LogMailboxRejectLogs = 0;
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
    LogsDisarmMailbox(TRUE);
    HacDbgSpinLockRelease(&g_LogLock);

    ExFreePoolWithTag(g_Logs, HACDBG_LOGS_TAG);
    g_Logs = NULL;
    g_LogCount = 0;
    g_LogNext = 0;
}

// 追加一条日志。邮箱可用时直接写进调试器；否则留在内核环里。
VOID
LogsAdd(
    _In_ const trap_frame_log_t* Log
    )
{
    LOG_MAILBOX_STATUS status;

    HacDbgSpinLockAcquire(&g_LogLock);

    if (g_LogMailboxActive != FALSE)
    {
        status = LogsPublishMailbox(Log);

        if (status == LogMailboxFailed)
        {
            status = LogsPublishMailbox(Log);
        }

        if (status == LogMailboxPublished)
        {
            HacDbgSpinLockRelease(&g_LogLock);
            return;
        }

        LogsDisarmMailbox(status == LogMailboxFailed ? TRUE : FALSE);
    }

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

UINT64
LogsRegisterMailbox(
    _In_ UINT64 Cr3,
    _In_ UINT64 VirtualAddress
    )
{
    struct
    {
        UINT64 Key;
        UINT64 Capacity;
        UINT64 Producer;
        UINT64 ProducerCopy;
    } header;
    LOG_MAILBOX_PAGE pages[HACDBG_LOG_MAILBOX_PAGES];

    _Static_assert(sizeof(header) == HACDBG_LOG_MAILBOX_HEADER_BYTES, "log mailbox header changed");
    UINT64 pageIndex;
    UINT64 logIndex;
    UINT64 pending;
    UINT64 first;
    GUEST_VIRTUAL_ADDRESS address;

    if (g_Logs == NULL || Cr3 == 0 || VirtualAddress == 0 ||
        (VirtualAddress & (PAGE_SIZE - 1)) != 0 ||
        VirtualAddress + sizeof(HACDBG_LOG_MAILBOX) < VirtualAddress)
    {
        return 0;
    }

    address = HacDbgGuestVirtualAddress(VirtualAddress);

    //
    // INVARIANT: Cr3 is the registering CPUID's guest page-table root.
    // VirtualAddress is a page-aligned HACDBG_LOG_MAILBOX in that process.
    // The debugger locks every page before this call.
    //
    if (GuestVirtualRead(Cr3, address, &header, sizeof(header)) != sizeof(header) ||
        header.Key == 0 || header.Capacity != HACDBG_LOG_MAILBOX_CAPACITY ||
        header.Producer != 0 || header.ProducerCopy != 0)
    {
        return 0;
    }

    for (pageIndex = 0; pageIndex < HACDBG_LOG_MAILBOX_PAGES; pageIndex++)
    {
        GUEST_VIRTUAL_ADDRESS page = HacDbgGuestVirtualAddress(VirtualAddress + (pageIndex * PAGE_SIZE));
        GUEST_PHYSICAL_ADDRESS pagePhysical;
        GUEST_PHYSICAL_ADDRESS ptePhysical;

        //
        // INVARIANT: page is one locked 4 KiB page of the mailbox. The
        // translation result is kept for later exits and is not a guest
        // mapping.
        //
        if (GuestVirtualTranslate4k(Cr3, page, &pagePhysical, &ptePhysical) != 1)
        {
            return 0;
        }

        pages[pageIndex].PagePhysical = pagePhysical.Value;
        pages[pageIndex].PtePhysical = ptePhysical.Value;
    }

    HacDbgSpinLockAcquire(&g_LogLock);
    LogsDisarmMailbox(FALSE);
    RtlCopyMemory(g_LogMailboxPages, pages, sizeof(g_LogMailboxPages));
    g_LogMailboxVa = VirtualAddress;
    g_LogMailboxKey = header.Key;
    g_LogMailboxProducer = 0;
    g_LogMailboxActive = TRUE;

    pending = g_LogCount;
    first = (g_LogNext + HACDBG_LOG_CAPACITY - pending) % HACDBG_LOG_CAPACITY;

    for (logIndex = 0; logIndex < pending; logIndex++)
    {
        UINT64 sourceIndex = (first + logIndex) % HACDBG_LOG_CAPACITY;

        if (LogsPublishMailbox(&g_Logs[sourceIndex]) != LogMailboxPublished)
        {
            LogsDisarmMailbox(TRUE);
            HacDbgSpinLockRelease(&g_LogLock);
            return 0;
        }
    }

    g_LogCount = 0;
    g_LogNext = 0;
    HacDbgSpinLockRelease(&g_LogLock);
    return 1;
}

UINT64
LogsUnregisterMailbox(
    VOID
    )
{
    if (g_Logs == NULL)
    {
        return 0;
    }

    HacDbgSpinLockAcquire(&g_LogLock);
    LogsDisarmMailbox(TRUE);
    HacDbgSpinLockRelease(&g_LogLock);
    return 1;
}

// 调用方持有 g_LogLock。键已经对不上时不改邮箱。
static VOID
LogsDisarmMailbox(
    _In_ BOOLEAN ZeroKey
    )
{
    if (g_LogMailboxActive == FALSE)
    {
        return;
    }

    if (ZeroKey != FALSE)
    {
        UINT64 zero = 0;

        (VOID)LogsMailboxAccess(0, &zero, sizeof(zero), TRUE);
    }

    g_LogMailboxActive = FALSE;
    g_LogMailboxVa = 0;
    g_LogMailboxKey = 0;
    g_LogMailboxProducer = 0;
    RtlZeroMemory(g_LogMailboxPages, sizeof(g_LogMailboxPages));
}

// 把一条记录写进邮箱并发布序号。调用方持有 g_LogLock。
static LOG_MAILBOX_STATUS
LogsPublishMailbox(
    _In_ const trap_frame_log_t* Log
    )
{
    UINT64 key = 0;
    UINT64 slot;
    UINT64 offset;
    UINT64 next;
    INT access;

    access = LogsMailboxAccess(0, &key, sizeof(key), FALSE);

    if (access < 0)
    {
        return LogMailboxRejected;
    }

    if (access == 0)
    {
        return LogMailboxFailed;
    }

    if (key != g_LogMailboxKey)
    {
        if (InterlockedIncrement(&g_LogMailboxRejectLogs) <= 4)
        {
            HACDBG_LOG("HacDbg: Err, log mailbox key mismatch va=0x%I64x.\n", g_LogMailboxVa);
        }

        return LogMailboxRejected;
    }

    slot = g_LogMailboxProducer % HACDBG_LOG_MAILBOX_CAPACITY;
    offset = HACDBG_LOG_MAILBOX_HEADER_BYTES + (slot * sizeof(trap_frame_log_t));
    access = LogsMailboxAccess(offset, (PVOID)Log, sizeof(*Log), TRUE);

    if (access < 0)
    {
        return LogMailboxRejected;
    }

    if (access == 0)
    {
        return LogMailboxFailed;
    }

    KeMemoryBarrier();
    next = g_LogMailboxProducer + 1;
    access = LogsMailboxAccess(offsetof(HACDBG_LOG_MAILBOX, producer), &next, sizeof(next), TRUE);

    if (access != 1)
    {
        return access < 0 ? LogMailboxRejected : LogMailboxFailed;
    }

    access = LogsMailboxAccess(offsetof(HACDBG_LOG_MAILBOX, producer_copy), &next, sizeof(next), TRUE);

    if (access != 1)
    {
        return access < 0 ? LogMailboxRejected : LogMailboxFailed;
    }

    g_LogMailboxProducer = next;
    return LogMailboxPublished;
}

// 1 成功，0 暂时读不到，-1 页已经不是注册时的那一页。调用方持有 g_LogLock。
static INT
LogsMailboxAccess(
    _In_ UINT64 Offset,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN ToMailbox
    )
{
    SIZE_T done = 0;

    if (g_LogMailboxActive == FALSE || Buffer == NULL || Size == 0)
    {
        return -1;
    }

    while (done < Size)
    {
        UINT64 position = Offset + (UINT64)done;
        UINT64 pageIndex = position / PAGE_SIZE;
        UINT64 pageOffset = position & (PAGE_SIZE - 1);
        SIZE_T chunk;
        SIZE_T transferred;
        INT state;
        GUEST_PHYSICAL_ADDRESS physical;

        if (position < Offset || pageIndex >= HACDBG_LOG_MAILBOX_PAGES)
        {
            return -1;
        }

        chunk = PAGE_SIZE - (SIZE_T)pageOffset;

        if (chunk > Size - done)
        {
            chunk = Size - done;
        }

        state = GuestPhysicalPteState(
            HacDbgGuestPhysicalAddress(g_LogMailboxPages[pageIndex].PtePhysical),
            HacDbgGuestPhysicalAddress(g_LogMailboxPages[pageIndex].PagePhysical));

        if (state != 1)
        {
            return state;
        }

        physical = HacDbgGuestPhysicalAddress(
            g_LogMailboxPages[pageIndex].PagePhysical + pageOffset);

        //
        // INVARIANT: physical is inside the mailbox page whose leaf PTE still
        // names the PFN captured at registration. The debugger locked that
        // page. This copy uses the host map of that guest PFN.
        //
        if (ToMailbox != FALSE)
        {
            transferred = PhysicalMemoryWrite(physical, (PUCHAR)Buffer + done, chunk);
        }
        else
        {
            transferred = PhysicalMemoryRead(physical, (PUCHAR)Buffer + done, chunk);
        }

        if (transferred != chunk)
        {
            return 0;
        }

        done += chunk;
    }

    return 1;
}
