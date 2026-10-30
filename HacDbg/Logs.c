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
#define HACDBG_LOG_PTE_ALIAS_PAGES 32
#define HACDBG_LOG_MAILBOX_PAGES \
    ((sizeof(HACDBG_LOG_MAILBOX) + PAGE_SIZE - 1) / PAGE_SIZE)

typedef enum _LOG_MAILBOX_STATUS
{
    LogMailboxPublished = 1,
    LogMailboxRejected = 0,
    LogMailboxFailed = -1,
    LogMailboxStale = -2
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
static UINT64 g_LogMailboxCr3;
static UINT64 g_LogMailboxKey;
static UINT64 g_LogMailboxProducer;
static BOOLEAN g_LogMailboxActive;
static LONG g_LogMailboxRejectLogs;
static HACDBG_SPIN_LOCK g_LogLock;
static GUEST_PAGE_ALIAS* g_LogDataAlias;
static GUEST_PAGE_ALIAS* g_LogPteAlias;
static volatile UINT64* g_LogLeafPte[HACDBG_LOG_MAILBOX_PAGES];
static UINT64 g_LogAssignedPage[HACDBG_LOG_MAILBOX_PAGES];
static BOOLEAN g_LogAliasAssigned;
static BOOLEAN g_LogAliasLive;

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

static BOOLEAN
LogsAssignAliases(
    VOID
    );

static BOOLEAN
LogsAliasMatches(
    VOID
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
    g_LogMailboxCr3 = 0;
    g_LogMailboxKey = 0;
    g_LogMailboxProducer = 0;
    g_LogMailboxActive = FALSE;
    g_LogMailboxRejectLogs = 0;
    g_LogAliasAssigned = FALSE;
    g_LogAliasLive = FALSE;

    for (ULONG pageIndex = 0; pageIndex < (ULONG)HACDBG_LOG_MAILBOX_PAGES; pageIndex++)
    {
        g_LogLeafPte[pageIndex] = NULL;
        g_LogAssignedPage[pageIndex] = 0;
    }
    HacDbgSpinLockInitialize(&g_LogLock);

    //
    // The alias windows are built before any processor enters the guest.
    // Later registration only writes the host PTEs that were materialized
    // here. That write does not call MmCopyMemory.
    //
    if (PhysicalMemoryPrepareGuestAlias((ULONG)HACDBG_LOG_MAILBOX_PAGES, &g_LogDataAlias) != STATUS_SUCCESS ||
        PhysicalMemoryPrepareGuestAlias(HACDBG_LOG_PTE_ALIAS_PAGES, &g_LogPteAlias) != STATUS_SUCCESS)
    {
        HACDBG_LOG("HacDbg: Err, log mailbox alias allocation failed.\n");
        PhysicalMemoryDestroyGuestAlias(g_LogDataAlias);
        PhysicalMemoryDestroyGuestAlias(g_LogPteAlias);
        g_LogDataAlias = NULL;
        g_LogPteAlias = NULL;
        ExFreePoolWithTag(g_Logs, HACDBG_LOGS_TAG);
        g_Logs = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

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

    PhysicalMemoryDestroyGuestAlias(g_LogDataAlias);
    PhysicalMemoryDestroyGuestAlias(g_LogPteAlias);
    g_LogDataAlias = NULL;
    g_LogPteAlias = NULL;
    g_LogAliasAssigned = FALSE;
    g_LogAliasLive = FALSE;
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

        //
        // A transient miss must not unregister the mailbox. The debugger
        // keeps reading the same buffer and will not come back until the
        // driver is unloaded. Only a key that is no longer ours means the
        // buffer was reused.
        //
        if (status == LogMailboxRejected)
        {
            LogsDisarmMailbox(FALSE);
        }
        else
        {
            HacDbgSpinLockRelease(&g_LogLock);
            return;
        }
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
    LOG_MAILBOX_PAGE* pages = NULL;

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

    //
    // One entry per mailbox page. That list does not fit on the kernel stack.
    //
    pages = (LOG_MAILBOX_PAGE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(LOG_MAILBOX_PAGE) * HACDBG_LOG_MAILBOX_PAGES,
                                               HACDBG_LOGS_TAG);

    if (pages == NULL)
    {
        HACDBG_LOG("HacDbg: Err, log mailbox page list allocation failed: %Iu bytes.\n",
                 sizeof(LOG_MAILBOX_PAGE) * HACDBG_LOG_MAILBOX_PAGES);
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
            ExFreePoolWithTag(pages, HACDBG_LOGS_TAG);
            return 0;
        }

        pages[pageIndex].PagePhysical = pagePhysical.Value;
        pages[pageIndex].PtePhysical = ptePhysical.Value;
    }

    HacDbgSpinLockAcquire(&g_LogLock);
    LogsDisarmMailbox(FALSE);
    RtlCopyMemory(g_LogMailboxPages, pages, sizeof(g_LogMailboxPages));
    ExFreePoolWithTag(pages, HACDBG_LOGS_TAG);
    g_LogMailboxVa = VirtualAddress;
    g_LogMailboxCr3 = Cr3;
    g_LogMailboxKey = header.Key;
    g_LogMailboxProducer = 0;

    if (g_LogAliasAssigned == FALSE)
    {
        if (LogsAssignAliases() == FALSE)
        {
            HacDbgSpinLockRelease(&g_LogLock);
            return 0;
        }
    }
    else
    {
        g_LogAliasLive = LogsAliasMatches();
    }

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

// 调用方持有 g_LogLock。别名还没有被任何处理器使用时才能清 PTE。
static VOID
LogsRollbackAlias(
    _In_ GUEST_PAGE_ALIAS* Alias,
    _In_ ULONG Count
    )
{
    ULONG index;

    for (index = 0; index < Count; index++)
    {
        PhysicalMemoryClearGuestAliasPage(Alias, index);
    }
}

// 调用方持有 g_LogLock。第一次注册时把宿主窗口指到邮箱页。
static BOOLEAN
LogsAssignAliases(
    VOID
    )
{
    ULONG pageIndex;
    ULONG uniqueCount = 0;
    UINT64 uniquePage[HACDBG_LOG_PTE_ALIAS_PAGES];
    PUCHAR pteBase;

    if (g_LogDataAlias == NULL || g_LogPteAlias == NULL)
    {
        return FALSE;
    }

    for (pageIndex = 0; pageIndex < (ULONG)HACDBG_LOG_MAILBOX_PAGES; pageIndex++)
    {
        if (PhysicalMemoryAssignGuestAliasPage(g_LogDataAlias, pageIndex,
                                                g_LogMailboxPages[pageIndex].PagePhysical) == FALSE)
        {
            LogsRollbackAlias(g_LogDataAlias, pageIndex);
            return FALSE;
        }

        g_LogAssignedPage[pageIndex] = g_LogMailboxPages[pageIndex].PagePhysical;
    }

    for (pageIndex = 0; pageIndex < (ULONG)HACDBG_LOG_MAILBOX_PAGES; pageIndex++)
    {
        UINT64 ptePage = g_LogMailboxPages[pageIndex].PtePhysical & ~(UINT64)(PAGE_SIZE - 1);
        ULONG slot;
        BOOLEAN found = FALSE;

        for (slot = 0; slot < uniqueCount; slot++)
        {
            if (uniquePage[slot] == ptePage)
            {
                found = TRUE;
                break;
            }
        }

        if (found != FALSE)
        {
            continue;
        }

        if (uniqueCount >= HACDBG_LOG_PTE_ALIAS_PAGES ||
            PhysicalMemoryAssignGuestAliasPage(g_LogPteAlias, uniqueCount, ptePage) == FALSE)
        {
            LogsRollbackAlias(g_LogDataAlias, (ULONG)HACDBG_LOG_MAILBOX_PAGES);
            LogsRollbackAlias(g_LogPteAlias, uniqueCount);
            return FALSE;
        }

        uniquePage[uniqueCount] = ptePage;
        uniqueCount++;
    }

    pteBase = (PUCHAR)PhysicalMemoryGuestAliasBase(g_LogPteAlias);

    for (pageIndex = 0; pageIndex < (ULONG)HACDBG_LOG_MAILBOX_PAGES; pageIndex++)
    {
        UINT64 ptePage = g_LogMailboxPages[pageIndex].PtePhysical & ~(UINT64)(PAGE_SIZE - 1);
        UINT64 pteOffset = g_LogMailboxPages[pageIndex].PtePhysical & (PAGE_SIZE - 1);
        ULONG slot;

        g_LogLeafPte[pageIndex] = NULL;

        for (slot = 0; slot < uniqueCount; slot++)
        {
            if (uniquePage[slot] != ptePage)
            {
                continue;
            }

            g_LogLeafPte[pageIndex] = (volatile UINT64*)(pteBase + ((SIZE_T)slot * PAGE_SIZE) + pteOffset);
            break;
        }

        if (g_LogLeafPte[pageIndex] == NULL)
        {
            LogsRollbackAlias(g_LogDataAlias, (ULONG)HACDBG_LOG_MAILBOX_PAGES);
            LogsRollbackAlias(g_LogPteAlias, uniqueCount);
            return FALSE;
        }
    }

    g_LogAliasAssigned = TRUE;
    g_LogAliasLive = TRUE;
    return TRUE;
}

// 调用方持有 g_LogLock。页帧仍是第一次注册时的那一组才继续走别名。
static BOOLEAN
LogsAliasMatches(
    VOID
    )
{
    ULONG pageIndex;

    if (g_LogAliasAssigned == FALSE)
    {
        return FALSE;
    }

    for (pageIndex = 0; pageIndex < (ULONG)HACDBG_LOG_MAILBOX_PAGES; pageIndex++)
    {
        volatile UINT64* leaf = g_LogLeafPte[pageIndex];
        UINT64 entry;

        if (g_LogMailboxPages[pageIndex].PagePhysical != g_LogAssignedPage[pageIndex] || leaf == NULL)
        {
            return FALSE;
        }

        entry = *leaf;

        if (PhysicalMemoryPteNamesPage(entry, g_LogAssignedPage[pageIndex]) != 1)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static INT
LogsAliasPageOk(
    _In_ ULONG PageIndex
    )
{
    volatile UINT64* leaf;
    UINT64 entry;

    if (g_LogAliasLive == FALSE || PageIndex >= (ULONG)HACDBG_LOG_MAILBOX_PAGES)
    {
        return 0;
    }

    leaf = g_LogLeafPte[PageIndex];

    if (leaf == NULL)
    {
        return 0;
    }

    entry = *leaf;
    return PhysicalMemoryPteNamesPage(entry, g_LogMailboxPages[PageIndex].PagePhysical);
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

    if (ZeroKey != FALSE && g_LogAliasLive != FALSE)
    {
        PUCHAR base = (PUCHAR)PhysicalMemoryGuestAliasBase(g_LogDataAlias);

        if (base != NULL)
        {
            *(volatile UINT64*)base = 0;
        }
    }
    else if (ZeroKey != FALSE)
    {
        UINT64 zero = 0;

        (VOID)LogsMailboxAccess(0, &zero, sizeof(zero), TRUE);
    }

    g_LogMailboxActive = FALSE;
    g_LogAliasLive = FALSE;
    g_LogMailboxVa = 0;
    g_LogMailboxCr3 = 0;
    g_LogMailboxKey = 0;
    g_LogMailboxProducer = 0;
    RtlZeroMemory(g_LogMailboxPages, sizeof(g_LogMailboxPages));
}

// 重新翻译一页。调用方持有 g_LogLock。不改已经发布过的宿主别名 PTE。
static INT
LogsRefreshPage(
    _In_ ULONG PageIndex
    )
{
    GUEST_VIRTUAL_ADDRESS page;
    GUEST_PHYSICAL_ADDRESS pagePhysical;
    GUEST_PHYSICAL_ADDRESS ptePhysical;

    if (g_LogMailboxCr3 == 0 || g_LogMailboxVa == 0 || PageIndex >= (ULONG)HACDBG_LOG_MAILBOX_PAGES)
    {
        return 0;
    }

    page = HacDbgGuestVirtualAddress(g_LogMailboxVa + ((UINT64)PageIndex * PAGE_SIZE));

    //
    // INVARIANT: page is one locked page of the debugger mailbox.
    // g_LogMailboxCr3 is the directory captured at registration.
    //
    if (GuestVirtualTranslate4k(g_LogMailboxCr3, page, &pagePhysical, &ptePhysical) != 1)
    {
        return 0;
    }

    g_LogMailboxPages[PageIndex].PagePhysical = pagePhysical.Value;
    g_LogMailboxPages[PageIndex].PtePhysical = ptePhysical.Value;
    return 1;
}

static INT
LogsRefreshSpan(
    _In_ UINT64 Offset,
    _In_ SIZE_T Size
    )
{
    UINT64 end;
    ULONG page;
    INT refreshed = 1;

    if (Size == 0 || Offset + Size < Offset)
    {
        return 0;
    }

    end = Offset + Size - 1;

    for (page = (ULONG)(Offset / PAGE_SIZE); page <= (ULONG)(end / PAGE_SIZE); page++)
    {
        if (LogsRefreshPage(page) != 1)
        {
            refreshed = 0;
        }
    }

    return refreshed;
}

// 通过临时映射写一页已经重新翻译过的邮箱。调用方持有 g_LogLock。
static LOG_MAILBOX_STATUS
LogsPublishDirect(
    _In_ const trap_frame_log_t* Log,
    _In_ BOOLEAN Retried
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
        if (Retried == FALSE && LogsRefreshSpan(0, sizeof(key)) != 0)
        {
            return LogsPublishDirect(Log, TRUE);
        }

        return LogMailboxFailed;
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
        if (Retried == FALSE && LogsRefreshSpan(offset, sizeof(*Log)) != 0)
        {
            return LogsPublishDirect(Log, TRUE);
        }

        return LogMailboxFailed;
    }

    if (access == 0)
    {
        return LogMailboxFailed;
    }

    KeMemoryBarrier();
    next = g_LogMailboxProducer + 1;
    access = LogsMailboxAccess(offsetof(HACDBG_LOG_MAILBOX, producer), &next, sizeof(next), TRUE);

    if (access < 0 && Retried == FALSE &&
        LogsRefreshSpan(offsetof(HACDBG_LOG_MAILBOX, producer), sizeof(next)) != 0)
    {
        return LogsPublishDirect(Log, TRUE);
    }

    if (access != 1)
    {
        return LogMailboxFailed;
    }

    access = LogsMailboxAccess(offsetof(HACDBG_LOG_MAILBOX, producer_copy), &next, sizeof(next), TRUE);

    if (access < 0 && Retried == FALSE &&
        LogsRefreshSpan(offsetof(HACDBG_LOG_MAILBOX, producer_copy), sizeof(next)) != 0)
    {
        return LogsPublishDirect(Log, TRUE);
    }

    if (access != 1)
    {
        return LogMailboxFailed;
    }

    g_LogMailboxProducer = next;
    return LogMailboxPublished;
}

// 别名覆盖这次写入的页时直接拷贝。调用方持有 g_LogLock。
static LOG_MAILBOX_STATUS
LogsPublishThroughAlias(
    _In_ const trap_frame_log_t* Log
    )
{
    PUCHAR base;
    UINT64 key;
    UINT64 slot;
    UINT64 offset;
    UINT64 end;
    UINT64 next;
    ULONG page;
    INT state;

    base = (PUCHAR)PhysicalMemoryGuestAliasBase(g_LogDataAlias);

    if (base == NULL)
    {
        return LogMailboxFailed;
    }

    state = LogsAliasPageOk(0);

    if (state < 0)
    {
        return LogMailboxStale;
    }

    if (state == 0)
    {
        return LogMailboxFailed;
    }

    key = *(volatile UINT64*)base;

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
    end = offset + sizeof(trap_frame_log_t) - 1;

    for (page = (ULONG)(offset / PAGE_SIZE); page <= (ULONG)(end / PAGE_SIZE); page++)
    {
        state = LogsAliasPageOk(page);

        if (state < 0)
        {
            return LogMailboxStale;
        }

        if (state == 0)
        {
            return LogMailboxFailed;
        }
    }

    RtlCopyMemory(base + offset, Log, sizeof(*Log));
    KeMemoryBarrier();
    next = g_LogMailboxProducer + 1;
    *(volatile UINT64*)(base + offsetof(HACDBG_LOG_MAILBOX, producer)) = next;
    *(volatile UINT64*)(base + offsetof(HACDBG_LOG_MAILBOX, producer_copy)) = next;
    g_LogMailboxProducer = next;
    return LogMailboxPublished;
}

// 把一条记录写进邮箱并发布序号。调用方持有 g_LogLock。
static LOG_MAILBOX_STATUS
LogsPublishMailbox(
    _In_ const trap_frame_log_t* Log
    )
{
    LOG_MAILBOX_STATUS status;

    if (g_LogAliasLive != FALSE)
    {
        status = LogsPublishThroughAlias(Log);

        if (status != LogMailboxStale)
        {
            return status;
        }

        //
        // The host alias still names the frames from the first registration.
        // Another processor may have cached that translation, so the PTEs
        // stay as they are and this record uses a fresh guest walk.
        //
        g_LogAliasLive = FALSE;
    }

    return LogsPublishDirect(Log, FALSE);
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
