/**
 * @file PhysicalMemory.c
 * @brief Guest physical and virtual memory access.
 *
 * @author HacDbg
 */

#include "PhysicalMemory.h"
#include "Debug.h"

#define HACDBG_PHYSICAL_TAG        'PcaH'
#define HACDBG_PHYSICAL_MAP_CHUNK  0x200000ull

typedef struct _PHYSICAL_RANGE
{
    UINT64 Start;
    UINT64 End;
} PHYSICAL_RANGE;

static PHYSICAL_RANGE* g_Ranges;
static ULONG g_RangeCount;
static BOOLEAN g_Initialized;
static BOOLEAN g_FiveLevelPaging;
static volatile LONG g_PhysicalFailureLogCount;
static volatile LONG g_TranslationFailureLogCount;

// 每条失败路径最多打印 64 次，避免刷屏。
static BOOLEAN
PhysicalMemoryShouldLogFailure(
    _Inout_ volatile LONG* Counter
    )
{
#if HACDBG_DISABLE_DEBUG_LOG
    // 日志关闭时不累计计数，直接跳过整段输出。
    UNREFERENCED_PARAMETER(Counter);
    return FALSE;
#else
    return InterlockedIncrement(Counter) <= 64;
#endif
}

// 释放 RAM 范围表。
static VOID
PhysicalMemoryFreeRanges(
    VOID
    )
{
    if (g_Ranges != NULL)
    {
        ExFreePoolWithTag(g_Ranges, HACDBG_PHYSICAL_TAG);
    }

    g_Ranges = NULL;
    g_RangeCount = 0;
}

// 查找物理地址所在的 RAM 范围，并返回剩余可用字节数。
static BOOLEAN
PhysicalMemoryFindRange(
    _In_ UINT64 Address,
    _Out_ UINT64* Available
    )
{
    ULONG index;

    for (index = 0; index < g_RangeCount; index++)
    {
        if (Address >= g_Ranges[index].Start && Address < g_Ranges[index].End)
        {
            *Available = g_Ranges[index].End - Address;
            return TRUE;
        }
    }

    *Available = 0;
    return FALSE;
}

// 把请求长度裁剪到 RAM 范围和单次映射上限。
static SIZE_T
PhysicalMemoryAvailableSize(
    _In_ UINT64 Address,
    _In_ SIZE_T Size
    )
{
    UINT64 available = 0;

    if (PhysicalMemoryFindRange(Address, &available) == FALSE)
    {
        return 0;
    }

    if (Size > available)
    {
        Size = (SIZE_T)available;
    }

    if (Size > HACDBG_PHYSICAL_MAP_CHUNK)
    {
        Size = (SIZE_T)HACDBG_PHYSICAL_MAP_CHUNK;
    }

    return Size;
}

// 读取固件 RAM 范围表，只记录，不建立常驻映射。
NTSTATUS
PhysicalMemoryInitialize(
    VOID
    )
{
    PHYSICAL_MEMORY_RANGE* ranges;
    PHYSICAL_MEMORY_RANGE* range;
    ULONG rangeCount = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (g_Initialized != FALSE)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    ranges = MmGetPhysicalMemoryRanges();
    if (ranges == NULL)
    {
        HACDBG_LOG("HacDbg: Err, MmGetPhysicalMemoryRanges returned NULL.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (range = ranges; range->BaseAddress.QuadPart != 0 || range->NumberOfBytes.QuadPart != 0; range++)
    {
        rangeCount++;
    }

    if (rangeCount == 0)
    {
        HACDBG_LOG("HacDbg: Err, firmware reported no RAM ranges.\n");
        ExFreePool(ranges);
        return STATUS_NOT_FOUND;
    }

    g_Ranges = (PHYSICAL_RANGE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                rangeCount * sizeof(*g_Ranges),
                                                HACDBG_PHYSICAL_TAG);
    if (g_Ranges == NULL)
    {
        HACDBG_LOG("HacDbg: Err, RAM range table allocation failed for %u entries.\n", rangeCount);
        ExFreePool(ranges);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (range = ranges; range->BaseAddress.QuadPart != 0 || range->NumberOfBytes.QuadPart != 0; range++)
    {
        UINT64 start = (UINT64)range->BaseAddress.QuadPart;
        UINT64 length = (UINT64)range->NumberOfBytes.QuadPart;
        UINT64 end;

        if (length == 0 || length > MAXUINT64 - start)
        {
            continue;
        }

        end = (start + length) & ~(UINT64)(PAGE_SIZE - 1);
        start &= ~(UINT64)(PAGE_SIZE - 1);

        if (end <= start)
        {
            continue;
        }

        if (end > HACDBG_GUEST_PHYSICAL_LIMIT)
        {
            HACDBG_LOG("HacDbg: Err, RAM range [0x%I64x, 0x%I64x) exceeds the 1 TiB NPT limit.\n",
                     start, end);
            status = STATUS_NOT_SUPPORTED;
            break;
        }

        g_Ranges[g_RangeCount].Start = start;
        g_Ranges[g_RangeCount].End = end;
        g_RangeCount++;
    }

    ExFreePool(ranges);

    if (!NT_SUCCESS(status) || g_RangeCount == 0)
    {
        HACDBG_LOG("HacDbg: Err, RAM range scan failed: status=0x%08x count=%u.\n",
                 status, g_RangeCount);
        PhysicalMemoryFreeRanges();
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    HACDBG_LOG("HacDbg: RAM map ready: %u ranges.\n", g_RangeCount);
    g_Initialized = TRUE;
    return STATUS_SUCCESS;
}

// 释放 RAM 范围表。
VOID
PhysicalMemoryCleanup(
    VOID
    )
{
    if (g_Initialized == FALSE)
    {
        return;
    }

    PhysicalMemoryFreeRanges();
    g_Initialized = FALSE;
}

// 记录客户是否启用五级页表。
VOID
PhysicalMemorySetFiveLevelPaging(
    _In_ BOOLEAN Enabled
    )
{
    g_FiveLevelPaging = Enabled;
}

// 临时映射一段客户物理内存，优先 MmMapIoSpace，失败后退回 MmMapIoSpaceEx。
PVOID
PhysicalMemoryMapTemporary(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _In_ SIZE_T Size,
    _Out_ SIZE_T* MappedSize
    )
{
    PHYSICAL_ADDRESS physical;
    PVOID mapped;

    *MappedSize = 0;

    if (Size == 0)
    {
        return NULL;
    }

    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
        if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
        {
            HACDBG_LOG("HacDbg: Err, physical map rejected pa=0x%I64x size=0x%I64x irql=%u.\n",
                     Address.Value, (UINT64)Size, KeGetCurrentIrql());
        }
        return NULL;
    }

    Size = PhysicalMemoryAvailableSize(Address.Value, Size);
    if (Size == 0)
    {
        if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
        {
            HACDBG_LOG("HacDbg: Err, physical map rejected pa=0x%I64x: not in %u RAM ranges.\n",
                     Address.Value, g_RangeCount);
        }
        return NULL;
    }

    physical.QuadPart = Address.Value;
    mapped = MmMapIoSpace(physical, Size, MmCached);
    if (mapped == NULL)
    {
        if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
        {
            HACDBG_LOG("HacDbg: Err, MmMapIoSpace cached failed pa=0x%I64x size=0x%I64x irql=%u.\n",
                     Address.Value, (UINT64)Size, KeGetCurrentIrql());
        }

        mapped = MmMapIoSpaceEx(physical, Size, PAGE_READWRITE);
        if (mapped == NULL)
        {
            if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
            {
                HACDBG_LOG("HacDbg: Err, MmMapIoSpaceEx cached failed pa=0x%I64x size=0x%I64x irql=%u.\n",
                         Address.Value, (UINT64)Size, KeGetCurrentIrql());
            }

            mapped = MmMapIoSpaceEx(physical, Size, PAGE_READWRITE | PAGE_NOCACHE);
            if (mapped == NULL)
            {
                if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
                {
                    HACDBG_LOG("HacDbg: Err, MmMapIoSpaceEx noncached failed pa=0x%I64x size=0x%I64x irql=%u.\n",
                             Address.Value, (UINT64)Size, KeGetCurrentIrql());
                }
                return NULL;
            }
        }
    }

    *MappedSize = Size;
    return mapped;
}

// 解除临时映射。
VOID
PhysicalMemoryUnmapTemporary(
    _In_ PVOID Base,
    _In_ SIZE_T Size
    )
{
    if (Base != NULL && Size != 0)
    {
        MmUnmapIoSpace(Base, Size);
    }
}

// 按页跨页复制；读优先 MmCopyMemory，写使用临时映射。
static SIZE_T
PhysicalMemoryCopy(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN ToGuest
    )
{
    SIZE_T copied = 0;

    while (copied < Size)
    {
        SIZE_T mappedSize = 0;
        GUEST_PHYSICAL_ADDRESS current;
        PVOID mapped;
        SIZE_T chunk;

        if (Address.Value + copied < Address.Value)
        {
            break;
        }

        if (ToGuest == FALSE && KeGetCurrentIrql() <= APC_LEVEL)
        {
            MM_COPY_ADDRESS copyAddress = { 0 };
            SIZE_T transferred = 0;
            SIZE_T copySize = PhysicalMemoryAvailableSize(Address.Value + copied, Size - copied);
            NTSTATUS copyStatus;

            if (copySize == 0)
            {
                if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
                {
                    HACDBG_LOG("HacDbg: Err, physical read rejected pa=0x%I64x size=0x%I64x.\n",
                             Address.Value + copied, (UINT64)(Size - copied));
                }
                break;
            }

            copyAddress.PhysicalAddress.QuadPart = (LONGLONG)(Address.Value + copied);
            copyStatus = MmCopyMemory((PUCHAR)Buffer + copied, copyAddress, copySize,
                                      MM_COPY_MEMORY_PHYSICAL, &transferred);
            if (NT_SUCCESS(copyStatus) && transferred != 0)
            {
                copied += transferred;
                if (transferred != copySize)
                {
                    break;
                }
                continue;
            }

            if (PhysicalMemoryShouldLogFailure(&g_PhysicalFailureLogCount) != FALSE)
            {
                HACDBG_LOG("HacDbg: Err, MmCopyMemory read failed pa=0x%I64x size=0x%I64x "
                         "status=0x%08x transferred=0x%I64x; falling back to mapping.\n",
                         Address.Value + copied, (UINT64)copySize, copyStatus, (UINT64)transferred);
            }
        }

        current = HacDbgGuestPhysicalAddress(Address.Value + copied);
        mapped = PhysicalMemoryMapTemporary(current, Size - copied, &mappedSize);
        if (mapped == NULL || mappedSize == 0)
        {
            break;
        }

        chunk = mappedSize;

        if (ToGuest != FALSE)
        {
            RtlCopyMemory(mapped, (PUCHAR)Buffer + copied, chunk);
        }
        else
        {
            RtlCopyMemory((PUCHAR)Buffer + copied, mapped, chunk);
        }

        PhysicalMemoryUnmapTemporary(mapped, chunk);
        copied += chunk;
    }

    return copied;
}

// 读客户物理内存。
SIZE_T
PhysicalMemoryRead(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    return PhysicalMemoryCopy(Address, Buffer, Size, FALSE);
}

// 写客户物理内存。
SIZE_T
PhysicalMemoryWrite(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _In_reads_bytes_(Size) const VOID* Buffer,
    _In_ SIZE_T Size
    )
{
    return PhysicalMemoryCopy(Address, (PVOID)Buffer, Size, TRUE);
}

// 按 CR3 遍历四/五级页表，支持 4 KiB、2 MiB 和 1 GiB 页。
BOOLEAN
_Success_(return != FALSE)
GuestVirtualToPhysical(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS VirtualAddress,
    _Out_ GUEST_PHYSICAL_ADDRESS* PhysicalAddress
    )
{
    UINT64 table = Cr3 & 0x000FFFFFFFFFF000ull;
    UINT64 offset;
    UINT64 entry = 0;
    UINT8 level;
    UINT8 levels = g_FiveLevelPaging != FALSE ? 5 : 4;
    UINT64 shift = g_FiveLevelPaging != FALSE ? 48 : 39;

    PhysicalAddress->Value = 0;

    for (level = 0; level < levels; level++, shift -= 9)
    {
        UINT64 index = (VirtualAddress.Value >> shift) & 0x1ffull;
        GUEST_PHYSICAL_ADDRESS entryAddress = HacDbgGuestPhysicalAddress(table + (index * sizeof(UINT64)));
        SIZE_T read = PhysicalMemoryRead(entryAddress, &entry, sizeof(entry));

        if (read != sizeof(entry))
        {
            if (PhysicalMemoryShouldLogFailure(&g_TranslationFailureLogCount) != FALSE)
            {
                HACDBG_LOG("HacDbg: Err, VA walk read failed level=%u cr3=0x%I64x va=0x%I64x "
                         "entry_pa=0x%I64x read=%I64x.\n",
                         level, Cr3, VirtualAddress.Value, entryAddress.Value, (UINT64)read);
            }
            return FALSE;
        }

        if ((entry & 1ull) == 0)
        {
            if (PhysicalMemoryShouldLogFailure(&g_TranslationFailureLogCount) != FALSE)
            {
                HACDBG_LOG("HacDbg: Err, VA walk not present level=%u cr3=0x%I64x va=0x%I64x "
                         "entry_pa=0x%I64x entry=0x%I64x.\n",
                         level, Cr3, VirtualAddress.Value, entryAddress.Value, entry);
            }
            return FALSE;
        }

        if (shift == 30 && (entry & (1ull << 7)) != 0)
        {
            offset = VirtualAddress.Value & 0x3fffffffull;
            PhysicalAddress->Value = (entry & 0x000FFFFFC0000000ull) + offset;
            return TRUE;
        }

        if (shift == 21 && (entry & (1ull << 7)) != 0)
        {
            offset = VirtualAddress.Value & 0x1fffffull;
            PhysicalAddress->Value = (entry & 0x000FFFFFFFE00000ull) + offset;
            return TRUE;
        }

        table = entry & 0x000FFFFFFFFFF000ull;
    }

    offset = VirtualAddress.Value & 0xfffull;
    PhysicalAddress->Value = (entry & 0x000FFFFFFFFFF000ull) + offset;

    return TRUE;
}

// 按页把客户虚拟地址复制到宿主缓冲区或写回客户。
static SIZE_T
GuestVirtualCopy(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS Address,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN ToGuest
    )
{
    SIZE_T copied = 0;

    while (copied < Size)
    {
        if (Address.Value + copied < Address.Value)
        {
            break;
        }

        GUEST_VIRTUAL_ADDRESS current = HacDbgGuestVirtualAddress(Address.Value + copied);
        GUEST_PHYSICAL_ADDRESS physical;
        SIZE_T pageLeft;
        SIZE_T chunk;
        SIZE_T actual;

        if (GuestVirtualToPhysical(Cr3, current, &physical) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, guest virtual copy translation failed cr3=0x%I64x va=0x%I64x "
                     "offset=0x%I64x.\n",
                     Cr3, current.Value, (UINT64)copied);
            break;
        }

        pageLeft = PAGE_SIZE - (SIZE_T)(current.Value & (PAGE_SIZE - 1));
        chunk = min(pageLeft, Size - copied);

        if (ToGuest != FALSE)
        {
            actual = PhysicalMemoryWrite(physical, (PUCHAR)Buffer + copied, chunk);
        }
        else
        {
            actual = PhysicalMemoryRead(physical, (PUCHAR)Buffer + copied, chunk);
        }

        copied += actual;

        if (actual != chunk)
        {
            HACDBG_LOG("HacDbg: Err, guest virtual copy short cr3=0x%I64x va=0x%I64x pa=0x%I64x "
                     "chunk=0x%I64x actual=0x%I64x.\n",
                     Cr3, current.Value, physical.Value, (UINT64)chunk, (UINT64)actual);
            break;
        }
    }

    return copied;
}

// 读客户虚拟内存。
SIZE_T
GuestVirtualRead(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    return GuestVirtualCopy(Cr3, Address, Buffer, Size, FALSE);
}

// 写客户虚拟内存。
SIZE_T
GuestVirtualWrite(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS Address,
    _In_reads_bytes_(Size) const VOID* Buffer,
    _In_ SIZE_T Size
    )
{
    return GuestVirtualCopy(Cr3, Address, (PVOID)Buffer, Size, TRUE);
}
