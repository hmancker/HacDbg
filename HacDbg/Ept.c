/**
 * @file Ept.c
 * @brief Extended page tables, execute hooks, and hidden pages.
 *
 * @author HacDbg
 */

#include "Ept.h"
#include "Debug.h"

#define HACDBG_EPT_TAG               'TcaH'
#define HACDBG_EPT_MAX_HOOKS         256
#define HACDBG_EPT_MAX_HIDDEN        1024
#define HACDBG_EPT_COVERED_BYTES     HACDBG_GUEST_PHYSICAL_LIMIT
#define HACDBG_EPT_TABLE_PAGES       ((HACDBG_EPT_COVERED_BYTES / (2ull * 1024ull * 1024ull)) / 512ull * 2ull + 6ull)
//
// 每个根最多为 256 个类型不统一的 2 MiB 页再配一张 4 KiB 表。
// 固定 MTRR 落在第一张 2 MiB 页里，变长 MTRR 最多 255 对。
//
#define HACDBG_EPT_MTRR_SPLIT_PAGES  (256ull * 2ull)
#define HACDBG_EPT_FIXED_PAGES       (HACDBG_EPT_TABLE_PAGES + 1ull + HACDBG_EPT_MTRR_SPLIT_PAGES)
#define HACDBG_EPT_SPLIT_PAGES       (HACDBG_EPT_MAX_HOOKS * 2ull + HACDBG_EPT_MAX_HIDDEN * 2ull + 128ull)
#define HACDBG_EPT_POOL_PAGES        (HACDBG_EPT_FIXED_PAGES + HACDBG_EPT_SPLIT_PAGES)
#define HACDBG_EPT_FIXED_CHUNK_PAGES 64ull
#define HACDBG_EPT_SPLIT_CHUNK_PAGES 8ull
#define HACDBG_EPT_MAX_CHUNKS        \
    ((HACDBG_EPT_FIXED_PAGES + HACDBG_EPT_FIXED_CHUNK_PAGES - 1ull) / HACDBG_EPT_FIXED_CHUNK_PAGES + \
     (HACDBG_EPT_SPLIT_PAGES + HACDBG_EPT_SPLIT_CHUNK_PAGES - 1ull) / HACDBG_EPT_SPLIT_CHUNK_PAGES)

//
// EPT entry bits from "Format of an EPT Page-Table Entry" and the 2 MiB PDE.
// Bits 5:3 are the EPT memory type. Bit 6 stays clear so PAT combines with
// that type. Bit 7 marks a large page.
//
#define EPT_READ                     (1ull << 0)
#define EPT_WRITE                    (1ull << 1)
#define EPT_EXECUTE                  (1ull << 2)
#define EPT_MEMORY_TYPE_SHIFT        3
#define EPT_LARGE                    (1ull << 7)
#define EPT_ADDRESS_MASK             0x000FFFFFFFFFF000ull
#define EPT_LARGE_2MB_MASK           0x000FFFFFFFE00000ull
#define EPT_TABLE_FLAGS              (EPT_READ | EPT_WRITE | EPT_EXECUTE)

//
// Architectural MTRR MSRs. IA32_MTRRCAP is FEH. Variable pairs start at 200H.
// Fixed ranges are 250H, 258H, 259H and 268H-26FH. IA32_MTRR_DEF_TYPE is 2FFH.
//
#define EPT_MSR_MTRRCAP              0x0FEull
#define EPT_MSR_MTRR_CAP_VCNT_MASK   0x0FFull
#define EPT_MSR_MTRR_CAP_FIX         (1ull << 8)
#define EPT_MSR_MTRR_PHYSBASE0       0x200ull
#define EPT_MSR_MTRR_FIX64K_00000    0x250ull
#define EPT_MSR_MTRR_FIX16K_80000    0x258ull
#define EPT_MSR_MTRR_FIX16K_A0000    0x259ull
#define EPT_MSR_MTRR_FIX4K_C0000     0x268ull
#define EPT_MSR_MTRR_DEF_TYPE        0x2FFull
#define EPT_MSR_MTRR_DEF_TYPE_MASK   0x0FFull
#define EPT_MSR_MTRR_DEF_FIXED       (1ull << 10)
#define EPT_MSR_MTRR_DEF_ENABLE      (1ull << 11)
#define EPT_MSR_MTRR_VALID           (1ull << 11)
#define EPT_MTRR_VARIABLE_CAPACITY   256u
#define EPT_MTRR_FIXED_PAGES         256u
#define EPT_MTRR_2MB_MASK            0x1FFFFFull
#define EPT_MTRR_2MB_PAGE_BITS       0x1FF000ull
#define EPT_CPUID_MTRR               (1u << 12)

//
// EPTP: WB memory type in bits 2:0, and page-walk length minus one (3 = 4 levels).
//
#define EPT_POINTER_FLAGS            (6ull | (3ull << 3))

typedef struct _EPT_HOOK
{
    volatile UINT64 TargetPage;
    UINT64 ShadowPage;
    volatile BOOLEAN Active;
    UINT8 Reserved[7];
} EPT_HOOK;

typedef struct _EPT_HIDDEN_PAGE
{
    UINT64 Page;
    BOOLEAN Active;
    UINT8 Reserved[7];
} EPT_HIDDEN_PAGE;

typedef struct _EPT_MTRR_RANGE
{
    UINT64 Base;
    UINT64 Mask;
    UINT8 Type;
    UINT8 Reserved[7];
} EPT_MTRR_RANGE;

static PVOID g_PageVirtual[HACDBG_EPT_POOL_PAGES];
static UINT64 g_PagePhysical[HACDBG_EPT_POOL_PAGES];
static PVOID g_ChunkAllocations[HACDBG_EPT_MAX_CHUNKS];
static UINT64 g_ChunkCount;
static UINT64 g_FixedPagesUsed;
static UINT64 g_FixedPagesCarved;
static UINT64 g_SplitPagesUsed;
static UINT64 g_SplitPagesCarved;
static UINT64 g_MainEptp;
static UINT64 g_HookEptp;
static UINT64 g_DummyPagePa;
static EPT_HOOK g_Hooks[HACDBG_EPT_MAX_HOOKS];
static EPT_HIDDEN_PAGE g_HiddenPages[HACDBG_EPT_MAX_HIDDEN];
static HACDBG_SPIN_LOCK g_EptLock;
static BOOLEAN g_Initialized;
static EPT_MTRR_RANGE g_MtrrVariable[EPT_MTRR_VARIABLE_CAPACITY];
static UINT32 g_MtrrVariableCount;
static UINT8 g_MtrrFixed[EPT_MTRR_FIXED_PAGES];
static UINT8 g_MtrrDefault;
static BOOLEAN g_MtrrEnabled;
static BOOLEAN g_MtrrFixedEnabled;

static BOOLEAN
EptFindHidden(
    _In_ UINT64 Page
    );

// 按页块从非分页池切出 EPT 表，块首强制 4 KiB 对齐。
static BOOLEAN
EptCarveChunk(
    _In_ UINT64 SlotStart,
    _In_ UINT64 PageCount
    )
{
    PVOID allocation;
    PVOID aligned;
    SIZE_T bytes;
    PHYSICAL_ADDRESS physical;
    UINT64 index;

    if (PageCount == 0 || SlotStart + PageCount > HACDBG_EPT_POOL_PAGES ||
        g_ChunkCount >= HACDBG_EPT_MAX_CHUNKS)
    {
        return FALSE;
    }

    bytes = (SIZE_T)(PageCount * PAGE_SIZE) + PAGE_SIZE;
    allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, HACDBG_EPT_TAG);
    if (allocation == NULL)
    {
        return FALSE;
    }

    aligned = (PVOID)(((ULONG_PTR)allocation + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    g_ChunkAllocations[g_ChunkCount] = allocation;
    g_ChunkCount++;

    for (index = 0; index < PageCount; index++)
    {
        PVOID page = (PVOID)((ULONG_PTR)aligned + (index * PAGE_SIZE));

        RtlZeroMemory(page, PAGE_SIZE);
        physical = MmGetPhysicalAddress(page);
        g_PageVirtual[SlotStart + index] = page;
        g_PagePhysical[SlotStart + index] = (UINT64)physical.QuadPart & EPT_ADDRESS_MASK;
    }

    return TRUE;
}

_Success_(return != NULL)
static VOID*
EptAllocatePage(
    _Out_ UINT64* PhysicalAddress
    )
{
    UINT64 index;
    UINT64 pageCount;

    *PhysicalAddress = 0;

    if (g_FixedPagesUsed >= HACDBG_EPT_FIXED_PAGES)
    {
        return NULL;
    }

    if (g_FixedPagesUsed >= g_FixedPagesCarved)
    {
        pageCount = min(HACDBG_EPT_FIXED_CHUNK_PAGES,
                        HACDBG_EPT_FIXED_PAGES - g_FixedPagesCarved);
        if (EptCarveChunk(g_FixedPagesCarved, pageCount) == FALSE)
        {
            return NULL;
        }
        g_FixedPagesCarved += pageCount;
    }

    index = g_FixedPagesUsed;
    *PhysicalAddress = g_PagePhysical[index];
    g_FixedPagesUsed++;
    return g_PageVirtual[index];
}

_Success_(return != NULL)
static VOID*
EptAllocateSplitPage(
    _Out_ UINT64* PhysicalAddress
    )
{
    UINT64 index;

    *PhysicalAddress = 0;

    if (g_SplitPagesUsed >= g_SplitPagesCarved)
    {
        return NULL;
    }

    index = HACDBG_EPT_FIXED_PAGES + g_SplitPagesUsed;
    *PhysicalAddress = g_PagePhysical[index];
    g_SplitPagesUsed++;
    return g_PageVirtual[index];
}

//
// 钩子安装发生在 CPUID 退出里，不能再调用池分配。拆分页在进入客户前切完。
//
static BOOLEAN
EptPreallocateSplitPages(
    VOID
    )
{
    while (g_SplitPagesCarved < HACDBG_EPT_SPLIT_PAGES)
    {
        UINT64 pageCount = min(HACDBG_EPT_SPLIT_CHUNK_PAGES,
                               HACDBG_EPT_SPLIT_PAGES - g_SplitPagesCarved);
        UINT64 slotStart = HACDBG_EPT_FIXED_PAGES + g_SplitPagesCarved;

        if (EptCarveChunk(slotStart, pageCount) == FALSE)
        {
            return FALSE;
        }

        g_SplitPagesCarved += pageCount;
    }

    return TRUE;
}

static UINT8
EptSupportedType(
    _In_ UINT8 Type
    )
{
    if (Type == 0 || Type == 1 || Type == 4 || Type == 5 || Type == 6)
    {
        return Type;
    }

    return 0;
}

static UINT64
EptMaxPhysicalMask(
    VOID
    )
{
    int cpuInfo[4];
    UINT32 maxPhysical;

    maxPhysical = 36;
    __cpuid(cpuInfo, (int)0x80000000);
    if ((UINT32)cpuInfo[0] >= 0x80000008u)
    {
        __cpuid(cpuInfo, (int)0x80000008);
        maxPhysical = (UINT32)cpuInfo[0] & 0xFFu;
        if (maxPhysical < 32 || maxPhysical > 52)
        {
            maxPhysical = 36;
        }
    }

    return ((1ull << maxPhysical) - 1ull) & ~0xFFFull;
}

static UINT32
EptStoreFixedRange(
    _In_ UINT64 Value,
    _In_ UINT32 PageIndex,
    _In_ UINT32 PagesPerByte
    )
{
    UINT32 byteIndex;

    for (byteIndex = 0; byteIndex < 8; byteIndex++)
    {
        UINT8 type = EptSupportedType((UINT8)((Value >> (byteIndex * 8)) & 0xFFull));
        UINT32 page;

        for (page = 0; page < PagesPerByte; page++)
        {
            if (PageIndex >= EPT_MTRR_FIXED_PAGES)
            {
                return PageIndex;
            }

            g_MtrrFixed[PageIndex] = type;
            PageIndex++;
        }
    }

    return PageIndex;
}

static VOID
EptLoadMtrrs(
    VOID
    )
{
    int cpuInfo[4];
    UINT64 cap;
    UINT64 defType;
    UINT64 addressMask;
    UINT32 variableCount;
    UINT32 index;
    UINT32 fixedPage;

    g_MtrrEnabled = FALSE;
    g_MtrrFixedEnabled = FALSE;
    g_MtrrVariableCount = 0;
    g_MtrrDefault = 0;
    RtlZeroMemory(g_MtrrVariable, sizeof(g_MtrrVariable));
    RtlZeroMemory(g_MtrrFixed, sizeof(g_MtrrFixed));

    __cpuid(cpuInfo, 1);
    if (((UINT32)cpuInfo[3] & EPT_CPUID_MTRR) == 0)
    {
        HACDBG_LOG("HacDbg: EPT has no MTRRs; guest-physical memory is UC.\n");
        return;
    }

    //
    // INVARIANT: CPUID.01H:EDX[12] is set, so these MTRR MSRs are architectural.
    // This runs before any processor enters VMX non-root operation.
    //
    cap = __readmsr(EPT_MSR_MTRRCAP);
    defType = __readmsr(EPT_MSR_MTRR_DEF_TYPE);
    if ((defType & EPT_MSR_MTRR_DEF_ENABLE) == 0)
    {
        HACDBG_LOG("HacDbg: EPT MTRRs are disabled; guest-physical memory is UC.\n");
        return;
    }

    g_MtrrEnabled = TRUE;
    g_MtrrDefault = EptSupportedType((UINT8)(defType & EPT_MSR_MTRR_DEF_TYPE_MASK));
    addressMask = EptMaxPhysicalMask();
    variableCount = (UINT32)(cap & EPT_MSR_MTRR_CAP_VCNT_MASK);
    if (variableCount > EPT_MTRR_VARIABLE_CAPACITY)
    {
        variableCount = EPT_MTRR_VARIABLE_CAPACITY;
    }

    for (index = 0; index < variableCount; index++)
    {
        UINT64 base = __readmsr(EPT_MSR_MTRR_PHYSBASE0 + ((UINT64)index * 2ull));
        UINT64 mask = __readmsr(EPT_MSR_MTRR_PHYSBASE0 + ((UINT64)index * 2ull) + 1ull);

        if ((mask & EPT_MSR_MTRR_VALID) == 0)
        {
            continue;
        }

        g_MtrrVariable[g_MtrrVariableCount].Base = base & addressMask;
        g_MtrrVariable[g_MtrrVariableCount].Mask = mask & addressMask;
        g_MtrrVariable[g_MtrrVariableCount].Type =
            EptSupportedType((UINT8)(base & 0xFFull));
        g_MtrrVariableCount++;
    }

    if ((cap & EPT_MSR_MTRR_CAP_FIX) != 0 &&
        (defType & EPT_MSR_MTRR_DEF_FIXED) != 0)
    {
        fixedPage = EptStoreFixedRange(__readmsr(EPT_MSR_MTRR_FIX64K_00000), 0, 16);
        fixedPage = EptStoreFixedRange(__readmsr(EPT_MSR_MTRR_FIX16K_80000), fixedPage, 4);
        fixedPage = EptStoreFixedRange(__readmsr(EPT_MSR_MTRR_FIX16K_A0000), fixedPage, 4);
        for (index = 0; index < 8; index++)
        {
            fixedPage = EptStoreFixedRange(
                __readmsr(EPT_MSR_MTRR_FIX4K_C0000 + index), fixedPage, 1);
        }

        if (fixedPage == EPT_MTRR_FIXED_PAGES)
        {
            g_MtrrFixedEnabled = TRUE;
        }
        else
        {
            HACDBG_LOG("HacDbg: Err, fixed MTRR map covered %u pages.\n", fixedPage);
        }
    }

    HACDBG_LOG("HacDbg: EPT memory types follow MTRRs default=%u fixed=%u variables=%u.\n",
               g_MtrrDefault,
               g_MtrrFixedEnabled,
               g_MtrrVariableCount);
}

static UINT8
EptMemoryType(
    _In_ UINT64 PhysicalAddress
    )
{
    UINT64 page = PhysicalAddress & EPT_ADDRESS_MASK;
    UINT32 index;
    UINT8 selected;
    BOOLEAN matched;
    BOOLEAN conflict;
    BOOLEAN sawUc;
    BOOLEAN sawWt;
    BOOLEAN sawWb;
    BOOLEAN sawOther;

    if (g_MtrrEnabled == FALSE)
    {
        return 0;
    }

    if (g_MtrrFixedEnabled != FALSE && page < 0x100000ull)
    {
        return g_MtrrFixed[(UINT32)(page >> PAGE_SHIFT)];
    }

    selected = g_MtrrDefault;
    matched = FALSE;
    conflict = FALSE;
    sawUc = FALSE;
    sawWt = FALSE;
    sawWb = FALSE;
    sawOther = FALSE;

    for (index = 0; index < g_MtrrVariableCount; index++)
    {
        UINT8 type;

        if ((page & g_MtrrVariable[index].Mask) !=
            (g_MtrrVariable[index].Base & g_MtrrVariable[index].Mask))
        {
            continue;
        }

        type = g_MtrrVariable[index].Type;
        if (matched == FALSE)
        {
            selected = type;
            matched = TRUE;
        }
        else if (type != selected)
        {
            conflict = TRUE;
        }

        if (type == 0)
        {
            sawUc = TRUE;
        }
        else if (type == 4)
        {
            sawWt = TRUE;
        }
        else if (type == 6)
        {
            sawWb = TRUE;
        }
        else
        {
            sawOther = TRUE;
        }
    }

    if (matched == FALSE)
    {
        return g_MtrrDefault;
    }

    if (sawUc != FALSE)
    {
        return 0;
    }

    if (conflict == FALSE)
    {
        return selected;
    }

    if (sawWt != FALSE && sawWb != FALSE && sawOther == FALSE)
    {
        return 4;
    }

    return 0;
}

static BOOLEAN
EptLargePageMayDiffer(
    _In_ UINT64 Base
    )
{
    UINT32 index;

    if (g_MtrrFixedEnabled != FALSE && Base < 0x100000ull)
    {
        return TRUE;
    }

    for (index = 0; index < g_MtrrVariableCount; index++)
    {
        UINT64 mask = g_MtrrVariable[index].Mask;

        if ((mask & EPT_MTRR_2MB_PAGE_BITS) == EPT_MTRR_2MB_PAGE_BITS)
        {
            continue;
        }

        if ((Base & mask & ~EPT_MTRR_2MB_MASK) ==
            (g_MtrrVariable[index].Base & mask & ~EPT_MTRR_2MB_MASK))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
EptLargePageType(
    _In_ UINT64 Base,
    _Out_ UINT8* Type
    )
{
    UINT8 first;
    UINT32 index;

    if (EptLargePageMayDiffer(Base) == FALSE)
    {
        *Type = EptMemoryType(Base);
        return TRUE;
    }

    first = EptMemoryType(Base);
    for (index = 1; index < 512; index++)
    {
        if (EptMemoryType(Base + ((UINT64)index << PAGE_SHIFT)) != first)
        {
            return FALSE;
        }
    }

    *Type = first;
    return TRUE;
}

static UINT64
EptAccessFlags(
    _In_ UINT64 PhysicalPage,
    _In_ BOOLEAN Executable
    )
{
    UINT64 flags = EPT_READ | EPT_WRITE |
                   ((UINT64)EptMemoryType(PhysicalPage) << EPT_MEMORY_TYPE_SHIFT);

    if (Executable != FALSE)
    {
        flags |= EPT_EXECUTE;
    }

    return flags;
}

static UINT64*
EptVirtualFromPhysical(
    _In_ UINT64 PhysicalAddress
    )
{
    UINT64 index;

    for (index = 0; index < g_FixedPagesCarved; index++)
    {
        if (g_PagePhysical[index] == (PhysicalAddress & EPT_ADDRESS_MASK))
        {
            return (UINT64*)g_PageVirtual[index];
        }
    }

    for (index = 0; index < g_SplitPagesCarved; index++)
    {
        UINT64 slot = HACDBG_EPT_FIXED_PAGES + index;

        if (g_PagePhysical[slot] == (PhysicalAddress & EPT_ADDRESS_MASK))
        {
            return (UINT64*)g_PageVirtual[slot];
        }
    }

    return NULL;
}

static UINT64*
EptPageFromEntry(
    _In_ UINT64 Entry
    )
{
    if ((Entry & EPT_READ) == 0 && (Entry & EPT_WRITE) == 0 && (Entry & EPT_EXECUTE) == 0)
    {
        return NULL;
    }

    return EptVirtualFromPhysical(Entry & EPT_ADDRESS_MASK);
}

static BOOLEAN
EptFindHook(
    _In_ UINT64 TargetPage,
    _Out_opt_ UINT32* IndexOut
    )
{
    UINT32 index;

    for (index = 0; index < HACDBG_EPT_MAX_HOOKS; index++)
    {
        if (g_Hooks[index].Active != FALSE && g_Hooks[index].TargetPage == TargetPage)
        {
            if (IndexOut != NULL)
            {
                *IndexOut = index;
            }

            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
EptFindHidden(
    _In_ UINT64 Page
    )
{
    UINT32 index;

    for (index = 0; index < HACDBG_EPT_MAX_HIDDEN; index++)
    {
        if (g_HiddenPages[index].Active != FALSE && g_HiddenPages[index].Page == Page)
        {
            return TRUE;
        }
    }

    return FALSE;
}

// 取得客户页对应的 4 KiB PTE；遇到 2 MiB 大页时拆开。
static UINT64*
EptPte(
    _In_ UINT64 Eptp,
    _In_ UINT64 GuestPage,
    _In_ BOOLEAN HookRoot
    )
{
    UINT64* pml4 = EptVirtualFromPhysical(Eptp & EPT_ADDRESS_MASK);
    UINT64* pdpt;
    UINT64* pd;
    UINT64* pde;
    UINT64* pt;
    UINT64 pdeValue;
    UINT64 splitPa;
    UINT64 base;
    UINT64 i;

    if (pml4 == NULL)
    {
        return NULL;
    }

    pdpt = EptPageFromEntry(pml4[(GuestPage >> 39) & 0x1ffull]);
    if (pdpt == NULL)
    {
        return NULL;
    }

    pd = EptPageFromEntry(pdpt[(GuestPage >> 30) & 0x1ffull]);
    if (pd == NULL)
    {
        return NULL;
    }

    pde = &pd[(GuestPage >> 21) & 0x1ffull];
    pdeValue = *pde;

    if ((pdeValue & EPT_LARGE) == 0)
    {
        pt = EptPageFromEntry(pdeValue);
        return pt == NULL ? NULL : &pt[(GuestPage >> PAGE_SHIFT) & 0x1ffull];
    }

    pt = (UINT64*)EptAllocateSplitPage(&splitPa);
    if (pt == NULL)
    {
        return NULL;
    }

    base = pdeValue & EPT_LARGE_2MB_MASK;

    for (i = 0; i < 512; i++)
    {
        UINT64 page = base + (i * PAGE_SIZE);
        UINT64 mapped = page;

        if (EptFindHidden(page) != FALSE)
        {
            mapped = g_DummyPagePa;
        }

        pt[i] = mapped | EptAccessFlags(mapped, HookRoot == FALSE);
    }

    *pde = (splitPa & EPT_ADDRESS_MASK) | EPT_TABLE_FLAGS;
    KeMemoryBarrier();
    return &pt[(GuestPage >> PAGE_SHIFT) & 0x1ffull];
}

static VOID
EptSetAdjacentExecutable(
    _In_ UINT64 TargetPage
    )
{
    UINT64* pte;

    if (TargetPage >= PAGE_SIZE && EptFindHidden(TargetPage - PAGE_SIZE) == FALSE)
    {
        pte = EptPte(g_HookEptp, TargetPage - PAGE_SIZE, TRUE);

        if (pte != NULL)
        {
            *pte |= EPT_EXECUTE;
        }
    }

    pte = EptFindHidden(TargetPage + PAGE_SIZE) == FALSE
              ? EptPte(g_HookEptp, TargetPage + PAGE_SIZE, TRUE)
              : NULL;

    if (pte != NULL)
    {
        *pte |= EPT_EXECUTE;
    }
}

NTSTATUS
EptInitialize(
    VOID
    )
{
    UINT64 mainPa;
    UINT64 hookPa;
    UINT64* mainPml4;
    UINT64* hookPml4;
    UINT64 root;
    UINT64 pml4Index;
    UINT64 pdptIndex;
    UINT64 pdIndex;

    if (g_Initialized != FALSE)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    EptLoadMtrrs();

    g_ChunkCount = 0;
    g_FixedPagesUsed = 0;
    g_FixedPagesCarved = 0;
    g_SplitPagesUsed = 0;
    g_SplitPagesCarved = 0;
    RtlZeroMemory(g_PageVirtual, sizeof(g_PageVirtual));
    RtlZeroMemory(g_PagePhysical, sizeof(g_PagePhysical));
    RtlZeroMemory(g_ChunkAllocations, sizeof(g_ChunkAllocations));
    RtlZeroMemory(g_Hooks, sizeof(g_Hooks));
    RtlZeroMemory(g_HiddenPages, sizeof(g_HiddenPages));
    HacDbgSpinLockInitialize(&g_EptLock);

    mainPml4 = EptAllocatePage(&mainPa);
    hookPml4 = EptAllocatePage(&hookPa);
    if (mainPml4 == NULL || hookPml4 == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (root = 0; root < 2; root++)
    {
        UINT64* pml4 = root == 0 ? mainPml4 : hookPml4;
        BOOLEAN hookRoot = root == 1;

        for (pml4Index = 0; pml4Index < 2; pml4Index++)
        {
            UINT64 pdptPa;
            UINT64* pdpt = EptAllocatePage(&pdptPa);

            if (pdpt == NULL)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            pml4[pml4Index] = (pdptPa & EPT_ADDRESS_MASK) | EPT_TABLE_FLAGS;

            for (pdptIndex = 0; pdptIndex < 512; pdptIndex++)
            {
                UINT64 pdPa;
                UINT64* pd = EptAllocatePage(&pdPa);

                if (pd == NULL)
                {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                pdpt[pdptIndex] = (pdPa & EPT_ADDRESS_MASK) | EPT_TABLE_FLAGS;

                for (pdIndex = 0; pdIndex < 512; pdIndex++)
                {
                    UINT64 guestAddress = (((pml4Index * 512) + pdptIndex) * 512 + pdIndex) *
                                          (2ull * 1024ull * 1024ull);
                    UINT8 type;
                    UINT64 flags;

                    if (EptLargePageType(guestAddress, &type) != FALSE)
                    {
                        flags = EPT_READ | EPT_WRITE | EPT_LARGE |
                                ((UINT64)type << EPT_MEMORY_TYPE_SHIFT);
                        if (hookRoot == FALSE)
                        {
                            flags |= EPT_EXECUTE;
                        }

                        pd[pdIndex] = guestAddress | flags;
                    }
                    else
                    {
                        UINT64 ptPa;
                        UINT64* pt = EptAllocatePage(&ptPa);
                        UINT32 pageIndex;

                        if (pt == NULL)
                        {
                            HACDBG_LOG("HacDbg: Err, EPT pool exhausted while splitting MTRR page 0x%I64x.\n",
                                       guestAddress);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }

                        for (pageIndex = 0; pageIndex < 512; pageIndex++)
                        {
                            UINT64 page = guestAddress + ((UINT64)pageIndex << PAGE_SHIFT);

                            pt[pageIndex] = page | EptAccessFlags(page, hookRoot == FALSE);
                        }

                        pd[pdIndex] = (ptPa & EPT_ADDRESS_MASK) | EPT_TABLE_FLAGS;
                    }
                }
            }
        }
    }

    {
        UINT64 dummyPa;
        PVOID dummy = EptAllocatePage(&dummyPa);

        if (dummy == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        g_DummyPagePa = dummyPa;
    }

    if (EptPreallocateSplitPages() == FALSE)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_MainEptp = (mainPa & EPT_ADDRESS_MASK) | EPT_POINTER_FLAGS;
    g_HookEptp = (hookPa & EPT_ADDRESS_MASK) | EPT_POINTER_FLAGS;
    g_Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
EptCleanup(
    VOID
    )
{
    UINT64 index;

    for (index = 0; index < g_ChunkCount; index++)
    {
        ExFreePoolWithTag(g_ChunkAllocations[index], HACDBG_EPT_TAG);
    }

    RtlZeroMemory(g_PageVirtual, sizeof(g_PageVirtual));
    RtlZeroMemory(g_PagePhysical, sizeof(g_PagePhysical));
    RtlZeroMemory(g_ChunkAllocations, sizeof(g_ChunkAllocations));
    g_ChunkCount = 0;
    g_FixedPagesUsed = 0;
    g_FixedPagesCarved = 0;
    g_SplitPagesUsed = 0;
    g_SplitPagesCarved = 0;
    g_MainEptp = 0;
    g_HookEptp = 0;
    g_DummyPagePa = 0;
    g_Initialized = FALSE;
    g_MtrrEnabled = FALSE;
    g_MtrrFixedEnabled = FALSE;
    g_MtrrVariableCount = 0;
    g_MtrrDefault = 0;
}

UINT64
EptMainEptp(
    VOID
    )
{
    return g_MainEptp;
}

UINT64
EptHookEptp(
    VOID
    )
{
    return g_HookEptp;
}

BOOLEAN
EptIsEnabled(
    VOID
    )
{
    return g_Initialized;
}

UINT32
EptFreeTableCount(
    VOID
    )
{
    return (UINT32)((HACDBG_EPT_FIXED_PAGES - g_FixedPagesUsed) +
                    (HACDBG_EPT_SPLIT_PAGES - g_SplitPagesUsed));
}

BOOLEAN
EptAddHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage,
    _In_ GUEST_PHYSICAL_ADDRESS ShadowPage
    )
{
    UINT64 target = TargetPage.Value & EPT_ADDRESS_MASK;
    UINT64 shadow = ShadowPage.Value & EPT_ADDRESS_MASK;
    UINT64* mainPte;
    UINT64* hookPte;
    UINT32 index;

    if (g_Initialized == FALSE || (TargetPage.Value & (PAGE_SIZE - 1)) != 0 ||
        (ShadowPage.Value & (PAGE_SIZE - 1)) != 0)
    {
        HACDBG_LOG("HacDbg: Err, EPT hook rejected initialized=%u target=0x%I64x shadow=0x%I64x.\n",
                 g_Initialized, TargetPage.Value, ShadowPage.Value);
        return FALSE;
    }

    HacDbgSpinLockAcquire(&g_EptLock);

    if (EptFindHook(target, NULL) != FALSE)
    {
        HACDBG_LOG("HacDbg: Err, EPT hook already exists for page 0x%I64x.\n", target);
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    for (index = 0; index < HACDBG_EPT_MAX_HOOKS; index++)
    {
        if (g_Hooks[index].Active == FALSE)
        {
            break;
        }
    }

    if (index == HACDBG_EPT_MAX_HOOKS)
    {
        HACDBG_LOG("HacDbg: Err, EPT hook table is full.\n");
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    mainPte = EptPte(g_MainEptp, target, FALSE);
    hookPte = EptPte(g_HookEptp, target, TRUE);

    if (mainPte == NULL || hookPte == NULL)
    {
        HACDBG_LOG("HacDbg: Err, EPT hook PTE lookup failed target=0x%I64x main=%p hook=%p.\n",
                 target, mainPte, hookPte);
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    g_Hooks[index].TargetPage = target;
    g_Hooks[index].ShadowPage = shadow;
    g_Hooks[index].Active = FALSE;

    *hookPte = (shadow & EPT_ADDRESS_MASK) | EptAccessFlags(shadow, TRUE);
    EptSetAdjacentExecutable(target);
    KeMemoryBarrier();
    g_Hooks[index].Active = TRUE;
    KeMemoryBarrier();
    *mainPte &= ~EPT_EXECUTE;
    HacDbgSpinLockRelease(&g_EptLock);
    return TRUE;
}

BOOLEAN
EptRemoveHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    )
{
    UINT64 target = TargetPage.Value & EPT_ADDRESS_MASK;
    UINT64* mainPte;
    UINT64* hookPte;
    UINT32 index;

    HacDbgSpinLockAcquire(&g_EptLock);

    if ((TargetPage.Value & (PAGE_SIZE - 1)) != 0 ||
        EptFindHook(target, &index) == FALSE)
    {
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    mainPte = EptPte(g_MainEptp, target, FALSE);
    hookPte = EptPte(g_HookEptp, target, TRUE);

    if (mainPte == NULL || hookPte == NULL)
    {
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    *mainPte |= EPT_EXECUTE;
    KeMemoryBarrier();
    g_Hooks[index].Active = FALSE;
    KeMemoryBarrier();

    if (EptFindHidden(target) != FALSE)
    {
        *hookPte = g_DummyPagePa | EptAccessFlags(g_DummyPagePa, FALSE);
    }
    else
    {
        *hookPte = target | EptAccessFlags(target, FALSE);
    }

    KeMemoryBarrier();
    HacDbgSpinLockRelease(&g_EptLock);
    return TRUE;
}

BOOLEAN
EptHidePage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    )
{
    UINT64 target = TargetPage.Value & EPT_ADDRESS_MASK;
    UINT64* mainPte;
    UINT64* hookPte;
    UINT32 index;

    if (g_Initialized == FALSE || (TargetPage.Value & (PAGE_SIZE - 1)) != 0)
    {
        HACDBG_LOG("HacDbg: Err, EPT hide rejected initialized=%u page=0x%I64x.\n",
                 g_Initialized, TargetPage.Value);
        return FALSE;
    }

    HacDbgSpinLockAcquire(&g_EptLock);

    if (EptFindHidden(target) != FALSE)
    {
        HACDBG_LOG("HacDbg: Err, EPT page 0x%I64x is already hidden.\n", target);
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    for (index = 0; index < HACDBG_EPT_MAX_HIDDEN; index++)
    {
        if (g_HiddenPages[index].Active == FALSE)
        {
            break;
        }
    }

    if (index == HACDBG_EPT_MAX_HIDDEN)
    {
        HACDBG_LOG("HacDbg: Err, EPT hidden page table is full.\n");
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    mainPte = EptPte(g_MainEptp, target, FALSE);
    hookPte = EptPte(g_HookEptp, target, TRUE);

    if (mainPte == NULL || hookPte == NULL)
    {
        HACDBG_LOG("HacDbg: Err, EPT hide PTE lookup failed page=0x%I64x main=%p hook=%p.\n",
                 target, mainPte, hookPte);
        HacDbgSpinLockRelease(&g_EptLock);
        return FALSE;
    }

    g_HiddenPages[index].Page = target;
    g_HiddenPages[index].Active = TRUE;

    if (EptFindHook(target, NULL) != FALSE)
    {
        *mainPte = g_DummyPagePa | EptAccessFlags(g_DummyPagePa, FALSE);
    }
    else
    {
        *mainPte = g_DummyPagePa | EptAccessFlags(g_DummyPagePa, TRUE);
        *hookPte = g_DummyPagePa | EptAccessFlags(g_DummyPagePa, FALSE);
    }

    KeMemoryBarrier();
    HacDbgSpinLockRelease(&g_EptLock);
    return TRUE;
}

BOOLEAN
EptHandleViolation(
    _In_ UINT64 Qualification,
    _In_ UINT64 GuestPhysical,
    _In_ UINT64 CurrentEptp,
    _Out_ UINT64* NextEptp
    )
{
    UINT64 page = GuestPhysical & EPT_ADDRESS_MASK;
    UINT64 currentRoot = CurrentEptp & EPT_ADDRESS_MASK;
    BOOLEAN hooked;

    *NextEptp = CurrentEptp;

    //
    // Bit 2 of the EPT-violation qualification is an instruction fetch.
    // Data faults are not part of the two-root hook switch.
    //
    if ((Qualification & EPT_EXECUTE) == 0 || g_Initialized == FALSE)
    {
        return FALSE;
    }

    hooked = EptFindHook(page, NULL);
    if (hooked != FALSE)
    {
        if (currentRoot != (g_HookEptp & EPT_ADDRESS_MASK))
        {
            *NextEptp = g_HookEptp;
        }

        return TRUE;
    }

    if (currentRoot == (g_HookEptp & EPT_ADDRESS_MASK))
    {
        *NextEptp = g_MainEptp;
        return TRUE;
    }

    return FALSE;
}
