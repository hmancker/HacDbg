/**
 * @file Npt.c
 * @brief Nested page tables, execute hooks, and hidden pages.
 *
 * @author HacDbg
 */

#include "Npt.h"
#include "Debug.h"
#include "PhysicalMemory.h"

#define HACDBG_NPT_TAG              'TcaH'
#define HACDBG_NPT_MAX_HOOKS        256
#define HACDBG_NPT_MAX_HIDDEN       1024
#define HACDBG_NPT_COVERED_BYTES    HACDBG_GUEST_PHYSICAL_LIMIT
#define HACDBG_NPT_TABLE_PAGES      ((HACDBG_NPT_COVERED_BYTES / (2ull * 1024ull * 1024ull)) / 512ull * 2ull + 6ull)
#define HACDBG_NPT_FIXED_PAGES      (HACDBG_NPT_TABLE_PAGES + 1ull)
#define HACDBG_NPT_SPLIT_PAGES      (HACDBG_NPT_MAX_HOOKS * 2ull + HACDBG_NPT_MAX_HIDDEN * 2ull + 128ull)
#define HACDBG_NPT_POOL_PAGES       (HACDBG_NPT_FIXED_PAGES + HACDBG_NPT_SPLIT_PAGES)
#define HACDBG_NPT_FIXED_CHUNK_PAGES 64ull
#define HACDBG_NPT_SPLIT_CHUNK_PAGES 8ull
#define HACDBG_NPT_MAX_CHUNKS       \
    ((HACDBG_NPT_FIXED_PAGES + HACDBG_NPT_FIXED_CHUNK_PAGES - 1ull) / HACDBG_NPT_FIXED_CHUNK_PAGES + \
     (HACDBG_NPT_SPLIT_PAGES + HACDBG_NPT_SPLIT_CHUNK_PAGES - 1ull) / HACDBG_NPT_SPLIT_CHUNK_PAGES)

#define NPT_PRESENT                 (1ull << 0)
#define NPT_WRITE                   (1ull << 1)
#define NPT_USER                    (1ull << 2)
#define NPT_LARGE                   (1ull << 7)
#define NPT_NX                      (1ull << 63)
#define NPT_ADDRESS_MASK            0x000FFFFFFFFFF000ull
#define NPT_LARGE_2MB_MASK          0x000FFFFFFFE00000ull

typedef struct _NPT_HOOK
{
    volatile UINT64 TargetPage;
    UINT64 ShadowPage;
    volatile BOOLEAN Active;
    UINT8 Reserved[7];
} NPT_HOOK;

typedef struct _NPT_HIDDEN_PAGE
{
    UINT64 Page;
    BOOLEAN Active;
    UINT8 Reserved[7];
} NPT_HIDDEN_PAGE;

static PVOID g_PageVirtual[HACDBG_NPT_POOL_PAGES];
static UINT64 g_PagePhysical[HACDBG_NPT_POOL_PAGES];
static PVOID g_ChunkAllocations[HACDBG_NPT_MAX_CHUNKS];
static UINT64 g_ChunkCount;
static UINT64 g_FixedPagesUsed;
static UINT64 g_FixedPagesCarved;
static UINT64 g_SplitPagesUsed;
static UINT64 g_SplitPagesCarved;
static UINT64 g_MainRootPa;
static UINT64 g_HookRootPa;
static UINT64 g_DummyPagePa;
static NPT_HOOK g_Hooks[HACDBG_NPT_MAX_HOOKS];
static NPT_HIDDEN_PAGE g_HiddenPages[HACDBG_NPT_MAX_HIDDEN];
static HACDBG_SPIN_LOCK g_NptLock;
static BOOLEAN g_Initialized;

static BOOLEAN
NptFindHidden(
    _In_ UINT64 Page
    );

// 按页块从非分页池切出 NPT 表，块首强制 4 KiB 对齐。
static BOOLEAN
NptCarveChunk(
    _In_ UINT64 SlotStart,
    _In_ UINT64 PageCount
    )
{
    PVOID allocation;
    PVOID aligned;
    SIZE_T bytes;
    PHYSICAL_ADDRESS physical;
    UINT64 index;

    if (PageCount == 0 || SlotStart + PageCount > HACDBG_NPT_POOL_PAGES ||
        g_ChunkCount >= HACDBG_NPT_MAX_CHUNKS)
    {
        return FALSE;
    }

    //
    // The extra page guarantees that a page-aligned base can be carved from
    // the allocation even when the pool block itself is not page-aligned.
    //
    bytes = (SIZE_T)(PageCount * PAGE_SIZE) + PAGE_SIZE;
    allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, HACDBG_NPT_TAG);
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
        g_PagePhysical[SlotStart + index] = (UINT64)physical.QuadPart & NPT_ADDRESS_MASK;
    }

    return TRUE;
}

// 分配一张固定表页（PML4/PDPT/PD）。
_Success_(return != NULL)
static VOID*
NptAllocatePage(
    _Out_ UINT64* PhysicalAddress
    )
{
    UINT64 index;
    UINT64 pageCount;

    *PhysicalAddress = 0;

    if (g_FixedPagesUsed >= HACDBG_NPT_FIXED_PAGES)
    {
        return NULL;
    }

    if (g_FixedPagesUsed >= g_FixedPagesCarved)
    {
        pageCount = min(HACDBG_NPT_FIXED_CHUNK_PAGES,
                        HACDBG_NPT_FIXED_PAGES - g_FixedPagesCarved);
        if (NptCarveChunk(g_FixedPagesCarved, pageCount) == FALSE)
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

// 从加载时切好的拆分页池取一页。
_Success_(return != NULL)
static VOID*
NptAllocateSplitPage(
    _Out_ UINT64* PhysicalAddress
    )
{
    UINT64 index;

    *PhysicalAddress = 0;

    if (g_SplitPagesUsed >= g_SplitPagesCarved)
    {
        return NULL;
    }

    index = HACDBG_NPT_FIXED_PAGES + g_SplitPagesUsed;
    *PhysicalAddress = g_PagePhysical[index];
    g_SplitPagesUsed++;
    return g_PageVirtual[index];
}

//
// 钩子安装发生在 CPUID 退出里，不能再调用池分配。拆分页在进入客户前切完。
//
static BOOLEAN
NptPreallocateSplitPages(
    VOID
    )
{
    while (g_SplitPagesCarved < HACDBG_NPT_SPLIT_PAGES)
    {
        UINT64 pageCount = min(HACDBG_NPT_SPLIT_CHUNK_PAGES,
                               HACDBG_NPT_SPLIT_PAGES - g_SplitPagesCarved);
        UINT64 slotStart = HACDBG_NPT_FIXED_PAGES + g_SplitPagesCarved;

        if (NptCarveChunk(slotStart, pageCount) == FALSE)
        {
            return FALSE;
        }

        g_SplitPagesCarved += pageCount;
    }

    return TRUE;
}

// 物理地址查回宿主虚拟地址，只扫描已切出的页。
static UINT64*
NptVirtualFromPhysical(
    _In_ UINT64 PhysicalAddress
    )
{
    UINT64 index;

    for (index = 0; index < g_FixedPagesCarved; index++)
    {
        if (g_PagePhysical[index] == (PhysicalAddress & NPT_ADDRESS_MASK))
        {
            return (UINT64*)g_PageVirtual[index];
        }
    }

    for (index = 0; index < g_SplitPagesCarved; index++)
    {
        UINT64 slot = HACDBG_NPT_FIXED_PAGES + index;

        if (g_PagePhysical[slot] == (PhysicalAddress & NPT_ADDRESS_MASK))
        {
            return (UINT64*)g_PageVirtual[slot];
        }
    }

    return NULL;
}

// 从 NPT 表项取出下一级表页。
static UINT64*
NptPageFromEntry(
    _In_ UINT64 Entry
    )
{
    if ((Entry & NPT_PRESENT) == 0)
    {
        return NULL;
    }

    UINT64 physical = Entry & NPT_ADDRESS_MASK;
    return NptVirtualFromPhysical(physical);
}

// 取得客户页对应的 PTE；遇到 2 MiB 大页时临时拆成 4 KiB 表。
static UINT64*
NptPte(
    _In_ UINT64 RootPa,
    _In_ UINT64 GuestPage,
    _In_ BOOLEAN HookRoot
    )
{
    UINT64* pml4 = NptVirtualFromPhysical(RootPa & NPT_ADDRESS_MASK);
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

    pdpt = NptPageFromEntry(pml4[(GuestPage >> 39) & 0x1ffull]);
    if (pdpt == NULL)
    {
        return NULL;
    }

    pd = NptPageFromEntry(pdpt[(GuestPage >> 30) & 0x1ffull]);
    if (pd == NULL)
    {
        return NULL;
    }

    pde = &pd[(GuestPage >> 21) & 0x1ffull];
    pdeValue = *pde;

    if ((pdeValue & NPT_LARGE) == 0)
    {
        pt = NptPageFromEntry(pdeValue);
        return pt == NULL ? NULL : &pt[(GuestPage >> PAGE_SHIFT) & 0x1ffull];
    }

    pt = (UINT64*)NptAllocateSplitPage(&splitPa);
    if (pt == NULL)
    {
        return NULL;
    }

    base = pdeValue & NPT_LARGE_2MB_MASK;

    for (i = 0; i < 512; i++)
    {
        UINT64 page = base + (i * PAGE_SIZE);
        UINT64 flags = NPT_PRESENT | NPT_WRITE | NPT_USER;

        if (HookRoot != FALSE || (pdeValue & NPT_NX) != 0)
        {
            flags |= NPT_NX;
        }

        if (NptFindHidden(page) != FALSE)
        {
            page = g_DummyPagePa;
        }

        pt[i] = page | flags;
    }

    *pde = (splitPa & NPT_ADDRESS_MASK) | NPT_PRESENT | NPT_WRITE | NPT_USER;
    KeMemoryBarrier();
    return &pt[(GuestPage >> PAGE_SHIFT) & 0x1ffull];
}

// 查找已注册的执行钩子。
static BOOLEAN
NptFindHook(
    _In_ UINT64 TargetPage,
    _Out_opt_ UINT32* IndexOut
    )
{
    UINT32 index;

    for (index = 0; index < HACDBG_NPT_MAX_HOOKS; index++)
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

BOOLEAN
NptContainsShadowPage(
    _In_ UINT64 PhysicalPage
    )
{
    UINT64 page = PhysicalPage & NPT_ADDRESS_MASK;
    UINT32 index;
    BOOLEAN found = FALSE;

    HacDbgSpinLockAcquire(&g_NptLock);

    for (index = 0; index < HACDBG_NPT_MAX_HOOKS; index++)
    {
        if (g_Hooks[index].Active != FALSE && g_Hooks[index].ShadowPage == page)
        {
            found = TRUE;
            break;
        }
    }

    HacDbgSpinLockRelease(&g_NptLock);
    return found;
}

// 查找已隐藏的客户物理页。
static BOOLEAN
NptFindHidden(
    _In_ UINT64 Page
    )
{
    UINT32 index;

    for (index = 0; index < HACDBG_NPT_MAX_HIDDEN; index++)
    {
        if (g_HiddenPages[index].Active != FALSE && g_HiddenPages[index].Page == Page)
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
NptContainsHookTarget(
    _In_ UINT64 PhysicalPage
    )
{
    BOOLEAN found;

    HacDbgSpinLockAcquire(&g_NptLock);
    found = NptFindHook(PhysicalPage & NPT_ADDRESS_MASK, NULL);
    HacDbgSpinLockRelease(&g_NptLock);
    return found;
}

BOOLEAN
NptContainsHiddenPage(
    _In_ UINT64 PhysicalPage
    )
{
    BOOLEAN found;

    HacDbgSpinLockAcquire(&g_NptLock);
    found = NptFindHidden(PhysicalPage & NPT_ADDRESS_MASK);
    HacDbgSpinLockRelease(&g_NptLock);
    return found;
}

//
// Clears NX for one guest page in the hook map. A shadow page or a hidden
// page is left unchanged. The caller holds g_NptLock. A 2 MiB leaf is split.
//
static BOOLEAN
NptGrantHookExecute(
    _In_ UINT64 Page
    )
{
    UINT64* pte;

    Page &= NPT_ADDRESS_MASK;

    if (NptFindHook(Page, NULL) != FALSE || NptFindHidden(Page) != FALSE)
    {
        return FALSE;
    }

    pte = NptPte(g_HookRootPa, Page, TRUE);
    if (pte == NULL)
    {
        return FALSE;
    }

    if ((*pte & NPT_NX) == 0)
    {
        return TRUE;
    }

    *pte &= ~NPT_NX;
    KeMemoryBarrier();
    return TRUE;
}

// 让钩子页数值上相邻的两页在钩子表中保持可执行。大页里这就是虚拟邻页。
static VOID
NptSetAdjacentExecutable(
    _In_ UINT64 TargetPage
    )
{
    if (TargetPage >= PAGE_SIZE)
    {
        NptGrantHookExecute(TargetPage - PAGE_SIZE);
    }

    NptGrantHookExecute(TargetPage + PAGE_SIZE);
}

// 客户 RIP 所在的 4 KiB 客户物理页。翻译失败时返回全 1。
static UINT64
NptGuestRipPage(
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRip
    )
{
    GUEST_PHYSICAL_ADDRESS physical = { 0 };

    if (GuestVirtualToPhysical(GuestCr3, HacDbgGuestVirtualAddress(GuestRip), &physical, NULL) == FALSE)
    {
        return ~0ull;
    }

    return physical.Value & NPT_ADDRESS_MASK;
}

// 建立主 NPT 和钩子 NPT，覆盖前 1 TiB 客户物理地址。
NTSTATUS
NptInitialize(
    VOID
    )
{
    UINT64 mainPml4Pa;
    UINT64 hookPml4Pa;
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
    HacDbgSpinLockInitialize(&g_NptLock);

    mainPml4 = NptAllocatePage(&mainPml4Pa);
    hookPml4 = NptAllocatePage(&hookPml4Pa);
    g_DummyPagePa = 0;

    if (mainPml4 == NULL || hookPml4 == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (root = 0; root < 2; root++)
    {
        UINT64 rootPa = root == 0 ? mainPml4Pa : hookPml4Pa;
        UINT64* pml4 = root == 0 ? mainPml4 : hookPml4;
        BOOLEAN hookRoot = root == 1;

        for (pml4Index = 0; pml4Index < 2; pml4Index++)
        {
            UINT64 pdptPa;
            UINT64* pdpt = NptAllocatePage(&pdptPa);

            if (pdpt == NULL)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            pml4[pml4Index] = (pdptPa & NPT_ADDRESS_MASK) | NPT_PRESENT | NPT_WRITE | NPT_USER;

            for (pdptIndex = 0; pdptIndex < 512; pdptIndex++)
            {
                UINT64 pdPa;
                UINT64* pd = NptAllocatePage(&pdPa);

                if (pd == NULL)
                {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                pdpt[pdptIndex] = (pdPa & NPT_ADDRESS_MASK) | NPT_PRESENT | NPT_WRITE | NPT_USER;

                for (pdIndex = 0; pdIndex < 512; pdIndex++)
                {
                    UINT64 guestAddress = (((pml4Index * 512) + pdptIndex) * 512 + pdIndex) * (2ull * 1024ull * 1024ull);
                    UINT64 flags = NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_LARGE;

                    if (hookRoot != FALSE)
                    {
                        flags |= NPT_NX;
                    }

                    pd[pdIndex] = guestAddress | flags;
                }
            }
        }

        if (rootPa == 0)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    g_MainRootPa = mainPml4Pa;
    g_HookRootPa = hookPml4Pa;

    g_DummyPagePa = 0;
    {
        UINT64 dummyPa;
        PVOID dummy = NptAllocatePage(&dummyPa);
        if (dummy == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_DummyPagePa = dummyPa;
    }

    if (NptPreallocateSplitPages() == FALSE)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Initialized = TRUE;
    return STATUS_SUCCESS;
}

// 释放所有 NPT 表和拆分页块。
VOID
NptCleanup(
    VOID
    )
{
    UINT64 index;

    for (index = 0; index < g_ChunkCount; index++)
    {
        ExFreePoolWithTag(g_ChunkAllocations[index], HACDBG_NPT_TAG);
    }

    RtlZeroMemory(g_PageVirtual, sizeof(g_PageVirtual));
    RtlZeroMemory(g_PagePhysical, sizeof(g_PagePhysical));
    RtlZeroMemory(g_ChunkAllocations, sizeof(g_ChunkAllocations));
    g_ChunkCount = 0;
    g_FixedPagesUsed = 0;
    g_FixedPagesCarved = 0;
    g_SplitPagesUsed = 0;
    g_SplitPagesCarved = 0;
    g_MainRootPa = 0;
    g_HookRootPa = 0;
    g_DummyPagePa = 0;
    g_Initialized = FALSE;
}

// 返回主 NPT 根物理地址。
UINT64
NptMainRootPa(
    VOID
    )
{
    return g_MainRootPa;
}

// 返回固定表和拆分页的剩余页数。
UINT32
NptFreeTableCount(
    VOID
    )
{
    return (UINT32)((HACDBG_NPT_FIXED_PAGES - g_FixedPagesUsed) +
                    (HACDBG_NPT_SPLIT_PAGES - g_SplitPagesUsed));
}

// 在主表中禁止目标页执行，在钩子表中把该页指向影子页。
BOOLEAN
NptAddHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage,
    _In_ GUEST_PHYSICAL_ADDRESS ShadowPage
    )
{
    UINT64 target = TargetPage.Value & NPT_ADDRESS_MASK;
    UINT64 shadow = ShadowPage.Value & NPT_ADDRESS_MASK;
    UINT64* mainPte;
    UINT64* hookPte;
    UINT32 index;

    if (g_Initialized == FALSE || (TargetPage.Value & (PAGE_SIZE - 1)) != 0 ||
        (ShadowPage.Value & (PAGE_SIZE - 1)) != 0)
    {
        HACDBG_LOG("HacDbg: Err, NPT hook rejected initialized=%u target=0x%I64x shadow=0x%I64x.\n",
                 g_Initialized, TargetPage.Value, ShadowPage.Value);
        return FALSE;
    }

    HacDbgSpinLockAcquire(&g_NptLock);

    if (NptFindHook(target, NULL) != FALSE)
    {
        HACDBG_LOG("HacDbg: Err, NPT hook already exists for page 0x%I64x.\n", target);
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    for (index = 0; index < HACDBG_NPT_MAX_HOOKS; index++)
    {
        if (g_Hooks[index].Active == FALSE)
        {
            break;
        }
    }

    if (index == HACDBG_NPT_MAX_HOOKS)
    {
        HACDBG_LOG("HacDbg: Err, NPT hook table is full.\n");
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    mainPte = NptPte(g_MainRootPa, target, FALSE);
    hookPte = NptPte(g_HookRootPa, target, TRUE);

    if (mainPte == NULL || hookPte == NULL)
    {
        HACDBG_LOG("HacDbg: Err, NPT hook PTE lookup failed target=0x%I64x main=%p hook=%p.\n",
                 target, mainPte, hookPte);
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    g_Hooks[index].TargetPage = target;
    g_Hooks[index].ShadowPage = shadow;
    g_Hooks[index].Active = FALSE;

    *hookPte = (shadow & NPT_ADDRESS_MASK) | NPT_PRESENT | NPT_WRITE | NPT_USER;
    NptSetAdjacentExecutable(target);
    KeMemoryBarrier();
    g_Hooks[index].Active = TRUE;
    KeMemoryBarrier();
    *mainPte |= NPT_NX;
    HacDbgSpinLockRelease(&g_NptLock);

    return TRUE;
}

// 撤销执行钩子，恢复主表可执行属性。
BOOLEAN
NptRemoveHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    )
{
    UINT64 target = TargetPage.Value & NPT_ADDRESS_MASK;
    UINT64* mainPte;
    UINT64* hookPte;
    UINT32 index;

    HacDbgSpinLockAcquire(&g_NptLock);

    if ((TargetPage.Value & (PAGE_SIZE - 1)) != 0 ||
        NptFindHook(target, &index) == FALSE)
    {
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    mainPte = NptPte(g_MainRootPa, target, FALSE);
    hookPte = NptPte(g_HookRootPa, target, TRUE);

    if (mainPte == NULL || hookPte == NULL)
    {
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    *mainPte &= ~NPT_NX;
    KeMemoryBarrier();
    g_Hooks[index].Active = FALSE;
    KeMemoryBarrier();

    if (NptFindHidden(target) != FALSE)
    {
        *hookPte = g_DummyPagePa | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_NX;
    }
    else
    {
        *hookPte = target | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_NX;
    }

    //
    // Adjacent pages stay executable in the hook table. Re-clearing them can
    // break an instruction that straddles a page still owned by another hook;
    // an extra executable identity page only delays the return to the main
    // table until the next non-hook page executes.
    //
    KeMemoryBarrier();
    HacDbgSpinLockRelease(&g_NptLock);

    return TRUE;
}

// 把目标页在主表和钩子表中替换成零页。
BOOLEAN
NptHidePage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    )
{
    UINT64 target = TargetPage.Value & NPT_ADDRESS_MASK;
    UINT64* mainPte;
    UINT64* hookPte;
    UINT32 index;

    if (g_Initialized == FALSE || (TargetPage.Value & (PAGE_SIZE - 1)) != 0)
    {
        HACDBG_LOG("HacDbg: Err, NPT hide rejected initialized=%u page=0x%I64x.\n",
                 g_Initialized, TargetPage.Value);
        return FALSE;
    }

    HacDbgSpinLockAcquire(&g_NptLock);

    if (NptFindHidden(target) != FALSE)
    {
        HACDBG_LOG("HacDbg: Err, NPT page 0x%I64x is already hidden.\n", target);
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    for (index = 0; index < HACDBG_NPT_MAX_HIDDEN; index++)
    {
        if (g_HiddenPages[index].Active == FALSE)
        {
            break;
        }
    }

    if (index == HACDBG_NPT_MAX_HIDDEN)
    {
        HACDBG_LOG("HacDbg: Err, NPT hidden page table is full.\n");
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    mainPte = NptPte(g_MainRootPa, target, FALSE);
    hookPte = NptPte(g_HookRootPa, target, TRUE);

    if (mainPte == NULL || hookPte == NULL)
    {
        HACDBG_LOG("HacDbg: Err, NPT hide PTE lookup failed page=0x%I64x main=%p hook=%p.\n",
                 target, mainPte, hookPte);
        HacDbgSpinLockRelease(&g_NptLock);
        return FALSE;
    }

    g_HiddenPages[index].Page = target;
    g_HiddenPages[index].Active = TRUE;

    if (NptFindHook(target, NULL) != FALSE)
    {
        *mainPte = g_DummyPagePa | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_NX;
    }
    else
    {
        *mainPte = g_DummyPagePa | NPT_PRESENT | NPT_WRITE | NPT_USER;
        *hookPte = g_DummyPagePa | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_NX;
    }

    KeMemoryBarrier();
    HacDbgSpinLockRelease(&g_NptLock);

    return TRUE;
}

// 执行型 NPF 时在两张 NPT 根之间切换。
BOOLEAN
NptHandleNestedPageFault(
    _Inout_ VMCB* Vmcb
    )
{
    UINT64 exitInfo = Vmcb->ControlArea.ExitInfo1;
    UINT64 physical = Vmcb->ControlArea.ExitInfo2;
    UINT64 page = physical & NPT_ADDRESS_MASK;
    UINT64 currentRoot = Vmcb->ControlArea.NCr3 & NPT_ADDRESS_MASK;
    UINT64 ripPage;
    BOOLEAN hooked;
    BOOLEAN granted;

    //
    // ExitInfo1 bit 0 is page present. Bit 4 is an instruction fetch.
    //
    if ((exitInfo & (1ull << 4)) == 0 || (exitInfo & 1ull) == 0)
    {
        return FALSE;
    }

    hooked = NptFindHook(page, NULL);

    //
    // An instruction is at most 15 bytes, so only a RIP in the last 14 bytes
    // of its page can touch the next page. Other fetches keep the fast path.
    //
    if ((Vmcb->StateSaveArea.Rip & (PAGE_SIZE - 1)) > (PAGE_SIZE - 15))
    {
        ripPage = NptGuestRipPage(Vmcb->StateSaveArea.Cr3, Vmcb->StateSaveArea.Rip);
    }
    else
    {
        ripPage = page;
    }

    //
    // The fetched instruction can cross two virtually adjacent pages whose
    // guest physical addresses are not numerically adjacent. User images are
    // mapped as 4 KiB pages, so GPA±4 KiB is the wrong neighbor. Leaving each
    // half executable in a different NPT root makes the fetch bounce forever.
    //
    if (hooked != FALSE)
    {
        if (currentRoot != (g_HookRootPa & NPT_ADDRESS_MASK))
        {
            Vmcb->ControlArea.NCr3 = g_HookRootPa;
            Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
            Vmcb->ControlArea.VmcbClean &= ~(1ull << 4);
        }

        if (ripPage != ~0ull && ripPage != page)
        {
            HacDbgSpinLockAcquire(&g_NptLock);
            granted = NptGrantHookExecute(ripPage);
            HacDbgSpinLockRelease(&g_NptLock);
            if (granted == FALSE)
            {
                return FALSE;
            }

            SvmFlushAllProcessors();
        }

        return TRUE;
    }

    if (currentRoot == (g_HookRootPa & NPT_ADDRESS_MASK))
    {
        if (ripPage != ~0ull && ripPage != page && NptFindHook(ripPage, NULL) != FALSE)
        {
            HacDbgSpinLockAcquire(&g_NptLock);
            granted = NptGrantHookExecute(page);
            HacDbgSpinLockRelease(&g_NptLock);
            if (granted == FALSE)
            {
                return FALSE;
            }

            SvmFlushAllProcessors();
            return TRUE;
        }

        Vmcb->ControlArea.NCr3 = g_MainRootPa;
        Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        Vmcb->ControlArea.VmcbClean &= ~(1ull << 4);
        return TRUE;
    }

    return FALSE;
}
