/**
 * @file Ept.h
 * @brief Extended page table interfaces.
 *
 * @author HacDbg
 */

#pragma once

#include "Types.h"

NTSTATUS
/**
 * @brief Builds the identity EPT roots. Leaf memory types come from the MTRRs.
 *
 * @return STATUS_SUCCESS on success; otherwise an NTSTATUS error.
 */
EptInitialize(
    VOID
    );

VOID
/**
 * @brief Releases the EPT table pool.
 */
EptCleanup(
    VOID
    );

UINT64
/**
 * @brief Returns the EPTP value of the primary identity map.
 */
EptMainEptp(
    VOID
    );

UINT64
/**
 * @brief Returns the EPTP value of the execute-hook map.
 */
EptHookEptp(
    VOID
    );

BOOLEAN
/**
 * @brief Reports whether EPT roots were built.
 */
EptIsEnabled(
    VOID
    );

UINT32
/**
 * @brief Returns the number of unused 4 KiB EPT table pages.
 */
EptFreeTableCount(
    VOID
    );

BOOLEAN
/**
 * @brief Maps an executable shadow page into the hook EPT.
 *
 * @param TargetPage Guest physical page whose execution is intercepted.
 * @param ShadowPage Guest physical page containing the replacement code.
 *
 * @return TRUE on success; otherwise FALSE.
 */
EptAddHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage,
    _In_ GUEST_PHYSICAL_ADDRESS ShadowPage
    );

VOID
/**
 * @brief Copies active hook sources into their nonpaged execute pages.
 *
 * @details Called before a SLAT flush. A failed source read leaves the
 * previous execute page in place.
 */
EptRefreshHookCopies(
    VOID
    );

BOOLEAN
/**
 * @brief Reports whether a physical page is an active execute-hook shadow.
 *
 * @param PhysicalPage Page-aligned host physical address.
 *
 * @return TRUE when an active hook maps this page as its shadow.
 */
EptContainsShadowPage(
    _In_ UINT64 PhysicalPage
    );

BOOLEAN
/**
 * @brief Reports whether a physical page is an active execute-hook target.
 *
 * @param PhysicalPage Page-aligned host physical address.
 *
 * @return TRUE when an active hook intercepts execution of this page.
 */
EptContainsHookTarget(
    _In_ UINT64 PhysicalPage
    );

BOOLEAN
/**
 * @brief Reports whether a physical page is replaced by the zero dummy page.
 *
 * @param PhysicalPage Page-aligned host physical address.
 *
 * @return TRUE when the page is an active hidden page.
 */
EptContainsHiddenPage(
    _In_ UINT64 PhysicalPage
    );

BOOLEAN
/**
 * @brief Removes one execute hook and restores the page permissions.
 *
 * @param TargetPage Guest physical page previously passed to EptAddHook.
 *
 * @return TRUE on success; otherwise FALSE.
 */
EptRemoveHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
/**
 * @brief Replaces a guest physical page with the zero dummy page in both EPT roots.
 *
 * @param TargetPage Guest physical page to hide.
 *
 * @return TRUE on success; otherwise FALSE.
 */
EptHidePage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
/**
 * @brief Restores a page hidden by EptHidePage to its identity translation.
 *
 * @param TargetPage Guest physical page previously passed to EptHidePage.
 *
 * @return TRUE on success; otherwise FALSE.
 *
 * @details A page that is also an execute-hook target keeps the hook map.
 * Only the main-root leaf is restored, still without execute permission.
 */
EptUnhidePage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
EptAddInjectHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage,
    _In_ GUEST_PHYSICAL_ADDRESS ShadowPage
    );

BOOLEAN
EptRemoveInjectHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
EptHideInjectPage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
EptUnhideInjectPage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
EptPatchHookCopy(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage,
    _In_ ULONG Offset,
    _In_reads_bytes_(Length) const VOID* Bytes,
    _In_ ULONG Length
    );

VOID
EptInjectSlotUsage(
    _Out_ ULONG* HookUsed,
    _Out_ ULONG* HookMax,
    _Out_ ULONG* HiddenUsed,
    _Out_ ULONG* HiddenMax
    );

BOOLEAN
/**
 * @brief Points one guest page at a payload frame in the private EPT root.
 *
 * @param DecoyPage Guest physical page installed in the guest page tables.
 * @param PayloadPage Host frame that contains the bytes the inject thread reads.
 * @param Executable TRUE when the private leaf must allow instruction fetch.
 *
 * @return TRUE when the private root has its own leaf for DecoyPage.
 *
 * @details The main root keeps the identity translation of DecoyPage. The
 * private root is not installed until EptUsePrivateRoot.
 */
EptMapPrivate(
    _In_ GUEST_PHYSICAL_ADDRESS DecoyPage,
    _In_ GUEST_PHYSICAL_ADDRESS PayloadPage,
    _In_ BOOLEAN Executable
    );

BOOLEAN
/**
 * @brief Restores one private-root leaf to the main-root identity translation.
 *
 * @param DecoyPage Guest physical page previously passed to EptMapPrivate.
 *
 * @return TRUE when that leaf no longer names a payload frame.
 *
 * @details Does not allocate and does not discard the private root. A missing
 * private override is success. FALSE means the leaf could not be rewritten.
 */
EptUnmapPrivate(
    _In_ GUEST_PHYSICAL_ADDRESS DecoyPage
    );

VOID
/**
 * @brief Counts occupied execute-hook and hidden-page slots.
 *
 * @param HookUsed Receives the number of active hooks.
 * @param HookMax Receives the hook table capacity.
 * @param HiddenUsed Receives the number of active hidden pages.
 * @param HiddenMax Receives the hidden-page capacity.
 */
EptSlotUsage(
    _Out_ ULONG* HookUsed,
    _Out_ ULONG* HookMax,
    _Out_ ULONG* HiddenUsed,
    _Out_ ULONG* HiddenMax
    );

BOOLEAN
/**
 * @brief Reports whether any logical processor is marked for the private root.
 */
EptAnyCpuPrivate(
    VOID
    );

BOOLEAN
/**
 * @brief Makes subsequent VM-exits install the private root as the data root.
 *
 * @param Enable TRUE publishes the private root. FALSE returns to the main root.
 *
 * @return FALSE when Enable is TRUE and no private root has been built.
 */
EptUsePrivateRoot(
    _In_ BOOLEAN Enable
    );

VOID
/**
 * @brief Forgets a private root that was never installed.
 *
 * @details Split pages already carved for it stay in the pool until unload.
 */
EptDropPrivate(
    VOID
    );

VOID
/**
 * @brief Remembers whether this logical processor's current thread uses the private root.
 *
 * @param Cpu KeGetCurrentProcessorNumber value.
 * @param UsePrivate TRUE selects the private root for later data-root reads.
 */
EptNoteCpuPrivate(
    _In_ UINT32 Cpu,
    _In_ BOOLEAN UsePrivate
    );

UINT64
/**
 * @brief Returns the EPTP a processor should use for data access.
 *
 * @details This is the private root while that root is published, otherwise
 * the main root. The hook root is not a data root.
 */
EptDataEptp(
    VOID
    );

UINT64
/**
 * @brief Returns the private EPTP, or zero when it has not been built.
 */
EptPrivateEptp(
    VOID
    );

BOOLEAN
/**
 * @brief Reports the data EPTP to install when the processor is not on the hook root.
 *
 * @param CurrentEptp EPTP currently in the VMCS.
 * @param NextEptp Receives the data EPTP when this function returns TRUE.
 *
 * @return TRUE when CurrentEptp should be replaced.
 */
EptInstallDataRoot(
    _In_ UINT64 CurrentEptp,
    _Out_ UINT64* NextEptp
    );

BOOLEAN
/**
 * @brief Selects the EPT root for an execute violation.
 *
 * @details When the faulting instruction crosses two guest pages that are not
 * both executable in one root, the missing half is made executable in the hook
 * map. InvalidateEpt is then TRUE and the caller must invalidate EPT.
 *
 * @param Qualification VM-exit qualification for the EPT violation.
 * @param GuestPhysical Faulting guest-physical address.
 * @param GuestCr3 Guest CR3 used to translate GuestRip.
 * @param GuestRip Guest instruction pointer at the violation.
 * @param CurrentEptp EPTP installed in the current VMCS.
 * @param NextEptp Receives the EPTP to install when this function returns TRUE.
 * @param InvalidateEpt Receives TRUE when a hook-map entry was changed.
 *
 * @return TRUE when the violation was handled; otherwise FALSE.
 */
EptHandleViolation(
    _In_ UINT64 Qualification,
    _In_ UINT64 GuestPhysical,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRip,
    _In_ UINT64 CurrentEptp,
    _Out_ UINT64* NextEptp,
    _Out_ BOOLEAN* InvalidateEpt
    );
