/**
 * @file Npt.h
 * @brief Nested page table interfaces.
 *
 * @author HacDbg
 */

#pragma once

#include "Svm.h"

NTSTATUS
/**
 * @brief Builds the identity NPT roots and their split-page pool.
 *
 * @return STATUS_SUCCESS on success; otherwise an NTSTATUS error.
 */
NptInitialize(
    VOID
    );

VOID
/**
 * @brief Releases the NPT table pool.
 */
NptCleanup(
    VOID
    );

UINT64
/**
 * @brief Returns the physical address of the primary NPT root.
 */
NptMainRootPa(
    VOID
    );

UINT32
/**
 * @brief Returns the number of unused 4 KiB NPT table pages.
 */
NptFreeTableCount(
    VOID
    );

BOOLEAN
/**
 * @brief Maps an executable shadow page into the hook NPT.
 *
 * @param TargetPage Guest physical page whose execution is intercepted.
 * @param ShadowPage Guest physical page containing the replacement code.
 *
 * @return TRUE on success; otherwise FALSE.
 */
NptAddHook(
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
NptRefreshHookCopies(
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
NptContainsShadowPage(
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
NptContainsHookTarget(
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
NptContainsHiddenPage(
    _In_ UINT64 PhysicalPage
    );

BOOLEAN
/**
 * @brief Removes one execute hook and restores the page permissions.
 *
 * @param TargetPage Guest physical page previously passed to NptAddHook.
 *
 * @return TRUE on success; otherwise FALSE.
 */
NptRemoveHook(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
/**
 * @brief Replaces a guest physical page with the zero dummy page in NPT.
 *
 * @param TargetPage Guest physical page to hide.
 *
 * @return TRUE on success; otherwise FALSE.
 */
NptHidePage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
/**
 * @brief Restores a page hidden by NptHidePage to its identity translation.
 *
 * @param TargetPage Guest physical page previously passed to NptHidePage.
 *
 * @return TRUE on success; otherwise FALSE.
 *
 * @details A page that is also an execute-hook target keeps the hook map.
 * Only the main-root leaf is restored, still with the no-execute bit.
 */
NptUnhidePage(
    _In_ GUEST_PHYSICAL_ADDRESS TargetPage
    );

BOOLEAN
/**
 * @brief Points one guest page at a payload frame in the private NPT root.
 *
 * @param DecoyPage Guest physical page installed in the guest page tables.
 * @param PayloadPage Host frame that contains the bytes the inject thread reads.
 * @param Executable TRUE when the private leaf must allow instruction fetch.
 *
 * @return TRUE when the private root has its own leaf for DecoyPage.
 *
 * @details The main root keeps the identity translation of DecoyPage.
 */
NptMapPrivate(
    _In_ GUEST_PHYSICAL_ADDRESS DecoyPage,
    _In_ GUEST_PHYSICAL_ADDRESS PayloadPage,
    _In_ BOOLEAN Executable
    );

BOOLEAN
/**
 * @brief Makes subsequent VM-exits install the private root as the data root.
 *
 * @param Enable TRUE publishes the private root. FALSE returns to the main root.
 *
 * @return FALSE when Enable is TRUE and no private root has been built.
 */
NptUsePrivateRoot(
    _In_ BOOLEAN Enable
    );

VOID
/**
 * @brief Forgets a private root that was never installed.
 */
NptDropPrivate(
    VOID
    );

VOID
/**
 * @brief Remembers whether this logical processor's current thread uses the private root.
 *
 * @param Cpu KeGetCurrentProcessorNumber value.
 * @param UsePrivate TRUE selects the private root for later data-root reads.
 */
NptNoteCpuPrivate(
    _In_ UINT32 Cpu,
    _In_ BOOLEAN UsePrivate
    );

UINT64
/**
 * @brief Returns the nCR3 a processor should use for data access.
 */
NptDataRootPa(
    VOID
    );

UINT32
/**
 * @brief Returns the ASID that belongs to NptDataRootPa.
 */
NptDataAsid(
    VOID
    );

BOOLEAN
/**
 * @brief Reports the data nCR3 to install when the processor is not on the hook root.
 *
 * @param CurrentRoot nCR3 currently in the VMCB.
 * @param NextRoot Receives the data nCR3 when this function returns TRUE.
 * @param NextAsid Receives the ASID for NextRoot.
 *
 * @return TRUE when CurrentRoot should be replaced.
 */
NptInstallDataRoot(
    _In_ UINT64 CurrentRoot,
    _Out_ UINT64* NextRoot,
    _Out_ UINT32* NextAsid
    );

BOOLEAN
/**
 * @brief Handles an execute-only nested page fault by selecting an NPT root.
 *
 * @details An instruction that crosses into a guest page which is not
 * numerically adjacent to the hooked page is made executable in the hook map.
 * Other processors are asked to flush the guest TLB when that entry changes.
 *
 * @param Vmcb Current processor VMCB.
 *
 * @return TRUE when the fault was handled; otherwise FALSE.
 */
NptHandleNestedPageFault(
    _Inout_ VMCB* Vmcb
    );
