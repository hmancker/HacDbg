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
