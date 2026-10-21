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
 * @brief Selects the EPT root for an execute violation.
 *
 * @param Qualification VM-exit qualification for the EPT violation.
 * @param GuestPhysical Faulting guest-physical address.
 * @param CurrentEptp EPTP installed in the current VMCS.
 * @param NextEptp Receives the EPTP to install when this function returns TRUE.
 *
 * @return TRUE when the violation was handled; otherwise FALSE.
 */
EptHandleViolation(
    _In_ UINT64 Qualification,
    _In_ UINT64 GuestPhysical,
    _In_ UINT64 CurrentEptp,
    _Out_ UINT64* NextEptp
    );
