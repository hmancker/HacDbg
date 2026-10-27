/**
 * @file Logs.h
 * @brief Trap frame log interfaces.
 *
 * @author HacDbg
 */

#pragma once

#include "Types.h"
#include "../shared/hypercall/hypercall_def.h"
#include "../shared/structures/trap_frame.h"

NTSTATUS
/**
 * @brief Allocates the nonpaged log ring.
 *
 * @return STATUS_SUCCESS on success; otherwise an NTSTATUS error.
 */
LogsInitialize(
    VOID
    );

VOID
/**
 * @brief Releases the log ring.
 */
LogsCleanup(
    VOID
    );

VOID
/**
 * @brief Appends one trap frame log.
 *
 * @param Log Log record to copy.
 */
LogsAdd(
    _In_ const trap_frame_log_t* Log
    );

UINT64
/**
 * @brief Copies pending logs into a guest virtual buffer and clears them.
 *
 * @param DestinationCr3 Guest page table root for Destination.
 * @param Destination Guest virtual destination.
 * @param MaximumCount Maximum records the caller can receive.
 *
 * @return Number of records copied, or -1 when the copy fails.
 */
LogsFlush(
    _In_ UINT64 DestinationCr3,
    _In_ GUEST_VIRTUAL_ADDRESS Destination,
    _In_ UINT64 MaximumCount
    );

UINT64
/**
 * @brief Registers the debugger page that receives the log sequence.
 *
 * @param Cr3 Page table root of the registering CPUID. Under KPTI this is
 * the debugger's user directory.
 * @param VirtualAddress Guest virtual address of one HACDBG_LOG_NOTIFY.
 * The structure must be 8-byte aligned and must not cross a page.
 *
 * @return 1 when the page is accepted; otherwise 0.
 */
LogsRegisterNotify(
    _In_ UINT64 Cr3,
    _In_ UINT64 VirtualAddress
    );

UINT64
/**
 * @brief Drops the log notify registration.
 *
 * @return 1.
 */
LogsUnregisterNotify(
    VOID
    );
