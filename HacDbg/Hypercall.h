/**
 * @file Hypercall.h
 * @brief CPUID hypercall entry points.
 *
 * @author HacDbg
 */

#pragma once

#include "Config.h"
#include "Guest.h"
#include "../shared/hypercall/control.h"

VOID
/**
 * @brief Initializes the hypercall synchronization state.
 */
HypercallInitialize(
    VOID
    );

VOID
/**
 * @brief Handles a CPUID VMEXIT, including HacDbg hypercalls.
 *
 * @param View Guest registers, CR3, and RIP. The caller advances RIP.
 */
HypercallHandleCpuid(
    _Inout_ HACDBG_GUEST_VIEW* View
    );

NTSTATUS
/**
 * @brief Executes one hypercall request received through the control device.
 *
 * @param Request Call description and result storage.
 *
 * @return STATUS_SUCCESS when the request was dispatched; otherwise an
 * NTSTATUS error.
 */
HypercallHandleIoctl(
    _Inout_ HACDBG_HYPERCALL_REQUEST* Request
    );

