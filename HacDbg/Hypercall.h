/**
 * @file Hypercall.h
 * @brief CPUID hypercall entry points.
 *
 * @author HacDbg
 */

#pragma once

#include "Svm.h"
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
 * @param GuestContext Current guest context.
 */
HypercallHandleCpuid(
    _Inout_ SVM_GUEST_CONTEXT* GuestContext
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

