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

VOID
/**
 * @brief Records a kernel page-table root for later read_guest_cr3 calls.
 *
 * @param Cr3 Guest CR3 observed while the guest was in kernel mode, or the
 * CR3 of the processor about to enter the guest from kernel context.
 *
 * @details A KPTI user directory is ignored. CPL 0 can still be using that
 * directory for the few instructions around the CR3 switch, and adopting it
 * makes later kernel reads fail.
 */
HypercallNoteKernelCr3(
    _In_ UINT64 Cr3
    );

