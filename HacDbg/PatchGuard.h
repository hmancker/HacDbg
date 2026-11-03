/**
 * @file PatchGuard.h
 * @brief Runtime Kernel Patch Protection disable.
 *
 * @author HacDbg
 */

#pragma once

#include <ntddk.h>

NTSTATUS
/**
 * @brief Stops runtime Kernel Patch Protection checks.
 *
 * @details Scheduled timer callbacks are rewritten as an encrypted null.
 * System threads whose start address is outside every loaded module are
 * retired. Call this before the first VMRUN or VMLAUNCH.
 *
 * @return STATUS_SUCCESS if every required step succeeded.
 *
 * @warning A missing pattern leaves PatchGuard running. DriverEntry must
 * then fail the load.
 */
PatchGuardDisable(
    VOID
    );

NTSTATUS
/**
 * @brief Makes KeBugCheckEx ignore CRITICAL_STRUCTURE_CORRUPTION.
 *
 * @details Call this only after every logical processor has entered the
 * guest, and before registering a callback that is outside the loader
 * list. Reads of the ntoskrnl page still see the original bytes. An
 * instruction fetch of KeBugCheckEx continues the original function
 * unless the bugcheck code is 0x109. On 19041 the failure path clears
 * CR0.WP, copies memory, and takes bit locks before it calls
 * SdbpCheckDll. The near jump that skips that path is made
 * unconditional, so the function's own success continuation runs. Other
 * builds drop CR8 to PASSIVE_LEVEL at mov ecx, 109h, then jump to the
 * epilogue. A 0x109 that still reaches KeBugCheckEx never returns to
 * the caller. It switches to a
 * per-processor stack, drops CR8 to PASSIVE_LEVEL, and clears both
 * ActiveDpc and DpcRoutineActive. A system thread that is not an
 * executive worker, and was not interrupted by a DPC, is ended. Any
 * other non-idle thread waits on an event that is never signaled, so
 * this processor returns to the dispatcher. The idle thread waits in
 * HLT with interrupts enabled. The same execute view turns
 * CcBcbProfiler and KiTimerDispatch into a return.
 *
 * @return STATUS_SUCCESS if every required hook is installed.
 */
PatchGuardArmBugcheckHook(
    VOID
    );

VOID
/**
 * @brief Frees the execute-hook pages allocated for PatchGuard.
 *
 * @details Safe to call when no hook was installed. Call it only after
 * every logical processor has left the guest.
 */
PatchGuardCleanup(
    VOID
    );
