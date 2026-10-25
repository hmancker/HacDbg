/**
 * @file Trace.h
 * @brief Per-processor VM-exit counters and optional event rings.
 *
 * @author HacDbg
 */

#pragma once

#include "Types.h"
#include "../shared/structures/trace.h"

typedef struct _HACDBG_TRACE_CPU_STATE HACDBG_TRACE_CPU_STATE;

/**
 * @brief Allocates the fixed trace state before any processor enters a guest.
 *
 * @return STATUS_SUCCESS, or an NTSTATUS error when the CPU limit is exceeded
 * or the state cannot be allocated and hidden from the guest.
 */
NTSTATUS
TraceInitialize(
    VOID
    );

/**
 * @brief Releases the trace state after all processors have left the guest.
 */
VOID
TraceCleanup(
    VOID
    );

/**
 * @brief Stops capture without modifying the recorded counters.
 */
VOID
TraceDisable(
    VOID
    );

/**
 * @brief Returns whether counting or event capture is enabled.
 */
BOOLEAN
TraceIsEnabled(
    VOID
    );

/**
 * @brief Returns whether the event ring layer is enabled.
 */
BOOLEAN
TraceEventsEnabled(
    VOID
    );

/**
 * @brief Gets the per-processor trace state used by an exit handler.
 *
 * @param CpuIndex Zero-based active processor index.
 *
 * @return The state pointer, or NULL when trace was not initialized for this
 * index.
 */
HACDBG_TRACE_CPU_STATE*
TraceCpuState(
    _In_ UINT32 CpuIndex
    );

/**
 * @brief Records one VM exit in the current processor's counters and ring.
 *
 * @details This runs in the exit path and performs no allocation, blocking, or
 * logging. The trace_control and trace_read hypercalls are ignored so reading
 * trace does not create additional trace events.
 */
VOID
TraceRecordExit(
    _In_ HACDBG_TRACE_CPU_STATE* Cpu,
    _In_ UINT64 Tsc,
    _In_ UINT64 Rip,
    _In_ UINT64 Cr3,
    _In_ UINT32 RawReason,
    _In_ UINT64 ExitInfo1,
    _In_ UINT64 ExitInfo2,
    _In_ UINT32 Flags,
    _In_ BOOLEAN IsCpuid,
    _In_ UINT64 Rcx
    );

/**
 * @brief Applies trace_control flags and returns 1 on success, 0 on failure.
 */
UINT64
TraceControl(
    _In_ UINT64 Flags,
    _In_ UINT64 SampleRate,
    _In_ UINT64 EventMask
    );

/**
 * @brief Copies a fixed-size snapshot into the calling guest process.
 *
 * @param DestinationCr3 Page table root for Destination.
 * @param Destination Guest virtual destination buffer.
 * @param Size Caller-provided buffer size.
 * @param CpuFilter CPU index to return, or HACDBG_TRACE_ALL_CPUS.
 *
 * @return Bytes written, or 0 on invalid arguments or guest write failure.
 */
UINT64
TraceRead(
    _In_ UINT64 DestinationCr3,
    _In_ GUEST_VIRTUAL_ADDRESS Destination,
    _In_ UINT64 Size,
    _In_ UINT64 CpuFilter
    );
