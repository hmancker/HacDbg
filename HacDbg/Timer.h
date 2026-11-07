#pragma once

#include <ntifs.h>

#include "../shared/kernel_timer.h"

/**
 * @brief Enumerates IO timers and processor DPC timers into Request.
 *
 * @details Caller must be at PASSIVE_LEVEL. Reserved selects the operation.
 * Scan reads the IO timer queue and each processor timer table. Remove
 * unlinks an IO timer or cancels a DPC timer. Rows[0] is the target.
 *
 * @param Request Receives Status, the rows, and Truncated when the table is full.
 *
 * @return The same code stored in Request->Status.
 */
NTSTATUS
TimerExecute(
    _Inout_ HACDBG_TIMER_REQUEST* Request
    );
