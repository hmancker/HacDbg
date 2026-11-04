#pragma once

#include <ntifs.h>

#include "../shared/process_control.h"

/**
 * @brief Runs one process-control request at PASSIVE_LEVEL.
 *
 * @param Request Buffered IOCTL body. Status receives the result.
 *
 * @return The same code stored in Request->Status.
 */
NTSTATUS
ProcessCtrlExecute(
    _Inout_ HACDBG_PROCESS_REQUEST* Request
    );

/**
 * @brief Stops the handle-table worker before the driver unloads.
 */
VOID
ProcessCtrlCleanup(
    VOID
    );
