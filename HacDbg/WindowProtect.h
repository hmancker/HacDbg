#pragma once

#include <ntifs.h>

#include "../shared/window_protect.h"

/**
 * @brief Runs one window-protection request at PASSIVE_LEVEL.
 *
 * @param Request Buffered IOCTL body. Status receives the result.
 *
 * @return The same code stored in Request->Status.
 */
NTSTATUS
WindowProtectExecute(
    _Inout_ HACDBG_WINDOW_REQUEST* Request
    );

/**
 * @brief Removes the display-affinity hook before the guest is stopped.
 */
VOID
WindowProtectCleanup(
    VOID
    );
