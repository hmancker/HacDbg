#pragma once

#include <ntifs.h>

#include "../shared/kernel_callback.h"

/**
 * @brief Enumerates kernel callbacks into Request.
 *
 * @details Caller must be at PASSIVE_LEVEL. Reserved is HACDBG_CALLBACK_OP_SCAN,
 * or remove, disable, or enable. A scan reads the callback lists. Remove writes
 * 0 into the callback table slot. Disable maps a shadow page and puts ret at
 * the callback entry. Enable removes that shadow page. Rows[0] is the target.
 *
 * @param Request Receives Status, the rows, and Truncated when the table is full.
 *
 * @return The same code stored in Request->Status.
 */
NTSTATUS
CallbackExecute(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request
    );
