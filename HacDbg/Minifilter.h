#pragma once

#include <ntifs.h>

#include "../shared/kernel_minifilter.h"

/**
 * @brief Enumerates registered minifilters into Request.
 *
 * @details Caller must be at PASSIVE_LEVEL. Reserved selects the operation.
 * Scan lists each filter and its pre and post callbacks. Disable places
 * xor eax, eax; ret at every callback entry through a shadow page. Enable
 * removes those shadow bytes. Rows[0].Filter is the FLT_FILTER for disable
 * and enable.
 *
 * @param Request Receives Status, the rows, and Truncated when the table is full.
 *
 * @return The same code stored in Request->Status.
 */
NTSTATUS
MinifilterExecute(
    _Inout_ HACDBG_MINIFILTER_REQUEST* Request
    );
