#pragma once

#include <ntifs.h>

#include "../shared/kernel_filter.h"

/**
 * @brief Enumerates legacy filter device stacks into Request.
 *
 * @details Caller must be at PASSIVE_LEVEL. Reserved selects the operation.
 * Scan lists the filter stacks. Detach unlinks Rows[0].DeviceObject from
 * Rows[0].HostDeviceObject. Devices lists every device of
 * Rows[0].DriverObject. Dispatch returns MajorFunction entries in Depth order,
 * with the routine address in DeviceObject.
 *
 * @param Request Receives Status, the rows, and Truncated when the table is full.
 *
 * @return The same code stored in Request->Status.
 */
NTSTATUS
FilterExecute(
    _Inout_ HACDBG_FILTER_REQUEST* Request
    );
