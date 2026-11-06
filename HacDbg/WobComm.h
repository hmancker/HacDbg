#pragma once

/**
 * @brief Installs the process and window request hook.
 *
 * @return STATUS_SUCCESS when the hook is installed. A scan miss returns
 * STATUS_NOT_FOUND and leaves the IOCTL path in place.
 */
NTSTATUS
WobCommInitialize(
    VOID
    );

/**
 * @brief Removes the hook before processors leave the guest.
 */
VOID
WobCommCleanup(
    VOID
    );
