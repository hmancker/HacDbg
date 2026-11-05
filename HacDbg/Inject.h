#pragma once

#include <ntifs.h>

/**
 * @brief Loads a DLL on a new thread, then by redirecting a user thread.
 *
 * @param Process Target process. The caller holds one reference.
 * @param Path Null-terminated Win32 path of a 64-bit DLL.
 *
 * @return STATUS_SUCCESS when the loader list contains the DLL.
 */
NTSTATUS
InjectApc(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path
    );

/**
 * @brief Maps a DLL with new user page tables and an execute disguise.
 *
 * @param Process Target process. The caller holds one reference.
 * @param Path Null-terminated Win32 path of a 64-bit DLL.
 *
 * @return STATUS_SUCCESS when the image entry has been started.
 *
 * @details The mapping has no loader entry. Executable pages are read as
 * zeros and executed from a shadow page. 32-bit processes are refused.
 */
NTSTATUS
InjectPte(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path
    );
