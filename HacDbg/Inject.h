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
 * @param HidePayload When TRUE, each executable payload frame is hidden
 * in the SLAT map after its execute hook is installed. Data pages stay
 * visible because the guest leaf points at them.
 *
 * @details The mapping has no loader entry. Executable pages are read as
 * zeros and executed from a shadow page. 32-bit processes are refused.
 */
NTSTATUS
InjectPte(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path,
    _In_ BOOLEAN HidePayload
    );

BOOLEAN
/**
 * @brief Records one thread that may use the private SLAT root.
 *
 * @param Thread System thread object. The caller holds one reference.
 * @param KernelCr3 Kernel directory of the thread's process.
 * @param UserCr3 User directory, or zero when KVA shadow is not in use.
 * @param KeptReference Receives TRUE when this function keeps the caller's reference.
 *
 * @return TRUE when the thread is in the allow list.
 */
InjectSlatAllow(
    _In_ PETHREAD Thread,
    _In_ UINT64 KernelCr3,
    _In_ UINT64 UserCr3,
    _Out_ BOOLEAN* KeptReference
    );

BOOLEAN
/**
 * @brief Reports whether any private-root thread is still recorded.
 */
InjectSlatArmed(
    VOID
    );

BOOLEAN
/**
 * @brief Reports whether this guest CR3 should use the private root.
 *
 * @param GuestCr3 Guest CR3, including PCID bits.
 *
 * @return TRUE when the private root applies.
 *
 * @details Compares the page-aligned CR3 with the directories recorded for
 * an injected process. It does not read guest memory.
 */
InjectSlatCr3Private(
    _In_ UINT64 GuestCr3
    );
