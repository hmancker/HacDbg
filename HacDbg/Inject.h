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

NTSTATUS
/**
 * @brief Starts the process-exit watcher used by PTE injection.
 *
 * @return STATUS_SUCCESS when the watcher thread is running.
 *
 * @details Call this after the processor is a guest. A manual-mapped image
 * cannot register a process notify routine, so the watcher waits on
 * referenced process objects.
 */
InjectInitialize(
    VOID
    );

VOID
/**
 * @brief Stops the watcher and retires every live PTE mapping.
 *
 * @details Call this while processors are still guests, before virtualization
 * stops. It does nothing when InjectInitialize did not run.
 */
InjectPrepareUnload(
    VOID
    );

VOID
/**
 * @brief Frees frames that teardown could not release while guests were running.
 *
 * @details Call this after virtualization has stopped.
 */
InjectReleaseLeaked(
    VOID
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
 * @brief Reports whether a recorded thread should still open CR3 exits.
 *
 * @details A slot whose thread has State==Terminated does not count. The
 * slot itself stays until the mapping is retired.
 */
InjectSlatArmed(
    VOID
    );

BOOLEAN
/**
 * @brief Reports whether this thread should use the private root.
 *
 * @param Thread KPRCB.CurrentThread. The caller does not pass a reference.
 *
 * @return TRUE when the thread is in the allow list and has not terminated.
 *
 * @details Pointer compare plus KTHREAD.State. It does not allocate, take a
 * lock, or dereference the thread. Safe on a VM-exit path.
 */
InjectSlatThreadPrivate(
    _In_ PETHREAD Thread
    );

VOID
/**
 * @brief Drops the current thread from the private-root allow list.
 *
 * @details The mapping stays until the process exits. Safe on a VM-exit
 * path: it does not take a lock or drop the thread reference.
 */
InjectDisarmCurrentThread(
    VOID
    );

//
// Shadow patch length. CPUID is the last instruction, so the VM-exit RIP
// plus the 2-byte CPUID length is the first original byte after the patch.
//
#define INJECT_CLEAN_PATCH_BYTES          15u
#define INJECT_CLEAN_CPUID_OFFSET         13u

BOOLEAN
/**
 * @brief Restores this process's guest page tables before rundown.
 *
 * @param GuestRip Guest instruction that is about to run, or the CPUID
 * inside the rundown shadow patch.
 *
 * @return TRUE when a hidden payload frame was translated back to itself.
 * The caller must flush SLAT before re-entering the guest.
 *
 * @details Called when that instruction is the address-space rundown
 * routine. Hidden frames are restored before guest page-table edits, so
 * rundown does not read them through the zero page. It does not free
 * frames. A failed unhide leaves Hidden set so a later teardown can retry.
 */
InjectQuiesceCurrentProcess(
    _In_ UINT64 GuestRip
    );

BOOLEAN
/**
 * @brief Reports whether GuestRip is the rundown shadow CPUID.
 *
 * @param GuestRip Guest RIP at a CPUID exit.
 *
 * @return TRUE when the shadow patch is armed and GuestRip is its CPUID.
 */
InjectMatchCleanCpuid(
    _In_ UINT64 GuestRip
    );

BOOLEAN
/**
 * @brief Writes the stolen address-space rundown prologue into the guest.
 *
 * @param GuestCr3 Guest CR3 at the CPUID exit.
 * @param GuestRsp Guest RSP at the CPUID exit.
 * @param GuestRbx Guest RBX.
 * @param GuestRbp Guest RBP.
 * @param GuestRsi Guest RSI.
 *
 * @return TRUE when the three home slots were written.
 *
 * @details The shadow patch saved the incoming RCX in R11, then executed
 * CPUID. The caller restores RCX from that R11, sets R11 to RSP, and
 * advances RIP by the CPUID length only.
 */
InjectEmulateCleanEntry(
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRsp,
    _In_ UINT64 GuestRbx,
    _In_ UINT64 GuestRbp,
    _In_ UINT64 GuestRsi
    );
