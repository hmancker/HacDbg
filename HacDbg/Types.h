/**
 * @file Types.h
 * @brief Semantic address and page-frame wrappers.
 *
 * @author HacDbg
 */

#pragma once

#include <ntddk.h>

#define HACDBG_GUEST_PHYSICAL_LIMIT (1ull << 40)

/**
 * @brief A physical address interpreted in the guest address space.
 */
typedef struct _GUEST_PHYSICAL_ADDRESS
{
    UINT64 Value;
} GUEST_PHYSICAL_ADDRESS;

/**
 * @brief A physical address used by the host page tables.
 */
typedef struct _HOST_PHYSICAL_ADDRESS
{
    UINT64 Value;
} HOST_PHYSICAL_ADDRESS;

/**
 * @brief A virtual address available in the host address space.
 */
typedef struct _HOST_VIRTUAL_ADDRESS
{
    UINT64 Value;
} HOST_VIRTUAL_ADDRESS;

/**
 * @brief A virtual address in the guest address space.
 */
typedef struct _GUEST_VIRTUAL_ADDRESS
{
    UINT64 Value;
} GUEST_VIRTUAL_ADDRESS;

/**
 * @brief A 4 KiB page frame number.
 */
typedef struct _PAGE_FRAME_NUMBER
{
    UINT64 Value;
} PAGE_FRAME_NUMBER;

/**
 * @brief A small lock that is safe to acquire above DISPATCH_LEVEL.
 */
typedef struct _HACDBG_SPIN_LOCK
{
    volatile LONG Locked;
} HACDBG_SPIN_LOCK;

static __inline VOID
/**
 * @brief Initializes an IRQL-agnostic internal lock.
 *
 * @param Lock Lock to initialize.
 */
HacDbgSpinLockInitialize(
    _Out_ HACDBG_SPIN_LOCK* Lock
    )
{
    Lock->Locked = 0;
}

static __inline VOID
/**
 * @brief Acquires an internal lock without changing IRQL.
 *
 * @param Lock Lock to acquire.
 */
HacDbgSpinLockAcquire(
    _Inout_ HACDBG_SPIN_LOCK* Lock
    )
{
    while (InterlockedCompareExchange(&Lock->Locked, 1, 0) != 0)
    {
        YieldProcessor();
    }

    KeMemoryBarrier();
}

static __inline VOID
/**
 * @brief Releases an internal lock.
 *
 * @param Lock Lock to release.
 */
HacDbgSpinLockRelease(
    _Inout_ HACDBG_SPIN_LOCK* Lock
    )
{
    KeMemoryBarrier();
    InterlockedExchange(&Lock->Locked, 0);
}

static __inline GUEST_PHYSICAL_ADDRESS
/**
 * @brief Wraps an integer as a guest physical address.
 *
 * @param Value Integer value.
 */
HacDbgGuestPhysicalAddress(
    _In_ UINT64 Value
    )
{
    GUEST_PHYSICAL_ADDRESS address = { Value };
    return address;
}

static __inline HOST_PHYSICAL_ADDRESS
/**
 * @brief Wraps an integer as a host physical address.
 *
 * @param Value Integer value.
 */
HacDbgHostPhysicalAddress(
    _In_ UINT64 Value
    )
{
    HOST_PHYSICAL_ADDRESS address = { Value };
    return address;
}

static __inline HOST_VIRTUAL_ADDRESS
/**
 * @brief Wraps a host pointer as a host virtual address.
 *
 * @param Value Host pointer.
 */
HacDbgHostVirtualAddress(
    _In_ PVOID Value
    )
{
    HOST_VIRTUAL_ADDRESS address = { (UINT64)(ULONG_PTR)Value };
    return address;
}

static __inline GUEST_VIRTUAL_ADDRESS
/**
 * @brief Wraps an integer as a guest virtual address.
 *
 * @param Value Integer value.
 */
HacDbgGuestVirtualAddress(
    _In_ UINT64 Value
    )
{
    GUEST_VIRTUAL_ADDRESS address = { Value };
    return address;
}

static __inline PAGE_FRAME_NUMBER
/**
 * @brief Wraps an integer as a page frame number.
 *
 * @param Value Page frame number.
 */
HacDbgPageFrameNumber(
    _In_ UINT64 Value
    )
{
    PAGE_FRAME_NUMBER frame = { Value };
    return frame;
}
