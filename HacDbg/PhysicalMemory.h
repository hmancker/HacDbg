/**
 * @file PhysicalMemory.h
 * @brief Guest memory access interfaces.
 *
 * @author HacDbg
 */

#pragma once

#include "Types.h"

NTSTATUS
/**
 * @brief Records the firmware-described RAM ranges for on-demand mapping.
 *
 * @return STATUS_SUCCESS on success; otherwise an NTSTATUS error.
 */
PhysicalMemoryInitialize(
    VOID
    );

VOID
/**
 * @brief Selects four-level or five-level guest page table walking.
 *
 * @param Enabled TRUE when the guest uses five-level paging.
 */
PhysicalMemorySetFiveLevelPaging(
    _In_ BOOLEAN Enabled
    );

VOID
/**
 * @brief Releases the RAM range table.
 */
PhysicalMemoryCleanup(
    VOID
    );

/**
 * @brief Maps a guest physical range temporarily for a bounded copy.
 *
 * @param Address Guest physical address.
 * @param Size Maximum bytes to map.
 * @param MappedSize Receives the number of bytes actually mapped.
 *
 * @return Host virtual address, or NULL when the range is not RAM or the
 * current IRQL is too high.
 */
PVOID
PhysicalMemoryMapTemporary(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _In_ SIZE_T Size,
    _Out_ SIZE_T* MappedSize
    );

/**
 * @brief Releases a mapping returned by PhysicalMemoryMapTemporary.
 *
 * @param Base Mapped host virtual address.
 * @param Size Size that was mapped.
 */
VOID
PhysicalMemoryUnmapTemporary(
    _In_ PVOID Base,
    _In_ SIZE_T Size
    );

SIZE_T
/**
 * @brief Reads guest physical memory.
 *
 * @param Address First guest physical byte.
 * @param Buffer Host destination.
 * @param Size Maximum bytes to read.
 *
 * @return Number of bytes copied.
 */
PhysicalMemoryRead(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

SIZE_T
/**
 * @brief Writes guest physical memory.
 *
 * @param Address First guest physical byte.
 * @param Buffer Host source.
 * @param Size Maximum bytes to write.
 *
 * @return Number of bytes copied.
 */
PhysicalMemoryWrite(
    _In_ GUEST_PHYSICAL_ADDRESS Address,
    _In_reads_bytes_(Size) const VOID* Buffer,
    _In_ SIZE_T Size
    );

BOOLEAN
_Success_(return != FALSE)
/**
 * @brief Translates a guest virtual address with the supplied CR3.
 *
 * @param Cr3 Guest page table root.
 * @param VirtualAddress Guest virtual address.
 * @param PhysicalAddress Receives the translated guest physical address.
 *
 * @return TRUE when a mapping exists; otherwise FALSE.
 */
GuestVirtualToPhysical(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS VirtualAddress,
    _Out_ GUEST_PHYSICAL_ADDRESS* PhysicalAddress
    );

SIZE_T
/**
 * @brief Reads through guest page tables.
 *
 * @param Cr3 Guest page table root.
 * @param Address Guest virtual address.
 * @param Buffer Host destination.
 * @param Size Maximum bytes to read.
 *
 * @return Number of bytes copied.
 */
GuestVirtualRead(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

SIZE_T
/**
 * @brief Writes through guest page tables.
 *
 * @param Cr3 Guest page table root.
 * @param Address Guest virtual address.
 * @param Buffer Host source.
 * @param Size Maximum bytes to write.
 *
 * @return Number of bytes copied.
 */
GuestVirtualWrite(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS Address,
    _In_reads_bytes_(Size) const VOID* Buffer,
    _In_ SIZE_T Size
    );
