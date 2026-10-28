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
 * @brief Records whether any logical processor may still be in the guest.
 *
 * @param Active TRUE before the first guest entry. FALSE only after every
 * processor has left the guest.
 *
 * @details While this is TRUE, physical reads must not call MmCopyMemory.
 * That API can send a TLB-shootdown IPI. Other processors are still in the
 * guest, so the IPI is delivered to the guest. The flush descriptor sits on
 * the host stack, which nested paging hides, and the guest reads zeros.
 * FALSE also drops kernel directories recorded for session-space translation.
 */
PhysicalMemorySetGuestRunning(
    _In_ BOOLEAN Active
    );

BOOLEAN
/**
 * @brief Reports whether a directory maps the Windows kernel image region.
 *
 * @param Cr3 Guest CR3. PCID and the no-flush bit are ignored.
 *
 * @return TRUE when the kernel image page-table slot is present.
 *
 * @details Windows places ntoskrnl in the 512 GiB region at
 * 0xFFFFF80000000000, PML4 index 0x1F0. A KPTI user directory leaves that
 * slot empty. Five-level paging checks PML5 index 0x1FF first.
 *
 * @warning A failed physical read is reported as FALSE. The caller must keep
 * the previously accepted directory. Do not call above DISPATCH_LEVEL: the
 * temporary map rejects that IRQL.
 */
PhysicalMemoryMapsKernelImage(
    _In_ UINT64 Cr3
    );

VOID
/**
 * @brief Records a kernel page-table root observed at CPL 0.
 *
 * @param Cr3 Guest CR3. PCID bits are ignored.
 *
 * @details The system process directory does not map session space. A later
 * kernel-address walk that misses in the caller's directory tries the
 * directories recorded here. The caller must reject a directory that does
 * not map the kernel image region before calling this function.
 */
PhysicalMemoryRememberKernelDirectory(
    _In_ UINT64 Cr3
    );

UINT64
/**
 * @brief Returns a kernel directory that still maps ntoskrnl.
 *
 * @param Preferred Directory to keep when it is still usable.
 *
 * @return A directory whose kernel-image slot is present, or 0 when none
 * of the recorded directories are.
 *
 * @details A recorded CR3 is dropped when that slot is not present. The
 * physical page is reused after the owning process exits, and walking it
 * then reads a user directory or ordinary code. A failed physical read
 * keeps Preferred.
 *
 * @warning Do not call above DISPATCH_LEVEL. The temporary map rejects
 * that IRQL and this function then keeps Preferred.
 */
PhysicalMemorySelectLiveKernelDirectory(
    _In_ UINT64 Preferred
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

BOOLEAN
/**
 * @brief Writes a guest RAM page back from the cache.
 *
 * @details Execute hooks publish bytes that were stored through another
 * mapping. A later fetch uses the EPT memory type of that page. When the
 * type does not snoop, the fetch reads DRAM and misses the cached stores.
 *
 * @param Page 4 KiB-aligned guest physical page in RAM.
 *
 * @return TRUE when the page was mapped and flushed.
 */
PhysicalMemoryFlushPage(
    _In_ GUEST_PHYSICAL_ADDRESS Page
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
 * @param NotResident Receives TRUE when the address is not mapped, or the
 * leaf was read and has no PFN. A debugger probe of that address is not a
 * driver fault. Stays FALSE when a page-table read fails, or the kernel
 * image region cannot be translated.
 *
 * @return TRUE when a mapping exists; otherwise FALSE.
 */
GuestVirtualToPhysical(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS VirtualAddress,
    _Out_ GUEST_PHYSICAL_ADDRESS* PhysicalAddress,
    _Out_opt_ BOOLEAN* NotResident
    );

INT
/**
 * @brief Translates one present 4 KiB guest page and its leaf PTE.
 *
 * @details Large pages and software PTEs are rejected. The caller uses the
 * returned page and PTE addresses on later exits instead of walking again.
 *
 * @param Cr3 Guest page table root.
 * @param VirtualAddress Guest virtual address inside the page.
 * @param PagePhysical Receives the 4 KiB-aligned guest physical page.
 * @param PtePhysical Receives the guest physical address of the leaf PTE.
 *
 * @return 1 when the leaf is a present 4 KiB PTE in RAM; otherwise 0.
 */
GuestVirtualTranslate4k(
    _In_ UINT64 Cr3,
    _In_ GUEST_VIRTUAL_ADDRESS VirtualAddress,
    _Out_ GUEST_PHYSICAL_ADDRESS* PagePhysical,
    _Out_ GUEST_PHYSICAL_ADDRESS* PtePhysical
    );

INT
/**
 * @brief Compares a cached leaf PTE with the page it must still name.
 *
 * @param PtePhysical Guest physical address of the leaf PTE.
 * @param PagePhysical 4 KiB-aligned guest physical page captured earlier.
 *
 * @return 1 when the PTE is present and names PagePhysical. 0 when the PTE
 * could not be read. -1 when the PTE was read and does not name that page.
 */
GuestPhysicalPteState(
    _In_ GUEST_PHYSICAL_ADDRESS PtePhysical,
    _In_ GUEST_PHYSICAL_ADDRESS PagePhysical
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
