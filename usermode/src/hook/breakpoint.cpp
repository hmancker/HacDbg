#include "breakpoint.h"

#include "hook.h"
#include "hook_disassembly.h"
#include "kernel_detour_holder.h"

#include <hypercall/hypercall_def.h>

#include "../hypercall/hypercall.h"
#include "../logs/logs.h"
#include "../system/system.h"
#include "../system/nt_offsets.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string_view>
#include <vector>

namespace
{
	constexpr std::uint64_t absolute_jump_size = 14;
	constexpr std::uint64_t relative_jump_size = 5;
	constexpr std::uint64_t cr3_address_mask = ~0xFFFull;
	// park clears TF, then waits without CPUID. It does not live in the hook
	// shadow: the wait page is executable on the main SLAT root.
	// Offsets match pause_spin2_template and pause_park_template.
	constexpr std::uint64_t pause_latch_immediate_offset = 0x0C;
	constexpr std::uint8_t pause_spin2_template[] = {
		0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0F, 0xA2, 0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	// Saved RFLAGS is at [rsp+0x78] after entry1 and entry2. IF is bit 1 of [rsp+0x79].
	// Relative jumps inside this block land on the compare at 0x0B, not on the TF clear.
	constexpr std::uint8_t pause_park_template[] = {
		0x9C, 0x48, 0x81, 0x64, 0x24, 0x00, 0xFF, 0xFE, 0xFF, 0xFF, 0x9D, 0x48, 0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x75, 0x10, 0x48, 0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x66,
		0x8C, 0xC8, 0xA8, 0x03, 0x75, 0x0E, 0xF6, 0x44, 0x24, 0x79, 0x02, 0x74, 0x03, 0xF4, 0xEB, 0xD5, 0xF3, 0x90, 0xEB,
		0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0xF3, 0x68, 0xF0, 0xD8, 0xFF, 0xFF, 0x33, 0xC9, 0x48, 0x89,
		0xE2, 0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0x48, 0x83, 0xC4, 0x08, 0xEB, 0xB3};
	constexpr std::uint64_t pause_spin2_size = sizeof(pause_spin2_template);
	constexpr std::uint64_t pause_park_size = sizeof(pause_park_template);

	static_assert(pause_spin2_size == 0x2C);
	static_assert(pause_park_size == 0x58);
	static_assert(pause_spin2_template[0x14] == 0x0F && pause_spin2_template[0x15] == 0xA2);
	static_assert(pause_spin2_template[0x1E] == 0xFF && pause_spin2_template[0x1F] == 0x25);
	static_assert(pause_park_template[0x0B] == 0x48);
	static_assert(pause_park_template[0x33] == 0xF4);
	static_assert(pause_park_template[0x50] == 0x0F && pause_park_template[0x51] == 0x05);
	// The pause poll hypercall restores the top five stack slots and then adds 40 to the logged rsp.
	constexpr std::uint64_t hypervisor_popped_bytes = 40;
	constexpr std::uint64_t pause_frame_bytes = 128;
	constexpr std::uint64_t pause_log_rsp_bias = pause_frame_bytes - hypervisor_popped_bytes;

	struct code_slot_t
	{
		std::uint64_t address = 0;
		std::uint64_t page_physical = 0;
		std::uint64_t offset = 0;
		std::vector<std::uint8_t> original = {};
		std::vector<std::uint8_t> bytes = {};
	};

	struct avoid_range_t
	{
		std::uint64_t address = 0;
		std::uint64_t size = 0;
	};

	struct breakpoint_t
	{
		std::uint64_t id = 0;
		std::uint64_t address = 0;
		std::uint64_t cr3 = 0;
		std::uint64_t page_physical = 0;
		std::uint64_t page_offset = 0;
		std::uint64_t span = 0;
		std::uint16_t detour_offset = 0;
		std::uint8_t enabled = 0;
		std::uint8_t pauses_thread = 0;
		std::uint64_t cave_page_physical = 0;
		std::uint64_t cave_offset = 0;
		std::vector<std::uint8_t> original_bytes = {};
		std::vector<std::uint8_t> patch_bytes = {};
		std::vector<std::uint8_t> cave_original = {};
		std::vector<std::uint8_t> cave_bytes = {};
		std::uint64_t resume_page_physical = 0;
		std::uint64_t resume_offset = 0;
		std::vector<std::uint8_t> resume_original = {};
		std::vector<std::uint8_t> resume_bytes = {};
		std::vector<code_slot_t> slots = {};
		std::uint64_t entry_address = 0;
		std::uint64_t resume_address = 0;
		std::uint64_t spin_page_physical = 0;
		std::uint64_t spin_rip_offset = 0;
		std::uint64_t go_rsp_page_physical = 0;
		std::uint64_t go_rsp_offset = 0;
		std::uint64_t go_target_page_physical = 0;
		std::uint64_t go_target_offset = 0;
		std::uint64_t step_address[2] = {};
		std::uint64_t step_capacity[2] = {};
		std::uint64_t step_page_physical[2] = {};
		std::uint64_t step_offset[2] = {};
	};

	struct pause_state_t
	{
		std::uint8_t valid = 0;
		std::uint64_t breakpoint_id = ~0ull;
		std::uint64_t live_rsp = 0;
		std::uint64_t expected_rip = 0;
		std::uint8_t rsp_edited = 0;
		breakpoint::registers_t registers = {};
	};

	pause_state_t pause_state = {};

	struct breakpoint_page_t
	{
		std::uint64_t page_physical = 0;
		std::uint8_t* shadow = nullptr;
		std::uint64_t shadow_physical = 0;
	};

	std::vector<breakpoint_t> breakpoints = {};
	std::vector<breakpoint_page_t> breakpoint_pages = {};

	std::uint64_t page_base_of(const std::uint64_t physical_address)
	{
		return physical_address & ~0xFFFull;
	}

	breakpoint_page_t* find_page(const std::uint64_t page_physical)
	{
		for (breakpoint_page_t& page : breakpoint_pages)
		{
			if (page.page_physical == page_physical)
			{
				return &page;
			}
		}

		return nullptr;
	}

	breakpoint_t* find_breakpoint(const std::uint64_t id)
	{
		for (breakpoint_t& breakpoint : breakpoints)
		{
			if (breakpoint.id == id)
			{
				return &breakpoint;
			}
		}

		return nullptr;
	}

	std::uint64_t allocate_id()
	{
		std::uint64_t id = 0;

		while (find_breakpoint(id) != nullptr)
		{
			id++;
		}

		return id;
	}

	std::uint8_t page_has_breakpoint(const std::uint64_t page_physical)
	{
		for (const breakpoint_t& breakpoint : breakpoints)
		{
			if (breakpoint.page_physical == page_physical ||
				(breakpoint.pauses_thread == 1 && (breakpoint.cave_page_physical == page_physical ||
					breakpoint.resume_page_physical == page_physical)))
			{
				return 1;
			}

			for (const code_slot_t& slot : breakpoint.slots)
			{
				if (slot.page_physical == page_physical)
				{
					return 1;
				}
			}
		}

		return 0;
	}

	std::uint8_t ranges_overlap(const std::uint64_t left, const std::uint64_t left_size, const std::uint64_t right,
	                            const std::uint64_t right_size)
	{
		return static_cast<std::uint8_t>(left < right + right_size && right < left + left_size);
	}

	void write_absolute_jump(std::uint8_t* const destination, const std::uint64_t address)
	{
		destination[0] = 0x68;
		*reinterpret_cast<std::uint32_t*>(destination + 1) = static_cast<std::uint32_t>(address);
		destination[5] = 0xC7;
		destination[6] = 0x44;
		destination[7] = 0x24;
		destination[8] = 0x04;
		*reinterpret_cast<std::uint32_t*>(destination + 9) = static_cast<std::uint32_t>(address >> 32);
		destination[13] = 0xC3;
	}

	void write_relative_jump(std::uint8_t* const destination, const std::uint64_t site, const std::uint64_t target)
	{
		const auto displacement = static_cast<std::int32_t>(static_cast<std::int64_t>(target) -
			static_cast<std::int64_t>(site + relative_jump_size));

		destination[0] = 0xE9;
		*reinterpret_cast<std::int32_t*>(destination + 1) = displacement;
	}

	std::uint8_t detour_holder_reaches(const std::uint64_t address)
	{
		const std::uint64_t base = hook::detour_holder_base();

		if (base == 0)
		{
			return 0;
		}

		const std::int64_t next_ip = static_cast<std::int64_t>(address + relative_jump_size);
		const std::int64_t lowest = static_cast<std::int64_t>(base) - next_ip;
		const std::int64_t highest = static_cast<std::int64_t>(base + page_size - 1) - next_ip;

		return static_cast<std::uint8_t>(lowest >= static_cast<std::int64_t>(INT32_MIN) &&
			highest <= static_cast<std::int64_t>(INT32_MAX));
	}

	std::uint64_t bytes_until_next_entry(const std::uint64_t address)
	{
		std::uint64_t nearest = 0;

		for (const auto& [module_name, module_info] : sys::kernel::modules_list)
		{
			if (address < module_info.base_address || address >= module_info.base_address + module_info.size)
			{
				continue;
			}

			const std::uint64_t module_end = module_info.base_address + module_info.size;

			if (nearest == 0 || module_end < nearest)
			{
				nearest = module_end;
			}

			for (const auto& [export_name, export_address] : module_info.exports)
			{
				if (export_address > address && (nearest == 0 || export_address < nearest))
				{
					nearest = export_address;
				}

				(void)export_name;
			}

			(void)module_name;
		}

		if (nearest <= address)
		{
			return ~0ull;
		}

		return nearest - address;
	}

	void publish_shadow_bytes(std::uint8_t* const shadow, const std::uint64_t offset, const std::uint64_t size)
	{
		for (std::uint64_t index = 0; index < size; index += 64)
		{
			_mm_clflush(shadow + offset + index);
		}

		FlushInstructionCache(GetCurrentProcess(), shadow + offset, static_cast<SIZE_T>(size));
		hypercall::flush_slat_cache();
	}

	void write_breakpoint_bytes(breakpoint_page_t& page, const breakpoint_t& breakpoint, const std::uint8_t enabled)
	{
		const std::uint8_t* const source = enabled == 1 ? breakpoint.patch_bytes.data() : breakpoint.original_bytes.data();

		std::memcpy(page.shadow + breakpoint.page_offset, source, breakpoint.patch_bytes.size());
		publish_shadow_bytes(page.shadow, breakpoint.page_offset, breakpoint.patch_bytes.size());

		if (breakpoint.pauses_thread == 1 && breakpoint.cave_bytes.empty() == false)
		{
			breakpoint_page_t* const cave_page = find_page(breakpoint.cave_page_physical);

			if (cave_page != nullptr)
			{
				const std::uint8_t* const cave_source = enabled == 1 ? breakpoint.cave_bytes.data() : breakpoint.cave_original.data();

				std::memcpy(cave_page->shadow + breakpoint.cave_offset, cave_source, breakpoint.cave_bytes.size());
				publish_shadow_bytes(cave_page->shadow, breakpoint.cave_offset, breakpoint.cave_bytes.size());
			}
		}

		if (breakpoint.resume_bytes.empty() == false)
		{
			breakpoint_page_t* const resume_page = find_page(breakpoint.resume_page_physical);

			if (resume_page != nullptr)
			{
				const std::uint8_t* const resume_source = enabled == 1 ? breakpoint.resume_bytes.data() : breakpoint.resume_original.data();

				std::memcpy(resume_page->shadow + breakpoint.resume_offset, resume_source, breakpoint.resume_bytes.size());
				publish_shadow_bytes(resume_page->shadow, breakpoint.resume_offset, breakpoint.resume_bytes.size());
			}
		}

		for (const code_slot_t& slot : breakpoint.slots)
		{
			breakpoint_page_t* const slot_page = find_page(slot.page_physical);

			if (slot_page == nullptr || slot.bytes.empty() == true)
			{
				continue;
			}

			const std::uint8_t* const slot_source = enabled == 1 ? slot.bytes.data() : slot.original.data();

			std::memcpy(slot_page->shadow + slot.offset, slot_source, slot.bytes.size());
			publish_shadow_bytes(slot_page->shadow, slot.offset, slot.bytes.size());
		}
	}

	std::uint8_t is_user_address(const std::uint64_t address)
	{
		return static_cast<std::uint8_t>(address <= 0x00007FFFFFFFFFFFull);
	}

	constexpr std::uint64_t page_table_entry_mask = 0x000FFFFFFFFFF000ull;

	std::uint8_t* user_trampoline_page = nullptr;
	std::uint64_t user_trampoline_physical = 0;
	std::uint64_t user_trampoline_virtual = 0;
	std::uint64_t user_trampoline_used = 0;

	std::uint64_t read_physical_qword(const std::uint64_t physical_address)
	{
		std::uint64_t value = 0;

		if (hypercall::read_guest_physical_memory(&value, physical_address, sizeof(value)) != sizeof(value))
		{
			return 0;
		}

		return value;
	}

	std::uint8_t write_physical_qword(const std::uint64_t physical_address, const std::uint64_t value)
	{
		return static_cast<std::uint8_t>(hypercall::write_guest_physical_memory(
			&value, physical_address, sizeof(value)) == sizeof(value));
	}

	std::uint64_t page_table_index(const std::uint64_t address, const std::uint64_t shift)
	{
		return (address >> shift) & 0x1FF;
	}

	std::uint8_t ensure_page_table_entry(const std::uint64_t table_physical, const std::uint64_t index,
	                                     std::uint64_t& next_physical, const std::uint8_t create)
	{
		const std::uint64_t entry_physical = (table_physical & page_table_entry_mask) + index * 8;
		const std::uint64_t entry = read_physical_qword(entry_physical);

		if ((entry & 1) == 1)
		{
			if ((entry & 0x80) == 0x80)
			{
				return 0;
			}

			next_physical = entry & page_table_entry_mask;

			return 1;
		}

		if (create == 0)
		{
			return 0;
		}

		auto* const table_page = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(page_size, PAGE_READWRITE));

		if (table_page == nullptr)
		{
			return 0;
		}

		std::memset(table_page, 0, page_size);

		const std::uint64_t table_page_physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(table_page), sys::directory_for_local_memory());

		if (table_page_physical == 0)
		{
			sys::user::free_memory(table_page);

			return 0;
		}

		const std::uint64_t new_entry = (table_page_physical & page_table_entry_mask) | 0x7;

		if (write_physical_qword(entry_physical, new_entry) == 0)
		{
			sys::user::free_memory(table_page);

			return 0;
		}

		next_physical = table_page_physical & page_table_entry_mask;

		return 1;
	}

	std::uint8_t map_user_page(const std::uint64_t cr3, const std::uint64_t virtual_address, const std::uint64_t physical_address)
	{
		std::uint64_t table = cr3 & page_table_entry_mask;
		const std::uint64_t shifts[] = {39, 30, 21};

		for (const std::uint64_t shift : shifts)
		{
			std::uint64_t next = 0;

			if (ensure_page_table_entry(table, page_table_index(virtual_address, shift), next, 1) == 0)
			{
				return 0;
			}

			table = next;
		}

		const std::uint64_t pte_physical = table + page_table_index(virtual_address, 12) * 8;
		const std::uint64_t pte = read_physical_qword(pte_physical);

		if ((pte & 1) == 1)
		{
			return static_cast<std::uint8_t>((pte & page_table_entry_mask) == (physical_address & page_table_entry_mask));
		}

		const std::uint64_t new_pte = (physical_address & page_table_entry_mask) | 0x7;

		return write_physical_qword(pte_physical, new_pte);
	}

	std::uint8_t user_page_is_present(const std::uint64_t cr3, const std::uint64_t virtual_address)
	{
		std::uint64_t table = cr3 & page_table_entry_mask;
		const std::uint64_t shifts[] = {39, 30, 21, 12};

		for (const std::uint64_t shift : shifts)
		{
			const std::uint64_t entry = read_physical_qword((table & page_table_entry_mask) + page_table_index(virtual_address, shift) * 8);

			if ((entry & 1) == 0)
			{
				return 0;
			}

			if ((entry & 0x80) == 0x80 && shift > 12)
			{
				return 1;
			}

			table = entry & page_table_entry_mask;
		}

		return 1;
	}

	std::uint8_t directory_already_listed(const std::vector<std::uint64_t>& directories, const std::uint64_t directory)
	{
		const std::uint64_t masked = directory & cr3_address_mask;

		if (masked == 0)
		{
			return 1;
		}

		for (const std::uint64_t existing : directories)
		{
			if ((existing & cr3_address_mask) == masked)
			{
				return 1;
			}
		}

		return 0;
	}

	// KPTI keeps user mappings in UserDirectoryTableBase. The kernel directory
	// has no user half, so a free-page scan there looks empty and then builds
	// page tables the user thread never walks.
	std::vector<std::uint64_t> directories_for_user_park(const std::uint64_t filter_cr3)
	{
		std::vector<std::uint64_t> directories = {};
		const nt_offsets_t* const nt = nt_offsets_current();
		const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
		const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

		if (nt == nullptr || system_process == aliases.end())
		{
			return directories;
		}

		std::uint64_t eprocess = 0;

		if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
				sizeof(eprocess) ||
			eprocess == 0)
		{
			return directories;
		}

		const std::uint64_t first = eprocess;
		const std::uint64_t filter = filter_cr3 & cr3_address_mask;

		// A user breakpoint names one process. Filter 0 used to walk every process.
		if (filter == 0)
		{
			return directories;
		}

		for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
		{
			std::uint64_t directory = 0;
			std::uint64_t user_directory = 0;

			if (hypercall::read_guest_virtual_memory(&directory, eprocess + nt->eprocess_directory_table_base, sys::current_cr3,
			                                        sizeof(directory)) == sizeof(directory))
			{
				if (nt->eprocess_user_directory_table_base != 0)
				{
					hypercall::read_guest_virtual_memory(&user_directory, eprocess + nt->eprocess_user_directory_table_base,
					                                     sys::current_cr3, sizeof(user_directory));
				}

				const std::uint64_t chosen = (user_directory & cr3_address_mask) != 0 ? user_directory : directory;
				const std::uint8_t matches = static_cast<std::uint8_t>(
					(directory & cr3_address_mask) == filter || (user_directory & cr3_address_mask) == filter ||
					(chosen & cr3_address_mask) == filter);

				if (matches == 1 && directory_already_listed(directories, chosen) == 0)
				{
					directories.push_back(chosen);
				}

				if (filter != 0 && matches == 1)
				{
					break;
				}
			}

			std::uint64_t flink = 0;

			if (hypercall::read_guest_virtual_memory(&flink, eprocess + nt->eprocess_active_process_links, sys::current_cr3,
			                                        sizeof(flink)) != sizeof(flink) ||
				flink == 0)
			{
				break;
			}

			eprocess = flink - nt->eprocess_active_process_links;

			if (eprocess == first)
			{
				break;
			}
		}

		return directories;
	}

	void raise_user_park_lock_quota()
	{
		SIZE_T minimum = 0;
		SIZE_T maximum = 0;
		constexpr SIZE_T want_minimum = 32ull * 1024ull * 1024ull;
		constexpr SIZE_T want_maximum = 64ull * 1024ull * 1024ull;

		if (GetProcessWorkingSetSize(GetCurrentProcess(), &minimum, &maximum) == 0)
		{
			return;
		}

		if (minimum >= want_minimum && maximum >= want_maximum)
		{
			return;
		}

		SetProcessWorkingSetSize(GetCurrentProcess(), minimum > want_minimum ? minimum : want_minimum,
		                         maximum > want_maximum ? maximum : want_maximum);
	}

	std::uint8_t map_user_park_page(const std::uint64_t filter_cr3)
	{
		constexpr std::uint64_t candidates[] = {
			0x0000000030000000ull, 0x0000000050000000ull, 0x0000000070000000ull, 0x00000000A0000000ull,
			0x00000000C0000000ull, 0x00000000E0000000ull, 0x0000000120000000ull, 0x0000000140000000ull,
			0x0000000180000000ull, 0x00000001C0000000ull, 0x0000000220000000ull, 0x0000000280000000ull,
			0x0000000300000000ull, 0x0000000380000000ull, 0x0000000400000000ull, 0x0000000480000000ull};

		raise_user_park_lock_quota();

		const std::vector<std::uint64_t> directories = directories_for_user_park(filter_cr3);

		if (directories.empty() == true)
		{
			return 0;
		}

		for (const std::uint64_t candidate : candidates)
		{
			std::uint8_t occupied = 0;

			for (const std::uint64_t directory : directories)
			{
				if (user_page_is_present(directory, candidate) == 1)
				{
					occupied = 1;

					break;
				}
			}

			if (occupied == 1)
			{
				continue;
			}

			std::uint8_t mapped = 1;

			for (const std::uint64_t directory : directories)
			{
				if (map_user_page(directory, candidate, user_trampoline_physical) == 0)
				{
					mapped = 0;

					break;
				}
			}

			if (mapped == 1)
			{
				user_trampoline_virtual = candidate;

				return 1;
			}
		}

		return 0;
	}

	// The park VA is chosen once. A later process still has to receive that same page.
	std::uint8_t map_existing_user_park(const std::uint64_t filter_cr3)
	{
		if (user_trampoline_virtual == 0 || user_trampoline_physical == 0)
		{
			return 0;
		}

		const std::vector<std::uint64_t> directories = directories_for_user_park(filter_cr3);

		if (directories.empty() == true)
		{
			return 0;
		}

		for (const std::uint64_t directory : directories)
		{
			if (map_user_page(directory, user_trampoline_virtual, user_trampoline_physical) == 0)
			{
				return 0;
			}
		}

		return 1;
	}

	std::uint64_t place_user_trampoline(const std::vector<std::uint8_t>& bytes, const std::uint64_t filter_cr3)
	{
		if (user_trampoline_page == nullptr)
		{
			raise_user_park_lock_quota();
			user_trampoline_page = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(page_size, PAGE_EXECUTE_READWRITE));

			if (user_trampoline_page == nullptr)
			{
				return 0;
			}

			std::memset(user_trampoline_page, 0xCC, page_size);
			user_trampoline_physical = hypercall::translate_guest_virtual_address(
				reinterpret_cast<std::uint64_t>(user_trampoline_page), sys::directory_for_local_memory());

			if (user_trampoline_physical == 0)
			{
				sys::user::free_memory(user_trampoline_page);
				user_trampoline_page = nullptr;

				return 0;
			}
		}

		if (user_trampoline_virtual == 0)
		{
			if (map_user_park_page(filter_cr3) == 0)
			{
				return 0;
			}
		}
		else if (map_existing_user_park(filter_cr3) == 0)
		{
			return 0;
		}

		if (user_trampoline_used + bytes.size() > page_size)
		{
			return 0;
		}

		const std::uint64_t virtual_address = user_trampoline_virtual + user_trampoline_used;

		std::memcpy(user_trampoline_page + user_trampoline_used, bytes.data(), bytes.size());
		FlushInstructionCache(GetCurrentProcess(), user_trampoline_page + user_trampoline_used, bytes.size());
		user_trampoline_used += (bytes.size() + 15) & ~0xFull;

		return virtual_address;
	}


	void free_page(breakpoint_page_t& page)
	{
		if (page.shadow != nullptr)
		{
			sys::user::free_memory(page.shadow);
			page.shadow = nullptr;
		}
	}

	std::uint8_t create_page(const std::uint64_t page_physical, breakpoint_page_t& page_out)
	{
		page_out = {};
		page_out.page_physical = page_physical;
		page_out.shadow = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(page_size, PAGE_READWRITE));

		if (page_out.shadow == nullptr)
		{
			LOG_ERR("failed to allocate breakpoint page");

			return 0;
		}

		const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(page_out.shadow, page_physical, page_size);

		if (bytes_read != page_size)
		{
			free_page(page_out);
			LOG_ERR("failed to read breakpoint page");

			return 0;
		}

		page_out.shadow_physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(page_out.shadow), sys::directory_for_local_memory());

		if (page_out.shadow_physical == 0)
		{
			free_page(page_out);
			LOG_ERR("failed to translate breakpoint page");

			return 0;
		}

		return 1;
	}

	std::uint8_t range_is_avoided(const std::uint64_t current, const std::vector<avoid_range_t>& avoids)
	{
		for (const avoid_range_t& avoid : avoids)
		{
			if (avoid.size != 0 && current >= avoid.address && current < avoid.address + avoid.size)
			{
				return 1;
			}
		}

		return 0;
	}

	std::uint64_t find_cave(const std::uint64_t address, const std::uint64_t size, const std::uint64_t translate_cr3,
	                        const std::vector<avoid_range_t>& avoids)
	{
		HMODULE module = nullptr;

		if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		                       reinterpret_cast<LPCSTR>(address), &module) == 0 || module == nullptr)
		{
			return 0;
		}

		const auto* const base = reinterpret_cast<const std::uint8_t*>(module);
		const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
		const IMAGE_SECTION_HEADER* const section = IMAGE_FIRST_SECTION(nt);

		for (std::uint16_t section_index = 0; section_index < nt->FileHeader.NumberOfSections; section_index++)
		{
			if ((section[section_index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
			{
				continue;
			}

			const std::uint64_t section_size = section[section_index].Misc.VirtualSize;
			std::uint64_t run = 0;
			std::uint64_t run_start = 0;

			for (std::uint64_t index = 0; index < section_size; index++)
			{
				const std::uint64_t current = reinterpret_cast<std::uint64_t>(base) + section[section_index].VirtualAddress + index;
				const std::uint8_t byte = base[section[section_index].VirtualAddress + index];
				const std::uint8_t is_padding = static_cast<std::uint8_t>(byte == 0xCC || byte == 0x90);
				const std::uint8_t avoided = range_is_avoided(current, avoids);

				if (is_padding == 1 && avoided == 0)
				{
					if (run == 0)
					{
						run_start = current;
					}

					run++;

					if (run >= size)
					{
						const std::uint64_t page_offset = run_start & 0xFFFull;

						if (page_offset + size <= page_size &&
							hypercall::translate_guest_virtual_address(run_start, translate_cr3) != 0)
						{
							return run_start;
						}

						const std::uint64_t skip = page_size - (current & 0xFFFull);

						if (skip > 1)
						{
							if (index + skip >= section_size)
							{
								index = section_size;
							}
							else
							{
								index += skip - 1;
							}
						}

						run = 0;
					}
				}
				else
				{
					run = 0;
				}
			}
		}

		return 0;
	}

	std::uint8_t write_rel32_at(std::uint8_t* const displacement, const std::uint64_t next_ip, const std::uint64_t target)
	{
		const std::int64_t delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(next_ip);

		if (delta < static_cast<std::int64_t>(INT32_MIN) || delta > static_cast<std::int64_t>(INT32_MAX))
		{
			return 0;
		}

		*reinterpret_cast<std::int32_t*>(displacement) = static_cast<std::int32_t>(delta);

		return 1;
	}

	std::uint32_t nt_delay_execution_ssn()
	{
		const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		if (ntdll == nullptr)
		{
			return 0;
		}

		const auto* const stub = reinterpret_cast<const std::uint8_t*>(GetProcAddress(ntdll, "NtDelayExecution"));

		if (stub == nullptr || stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8)
		{
			return 0;
		}

		return *reinterpret_cast<const std::uint32_t*>(stub + 4);
	}

	std::uint8_t build_pause_spin2(std::vector<std::uint8_t>& bytes, const std::uint64_t spin2, const std::uint64_t breakpoint_rip,
	                               const std::uint64_t go1, const std::uint64_t park)
	{
		bytes.assign(pause_spin2_template, pause_spin2_template + pause_spin2_size);
		std::memcpy(bytes.data() + 2, &breakpoint_rip, sizeof(breakpoint_rip));
		std::memcpy(bytes.data() + 0x24, &park, sizeof(park));

		if (write_rel32_at(bytes.data() + 0x1A, spin2 + 0x1E, go1) == 0)
		{
			return 0;
		}

		return 1;
	}

	std::uint8_t build_pause_park(std::vector<std::uint8_t>& bytes, const std::uint64_t park, const std::uint64_t after_wait,
	                              const std::uint64_t flag)
	{
		bytes.assign(pause_park_template, pause_park_template + pause_park_size);
		*reinterpret_cast<std::uint32_t*>(bytes.data() + 0x3B) = nt_delay_execution_ssn();

		if (write_rel32_at(bytes.data() + 0x0E, park + 0x13, flag) == 0 ||
			write_rel32_at(bytes.data() + 0x18, park + 0x20, flag) == 0 ||
			write_rel32_at(bytes.data() + 0x21, park + 0x25, after_wait) == 0)
		{
			return 0;
		}

		return 1;
	}

	std::uint8_t stamp_pause_latch_pa(std::vector<std::uint8_t>& bytes, const std::uint64_t latch_physical)
	{
		if (bytes.size() != pause_spin2_size || latch_physical == 0 ||
		    (latch_physical & 0xFFFull) > page_size - sizeof(std::uint64_t))
		{
			return 0;
		}

		std::memcpy(bytes.data() + pause_latch_immediate_offset, &latch_physical, sizeof(latch_physical));

		return 1;
	}

	struct pause_park_site_t
	{
		std::uint64_t park = 0;
		std::uint64_t latch_physical = 0;
	};

	// Park code, an absolute jump back to spin1, the HACLATCH signature, and the latch.
	constexpr std::uint64_t pause_park_tail_size = 12;
	constexpr std::uint64_t pause_park_blob_size = pause_park_size + pause_park_tail_size + 16;

	// reentry is spin1. User wait uses SYSCALL, which replaces RCX and RDX.
	// spin2's CPUID is a hypercall only while RCX still holds the key, so the
	// confirmation must reload that key and the CR3 filter before CPUID.
	std::uint8_t commit_pause_park(std::uint8_t* const page, const std::uint64_t page_virtual,
	                               const std::uint64_t page_physical, const std::uint64_t offset,
	                               const std::uint64_t reentry, pause_park_site_t& site)
	{
		if (page == nullptr || offset + pause_park_blob_size > page_size)
		{
			return 0;
		}

		const std::uint64_t park = page_virtual + offset;
		const std::uint64_t tail = park + pause_park_size;
		const std::uint64_t latch = tail + pause_park_tail_size + sizeof(std::uint64_t);
		std::vector<std::uint8_t> code = {};

		if (build_pause_park(code, park, tail, latch) == 0 || code.size() != pause_park_size)
		{
			return 0;
		}

		std::uint8_t tail_bytes[pause_park_tail_size] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};

		std::memcpy(tail_bytes + 2, &reentry, sizeof(reentry));
		std::memcpy(page + offset, code.data(), code.size());
		std::memcpy(page + offset + pause_park_size, tail_bytes, sizeof(tail_bytes));
		std::memcpy(page + offset + pause_park_size + pause_park_tail_size, &pause_latch_signature,
		            sizeof(pause_latch_signature));
		std::memset(page + offset + pause_park_size + pause_park_tail_size + sizeof(std::uint64_t), 0,
		            sizeof(std::uint64_t));
		FlushInstructionCache(GetCurrentProcess(), page + offset, static_cast<SIZE_T>(pause_park_blob_size));

		site.park = park;
		site.latch_physical = (page_physical & ~0xFFFull) + offset + pause_park_size + pause_park_tail_size +
			sizeof(std::uint64_t);

		return 1;
	}

	std::uint8_t place_user_pause_park(const std::uint64_t filter_cr3, const std::uint64_t reentry, pause_park_site_t& site)
	{
		std::vector<std::uint8_t> placeholder(static_cast<std::size_t>(pause_park_blob_size), 0xCC);
		const std::uint64_t blob = place_user_trampoline(placeholder, filter_cr3);

		if (blob == 0 || user_trampoline_page == nullptr || blob < user_trampoline_virtual)
		{
			return 0;
		}

		return commit_pause_park(user_trampoline_page, user_trampoline_virtual, user_trampoline_physical,
		                         blob - user_trampoline_virtual, reentry, site);
	}

	std::uint64_t find_fit(const std::uint64_t hint, const std::uint64_t translate_cr3, const std::uint64_t maximum,
	                       const std::uint64_t minimum, std::vector<avoid_range_t>& avoids, std::uint64_t& size_out)
	{
		for (std::uint64_t size = maximum; size >= minimum; size--)
		{
			const std::uint64_t found = find_cave(hint, size, translate_cr3, avoids);

			if (found != 0)
			{
				size_out = size;
				avoids.push_back({found, size});

				return found;
			}

			if (size == minimum)
			{
				break;
			}
		}

		size_out = 0;

		return 0;
	}

	std::uint8_t same_cr3(const std::uint64_t left, const std::uint64_t right)
	{
		if (left == 0 || right == 0)
		{
			return 1;
		}

		return static_cast<std::uint8_t>((left & cr3_address_mask) == (right & cr3_address_mask));
	}

	std::uint8_t other_uses_page(const std::uint64_t page_physical, const std::uint64_t except_id)
	{
		for (const breakpoint_t& breakpoint : breakpoints)
		{
			if (breakpoint.id == except_id)
			{
				continue;
			}

			if (breakpoint.page_physical == page_physical || breakpoint.cave_page_physical == page_physical ||
				breakpoint.resume_page_physical == page_physical)
			{
				return 1;
			}

			for (const code_slot_t& slot : breakpoint.slots)
			{
				if (slot.page_physical == page_physical)
				{
					return 1;
				}
			}
		}

		return 0;
	}

	void restore_slot(const code_slot_t& slot)
	{
		breakpoint_page_t* const page = find_page(slot.page_physical);

		if (page == nullptr || slot.original.empty() == true)
		{
			return;
		}

		std::memcpy(page->shadow + slot.offset, slot.original.data(), slot.original.size());
		publish_shadow_bytes(page->shadow, slot.offset, slot.original.size());
	}

	void release_user_slots(breakpoint_t& breakpoint)
	{
		std::vector<std::uint64_t> pages = {};

		for (const code_slot_t& slot : breakpoint.slots)
		{
			std::uint8_t seen = 0;

			for (const std::uint64_t page : pages)
			{
				if (page == slot.page_physical)
				{
					seen = 1;

					break;
				}
			}

			if (seen == 0)
			{
				pages.push_back(slot.page_physical);
			}
		}

		for (const std::uint64_t page_physical : pages)
		{
			const std::uint8_t others = other_uses_page(page_physical, breakpoint.id);

			if (others == 0 && page_physical != breakpoint.page_physical)
			{
				if (hypercall::remove_slat_code_hook(page_physical) == 0)
				{
					LOG_ERR("unable to remove breakpoint cave");

					continue;
				}

				for (std::size_t index = 0; index < breakpoint_pages.size(); index++)
				{
					if (breakpoint_pages[index].page_physical == page_physical)
					{
						free_page(breakpoint_pages[index]);
						breakpoint_pages.erase(breakpoint_pages.begin() + static_cast<std::ptrdiff_t>(index));

						break;
					}
				}
			}
			else
			{
				for (const code_slot_t& slot : breakpoint.slots)
				{
					if (slot.page_physical == page_physical)
					{
						restore_slot(slot);
					}
				}
			}
		}
	}

	std::uint8_t patch_shadow_bytes(const std::uint64_t page_physical, const std::uint64_t offset, const void* const bytes,
	                                const std::uint64_t size)
	{
		breakpoint_page_t* const page = find_page(page_physical);

		if (page == nullptr || page->shadow == nullptr)
		{
			return 0;
		}

		std::memcpy(page->shadow + offset, bytes, static_cast<std::size_t>(size));
		publish_shadow_bytes(page->shadow, offset, size);

		return 1;
	}

	struct reg_binding_t
	{
		const char* name;
		std::uint64_t breakpoint::registers_t::* field;
		std::int32_t live_offset;
		std::uint8_t width;
	};

	constexpr reg_binding_t register_bindings[] = {
		{"rax", &breakpoint::registers_t::rax, 32, 8},
		{"eax", &breakpoint::registers_t::rax, 32, 4},
		{"rcx", &breakpoint::registers_t::rcx, 24, 8},
		{"ecx", &breakpoint::registers_t::rcx, 24, 4},
		{"rdx", &breakpoint::registers_t::rdx, 16, 8},
		{"edx", &breakpoint::registers_t::rdx, 16, 4},
		{"rbx", &breakpoint::registers_t::rbx, 112, 8},
		{"ebx", &breakpoint::registers_t::rbx, 112, 4},
		{"rsp", &breakpoint::registers_t::rsp, -1, 8},
		{"esp", &breakpoint::registers_t::rsp, -1, 4},
		{"rbp", &breakpoint::registers_t::rbp, 104, 8},
		{"ebp", &breakpoint::registers_t::rbp, 104, 4},
		{"rsi", &breakpoint::registers_t::rsi, 96, 8},
		{"esi", &breakpoint::registers_t::rsi, 96, 4},
		{"rdi", &breakpoint::registers_t::rdi, 88, 8},
		{"edi", &breakpoint::registers_t::rdi, 88, 4},
		{"r8", &breakpoint::registers_t::r8, 8, 8},
		{"r8d", &breakpoint::registers_t::r8, 8, 4},
		{"r9", &breakpoint::registers_t::r9, 80, 8},
		{"r9d", &breakpoint::registers_t::r9, 80, 4},
		{"r10", &breakpoint::registers_t::r10, 72, 8},
		{"r10d", &breakpoint::registers_t::r10, 72, 4},
		{"r11", &breakpoint::registers_t::r11, 0, 8},
		{"r11d", &breakpoint::registers_t::r11, 0, 4},
		{"r12", &breakpoint::registers_t::r12, 64, 8},
		{"r12d", &breakpoint::registers_t::r12, 64, 4},
		{"r13", &breakpoint::registers_t::r13, 56, 8},
		{"r13d", &breakpoint::registers_t::r13, 56, 4},
		{"r14", &breakpoint::registers_t::r14, 48, 8},
		{"r14d", &breakpoint::registers_t::r14, 48, 4},
		{"r15", &breakpoint::registers_t::r15, 40, 8},
		{"r15d", &breakpoint::registers_t::r15, 40, 4},
		{"rip", &breakpoint::registers_t::rip, -1, 8},
		{"eip", &breakpoint::registers_t::rip, -1, 4},
		{"efl", &breakpoint::registers_t::rflags, 120, 4},
		{"rflags", &breakpoint::registers_t::rflags, 120, 8},
	};

	std::uint8_t binding_name_equals(const std::string_view left, const char* const right)
	{
		std::uint64_t index = 0;

		while (right[index] != '\0')
		{
			if (index >= left.size())
			{
				return 0;
			}

			const char candidate = static_cast<char>(std::tolower(static_cast<unsigned char>(left[index])));

			if (candidate != right[index])
			{
				return 0;
			}

			index++;
		}

		return static_cast<std::uint8_t>(index == left.size());
	}

	const reg_binding_t* find_binding(const std::string_view name)
	{
		for (const reg_binding_t& binding : register_bindings)
		{
			if (binding_name_equals(name, binding.name) == 1)
			{
				return &binding;
			}
		}

		return nullptr;
	}

	void fill_pause_from_log(breakpoint_t& breakpoint, const trap_frame_log_t& log)
	{
		pause_state.breakpoint_id = breakpoint.id;
		pause_state.registers = {};
		pause_state.registers.rax = log.rax;
		pause_state.registers.rcx = log.rcx;
		pause_state.registers.rdx = log.rdx;
		pause_state.registers.rbx = log.rbx;
		pause_state.registers.rbp = log.rbp;
		pause_state.registers.rsi = log.rsi;
		pause_state.registers.rdi = log.rdi;
		pause_state.registers.r8 = log.r8;
		pause_state.registers.r9 = log.r9;
		pause_state.registers.r10 = log.r10;
		pause_state.registers.r11 = log.r11;
		pause_state.registers.r12 = log.r12;
		pause_state.registers.r13 = log.r13;
		pause_state.registers.r14 = log.r14;
		pause_state.registers.r15 = log.r15;
		pause_state.registers.rip = log.rip;
		pause_state.registers.cr3 = log.cr3;
		pause_state.live_rsp = log.rsp - hypervisor_popped_bytes;
		pause_state.registers.rsp = log.rsp + pause_log_rsp_bias;
		pause_state.rsp_edited = 0;

		std::uint64_t flags = 0;

		if (hypercall::read_guest_virtual_memory(&flags, pause_state.live_rsp + 120, log.cr3, sizeof(flags)) == sizeof(flags))
		{
			pause_state.registers.rflags = flags;
			pause_state.registers.rflags_known = 1;
		}

		pause_state.expected_rip = 0;
		pause_state.valid = 1;
	}

	void observe_logs_impl(const trap_frame_log_t* const logs, const std::uint64_t count)
	{
		if (logs == nullptr || count == 0)
		{
			return;
		}

		for (std::uint64_t index = count; index > 0; index--)
		{
			const trap_frame_log_t& log = logs[index - 1];

			breakpoint_t* matched = nullptr;

			if (pause_state.expected_rip != 0 && log.rip == pause_state.expected_rip &&
				same_cr3(pause_state.registers.cr3, log.cr3) == 1)
			{
				matched = find_breakpoint(pause_state.breakpoint_id);
			}

			if (matched == nullptr)
			{
				for (breakpoint_t& candidate : breakpoints)
				{
					if (candidate.pauses_thread == 1 && candidate.enabled == 1 && candidate.address == log.rip &&
						same_cr3(candidate.cr3, log.cr3) == 1)
					{
						matched = &candidate;

						break;
					}
				}
			}

			if (matched == nullptr)
			{
				continue;
			}

			fill_pause_from_log(*matched, log);

			return;
		}
	}

	std::uint8_t commit_slot(breakpoint_page_t* const shadow, const std::uint64_t page_physical, const std::uint64_t address,
	                         const std::vector<std::uint8_t>& bytes, code_slot_t& slot_out)
	{
		const std::uint64_t offset = address & 0xFFFull;

		if (shadow == nullptr || offset + bytes.size() > page_size)
		{
			return 0;
		}

		slot_out = {};
		slot_out.address = address;
		slot_out.page_physical = page_physical;
		slot_out.offset = offset;
		slot_out.original.assign(shadow->shadow + offset, shadow->shadow + offset + bytes.size());
		slot_out.bytes = bytes;
		std::memcpy(shadow->shadow + offset, bytes.data(), bytes.size());

		return 1;
	}

	std::uint8_t install_user_pause(const std::uint64_t address, const std::uint64_t cr3, const std::uint64_t translate_cr3,
	                                const std::uint64_t page_physical, const std::uint64_t page_offset, breakpoint_page_t* page,
	                                const std::uint8_t created_page, breakpoint_page_t& new_page,
	                                const std::vector<std::uint8_t>& relocated, const std::uint64_t span,
	                                const std::uint64_t jump_size, std::uint64_t& id_out)
	{
		std::vector<breakpoint_page_t> owned = {};

		owned.reserve(16);

		auto fail = [&]() -> std::uint8_t
		{
			for (breakpoint_page_t& owned_page : owned)
			{
				free_page(owned_page);
			}

			owned.clear();

			if (created_page == 1)
			{
				free_page(new_page);
			}

			return 0;
		};

		auto ensure_shadow = [&](const std::uint64_t physical) -> breakpoint_page_t*
		{
			if (physical == page_physical)
			{
				return page;
			}

			for (breakpoint_page_t& existing : breakpoint_pages)
			{
				if (existing.page_physical == physical)
				{
					return &existing;
				}
			}

			for (breakpoint_page_t& existing : owned)
			{
				if (existing.page_physical == physical)
				{
					return &existing;
				}
			}

			if (owned.size() == owned.capacity())
			{
				return nullptr;
			}

			breakpoint_page_t created = {};

			if (create_page(physical, created) == 0)
			{
				return nullptr;
			}

			owned.push_back(std::move(created));

			return &owned.back();
		};

		if (page == nullptr || relocated.empty() == true || jump_size != relative_jump_size)
		{
			LOG_ERR("failed to build the user breakpoint");

			return fail();
		}

		std::vector<avoid_range_t> avoids = {{address, span}};
		std::uint64_t ignored_size = 0;
		std::uint64_t step1_size = 0;
		std::uint64_t step2_size = 0;
		const std::uint64_t step1 = find_fit(address, translate_cr3, 26, 20, avoids, step1_size);
		const std::uint64_t entry1 = find_fit(address, translate_cr3, 25, 25, avoids, ignored_size);
		const std::uint64_t spin2 = find_fit(address, translate_cr3, pause_spin2_size, pause_spin2_size, avoids, ignored_size);
		const std::uint64_t step2 = find_fit(address, translate_cr3, 25, 19, avoids, step2_size);
		const std::uint64_t go1 = find_fit(address, translate_cr3, 22, 22, avoids, ignored_size);
		const std::uint64_t go2 = find_fit(address, translate_cr3, 22, 22, avoids, ignored_size);
		const std::uint64_t spin1 = find_fit(address, translate_cr3, 20, 20, avoids, ignored_size);
		const std::uint64_t go3 = find_fit(address, translate_cr3, 14, 14, avoids, ignored_size);
		const std::uint64_t entry2 = find_fit(address, translate_cr3, 9, 9, avoids, ignored_size);
		const std::uint64_t resume_size = relocated.size() + relative_jump_size;
		const std::uint64_t resume = find_cave(address, resume_size, translate_cr3, avoids);

		if (step1 == 0 || entry1 == 0 || spin2 == 0 || step2 == 0 || go1 == 0 || go2 == 0 || spin1 == 0 || go3 == 0 ||
			entry2 == 0)
		{
			LOG_ERR("no code cave for the user breakpoint");

			return fail();
		}

		if (resume == 0)
		{
			LOG_ERR("no code cave for the resumed instructions");

			return fail();
		}

		pause_park_site_t park_site = {};

		if (place_user_pause_park(cr3, spin1, park_site) == 0)
		{
			LOG_ERR("failed to place the pause park");

			return fail();
		}

		const std::int64_t hook_delta = static_cast<std::int64_t>(entry1) - static_cast<std::int64_t>(address + relative_jump_size);

		if (hook_delta < static_cast<std::int64_t>(INT32_MIN) || hook_delta > static_cast<std::int64_t>(INT32_MAX))
		{
			LOG_ERR("user breakpoint continuation is out of range");

			return fail();
		}

		hypercall_info_t call_info = {};

		call_info.primary_key = hypercall_primary_key;
		call_info.secondary_key = hypercall_secondary_key;
		call_info.call_type = hypercall_type_t::breakpoint;
		call_info.call_reserved_data = breakpoint_pause_poll;

		std::vector<std::uint8_t> entry1_bytes = {
			0x9C, 0x53, 0x55, 0x56, 0x57, 0x41, 0x51, 0x41, 0x52, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x50, 0x51,
			0x52, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> entry2_bytes = {0x41, 0x50, 0x41, 0x53, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> spin1_bytes = {0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                         0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> spin2_bytes;
		std::vector<std::uint8_t> pop_prefix = {0x41, 0x5B, 0x41, 0x58, 0x5A, 0x59, 0x58, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D,
		                                        0x41, 0x5C, 0x41, 0x5A, 0xE9, 0x00, 0x00, 0x00, 0x00};
		// Ten nops stand where `mov rsp, imm64` is written once the thread is actually paused.
		// Other processes take this path immediately, and rsp is already restored by the pops.
		std::vector<std::uint8_t> go2_bytes = {0x41, 0x59, 0x5F, 0x5E, 0x5D, 0x5B, 0x9D, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		                                       0x90, 0x90, 0x90, 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> go3_bytes(absolute_jump_size);
		std::vector<std::uint8_t> resume_body = relocated;
		std::vector<std::uint8_t> go1_bytes = pop_prefix;

		resume_body.resize(resume_size);
		write_absolute_jump(go3_bytes.data(), resume);

		if (write_rel32_at(&entry1_bytes[21], entry1 + entry1_bytes.size(), entry2) == 0 ||
			write_rel32_at(&entry2_bytes[5], entry2 + entry2_bytes.size(), spin1) == 0 ||
			write_rel32_at(&spin1_bytes[16], spin1 + spin1_bytes.size(), spin2) == 0 ||
			build_pause_spin2(spin2_bytes, spin2, address, go1, park_site.park) == 0 ||
			stamp_pause_latch_pa(spin2_bytes, park_site.latch_physical) == 0 ||
			write_rel32_at(&go1_bytes[18], go1 + go1_bytes.size(), go2) == 0 ||
			write_rel32_at(&go2_bytes[18], go2 + go2_bytes.size(), go3) == 0)
		{
			LOG_ERR("user breakpoint continuation is out of range");

			return fail();
		}

		const std::int64_t resume_delta = static_cast<std::int64_t>(address + span) -
			static_cast<std::int64_t>(resume + relocated.size() + relative_jump_size);

		if (resume_delta < static_cast<std::int64_t>(INT32_MIN) || resume_delta > static_cast<std::int64_t>(INT32_MAX))
		{
			LOG_ERR("user breakpoint continuation is out of range");

			return fail();
		}

		write_relative_jump(resume_body.data() + relocated.size(), resume + relocated.size(), address + span);
		*reinterpret_cast<std::uint32_t*>(&spin1_bytes[1]) = static_cast<std::uint32_t>(call_info.value);
		std::memcpy(&spin1_bytes[7], &cr3, sizeof(cr3));

		if (entry1_bytes.size() != 25 || entry2_bytes.size() != 9 || spin1_bytes.size() != 20 ||
			spin2_bytes.size() != pause_spin2_size || go1_bytes.size() != 22 || go2_bytes.size() != 22)
		{
			LOG_ERR("failed to build the user breakpoint");

			return fail();
		}

		struct piece_t
		{
			std::uint64_t address;
			std::vector<std::uint8_t>* bytes;
		};

		const piece_t pieces[] = {
			{entry1, &entry1_bytes}, {entry2, &entry2_bytes}, {spin1, &spin1_bytes}, {spin2, &spin2_bytes},
			{go1, &go1_bytes}, {go2, &go2_bytes}, {go3, &go3_bytes}, {resume, &resume_body}};

		breakpoint_t breakpoint = {};

		breakpoint.address = address;
		breakpoint.cr3 = cr3;
		breakpoint.page_physical = page_physical;
		breakpoint.page_offset = page_offset;
		breakpoint.span = span;
		breakpoint.pauses_thread = 1;
		breakpoint.enabled = 1;
		breakpoint.entry_address = entry1;
		breakpoint.resume_address = resume;
		breakpoint.step_address[0] = step1;
		breakpoint.step_address[1] = step2;
		breakpoint.step_capacity[0] = step1_size;
		breakpoint.step_capacity[1] = step2_size;

		std::vector<std::uint8_t> step1_bytes(static_cast<std::size_t>(step1_size), 0x90);
		std::vector<std::uint8_t> step2_bytes(static_cast<std::size_t>(step2_size), 0x90);

		if (write_rel32_at(&step1_bytes[1], step1 + relative_jump_size, entry1) == 0 ||
			write_rel32_at(&step2_bytes[1], step2 + relative_jump_size, entry1) == 0)
		{
			LOG_ERR("user breakpoint continuation is out of range");

			return fail();
		}

		step1_bytes[0] = 0xE9;
		step2_bytes[0] = 0xE9;
		const piece_t step_pieces[] = {{step1, &step1_bytes}, {step2, &step2_bytes}};

		auto abort_install = [&](const std::uint8_t patch_written) -> std::uint8_t
		{
			for (const code_slot_t& slot : breakpoint.slots)
			{
				std::uint8_t is_owned = 0;

				for (const breakpoint_page_t& owned_page : owned)
				{
					if (owned_page.page_physical == slot.page_physical)
					{
						is_owned = 1;

						break;
					}
				}

				if (is_owned == 1 || slot.original.empty() == true)
				{
					continue;
				}

				breakpoint_page_t* const shadow = slot.page_physical == page_physical ? page : find_page(slot.page_physical);

				if (shadow != nullptr)
				{
					std::memcpy(shadow->shadow + slot.offset, slot.original.data(), slot.original.size());
				}
			}

			if (patch_written == 1 && breakpoint.original_bytes.empty() == false && page != nullptr)
			{
				std::memcpy(page->shadow + page_offset, breakpoint.original_bytes.data(), breakpoint.original_bytes.size());
			}

			return fail();
		};

		auto place_piece = [&](const piece_t& piece, code_slot_t& slot_out) -> std::uint8_t
		{
			const std::uint64_t physical = hypercall::translate_guest_virtual_address(piece.address, translate_cr3);

			if (physical == 0)
			{
				LOG_ERR("failed to translate user breakpoint cave");

				return 0;
			}

			breakpoint_page_t* const shadow = ensure_shadow(page_base_of(physical));

			if (shadow == nullptr)
			{
				return 0;
			}

			if (commit_slot(shadow, page_base_of(physical), piece.address, *piece.bytes, slot_out) == 0)
			{
				LOG_ERR("user breakpoint cave crosses a page");

				return 0;
			}

			return 1;
		};

		for (const piece_t& piece : pieces)
		{
			code_slot_t slot = {};

			if (place_piece(piece, slot) == 0)
			{
				return abort_install(0);
			}

			if (piece.address == spin2)
			{
				breakpoint.spin_page_physical = slot.page_physical;
				breakpoint.spin_rip_offset = slot.offset + 2;
			}
			else if (piece.address == go2)
			{
				breakpoint.go_rsp_page_physical = slot.page_physical;
				breakpoint.go_rsp_offset = slot.offset + 7;
			}
			else if (piece.address == go3)
			{
				breakpoint.go_target_page_physical = slot.page_physical;
				breakpoint.go_target_offset = slot.offset;
			}

			breakpoint.slots.push_back(std::move(slot));
		}

		for (std::uint8_t index = 0; index < 2; index++)
		{
			code_slot_t slot = {};

			if (place_piece(step_pieces[index], slot) == 0)
			{
				return abort_install(0);
			}

			breakpoint.step_page_physical[index] = slot.page_physical;
			breakpoint.step_offset[index] = slot.offset;
			breakpoint.slots.push_back(std::move(slot));
		}

		std::vector<std::uint8_t> patch(static_cast<std::size_t>(jump_size));

		write_relative_jump(patch.data(), address, entry1);
		breakpoint.original_bytes.assign(page->shadow + page_offset, page->shadow + page_offset + patch.size());
		breakpoint.patch_bytes = patch;
		std::memcpy(page->shadow + page_offset, patch.data(), patch.size());

		std::vector<std::uint64_t> hooked_now = {};

		auto hook_new_page = [&](const std::uint64_t physical, breakpoint_page_t* const shadow) -> std::uint8_t
		{
			for (const breakpoint_page_t& existing : breakpoint_pages)
			{
				if (existing.page_physical == physical)
				{
					return 1;
				}
			}

			if (shadow == nullptr || hypercall::add_slat_code_hook(physical, shadow->shadow_physical) == 0)
			{
				return 0;
			}

			hooked_now.push_back(physical);

			return 1;
		};

		auto rollback_hooks = [&]()
		{
			for (const std::uint64_t physical : hooked_now)
			{
				if (hypercall::remove_slat_code_hook(physical) == 0)
				{
					LOG_ERR("unable to remove breakpoint page");
				}
			}
		};

		if (created_page == 1 && hook_new_page(page_physical, page) == 0)
		{
			rollback_hooks();
			LOG_ERR("failed to hook breakpoint page");

			return abort_install(1);
		}

		for (breakpoint_page_t& owned_page : owned)
		{
			if (hook_new_page(owned_page.page_physical, &owned_page) == 0)
			{
				rollback_hooks();
				LOG_ERR("failed to hook user breakpoint cave");

				return abort_install(1);
			}
		}

		if (created_page == 1)
		{
			breakpoint_pages.push_back(new_page);
		}

		for (breakpoint_page_t& owned_page : owned)
		{
			breakpoint_pages.push_back(owned_page);
		}

		owned.clear();

		breakpoint_page_t* const site_page = find_page(page_physical);

		if (site_page == nullptr)
		{
			LOG_ERR("failed to hook breakpoint page");

			return 0;
		}

		publish_shadow_bytes(site_page->shadow, page_offset, patch.size());

		for (const code_slot_t& slot : breakpoint.slots)
		{
			breakpoint_page_t* const slot_page = find_page(slot.page_physical);

			if (slot_page != nullptr)
			{
				publish_shadow_bytes(slot_page->shadow, slot.offset, slot.bytes.size());
			}
		}

		breakpoint.id = allocate_id();
		id_out = breakpoint.id;
		breakpoints.push_back(std::move(breakpoint));
		LOG_INFO("breakpoint {} set, the thread pauses until g", id_out);

		return 1;
	}

	std::uint8_t user_directory_is_live(const std::uint64_t cr3)
	{
		if ((cr3 & cr3_address_mask) == 0)
		{
			return 0;
		}

		return static_cast<std::uint8_t>(directories_for_user_park(cr3).empty() == false);
	}

	// The owner thread exited while the pause was still latched. Later hits are
	// non-owners and return 1 until this record is dropped.
	void release_dead_pause_owner()
	{
		if (pause_state.valid == 0 || pause_state.registers.cr3 == 0 ||
			user_directory_is_live(pause_state.registers.cr3) == 1)
		{
			return;
		}

		hypercall::breakpoint_abandon();
		pause_state.valid = 0;
		pause_state.breakpoint_id = ~0ull;
	}

	std::uint8_t drop_stale_user_breakpoints(const std::uint64_t page_physical, const std::uint64_t page_offset,
	                                         const std::uint64_t span)
	{
		std::vector<std::uint64_t> stale = {};

		for (const breakpoint_t& breakpoint : breakpoints)
		{
			if (is_user_address(breakpoint.address) == 0 || breakpoint.page_physical != page_physical)
			{
				continue;
			}

			if (ranges_overlap(page_offset, span, breakpoint.page_offset, breakpoint.span) == 0)
			{
				continue;
			}

			if (breakpoint.cr3 != 0 && user_directory_is_live(breakpoint.cr3) == 1)
			{
				continue;
			}

			stale.push_back(breakpoint.id);
		}

		for (const std::uint64_t id : stale)
		{
			if (pause_state.valid == 1 && pause_state.breakpoint_id == id)
			{
				hypercall::breakpoint_abandon();
				pause_state.valid = 0;
				pause_state.breakpoint_id = ~0ull;
			}

			if (breakpoint::remove(id) == 0)
			{
				return 0;
			}
		}

		return 1;
	}

	std::uint8_t arm_direct_pause_impl(const std::uint64_t logical_rip, const std::uint64_t cr3, const std::uint64_t cave_hint,
	                                   std::uint64_t& entry_out, std::uint64_t& id_out)
	{
		entry_out = 0;
		id_out = 0;

		if (is_user_address(logical_rip) == 0 || cr3 == 0 || is_user_address(cave_hint) == 0)
		{
			LOG_ERR("failed to build the user breakpoint");

			return 0;
		}

		std::uint64_t stale_id = 0;

		for (const breakpoint_t& breakpoint : breakpoints)
		{
			if (breakpoint.address != logical_rip || same_cr3(breakpoint.cr3, cr3) == 0)
			{
				continue;
			}

			if (breakpoint.page_physical == 0 && breakpoint.slots.empty() == false)
			{
				stale_id = breakpoint.id;

				break;
			}

			LOG_ERR("breakpoint already exists");

			return 0;
		}

		if (stale_id != 0 && breakpoint::remove(stale_id) == 0)
		{
			return 0;
		}

		std::vector<breakpoint_page_t> owned = {};

		owned.reserve(16);

		auto fail = [&]() -> std::uint8_t
		{
			for (breakpoint_page_t& owned_page : owned)
			{
				free_page(owned_page);
			}

			owned.clear();

			return 0;
		};

		auto ensure_shadow = [&](const std::uint64_t physical) -> breakpoint_page_t*
		{
			for (breakpoint_page_t& existing : breakpoint_pages)
			{
				if (existing.page_physical == physical)
				{
					return &existing;
				}
			}

			for (breakpoint_page_t& existing : owned)
			{
				if (existing.page_physical == physical)
				{
					return &existing;
				}
			}

			if (owned.size() == owned.capacity())
			{
				return nullptr;
			}

			breakpoint_page_t created = {};

			if (create_page(physical, created) == 0)
			{
				return nullptr;
			}

			owned.push_back(std::move(created));

			return &owned.back();
		};

		std::vector<avoid_range_t> avoids = {{logical_rip, 16}};
		std::uint64_t ignored_size = 0;
		std::uint64_t step1_size = 0;
		std::uint64_t step2_size = 0;
		const std::uint64_t step1 = find_fit(cave_hint, cr3, 26, 20, avoids, step1_size);
		const std::uint64_t entry1 = find_fit(cave_hint, cr3, 25, 25, avoids, ignored_size);
		const std::uint64_t spin2 = find_fit(cave_hint, cr3, pause_spin2_size, pause_spin2_size, avoids, ignored_size);
		const std::uint64_t step2 = find_fit(cave_hint, cr3, 25, 19, avoids, step2_size);
		const std::uint64_t go1 = find_fit(cave_hint, cr3, 22, 22, avoids, ignored_size);
		const std::uint64_t go2 = find_fit(cave_hint, cr3, 22, 22, avoids, ignored_size);
		const std::uint64_t spin1 = find_fit(cave_hint, cr3, 20, 20, avoids, ignored_size);
		const std::uint64_t go3 = find_fit(cave_hint, cr3, 14, 14, avoids, ignored_size);
		const std::uint64_t entry2 = find_fit(cave_hint, cr3, 9, 9, avoids, ignored_size);

		if (step1 == 0 || entry1 == 0 || spin2 == 0 || step2 == 0 || go1 == 0 || go2 == 0 || spin1 == 0 || go3 == 0 ||
			entry2 == 0)
		{
			LOG_ERR("no code cave for the user breakpoint");

			return fail();
		}

		pause_park_site_t park_site = {};

		if (place_user_pause_park(cr3, spin1, park_site) == 0)
		{
			LOG_ERR("failed to place the pause park");

			return fail();
		}

		hypercall_info_t call_info = {};

		call_info.primary_key = hypercall_primary_key;
		call_info.secondary_key = hypercall_secondary_key;
		call_info.call_type = hypercall_type_t::breakpoint;
		call_info.call_reserved_data = breakpoint_pause_poll;

		std::vector<std::uint8_t> entry1_bytes = {
			0x9C, 0x53, 0x55, 0x56, 0x57, 0x41, 0x51, 0x41, 0x52, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x50, 0x51,
			0x52, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> entry2_bytes = {0x41, 0x50, 0x41, 0x53, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> spin1_bytes = {0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                         0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> spin2_bytes;
		std::vector<std::uint8_t> pop_prefix = {0x41, 0x5B, 0x41, 0x58, 0x5A, 0x59, 0x58, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D,
		                                        0x41, 0x5C, 0x41, 0x5A, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> go1_bytes = pop_prefix;
		std::vector<std::uint8_t> go2_bytes = {0x41, 0x59, 0x5F, 0x5E, 0x5D, 0x5B, 0x9D, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		                                       0x90, 0x90, 0x90, 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> go3_bytes(absolute_jump_size);

		write_absolute_jump(go3_bytes.data(), logical_rip);

		if (write_rel32_at(&entry1_bytes[21], entry1 + entry1_bytes.size(), entry2) == 0 ||
			write_rel32_at(&entry2_bytes[5], entry2 + entry2_bytes.size(), spin1) == 0 ||
			write_rel32_at(&spin1_bytes[16], spin1 + spin1_bytes.size(), spin2) == 0 ||
			build_pause_spin2(spin2_bytes, spin2, logical_rip, go1, park_site.park) == 0 ||
			stamp_pause_latch_pa(spin2_bytes, park_site.latch_physical) == 0 ||
			write_rel32_at(&go1_bytes[18], go1 + go1_bytes.size(), go2) == 0 ||
			write_rel32_at(&go2_bytes[18], go2 + go2_bytes.size(), go3) == 0)
		{
			LOG_ERR("user breakpoint continuation is out of range");

			return fail();
		}

		*reinterpret_cast<std::uint32_t*>(&spin1_bytes[1]) = static_cast<std::uint32_t>(call_info.value);
		// The caller points one thread at this cave. That thread may return with either
		// directory table. The shared instruction is not patched, so other processes do not enter.
		const std::uint64_t filter_cr3 = 0;
		std::memcpy(&spin1_bytes[7], &filter_cr3, sizeof(filter_cr3));

		struct piece_t
		{
			std::uint64_t address;
			std::vector<std::uint8_t>* bytes;
		};

		const piece_t pieces[] = {
			{entry1, &entry1_bytes}, {entry2, &entry2_bytes}, {spin1, &spin1_bytes}, {spin2, &spin2_bytes},
			{go1, &go1_bytes}, {go2, &go2_bytes}, {go3, &go3_bytes}};

		breakpoint_t breakpoint = {};

		breakpoint.address = logical_rip;
		breakpoint.cr3 = 0;
		breakpoint.span = 0;
		breakpoint.pauses_thread = 1;
		breakpoint.enabled = 1;
		breakpoint.entry_address = entry1;
		breakpoint.resume_address = logical_rip;
		breakpoint.step_address[0] = step1;
		breakpoint.step_address[1] = step2;
		breakpoint.step_capacity[0] = step1_size;
		breakpoint.step_capacity[1] = step2_size;

		std::vector<std::uint8_t> step1_bytes(static_cast<std::size_t>(step1_size), 0x90);
		std::vector<std::uint8_t> step2_bytes(static_cast<std::size_t>(step2_size), 0x90);

		if (write_rel32_at(&step1_bytes[1], step1 + relative_jump_size, entry1) == 0 ||
			write_rel32_at(&step2_bytes[1], step2 + relative_jump_size, entry1) == 0)
		{
			LOG_ERR("user breakpoint continuation is out of range");

			return fail();
		}

		step1_bytes[0] = 0xE9;
		step2_bytes[0] = 0xE9;
		const piece_t step_pieces[] = {{step1, &step1_bytes}, {step2, &step2_bytes}};

		auto place_piece = [&](const piece_t& piece, code_slot_t& slot_out) -> std::uint8_t
		{
			const std::uint64_t physical = hypercall::translate_guest_virtual_address(piece.address, cr3);

			if (physical == 0)
			{
				LOG_ERR("failed to translate user breakpoint cave");

				return 0;
			}

			breakpoint_page_t* const shadow = ensure_shadow(page_base_of(physical));

			if (shadow == nullptr)
			{
				return 0;
			}

			if (commit_slot(shadow, page_base_of(physical), piece.address, *piece.bytes, slot_out) == 0)
			{
				LOG_ERR("user breakpoint cave crosses a page");

				return 0;
			}

			return 1;
		};

		for (const piece_t& piece : pieces)
		{
			code_slot_t slot = {};

			if (place_piece(piece, slot) == 0)
			{
				return fail();
			}

			if (piece.address == spin2)
			{
				breakpoint.spin_page_physical = slot.page_physical;
				breakpoint.spin_rip_offset = slot.offset + 2;
			}
			else if (piece.address == go2)
			{
				breakpoint.go_rsp_page_physical = slot.page_physical;
				breakpoint.go_rsp_offset = slot.offset + 7;
			}
			else if (piece.address == go3)
			{
				breakpoint.go_target_page_physical = slot.page_physical;
				breakpoint.go_target_offset = slot.offset;
			}

			breakpoint.slots.push_back(std::move(slot));
		}

		for (std::uint8_t index = 0; index < 2; index++)
		{
			code_slot_t slot = {};

			if (place_piece(step_pieces[index], slot) == 0)
			{
				return fail();
			}

			breakpoint.step_page_physical[index] = slot.page_physical;
			breakpoint.step_offset[index] = slot.offset;
			breakpoint.slots.push_back(std::move(slot));
		}

		std::vector<std::uint64_t> hooked_now = {};

		auto hook_new_page = [&](const std::uint64_t physical, breakpoint_page_t* const shadow) -> std::uint8_t
		{
			for (const breakpoint_page_t& existing : breakpoint_pages)
			{
				if (existing.page_physical == physical)
				{
					return 1;
				}
			}

			if (shadow == nullptr || hypercall::add_slat_code_hook(physical, shadow->shadow_physical) == 0)
			{
				return 0;
			}

			hooked_now.push_back(physical);

			return 1;
		};

		for (breakpoint_page_t& owned_page : owned)
		{
			if (hook_new_page(owned_page.page_physical, &owned_page) == 0)
			{
				for (const std::uint64_t physical : hooked_now)
				{
					if (hypercall::remove_slat_code_hook(physical) == 0)
					{
						LOG_ERR("unable to remove breakpoint page");
					}
				}

				LOG_ERR("failed to hook user breakpoint cave");

				return fail();
			}
		}

		for (breakpoint_page_t& owned_page : owned)
		{
			breakpoint_pages.push_back(owned_page);
		}

		owned.clear();

		for (const code_slot_t& slot : breakpoint.slots)
		{
			breakpoint_page_t* const slot_page = find_page(slot.page_physical);

			if (slot_page != nullptr)
			{
				publish_shadow_bytes(slot_page->shadow, slot.offset, slot.bytes.size());
			}
		}

		breakpoint.id = allocate_id();
		entry_out = entry1;
		id_out = breakpoint.id;
		breakpoints.push_back(std::move(breakpoint));
		LOG_INFO("breakpoint {} set, the thread pauses until g", id_out);

		return 1;
	}
}

std::uint8_t install_kernel_pause(std::uint64_t address, std::uint64_t cr3, std::uint64_t& id_out, std::uint8_t patch_site = 1);

std::uint8_t breakpoint::arm_direct_pause(const std::uint64_t logical_rip, const std::uint64_t cr3, const std::uint64_t cave_hint,
                                          std::uint64_t& entry_out, std::uint64_t& id_out)
{
	return arm_direct_pause_impl(logical_rip, cr3, cave_hint, entry_out, id_out);
}

std::uint8_t breakpoint::arm_kernel_pause(const std::uint64_t logical_rip, const std::uint64_t cr3, std::uint64_t& entry_out,
                                          std::uint64_t& id_out)
{
	entry_out = 0;
	id_out = 0;

	if (is_user_address(logical_rip) == 1 || breakpoint::add(logical_rip, cr3, id_out) == 0)
	{
		return 0;
	}

	const breakpoint_t* const installed = find_breakpoint(id_out);

	if (installed == nullptr || installed->entry_address == 0)
	{
		if (id_out != 0)
		{
			breakpoint::remove(id_out);
		}

		id_out = 0;

		return 0;
	}

	entry_out = installed->entry_address;

	return 1;
}

std::uint8_t breakpoint::arm_kernel_redirect(const std::uint64_t logical_rip, const std::uint64_t cr3, std::uint64_t& entry_out,
                                             std::uint64_t& id_out)
{
	entry_out = 0;
	id_out = 0;

	if (is_user_address(logical_rip) == 1 || install_kernel_pause(logical_rip, cr3, id_out, 0) == 0)
	{
		return 0;
	}

	const breakpoint_t* const installed = find_breakpoint(id_out);

	if (installed == nullptr || installed->entry_address == 0)
	{
		if (id_out != 0)
		{
			breakpoint::remove(id_out);
		}

		id_out = 0;

		return 0;
	}

	entry_out = installed->entry_address;

	return 1;
}

std::uint64_t breakpoint::cr3_for_process(const std::uint64_t process_id)
{
	const nt_offsets_t* const nt = nt_offsets_current();
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

	if (nt == nullptr || system_process == aliases.end())
	{
		return 0;
	}

	std::uint64_t eprocess = 0;

	if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
			sizeof(eprocess) || eprocess == 0)
	{
		return 0;
	}

	const std::uint64_t first = eprocess;

	for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
	{
		std::uint64_t pid = 0;

		if (hypercall::read_guest_virtual_memory(&pid, eprocess + nt->eprocess_unique_process_id, sys::current_cr3, sizeof(pid)) ==
				sizeof(pid) && pid == process_id)
		{
			std::uint64_t directory = 0;

			if (hypercall::read_guest_virtual_memory(&directory, eprocess + nt->eprocess_directory_table_base, sys::current_cr3,
			                                        sizeof(directory)) == sizeof(directory))
			{
				return directory;
			}

			return 0;
		}

		std::uint64_t flink = 0;

		if (hypercall::read_guest_virtual_memory(&flink, eprocess + nt->eprocess_active_process_links, sys::current_cr3,
		                                        sizeof(flink)) != sizeof(flink) || flink == 0)
		{
			break;
		}

		eprocess = flink - nt->eprocess_active_process_links;

		if (eprocess == first)
		{
			break;
		}
	}

	return 0;
}

	constexpr std::uint64_t kernel_pause_fixed =
		25 + 9 + 20 + pause_spin2_size + 22 + 22 + 14 + 26 + 25;
	constexpr std::uint64_t kernel_pause_slack = 96;
	constexpr std::uint64_t kernel_pause_need = kernel_pause_fixed + kernel_pause_slack;

	std::uint64_t kernel_directory()
	{
		const nt_offsets_t* const nt = nt_offsets_current();
		const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
		const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

		if (nt == nullptr || system_process == aliases.end())
		{
			return 0;
		}

		std::uint64_t eprocess = 0;

		if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
				sizeof(eprocess) ||
			eprocess == 0)
		{
			return 0;
		}

		std::uint64_t directory = 0;

		if (hypercall::read_guest_virtual_memory(&directory, eprocess + nt->eprocess_directory_table_base, sys::current_cr3,
		                                        sizeof(directory)) != sizeof(directory) ||
			directory == 0)
		{
			return 0;
		}

		return directory;
	}

	std::uint8_t* kernel_pause_page = nullptr;
	std::uint64_t kernel_pause_physical = 0;
	std::uint64_t kernel_pause_virtual = 0;
	std::uint64_t kernel_pause_used = 0;

	std::uint8_t ensure_supervisor_entry(const std::uint64_t table_physical, const std::uint64_t index,
	                                     std::uint64_t& next_physical, const std::uint8_t create)
	{
		const std::uint64_t entry_physical = (table_physical & page_table_entry_mask) + index * 8;
		const std::uint64_t entry = read_physical_qword(entry_physical);

		if ((entry & 1) == 1)
		{
			if ((entry & 0x80) == 0x80 || (entry & (1ull << 63)) != 0)
			{
				return 0;
			}

			next_physical = entry & page_table_entry_mask;

			return 1;
		}

		if (create == 0)
		{
			return 0;
		}

		auto* const table_page = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(page_size, PAGE_READWRITE));

		if (table_page == nullptr)
		{
			return 0;
		}

		std::memset(table_page, 0, page_size);

		const std::uint64_t table_page_physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(table_page), sys::directory_for_local_memory());

		if (table_page_physical == 0)
		{
			sys::user::free_memory(table_page);

			return 0;
		}

		const std::uint64_t new_entry = (table_page_physical & page_table_entry_mask) | 0x3;

		if (write_physical_qword(entry_physical, new_entry) == 0)
		{
			sys::user::free_memory(table_page);

			return 0;
		}

		next_physical = table_page_physical & page_table_entry_mask;

		return 1;
	}

	std::uint8_t map_supervisor_page(const std::uint64_t cr3, const std::uint64_t virtual_address,
	                                 const std::uint64_t physical_address)
	{
		if ((virtual_address & 0xFFFF800000000000ull) != 0xFFFF800000000000ull)
		{
			return 0;
		}

		std::uint64_t table = cr3 & page_table_entry_mask;
		const std::uint64_t shifts[] = {39, 30, 21};

		for (std::size_t level = 0; level < 3; level++)
		{
			std::uint64_t next = 0;

			if (ensure_supervisor_entry(table, page_table_index(virtual_address, shifts[level]), next,
			                            level == 0 ? 0 : 1) == 0)
			{
				return 0;
			}

			table = next;
		}

		const std::uint64_t pte_physical = table + page_table_index(virtual_address, 12) * 8;
		const std::uint64_t pte = read_physical_qword(pte_physical);

		if ((pte & 1) == 1)
		{
			return static_cast<std::uint8_t>((pte & page_table_entry_mask) == (physical_address & page_table_entry_mask));
		}

		const std::uint64_t new_pte = (physical_address & page_table_entry_mask) | 0x63;

		return write_physical_qword(pte_physical, new_pte);
	}

	std::uint8_t ensure_kernel_pause_page(const std::uint64_t kernel_cr3)
	{
		if (kernel_pause_page != nullptr)
		{
			return 1;
		}

		const auto module = sys::kernel::modules_list.find("ntoskrnl.exe");

		if (module == sys::kernel::modules_list.end() || module->second.base_address == 0 || module->second.size == 0)
		{
			return 0;
		}

		auto* const page = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(page_size, PAGE_EXECUTE_READWRITE));

		if (page == nullptr)
		{
			return 0;
		}

		std::memset(page, 0xCC, page_size);

		const std::uint64_t physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(page), sys::directory_for_local_memory());

		if (physical == 0)
		{
			sys::user::free_memory(page);

			return 0;
		}

		const std::uint64_t start = (module->second.base_address + module->second.size + page_size - 1) & ~0xFFFull;
		constexpr std::uint64_t scan = 64ull * 1024ull * 1024ull;

		for (std::uint64_t offset = 0; offset < scan; offset += page_size)
		{
			const std::uint64_t candidate = start + offset;

			if (user_page_is_present(kernel_cr3, candidate) == 1)
			{
				continue;
			}

			if (map_supervisor_page(kernel_cr3, candidate, physical) == 0)
			{
				continue;
			}

			kernel_pause_page = page;
			kernel_pause_physical = physical & page_table_entry_mask;
			kernel_pause_virtual = candidate;
			kernel_pause_used = 0;

			return 1;
		}

		sys::user::free_memory(page);

		return 0;
	}

	std::uint8_t place_kernel_pause_park(const std::uint64_t kernel_cr3, const std::uint64_t reentry, pause_park_site_t& site)
	{
		if (ensure_kernel_pause_page(kernel_cr3) == 0)
		{
			return 0;
		}

		if (kernel_pause_used + pause_park_blob_size > page_size)
		{
			return 0;
		}

		const std::uint64_t offset = kernel_pause_used;

		if (commit_pause_park(kernel_pause_page, kernel_pause_virtual, kernel_pause_physical, offset, reentry, site) == 0)
		{
			return 0;
		}

		kernel_pause_used += (pause_park_blob_size + 15) & ~0xFull;

		return 1;
	}

	std::uint8_t rel32_reaches(const std::uint64_t site, const std::uint64_t target)
	{
		const std::int64_t delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(site + relative_jump_size);

		return static_cast<std::uint8_t>(delta >= static_cast<std::int64_t>(INT32_MIN) &&
			delta <= static_cast<std::int64_t>(INT32_MAX));
	}

	std::uint8_t guest_read(void* const destination, const std::uint64_t address, const std::uint64_t cr3,
	                        const std::uint64_t size)
	{
		return static_cast<std::uint8_t>(hypercall::read_guest_virtual_memory(destination, address, cr3, size) == size);
	}

	std::uint8_t cave_conflicts(const std::uint64_t address, const std::uint64_t size, const std::uint64_t site)
	{
		if (ranges_overlap(address, size, site, 32) == 1)
		{
			return 1;
		}

		const std::uint64_t holder = hook::detour_holder_base();

		if (holder != 0 && address < holder + page_size && holder < address + size)
		{
			return 1;
		}

		for (const breakpoint_t& breakpoint : breakpoints)
		{
			if (breakpoint.span != 0 && ranges_overlap(address, size, breakpoint.address, breakpoint.span) == 1)
			{
				return 1;
			}

			for (const code_slot_t& slot : breakpoint.slots)
			{
				if (slot.bytes.empty() == false && ranges_overlap(address, size, slot.address, slot.bytes.size()) == 1)
				{
					return 1;
				}
			}
		}

		return 0;
	}

	std::uint64_t padding_run(const std::uint8_t* const page, const std::uint64_t page_address, const std::uint64_t readable,
	                          const std::uint64_t site, const std::uint64_t kernel_cr3)
	{
		std::uint64_t run = 0;
		std::uint64_t run_start = 0;

		for (std::uint64_t index = 0; index < readable; index++)
		{
			const std::uint64_t current = page_address + index;
			const std::uint8_t byte = page[index];
			const std::uint8_t padding = static_cast<std::uint8_t>(byte == 0xCC || byte == 0x90);

			if (padding == 0)
			{
				run = 0;

				continue;
			}

			if (run == 0)
			{
				run_start = current;
			}

			run++;

			if ((run_start & 0xFFFull) + kernel_pause_need > page_size)
			{
				run = 0;

				continue;
			}

			if (run < kernel_pause_need)
			{
				continue;
			}

			if (cave_conflicts(run_start, kernel_pause_need, site) == 1)
			{
				run = 0;

				continue;
			}

			const std::uint64_t physical = hypercall::translate_guest_virtual_address(run_start, kernel_cr3);

			if (physical == 0 || hook::contains_hooked_page(physical) == 1)
			{
				run = 0;

				continue;
			}

			return run_start;
		}

		return 0;
	}

	std::uint64_t find_kernel_cave(const std::uint64_t site, const std::uint64_t kernel_cr3)
	{
		const auto module = sys::kernel::modules_list.find("ntoskrnl.exe");

		if (module == sys::kernel::modules_list.end() || module->second.base_address == 0)
		{
			return 0;
		}

		const std::uint64_t image = module->second.base_address;
		std::uint8_t headers[0x1000] = {};

		if (guest_read(headers, image, kernel_cr3, sizeof(headers)) == 0)
		{
			return 0;
		}

		const std::uint32_t lfanew = *reinterpret_cast<std::uint32_t*>(headers + 0x3C);

		if (lfanew > sizeof(headers) - 0x108)
		{
			return 0;
		}

		const std::uint16_t section_count = *reinterpret_cast<std::uint16_t*>(headers + lfanew + 6);
		const std::uint16_t optional_size = *reinterpret_cast<std::uint16_t*>(headers + lfanew + 20);
		const std::uint32_t section_offset = lfanew + 24 + optional_size;

		if (section_count == 0 || section_count > 96 || section_offset + section_count * 40 > sizeof(headers))
		{
			return 0;
		}

		const std::uint64_t holder_page = hook::detour_holder_base() & ~0xFFFull;

		for (std::uint8_t pass = 0; pass < 2; pass++)
		{
			for (std::uint16_t section_index = 0; section_index < section_count; section_index++)
			{
				const std::uint8_t* const section = headers + section_offset + section_index * 40;
				const std::uint32_t virtual_size = *reinterpret_cast<const std::uint32_t*>(section + 8);
				const std::uint32_t virtual_address = *reinterpret_cast<const std::uint32_t*>(section + 12);
				const std::uint32_t characteristics = *reinterpret_cast<const std::uint32_t*>(section + 36);
				char name[9] = {};

				std::memcpy(name, section, 8);

				const std::uint8_t is_pad = static_cast<std::uint8_t>(std::string_view(name).find("Pad") != std::string_view::npos);

				if ((characteristics & 0x20000000) == 0 || virtual_size == 0 || (pass == 0 && is_pad == 0) ||
					(pass == 1 && is_pad == 1))
				{
					continue;
				}

				for (std::uint32_t offset = 0; offset < virtual_size; offset += static_cast<std::uint32_t>(page_size))
				{
					const std::uint64_t page_address = image + virtual_address + offset;

					if (holder_page != 0 && page_address == holder_page)
					{
						continue;
					}

					const std::uint64_t readable = virtual_size - offset < page_size ? virtual_size - offset : page_size;
					std::uint8_t page[0x1000] = {};

					if (guest_read(page, page_address, kernel_cr3, readable) == 0)
					{
						continue;
					}

					const std::uint64_t found = padding_run(page, page_address, readable, site, kernel_cr3);

					if (found != 0)
					{
						return found;
					}
				}
			}
		}

		return 0;
	}

	std::uint8_t install_kernel_pause(const std::uint64_t address, const std::uint64_t cr3, std::uint64_t& id_out,
	                                 const std::uint8_t patch_site)
	{
		id_out = 0;

		const std::uint64_t kernel_cr3 = kernel_directory();

		if (kernel_cr3 == 0)
		{
			LOG_ERR("kernel directory is not available");

			return 0;
		}

		const std::uint64_t cave = find_kernel_cave(address, kernel_cr3);

		if (cave == 0)
		{
			LOG_ERR("no code cave for the kernel breakpoint");

			return 0;
		}

		const std::uint8_t cave_in_range = rel32_reaches(address, cave);
		const std::uint64_t jump_size = cave_in_range == 1 ? relative_jump_size : absolute_jump_size;
		const std::uint64_t return_jump_size = cave_in_range == 1 ? relative_jump_size : absolute_jump_size;
		const std::uint64_t physical_address = hypercall::translate_guest_virtual_address(address, kernel_cr3);

		if (physical_address == 0)
		{
			LOG_ERR("failed to translate address");

			return 0;
		}

		if (hook::contains_hooked_page(physical_address) == 1)
		{
			LOG_ERR("page is used by a kernel hook");

			return 0;
		}

		const std::uint64_t page_physical = page_base_of(physical_address);
		const std::uint64_t page_offset = physical_address & 0xFFFull;
		const std::uint64_t bytes_left_in_page = page_size - page_offset;
		const std::uint64_t bytes_until_next = bytes_until_next_entry(address);
		const std::uint64_t bytes_available = bytes_left_in_page < bytes_until_next ? bytes_left_in_page : bytes_until_next;
		std::vector<std::uint8_t> instruction_buffer(static_cast<std::size_t>(bytes_left_in_page + 15));

		if (hypercall::read_guest_virtual_memory(instruction_buffer.data(), address, kernel_cr3, bytes_left_in_page) == 0)
		{
			LOG_ERR("failed to read breakpoint site");

			return 0;
		}

		const auto aligned_bytes = hook_disasm::get_routine_aligned_bytes(instruction_buffer.data(), jump_size, address);

		if (aligned_bytes.first.empty() == true || aligned_bytes.second < jump_size)
		{
			LOG_ERR("failed to decode breakpoint site");

			return 0;
		}

		if (aligned_bytes.second > bytes_available)
		{
			LOG_ERR(bytes_until_next <= bytes_left_in_page ? "breakpoint would overwrite the next function"
			                                               : "breakpoint crosses a page");

			return 0;
		}

		if (aligned_bytes.first.size() + absolute_jump_size > kernel_pause_slack)
		{
			LOG_ERR("breakpoint site is too large for the kernel pause stub");

			return 0;
		}

		for (const breakpoint_t& breakpoint : breakpoints)
		{
			if (breakpoint.page_physical == page_physical &&
				ranges_overlap(page_offset, aligned_bytes.second, breakpoint.page_offset, breakpoint.span) == 1)
			{
				LOG_ERR("breakpoint overlaps an existing breakpoint");

				return 0;
			}
		}

		const std::uint64_t resume_size = aligned_bytes.first.size() + return_jump_size;
		std::uint64_t cursor = cave;
		const std::uint64_t entry1 = cursor;

		cursor += 25;

		const std::uint64_t entry2 = cursor;

		cursor += 9;

		const std::uint64_t spin1 = cursor;

		cursor += 20;

		const std::uint64_t spin2 = cursor;

		cursor += pause_spin2_size;

		const std::uint64_t go1 = cursor;

		cursor += 22;

		const std::uint64_t go2 = cursor;

		cursor += 22;

		const std::uint64_t go3 = cursor;

		cursor += 14;

		const std::uint64_t resume = cursor;

		cursor += resume_size;

		const std::uint64_t step1 = cursor;

		cursor += 26;

		const std::uint64_t step2 = cursor;

		cursor += 25;

		if (cursor - cave > kernel_pause_need || (cave & 0xFFFull) + (cursor - cave) > page_size)
		{
			LOG_ERR("no code cave for the kernel breakpoint");

			return 0;
		}

		pause_park_site_t park_site = {};

		if (place_kernel_pause_park(kernel_cr3, spin1, park_site) == 0)
		{
			LOG_ERR("failed to place the pause park");

			return 0;
		}

		hypercall_info_t call_info = {};

		call_info.primary_key = hypercall_primary_key;
		call_info.secondary_key = hypercall_secondary_key;
		call_info.call_type = hypercall_type_t::breakpoint;
		call_info.call_reserved_data = breakpoint_pause_poll;

		std::vector<std::uint8_t> entry1_bytes = {
			0x9C, 0x53, 0x55, 0x56, 0x57, 0x41, 0x51, 0x41, 0x52, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x50, 0x51,
			0x52, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> entry2_bytes = {0x41, 0x50, 0x41, 0x53, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> spin1_bytes = {0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                         0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> spin2_bytes;
		std::vector<std::uint8_t> pop_prefix = {0x41, 0x5B, 0x41, 0x58, 0x5A, 0x59, 0x58, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D,
		                                        0x41, 0x5C, 0x41, 0x5A, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> go2_bytes = {0x41, 0x59, 0x5F, 0x5E, 0x5D, 0x5B, 0x9D, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		                                       0x90, 0x90, 0x90, 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00};
		std::vector<std::uint8_t> go3_bytes(absolute_jump_size);
		std::vector<std::uint8_t> resume_body = aligned_bytes.first;
		std::vector<std::uint8_t> go1_bytes = pop_prefix;

		resume_body.resize(static_cast<std::size_t>(resume_size));
		// A redirected thread must resume at the original instruction with its own RSP.
		// Copying an RSP-relative instruction out of KiSwapContext computes the wrong address.
		write_absolute_jump(go3_bytes.data(), patch_site == 1 ? resume : address);

		if (return_jump_size == relative_jump_size)
		{
			write_relative_jump(resume_body.data() + aligned_bytes.first.size(), resume + aligned_bytes.first.size(),
			                    address + aligned_bytes.second);
		}
		else
		{
			write_absolute_jump(resume_body.data() + aligned_bytes.first.size(), address + aligned_bytes.second);
		}

		if (write_rel32_at(&entry1_bytes[21], entry1 + entry1_bytes.size(), entry2) == 0 ||
			write_rel32_at(&entry2_bytes[5], entry2 + entry2_bytes.size(), spin1) == 0 ||
			write_rel32_at(&spin1_bytes[16], spin1 + spin1_bytes.size(), spin2) == 0 ||
			build_pause_spin2(spin2_bytes, spin2, address, go1, park_site.park) == 0 ||
			stamp_pause_latch_pa(spin2_bytes, park_site.latch_physical) == 0 ||
			write_rel32_at(&go1_bytes[18], go1 + go1_bytes.size(), go2) == 0 ||
			write_rel32_at(&go2_bytes[18], go2 + go2_bytes.size(), go3) == 0)
		{
			LOG_ERR("kernel breakpoint continuation is out of range");

			return 0;
		}

		*reinterpret_cast<std::uint32_t*>(&spin1_bytes[1]) = static_cast<std::uint32_t>(call_info.value);
		std::memcpy(&spin1_bytes[7], &cr3, sizeof(cr3));

		struct piece_t
		{
			std::uint64_t address;
			std::vector<std::uint8_t>* bytes;
		};

		const piece_t pieces[] = {
			{entry1, &entry1_bytes}, {entry2, &entry2_bytes}, {spin1, &spin1_bytes}, {spin2, &spin2_bytes},
			{go1, &go1_bytes}, {go2, &go2_bytes}, {go3, &go3_bytes}, {resume, &resume_body}};

		breakpoint_t breakpoint = {};

		breakpoint.address = address;
		breakpoint.cr3 = cr3;
		breakpoint.page_physical = page_physical;
		breakpoint.page_offset = page_offset;
		breakpoint.span = aligned_bytes.second;
		breakpoint.pauses_thread = 1;
		breakpoint.enabled = 1;
		breakpoint.entry_address = entry1;
		breakpoint.resume_address = resume;
		breakpoint.step_address[0] = step1;
		breakpoint.step_address[1] = step2;
		breakpoint.step_capacity[0] = 26;
		breakpoint.step_capacity[1] = 25;

		std::vector<std::uint8_t> step1_bytes(26, 0x90);
		std::vector<std::uint8_t> step2_bytes(25, 0x90);

		if (write_rel32_at(&step1_bytes[1], step1 + relative_jump_size, entry1) == 0 ||
			write_rel32_at(&step2_bytes[1], step2 + relative_jump_size, entry1) == 0)
		{
			LOG_ERR("kernel breakpoint continuation is out of range");

			return 0;
		}

		step1_bytes[0] = 0xE9;
		step2_bytes[0] = 0xE9;

		const piece_t step_pieces[] = {{step1, &step1_bytes}, {step2, &step2_bytes}};
		std::vector<breakpoint_page_t> owned = {};

		owned.reserve(4);

		auto fail = [&]() -> std::uint8_t
		{
			for (breakpoint_page_t& owned_page : owned)
			{
				free_page(owned_page);
			}

			return 0;
		};

		auto ensure_shadow = [&](const std::uint64_t physical) -> breakpoint_page_t*
		{
			for (breakpoint_page_t& existing : breakpoint_pages)
			{
				if (existing.page_physical == physical)
				{
					return &existing;
				}
			}

			for (breakpoint_page_t& existing : owned)
			{
				if (existing.page_physical == physical)
				{
					return &existing;
				}
			}

			breakpoint_page_t created = {};

			if (create_page(physical, created) == 0)
			{
				return nullptr;
			}

			owned.push_back(std::move(created));

			return &owned.back();
		};

		auto place_piece = [&](const piece_t& piece, code_slot_t& slot_out) -> std::uint8_t
		{
			const std::uint64_t physical = hypercall::translate_guest_virtual_address(piece.address, kernel_cr3);

			if (physical == 0)
			{
				LOG_ERR("failed to translate kernel breakpoint cave");

				return 0;
			}

			breakpoint_page_t* const shadow = ensure_shadow(page_base_of(physical));

			if (shadow == nullptr)
			{
				return 0;
			}

			if (commit_slot(shadow, page_base_of(physical), piece.address, *piece.bytes, slot_out) == 0)
			{
				LOG_ERR("kernel breakpoint cave crosses a page");

				return 0;
			}

			return 1;
		};

		for (const piece_t& piece : pieces)
		{
			code_slot_t slot = {};

			if (place_piece(piece, slot) == 0)
			{
				return fail();
			}

			if (piece.address == spin2)
			{
				breakpoint.spin_page_physical = slot.page_physical;
				breakpoint.spin_rip_offset = slot.offset + 2;
			}
			else if (piece.address == go2)
			{
				breakpoint.go_rsp_page_physical = slot.page_physical;
				breakpoint.go_rsp_offset = slot.offset + 7;
			}
			else if (piece.address == go3)
			{
				breakpoint.go_target_page_physical = slot.page_physical;
				breakpoint.go_target_offset = slot.offset;
			}

			breakpoint.slots.push_back(std::move(slot));
		}

		for (std::uint8_t index = 0; index < 2; index++)
		{
			code_slot_t slot = {};

			if (place_piece(step_pieces[index], slot) == 0)
			{
				return fail();
			}

			breakpoint.step_page_physical[index] = slot.page_physical;
			breakpoint.step_offset[index] = slot.offset;
			breakpoint.slots.push_back(std::move(slot));
		}

		if (patch_site == 0)
		{
			breakpoint.page_physical = 0;
		}

		breakpoint_page_t* site = patch_site == 0 ? nullptr : ensure_shadow(page_physical);

		if (patch_site == 1 && site == nullptr)
		{
			LOG_ERR("failed to allocate breakpoint page");

			return fail();
		}

		std::vector<std::uint8_t> patch(static_cast<std::size_t>(jump_size));

		if (patch_site == 1)
		{
			if (jump_size == relative_jump_size)
			{
				write_relative_jump(patch.data(), address, entry1);
			}
			else
			{
				write_absolute_jump(patch.data(), entry1);
			}

			breakpoint.original_bytes.assign(site->shadow + page_offset, site->shadow + page_offset + patch.size());
			breakpoint.patch_bytes = patch;
			std::memcpy(site->shadow + page_offset, patch.data(), patch.size());
		}

		std::uint8_t site_existed = 0;

		for (const breakpoint_page_t& existing : breakpoint_pages)
		{
			if (existing.page_physical == page_physical)
			{
				site_existed = 1;

				break;
			}
		}

		std::vector<std::uint64_t> hooked_now = {};

		auto hook_new_page = [&](const std::uint64_t physical) -> std::uint8_t
		{
			for (const breakpoint_page_t& existing : breakpoint_pages)
			{
				if (existing.page_physical == physical)
				{
					return 1;
				}
			}

			for (breakpoint_page_t& owned_page : owned)
			{
				if (owned_page.page_physical != physical)
				{
					continue;
				}

				if (hypercall::add_slat_code_hook(physical, owned_page.shadow_physical) == 0)
				{
					return 0;
				}

				hooked_now.push_back(physical);

				return 1;
			}

			return 0;
		};

		for (breakpoint_page_t& owned_page : owned)
		{
			if (hook_new_page(owned_page.page_physical) == 0)
			{
				for (const std::uint64_t physical : hooked_now)
				{
					if (hypercall::remove_slat_code_hook(physical) == 0)
					{
						LOG_ERR("unable to remove breakpoint page");
					}
				}

				LOG_ERR("failed to hook kernel breakpoint page");

				if (site_existed == 1 && breakpoint.original_bytes.empty() == false)
				{
					std::memcpy(site->shadow + page_offset, breakpoint.original_bytes.data(), breakpoint.original_bytes.size());
				}

				return fail();
			}
		}

		for (breakpoint_page_t& owned_page : owned)
		{
			breakpoint_pages.push_back(owned_page);
		}

		owned.clear();

		for (const code_slot_t& slot : breakpoint.slots)
		{
			breakpoint_page_t* const slot_page = find_page(slot.page_physical);

			if (slot_page != nullptr)
			{
				publish_shadow_bytes(slot_page->shadow, slot.offset, slot.bytes.size());
			}
		}

		breakpoint_page_t* const site_page = find_page(page_physical);

		if (site_page != nullptr)
		{
			publish_shadow_bytes(site_page->shadow, page_offset, patch.size());
		}

		breakpoint.id = allocate_id();
		id_out = breakpoint.id;
		breakpoints.push_back(std::move(breakpoint));
		LOG_INFO("breakpoint {} set, the thread pauses until g", id_out);

		return 1;
	}


//
// User execution on Intel uses EPROCESS.UserDirectoryTableBase while KVA
// shadow is on. DirectoryTableBase is the kernel directory and does not match
// the CR3 seen at the breakpoint. AMD leaves the user directory empty, so the
// kernel directory stays in use.
//
static std::uint64_t user_execution_cr3(const std::uint64_t cr3, const std::uint64_t address)
{
	const nt_offsets_t* const nt = nt_offsets_current();
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

	if (nt == nullptr || nt->eprocess_user_directory_table_base == 0 || system_process == aliases.end() ||
		sys::current_cr3 == 0)
	{
		return cr3;
	}

	std::uint64_t eprocess = 0;

	if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
			sizeof(eprocess) || eprocess == 0)
	{
		return cr3;
	}

	const std::uint64_t first = eprocess;

	for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
	{
		std::uint64_t directory = 0;
		std::uint64_t user_directory = 0;

		const std::uint8_t have_directory = static_cast<std::uint8_t>(
			hypercall::read_guest_virtual_memory(&directory, eprocess + nt->eprocess_directory_table_base, sys::current_cr3,
			                                     sizeof(directory)) == sizeof(directory) &&
			(directory & cr3_address_mask) != 0);
		const std::uint8_t have_user = static_cast<std::uint8_t>(
			hypercall::read_guest_virtual_memory(&user_directory, eprocess + nt->eprocess_user_directory_table_base,
			                                     sys::current_cr3, sizeof(user_directory)) == sizeof(user_directory) &&
			(user_directory & cr3_address_mask) != 0);
		const std::uint8_t matches = static_cast<std::uint8_t>(
			(have_directory == 1 && (directory & cr3_address_mask) == (cr3 & cr3_address_mask)) ||
			(have_user == 1 && (user_directory & cr3_address_mask) == (cr3 & cr3_address_mask)));

		if (matches == 1 && have_user == 1 &&
			hypercall::translate_guest_virtual_address(address, user_directory) != 0)
		{
			return user_directory;
		}

		if (matches == 1)
		{
			return cr3;
		}

		std::uint64_t flink = 0;

		if (hypercall::read_guest_virtual_memory(&flink, eprocess + nt->eprocess_active_process_links, sys::current_cr3,
		                                        sizeof(flink)) != sizeof(flink) || flink == 0)
		{
			break;
		}

		eprocess = flink - nt->eprocess_active_process_links;

		if (eprocess == first)
		{
			break;
		}
	}

	return cr3;
}

std::uint8_t breakpoint::add(const std::uint64_t address, const std::uint64_t cr3, std::uint64_t& id_out)
{
	if (is_user_address(address) == 1 && cr3 == 0)
	{
		LOG_ERR("user breakpoint requires a process id");

		return 0;
	}

	release_dead_pause_owner();

	const std::uint64_t effective_cr3 = is_user_address(address) == 1 && cr3 != 0 ? user_execution_cr3(cr3, address) : cr3;

	for (const breakpoint_t& breakpoint : breakpoints)
	{
		if (breakpoint.address == address && breakpoint.cr3 == effective_cr3)
		{
			LOG_ERR("breakpoint already exists");

			return 0;
		}
	}

	if (is_user_address(address) == 0)
	{
		return install_kernel_pause(address, cr3, id_out);
	}

	const std::uint64_t translate_cr3 = effective_cr3 == 0 ? sys::current_cr3 : effective_cr3;

	if (translate_cr3 == 0)
	{
		LOG_ERR("current cr3 is not set");

		return 0;
	}

	const std::uint64_t physical_address = hypercall::translate_guest_virtual_address(address, translate_cr3);

	if (physical_address == 0)
	{
		LOG_ERR("failed to translate address");

		return 0;
	}

	if (hook::contains_hooked_page(physical_address) == 1)
	{
		LOG_ERR("page is used by a kernel hook");

		return 0;
	}

	const std::uint64_t page_physical = page_base_of(physical_address);
	const std::uint64_t page_offset = physical_address & 0xFFFull;
	const std::uint64_t jump_size = relative_jump_size;
	const std::uint64_t bytes_left_in_page = page_size - page_offset;
	const std::uint64_t bytes_until_next = bytes_until_next_entry(address);
	const std::uint64_t bytes_available = bytes_left_in_page < bytes_until_next ? bytes_left_in_page : bytes_until_next;

	std::vector<std::uint8_t> instruction_buffer(static_cast<std::size_t>(bytes_left_in_page + 15));
	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		instruction_buffer.data(), address, translate_cr3, bytes_left_in_page);

	if (bytes_read == 0)
	{
		LOG_ERR("failed to read breakpoint site");

		return 0;
	}

	const auto aligned_bytes = hook_disasm::get_routine_aligned_bytes(instruction_buffer.data(), jump_size, address);

	if (aligned_bytes.first.empty() == true || aligned_bytes.second < jump_size)
	{
		LOG_ERR("failed to decode breakpoint site");

		return 0;
	}

	if (aligned_bytes.second > bytes_available)
	{
		if (bytes_until_next <= bytes_left_in_page)
		{
			LOG_ERR("breakpoint would overwrite the next function");
		}
		else
		{
			LOG_ERR("breakpoint crosses a page");
		}

		return 0;
	}

	if (is_user_address(address) == 1 &&
		drop_stale_user_breakpoints(page_physical, page_offset, aligned_bytes.second) == 0)
	{
		return 0;
	}

	for (const breakpoint_t& breakpoint : breakpoints)
	{
		if (breakpoint.page_physical == page_physical &&
			ranges_overlap(page_offset, aligned_bytes.second, breakpoint.page_offset, breakpoint.span) == 1)
		{
			LOG_ERR("breakpoint overlaps an existing breakpoint");

			return 0;
		}
	}

	breakpoint_page_t* page = find_page(page_physical);
	breakpoint_page_t new_page = {};
	const std::uint8_t created_page = page == nullptr ? 1 : 0;

	if (created_page == 1)
	{
		if (create_page(page_physical, new_page) == 0)
		{
			return 0;
		}

		page = &new_page;
	}

	return install_user_pause(address, effective_cr3, translate_cr3, page_physical, page_offset, page, created_page, new_page,
	                          aligned_bytes.first, aligned_bytes.second, jump_size, id_out);
}

std::uint8_t breakpoint::remove(const std::uint64_t id)
{
	breakpoint_t* const breakpoint = find_breakpoint(id);

	if (breakpoint == nullptr)
	{
		LOG_ERR("breakpoint not found");

		return 0;
	}

	if (pause_state.valid == 1 && pause_state.breakpoint_id == id)
	{
		LOG_ERR("thread is paused on this breakpoint; use g before bc");

		return 0;
	}

	breakpoint_page_t* const page = find_page(breakpoint->page_physical);

	if (page == nullptr)
	{
		if (breakpoint->page_physical != 0 || breakpoint->slots.empty() == true)
		{
			LOG_ERR("breakpoint page not found");

			return 0;
		}

		release_user_slots(*breakpoint);

		for (std::size_t index = 0; index < breakpoints.size(); index++)
		{
			if (breakpoints[index].id == id)
			{
				breakpoints.erase(breakpoints.begin() + static_cast<std::ptrdiff_t>(index));

				break;
			}
		}

		LOG_INFO("breakpoint {} cleared", id);

		return 1;
	}

	const std::uint64_t page_physical = breakpoint->page_physical;
	const std::uint8_t last_on_page = static_cast<std::uint8_t>(other_uses_page(page_physical, id) == 0);

	if (last_on_page == 1 && hypercall::remove_slat_code_hook(page_physical) == 0)
	{
		LOG_ERR("unable to remove breakpoint page");

		return 0;
	}

	if (breakpoint->enabled == 1 && last_on_page == 0)
	{
		std::memcpy(page->shadow + breakpoint->page_offset, breakpoint->original_bytes.data(),
		            breakpoint->original_bytes.size());
		publish_shadow_bytes(page->shadow, breakpoint->page_offset, breakpoint->original_bytes.size());
	}

	if (breakpoint->pauses_thread == 0)
	{
		void* const detour_buffer = kernel_detour_holder::get_allocation_from_offset(breakpoint->detour_offset);

		kernel_detour_holder::free_memory(detour_buffer);
	}
	else if (breakpoint->slots.empty() == false)
	{
		release_user_slots(*breakpoint);
	}
	else
	{
		breakpoint_page_t* const cave_page = find_page(breakpoint->cave_page_physical);
		const std::uint8_t cave_is_site = static_cast<std::uint8_t>(breakpoint->cave_page_physical == page_physical);
		std::uint64_t cave_users = 0;

		for (const breakpoint_t& existing : breakpoints)
		{
			if (existing.pauses_thread == 1 && existing.cave_page_physical == breakpoint->cave_page_physical)
			{
				cave_users++;
			}
		}

		if (cave_page != nullptr && cave_users == 1 && cave_is_site == 0)
		{
			if (hypercall::remove_slat_code_hook(breakpoint->cave_page_physical) == 0)
			{
				LOG_ERR("unable to remove breakpoint cave");

				return 0;
			}
		}
		else if (cave_page != nullptr && breakpoint->enabled == 1)
		{
			std::memcpy(cave_page->shadow + breakpoint->cave_offset, breakpoint->cave_original.data(),
			            breakpoint->cave_original.size());
			publish_shadow_bytes(cave_page->shadow, breakpoint->cave_offset, breakpoint->cave_original.size());
		}

		if (cave_page != nullptr && cave_users == 1 && cave_is_site == 0)
		{
			free_page(*cave_page);

			for (std::size_t index = 0; index < breakpoint_pages.size(); index++)
			{
				if (breakpoint_pages[index].page_physical == breakpoint->cave_page_physical)
				{
					breakpoint_pages.erase(breakpoint_pages.begin() + static_cast<std::ptrdiff_t>(index));

					break;
				}
			}
		}

		breakpoint_page_t* const resume_page = find_page(breakpoint->resume_page_physical);
		const std::uint8_t resume_is_other = static_cast<std::uint8_t>(
			breakpoint->resume_page_physical != page_physical && breakpoint->resume_page_physical != breakpoint->cave_page_physical);
		std::uint64_t resume_users = 0;

		for (const breakpoint_t& existing : breakpoints)
		{
			if (existing.pauses_thread == 1 && existing.resume_page_physical == breakpoint->resume_page_physical)
			{
				resume_users++;
			}
		}

		if (resume_page != nullptr && resume_users == 1 && resume_is_other == 1)
		{
			if (hypercall::remove_slat_code_hook(breakpoint->resume_page_physical) == 0)
			{
				LOG_ERR("unable to remove resumed instructions");

				return 0;
			}

			free_page(*resume_page);

			for (std::size_t index = 0; index < breakpoint_pages.size(); index++)
			{
				if (breakpoint_pages[index].page_physical == breakpoint->resume_page_physical)
				{
					breakpoint_pages.erase(breakpoint_pages.begin() + static_cast<std::ptrdiff_t>(index));

					break;
				}
			}
		}
		else if (resume_page != nullptr && breakpoint->enabled == 1 && breakpoint->resume_bytes.empty() == false)
		{
			std::memcpy(resume_page->shadow + breakpoint->resume_offset, breakpoint->resume_original.data(),
			            breakpoint->resume_original.size());
			publish_shadow_bytes(resume_page->shadow, breakpoint->resume_offset, breakpoint->resume_original.size());
		}
	}



	for (std::size_t index = 0; index < breakpoints.size(); index++)
	{
		if (breakpoints[index].id == id)
		{
			breakpoints.erase(breakpoints.begin() + static_cast<std::ptrdiff_t>(index));

			break;
		}
	}

	if (page_has_breakpoint(page_physical) == 0)
	{
		free_page(*page);

		for (std::size_t index = 0; index < breakpoint_pages.size(); index++)
		{
			if (breakpoint_pages[index].page_physical == page_physical)
			{
				breakpoint_pages.erase(breakpoint_pages.begin() + static_cast<std::ptrdiff_t>(index));

				break;
			}
		}
	}

	LOG_INFO("breakpoint {} cleared", id);

	return 1;
}

std::uint8_t breakpoint::remove_all()
{
	if (breakpoints.empty() == true)
	{
		LOG_ERR("no breakpoints");

		return 0;
	}

	while (breakpoints.empty() == false)
	{
		const std::uint64_t id = breakpoints.back().id;

		if (remove(id) == 0)
		{
			return 0;
		}
	}

	return 1;
}

std::uint8_t breakpoint::set_enabled(const std::uint64_t id, const std::uint8_t enabled)
{
	breakpoint_t* const breakpoint = find_breakpoint(id);

	if (breakpoint == nullptr)
	{
		LOG_ERR("breakpoint not found");

		return 0;
	}

	if (breakpoint->enabled == enabled)
	{
		return 1;
	}

	if (pause_state.valid == 1 && pause_state.breakpoint_id == id)
	{
		LOG_ERR("thread is paused on this breakpoint; use g before bd");

		return 0;
	}

	breakpoint_page_t* const page = find_page(breakpoint->page_physical);

	if (page == nullptr)
	{
		if (breakpoint->page_physical != 0 || breakpoint->patch_bytes.empty() == false)
		{
			LOG_ERR("breakpoint page not found");

			return 0;
		}

		breakpoint->enabled = enabled;
		LOG_INFO("breakpoint {} {}", id, enabled == 1 ? "enabled" : "disabled");

		return 1;
	}

	write_breakpoint_bytes(*page, *breakpoint, enabled);
	breakpoint->enabled = enabled;

	LOG_INFO("breakpoint {} {}", id, enabled == 1 ? "enabled" : "disabled");

	return 1;
}

std::uint8_t breakpoint::set_all_enabled(const std::uint8_t enabled)
{
	if (breakpoints.empty() == true)
	{
		LOG_ERR("no breakpoints");

		return 0;
	}

	for (const breakpoint_t& breakpoint : breakpoints)
	{
		if (set_enabled(breakpoint.id, enabled) == 0)
		{
			return 0;
		}
	}

	return 1;
}

std::vector<breakpoint::info_t> breakpoint::list()
{
	std::vector<info_t> infos = {};

	infos.reserve(breakpoints.size());

	for (const breakpoint_t& breakpoint : breakpoints)
	{
		info_t info = {};

		info.id = breakpoint.id;
		info.address = breakpoint.address;
		info.cr3 = breakpoint.cr3;
		info.enabled = breakpoint.enabled;
		info.pauses_thread = breakpoint.pauses_thread;
		infos.push_back(info);
	}

	return infos;
}

std::vector<breakpoint::monitor_site_t> monitor_site_list = {};
std::deque<breakpoint::monitor_hit_t> monitor_hit_list = {};

void breakpoint::clean_up()
{
	monitor_site_list.clear();
	monitor_hit_list.clear();

	if (pause_state.valid == 1)
	{
		resume_paused();
	}

	while (breakpoints.empty() == false)
	{
		if (remove(breakpoints.back().id) == 0)
		{
			break;
		}
	}
}

std::deque<trap_frame_log_t> pending_logs = {};

constexpr std::size_t monitor_site_limit = 64;
constexpr std::size_t monitor_hit_limit = 2048;

std::uint8_t monitor_log_matches(const breakpoint::monitor_site_t& site, const std::uint64_t rip)
{
	if (rip == 0)
	{
		return 0;
	}

	if (rip == site.address || rip == site.log_rip)
	{
		return 1;
	}

	if (site.span != 0 && rip >= site.address && rip - site.address < site.span)
	{
		return 1;
	}

	return 0;
}

void note_one_monitor_log(const trap_frame_log_t& log)
{
	if (log.rip == 0)
	{
		return;
	}

	for (breakpoint::monitor_site_t& site : monitor_site_list)
	{
		if (monitor_log_matches(site, log.rip) == 0)
		{
			continue;
		}

		site.hits++;

		if (monitor_hit_list.size() == monitor_hit_limit)
		{
			monitor_hit_list.pop_front();
		}

		breakpoint::monitor_hit_t hit = {};
		hit.address = site.address;
		hit.log = log;
		monitor_hit_list.push_back(hit);

		return;
	}
}

void remember_flushed_logs(const trap_frame_log_t* const logs, const std::uint64_t count)
{
	constexpr std::uint64_t pending_log_limit = 2840;

	if (logs == nullptr)
	{
		return;
	}

	for (std::uint64_t index = 0; index < count; index++)
	{
		if (logs[index].rip == 0)
		{
			continue;
		}

		if (pending_logs.size() == pending_log_limit)
		{
			pending_logs.pop_front();
		}

		pending_logs.push_back(logs[index]);
		note_one_monitor_log(logs[index]);
	}
}

void discard_pause_log(const breakpoint_t* const breakpoint, const trap_frame_log_t& log)
{
	if (breakpoint != nullptr && log.rip == breakpoint->address && same_cr3(breakpoint->cr3, log.cr3) == 1)
	{
		return;
	}

	remember_flushed_logs(&log, 1);
}

void discard_stale_pause_logs(const breakpoint_t* const breakpoint)
{
	constexpr std::uint64_t log_count = 2840;
	std::vector<trap_frame_log_t> logs(log_count);
	const std::uint64_t logs_flushed = hypercall::flush_logs(logs);

	if (logs_flushed != static_cast<std::uint64_t>(-1))
	{
		for (std::uint64_t index = 0; index < logs_flushed; index++)
		{
			discard_pause_log(breakpoint, logs[index]);
		}
	}

	std::vector<trap_frame_log_t> kept = {};

	for (const trap_frame_log_t& log : pending_logs)
	{
		if (breakpoint != nullptr && log.rip == breakpoint->address && same_cr3(breakpoint->cr3, log.cr3) == 1)
		{
			continue;
		}

		kept.push_back(log);
	}

	pending_logs.assign(kept.begin(), kept.end());
}

std::uint8_t flush_into_pause_state(const std::uint8_t report_error, const std::uint8_t observe)
{
	constexpr std::uint64_t log_count = 2840;
	std::vector<trap_frame_log_t> logs(log_count);
	const std::uint64_t logs_flushed = hypercall::flush_logs(logs);

	if (logs_flushed == static_cast<std::uint64_t>(-1))
	{
		if (report_error == 1)
		{
			LOG_ERR("failed to flush logs");
		}

		return 0;
	}

	if (logs_flushed > 0)
	{
		remember_flushed_logs(logs.data(), logs_flushed);

		if (observe == 1)
		{
			observe_logs_impl(logs.data(), logs_flushed);
		}
	}

	return 1;
}

void breakpoint::observe_pause_logs(const trap_frame_log_t* const logs, const std::uint64_t count)
{
	observe_logs_impl(logs, count);
}

std::uint8_t reconsider_pending_logs()
{
	if (pause_state.valid == 1 || pending_logs.empty() == true)
	{
		return pause_state.valid;
	}

	const std::vector<trap_frame_log_t> logs(pending_logs.begin(), pending_logs.end());

	observe_logs_impl(logs.data(), logs.size());

	return pause_state.valid;
}

std::uint8_t breakpoint::capture_pause()
{
	if (pause_state.valid == 1)
	{
		return 1;
	}

	if (reconsider_pending_logs() == 1)
	{
		return 1;
	}

	if (flush_into_pause_state(1, 1) == 0)
	{
		return 0;
	}

	return pause_state.valid;
}

std::uint8_t breakpoint::poll_new_pause()
{
	if (pause_state.valid == 1)
	{
		//
		// A paused thread used to skip the mailbox. Monitor hits on other
		// processors would sit there until fl. Copy them without replacing
		// the pause this thread already owns.
		//
		if (hypercall::log_notify_idle() == 0)
		{
			flush_into_pause_state(0, 0);
		}

		return 0;
	}

	if (reconsider_pending_logs() == 1)
	{
		return 1;
	}

	if (hypercall::log_notify_idle() != 0)
	{
		return 0;
	}

	if (flush_into_pause_state(0, 1) == 0)
	{
		return 0;
	}

	return pause_state.valid;
}

std::uint8_t breakpoint::add_monitor(const std::uint64_t address, const std::uint64_t log_rip,
                                         const std::uint64_t span)
{
	if (address == 0 || log_rip == 0)
	{
		return 0;
	}

	for (monitor_site_t& site : monitor_site_list)
	{
		if (site.address == address)
		{
			site.log_rip = log_rip;
			site.span = span;

			return 1;
		}
	}

	if (monitor_site_list.size() == monitor_site_limit)
	{
		return 0;
	}

	monitor_site_t site = {};
	site.address = address;
	site.log_rip = log_rip;
	site.span = span;
	monitor_site_list.push_back(site);

	return 1;
}

void breakpoint::remove_monitor(const std::uint64_t address)
{
	std::vector<monitor_site_t> kept = {};

	for (const monitor_site_t& site : monitor_site_list)
	{
		if (site.address != address)
		{
			kept.push_back(site);
		}
	}

	monitor_site_list = std::move(kept);
}

void breakpoint::note_monitor_logs(const trap_frame_log_t* const logs, const std::uint64_t count)
{
	if (logs == nullptr)
	{
		return;
	}

	for (std::uint64_t index = 0; index < count; index++)
	{
		note_one_monitor_log(logs[index]);
	}
}

std::vector<breakpoint::monitor_site_t> breakpoint::monitor_sites()
{
	return monitor_site_list;
}

std::vector<breakpoint::monitor_hit_t> breakpoint::take_monitor_hits()
{
	std::vector<monitor_hit_t> hits(monitor_hit_list.begin(), monitor_hit_list.end());

	monitor_hit_list.clear();

	return hits;
}

std::uint8_t breakpoint::has_paused_thread()
{
	const hypercall::GuestSection guest;

	return pause_state.valid;
}

std::uint64_t breakpoint::paused_breakpoint_id()
{
	return pause_state.breakpoint_id;
}

std::vector<trap_frame_log_t> breakpoint::take_pending_logs()
{
	std::vector<trap_frame_log_t> logs(pending_logs.begin(), pending_logs.end());

	pending_logs.clear();

	return logs;
}

std::uint8_t breakpoint::paused_registers(registers_t& registers_out)
{
	const hypercall::GuestSection guest;

	if (pause_state.valid == 0)
	{
		return 0;
	}

	registers_out = pause_state.registers;

	return 1;
}

std::uint8_t breakpoint::set_paused_register(const std::string_view name, const std::uint64_t value)
{
	if (pause_state.valid == 0)
	{
		LOG_ERR("no paused thread");

		return 0;
	}

	const reg_binding_t* const binding = find_binding(name);

	if (binding == nullptr)
	{
		LOG_ERR("invalid register");

		return 0;
	}

	std::uint64_t stored = value;

	if (binding->width == 4)
	{
		stored &= 0xFFFFFFFFull;
	}

	pause_state.registers.*(binding->field) = stored;

	if (binding->field == &breakpoint::registers_t::rsp)
	{
		pause_state.rsp_edited = 1;
	}

	if (binding->field == &registers_t::rflags)
	{
		pause_state.registers.rflags_known = 1;
	}

	if (binding->live_offset < 0)
	{
		return 1;
	}

	const std::uint64_t slot = pause_state.live_rsp + static_cast<std::uint64_t>(binding->live_offset);

	if (hypercall::write_guest_virtual_memory(&stored, slot, pause_state.registers.cr3, sizeof(stored)) != sizeof(stored))
	{
		LOG_ERR("failed to write register");

		return 0;
	}

	return 1;
}

std::uint8_t breakpoint::read_paused_virtual(void* const buffer, const std::uint64_t address, const std::uint64_t size)
{
	const hypercall::GuestSection guest;

	if (buffer == nullptr || pause_state.registers.cr3 == 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(hypercall::read_guest_virtual_memory(buffer, address, pause_state.registers.cr3, size) == size);
}

std::uint8_t breakpoint::write_paused_virtual(const void* const buffer, const std::uint64_t address, const std::uint64_t size)
{
	const hypercall::GuestSection guest;

	if (buffer == nullptr || pause_state.registers.cr3 == 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(
		hypercall::write_guest_virtual_memory(buffer, address, pause_state.registers.cr3, size) == size);
}

std::uint64_t breakpoint::pause_entry_address()
{
	const breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);

	if (breakpoint == nullptr)
	{
		return 0;
	}

	return breakpoint->entry_address;
}

std::uint64_t breakpoint::step_cave_address(const std::uint8_t index)
{
	const breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);

	if (breakpoint == nullptr || index > 1)
	{
		return 0;
	}

	return breakpoint->step_address[index];
}

std::uint64_t breakpoint::step_cave_capacity(const std::uint8_t index)
{
	const breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);

	if (breakpoint == nullptr || index > 1)
	{
		return 0;
	}

	return breakpoint->step_capacity[index];
}

std::uint8_t breakpoint::write_step_cave(const std::uint8_t index, const std::uint8_t* const code, const std::uint64_t size)
{
	breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);

	if (breakpoint == nullptr || index > 1 || code == nullptr || size == 0 || size > breakpoint->step_capacity[index])
	{
		LOG_ERR("step instruction does not fit");

		return 0;
	}

	code_slot_t* slot = nullptr;

	for (code_slot_t& candidate : breakpoint->slots)
	{
		if (candidate.address == breakpoint->step_address[index])
		{
			slot = &candidate;

			break;
		}
	}

	if (slot == nullptr)
	{
		LOG_ERR("step instruction does not fit");

		return 0;
	}

	std::vector<std::uint8_t> body(slot->bytes.size(), 0x90);

	std::memcpy(body.data(), code, static_cast<std::size_t>(size));

	if (size + relative_jump_size <= body.size())
	{
		body[static_cast<std::size_t>(size)] = 0xE9;

		if (write_rel32_at(body.data() + size + 1, breakpoint->step_address[index] + size + relative_jump_size,
		                   breakpoint->entry_address) == 0)
		{
			LOG_ERR("step instruction does not fit");

			return 0;
		}
	}

	slot->bytes = body;

	return patch_shadow_bytes(breakpoint->step_page_physical[index], breakpoint->step_offset[index], body.data(), body.size());
}

std::uint8_t breakpoint::set_pause_site_patched(const std::uint8_t patched)
{
	breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);
	breakpoint_page_t* const page = breakpoint == nullptr ? nullptr : find_page(breakpoint->page_physical);

	if (breakpoint == nullptr)
	{
		return 0;
	}

	if (breakpoint->original_bytes.empty() == true && breakpoint->patch_bytes.empty() == true)
	{
		return 1;
	}

	if (page == nullptr)
	{
		return 0;
	}

	const std::vector<std::uint8_t>& source = patched == 1 ? breakpoint->patch_bytes : breakpoint->original_bytes;

	std::memcpy(page->shadow + breakpoint->page_offset, source.data(), source.size());
	publish_shadow_bytes(page->shadow, breakpoint->page_offset, source.size());

	return 1;
}

std::uint8_t breakpoint::continue_paused_thread(const std::uint64_t logical_rip, const std::uint64_t go_target,
                                                const std::uint64_t wait_ms)
{
	if (pause_state.valid == 0)
	{
		LOG_ERR("no paused thread");

		return 0;
	}

	breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);

	if (breakpoint == nullptr)
	{
		LOG_ERR("no paused thread");

		return 0;
	}

	std::uint8_t rsp_move[10] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

	// The pops already restore this thread's rsp. A shared mov rsp stays in the stub and
	// is executed by the next caller, including a newer hit of the same breakpoint.
	if (pause_state.rsp_edited == 1)
	{
		rsp_move[0] = 0x48;
		rsp_move[1] = 0xBC;
		std::memcpy(rsp_move + 2, &pause_state.registers.rsp, sizeof(pause_state.registers.rsp));
	}

	if (patch_shadow_bytes(breakpoint->spin_page_physical, breakpoint->spin_rip_offset, &logical_rip, sizeof(logical_rip)) == 0 ||
		patch_shadow_bytes(breakpoint->go_rsp_page_physical, breakpoint->go_rsp_offset, rsp_move, sizeof(rsp_move)) == 0)
	{
		LOG_ERR("failed to update the paused thread");

		return 0;
	}

	std::uint8_t jump[absolute_jump_size] = {};

	write_absolute_jump(jump, go_target);

	if (patch_shadow_bytes(breakpoint->go_target_page_physical, breakpoint->go_target_offset, jump, sizeof(jump)) == 0)
	{
		LOG_ERR("failed to update the paused thread");

		return 0;
	}

	const std::uint64_t paused_cr3 = pause_state.registers.cr3;
	const std::uint64_t paused_id = pause_state.breakpoint_id;

	pause_state.expected_rip = wait_ms == 0 ? 0 : logical_rip;
	pause_state.valid = 0;
	pause_state.rsp_edited = 0;
	pause_state.breakpoint_id = paused_id;
	pause_state.registers.cr3 = paused_cr3;
	discard_stale_pause_logs(breakpoint);
	hypercall::breakpoint_resume();

	if (wait_ms == 0)
	{
		return 1;
	}

	const ULONGLONG started = GetTickCount64();

	while (GetTickCount64() - started < wait_ms)
	{
		if (hypercall::log_notify_idle() == 0 && flush_into_pause_state(0, 1) == 1 && pause_state.valid == 1)
		{
			return 1;
		}

		Sleep(10);
	}

	pause_state.expected_rip = 0;
	LOG_ERR("timed out waiting for the thread");

	return 0;
}

std::uint8_t any_pausing_breakpoint()
{
	for (const breakpoint_t& breakpoint : breakpoints)
	{
		if (breakpoint.pauses_thread == 1 && breakpoint.enabled == 1)
		{
			return 1;
		}
	}

	return 0;
}

std::uint8_t breakpoint::resume_paused()
{
	capture_pause();

	if (pause_state.valid == 0)
	{
		if (any_pausing_breakpoint() == 0)
		{
			LOG_ERR("no paused thread");

			return 0;
		}

		// The thread can be spinning in the pause stub before a record is latched.
		for (breakpoint_t& spinning : breakpoints)
		{
			if (spinning.pauses_thread == 1 && spinning.enabled == 1)
			{
				discard_stale_pause_logs(&spinning);
			}
		}

		hypercall::breakpoint_resume();

		return 1;
	}

	breakpoint_t* const breakpoint = find_breakpoint(pause_state.breakpoint_id);

	if (breakpoint == nullptr)
	{
		LOG_ERR("no paused thread");

		return 0;
	}

	std::uint64_t target = pause_state.registers.rip;

	if (target == breakpoint->address)
	{
		target = breakpoint->resume_address;
	}
	else if (target > breakpoint->address && target < breakpoint->address + breakpoint->span)
	{
		const std::uint64_t tail = breakpoint->address + breakpoint->span - target;

		if (tail + relative_jump_size > breakpoint->step_capacity[0])
		{
			LOG_ERR("resumed instructions do not fit");

			return 0;
		}

		std::vector<std::uint8_t> code(static_cast<std::size_t>(tail + relative_jump_size));

		if (hypercall::read_guest_virtual_memory(code.data(), target, pause_state.registers.cr3, tail) != tail)
		{
			LOG_ERR("failed to read resumed instructions");

			return 0;
		}

		write_relative_jump(code.data() + tail, breakpoint->step_address[0] + tail, breakpoint->address + breakpoint->span);

		if (write_step_cave(0, code.data(), code.size()) == 0)
		{
			return 0;
		}

		target = breakpoint->step_address[0];
	}

	return continue_paused_thread(breakpoint->address, target, 0);
}
