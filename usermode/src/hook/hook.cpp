#include "hook.h"
#include "kernel_detour_holder.h"
#include "../system/system.h"
#include "../hypercall/hypercall.h"
#include "../logs/logs.h"

#include <Windows.h>
#include <immintrin.h>
#include <vector>
#include <array>
#include <memory_resource>
#include <unordered_map>

#include "hook_disassembly.h"

namespace
{
	struct kernel_hook_patch_t
	{
		std::uint64_t offset = 0;
		std::vector<std::uint8_t> original = {};
	};

	std::unordered_map<std::uint64_t, hook::kernel_hook_info_t> kernel_hook_list = {};
	std::unordered_map<std::uint64_t, kernel_hook_patch_t> kernel_hook_patches = {};

	std::uint64_t kernel_detour_section_base = 0;
	std::uint64_t kernel_detour_section_size = 0;
	std::uint64_t kernel_detour_holder_base = 0;
	std::uint64_t kernel_detour_holder_physical_page = 0;
	std::uint8_t* kernel_detour_holder_shadow_page_mapped = nullptr;

	constexpr std::size_t inline_hook_bytes_size = 14;
	constexpr std::uint64_t inline_jump_rel32_size = 5;
	constexpr std::uint64_t detour_cave_minimum = 0x80;

	std::uint8_t padding_byte(const std::uint8_t value)
	{
		return static_cast<std::uint8_t>(value == 0 || value == 0xCC);
	}

	void longest_padding_cave(const std::uint8_t* const page, const std::uint64_t page_bytes,
	                          std::uint64_t& offset_out, std::uint64_t& size_out)
	{
		offset_out = 0;
		size_out = 0;

		std::uint64_t index = 0;

		while (index < page_bytes)
		{
			if (padding_byte(page[index]) == 0)
			{
				index++;

				continue;
			}

			const std::uint64_t start = index;

			while (index < page_bytes && padding_byte(page[index]) == 1)
			{
				index++;
			}

			std::uint64_t cave_offset = start;
			std::uint64_t cave_size = index - start;

			if ((cave_offset & 1) != 0)
			{
				cave_offset++;
				cave_size--;
			}

			cave_size &= ~1ull;

			if (cave_size > size_out)
			{
				offset_out = cave_offset;
				size_out = cave_size;
			}
		}
	}

	void* shadow_for_page(const std::uint64_t page_pfn, std::uint8_t& overflow_out)
	{
		overflow_out = 0;
		void* shadow = nullptr;

		for (const auto& [address, info] : kernel_hook_list)
		{
			if (info.original_page_pfn() != page_pfn && info.overflow_page_pfn() != page_pfn)
			{
				continue;
			}

			if (info.overflow_page_pfn() != 0)
			{
				overflow_out = 1;
			}

			shadow = info.mapped_shadow_page();

			if (info.original_page_pfn() == page_pfn)
			{
				return shadow;
			}

			(void)address;
		}

		return shadow;
	}

	std::uint8_t patch_overlaps(const std::uint64_t page_pfn, const std::uint64_t offset, const std::uint64_t length)
	{
		const std::uint64_t end = offset + length;

		for (const auto& [address, info] : kernel_hook_list)
		{
			if (info.original_page_pfn() != page_pfn)
			{
				continue;
			}

			const auto found = kernel_hook_patches.find(address);

			if (found == kernel_hook_patches.end())
			{
				continue;
			}

			const std::uint64_t other = found->second.offset;
			const std::uint64_t other_end = other + found->second.original.size();

			if (offset < other_end && other < end)
			{
				return 1;
			}
		}

		return 0;
	}

	std::uint8_t shadow_still_used(void* const shadow, const std::uint64_t except)
	{
		for (const auto& [address, info] : kernel_hook_list)
		{
			if (address != except && info.mapped_shadow_page() == shadow)
			{
				return 1;
			}
		}

		return 0;
	}

	void publish_shadow_bytes(void* const address, const std::uint64_t size)
	{
		if (address == nullptr || size == 0)
		{
			return;
		}

		auto* const bytes = static_cast<std::uint8_t*>(address);

		for (std::uint64_t index = 0; index < size; index += 64)
		{
			_mm_clflush(bytes + index);
		}

		_mm_mfence();
		FlushInstructionCache(GetCurrentProcess(), address, static_cast<SIZE_T>(size));
	}
}

std::uint8_t hook::set_up()
{
	//
	// The first page of the executable padding section still contains live
	// instructions. A detour written over those bytes runs when that function
	// reaches them.
	//
	std::array<std::uint8_t, page_size> page_bytes = {};
	std::uint64_t chosen_page = 0;
	std::uint64_t chosen_physical = 0;
	std::uint64_t cave_offset = 0;
	std::uint64_t cave_size = 0;
	const std::uint64_t section_end = kernel_detour_section_base + kernel_detour_section_size;
	const std::uint64_t first_page = (kernel_detour_section_base + page_size - 1) & ~(page_size - 1);

	for (std::uint64_t page = first_page; page + page_size <= section_end; page += page_size)
	{
		const std::uint64_t physical = hypercall::translate_guest_virtual_address(page, sys::current_cr3) &
			~(page_size - 1);

		if (physical == 0)
		{
			continue;
		}

		if (hypercall::read_guest_physical_memory(page_bytes.data(), physical, page_size) != page_size)
		{
			continue;
		}

		std::uint64_t offset = 0;
		std::uint64_t size = 0;

		longest_padding_cave(page_bytes.data(), page_size, offset, size);

		if (size < detour_cave_minimum || size <= cave_size)
		{
			continue;
		}

		chosen_page = page;
		chosen_physical = physical;
		cave_offset = offset;
		cave_size = size;

		if (size == page_size)
		{
			break;
		}
	}

	if (chosen_page == 0)
	{
		LOG_ERR("kernel hook holder has no unused padding");

		return 0;
	}

	kernel_detour_holder_base = chosen_page;

	if (kernel_detour_holder_shadow_page_mapped == nullptr)
	{
		kernel_detour_holder_shadow_page_mapped = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(
			page_size, PAGE_READWRITE));
	}

	if (kernel_detour_holder_shadow_page_mapped == nullptr)
	{
		return 0;
	}

	const std::uint64_t shadow_page_physical = hypercall::translate_guest_virtual_address(
		reinterpret_cast<std::uint64_t>(kernel_detour_holder_shadow_page_mapped), sys::directory_for_local_memory());

	if (shadow_page_physical == 0)
	{
		return 0;
	}

	kernel_detour_holder_physical_page = chosen_physical;

	// in case of a previously wrongfully ended session which would've left the hook still applied
	hypercall::remove_slat_code_hook(kernel_detour_holder_physical_page);

	memcpy(kernel_detour_holder_shadow_page_mapped, page_bytes.data(), page_size);

	kernel_detour_holder::set_up(reinterpret_cast<std::uint64_t>(kernel_detour_holder_shadow_page_mapped), cave_offset,
	                             cave_size);

	publish_shadow_bytes(kernel_detour_holder_shadow_page_mapped, page_size);

	const std::uint64_t hook_status = hypercall::add_slat_code_hook(kernel_detour_holder_physical_page,
	                                                                shadow_page_physical);

	if (hook_status == 0)
	{
		kernel_detour_holder_physical_page = 0;

		return 0;
	}

	return 1;
}

std::uint8_t hook::ensure_detour_holder()
{
	if (kernel_detour_holder_physical_page != 0)
	{
		return 1;
	}

	return set_up();
}

std::uint64_t hook::detour_holder_base()
{
	return kernel_detour_holder_base;
}

std::uint8_t hook::contains_hooked_page(const std::uint64_t physical_address)
{
	const std::uint64_t page = physical_address & ~0xFFFull;

	if (kernel_detour_holder_physical_page != 0 && (kernel_detour_holder_physical_page & ~0xFFFull) == page)
	{
		return 1;
	}

	for (const auto& [virtual_address, info] : kernel_hook_list)
	{
		if ((info.original_page_pfn() << 12) == page)
		{
			return 1;
		}

		if (info.overflow_page_pfn() != 0 && (info.overflow_page_pfn() << 12) == page)
		{
			return 1;
		}

		(void)virtual_address;
	}

	return 0;
}

void hook::clean_up()
{
	std::vector<std::uint64_t> addresses = {};

	addresses.reserve(kernel_hook_list.size());

	for (const auto& [virtual_address, info] : kernel_hook_list)
	{
		addresses.push_back(virtual_address);

		(void)info;
	}

	for (const std::uint64_t virtual_address : addresses)
	{
		remove_kernel_hook(virtual_address, 1);
	}

	kernel_hook_list.clear();

	if (kernel_detour_holder_physical_page != 0)
	{
		hypercall::remove_slat_code_hook(kernel_detour_holder_physical_page);
	}
}

void hook::set_kernel_detour_holder_base(const std::uint64_t address, const std::uint64_t size)
{
	kernel_detour_section_base = address;
	kernel_detour_section_size = size;
}

static std::pair<std::vector<std::uint8_t>, std::uint64_t> load_original_bytes_into_shadow_page(
	std::uint8_t* shadow_page_virtual, const std::uint64_t routine_to_hook_virtual, const std::uint8_t is_overflow_hook,
	const std::uint64_t minimum_size)
{
	const std::uint64_t page_offset = routine_to_hook_virtual & 0xFFF;

	hypercall::read_guest_virtual_memory(shadow_page_virtual, routine_to_hook_virtual - page_offset, sys::current_cr3,
	                                     is_overflow_hook == 1 ? (page_size * 2) : page_size);

	return hook_disasm::get_routine_aligned_bytes(shadow_page_virtual + page_offset, minimum_size,
	                                              routine_to_hook_virtual);
}

static std::vector<std::uint8_t> absolute_jump(std::uint64_t target);
static std::vector<std::uint8_t> relative_jump(std::uint64_t site, std::uint64_t target);

static std::uint8_t set_up_inline_hook(std::uint8_t* shadow_page_virtual, const std::uint64_t routine_to_hook_virtual,
                                       const std::uint64_t routine_to_hook_physical, const std::uint64_t detour_address,
                                       const std::uint64_t patch_length, const std::uint8_t is_overflow_hook,
                                       std::uint64_t& overflow_shadow_page_physical_address,
                                       std::uint64_t& overflow_page_physical_address)
{
	std::vector<std::uint8_t> inline_hook_bytes = {};

	//
	// The monitor stub and any post bytes run in the detour. The function
	// entry keeps only the jump, so a short neighbor on the same page can
	// still be hooked.
	//
	if (patch_length == inline_jump_rel32_size)
	{
		inline_hook_bytes = relative_jump(routine_to_hook_virtual, detour_address);
	}

	if (inline_hook_bytes.empty() == true)
	{
		inline_hook_bytes = absolute_jump(detour_address);
	}

	if (inline_hook_bytes.size() != patch_length)
	{
		return 0;
	}

	const std::uint64_t page_offset = routine_to_hook_physical & 0xFFF;

	if (is_overflow_hook == 1)
	{
		std::uint8_t* overflow_shadow_page_virtual = shadow_page_virtual + page_size;

		overflow_shadow_page_physical_address = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(overflow_shadow_page_virtual), sys::directory_for_local_memory());

		if (overflow_shadow_page_physical_address == 0)
		{
			return 0;
		}

		const std::uint64_t overflow_page_virtual_address = routine_to_hook_virtual + page_size;

		overflow_page_physical_address = hypercall::translate_guest_virtual_address(
			overflow_page_virtual_address, sys::current_cr3);

		if (overflow_page_physical_address == 0)
		{
			return 0;
		}

		const std::uint64_t hook_end = page_offset + inline_hook_bytes.size();
		const std::uint64_t bytes_overflowed = hook_end - page_size;

		const std::uint64_t prior_page_copy_size = inline_hook_bytes.size() - bytes_overflowed;

		memcpy(shadow_page_virtual + page_offset, inline_hook_bytes.data(), prior_page_copy_size);
		memcpy(overflow_shadow_page_virtual, inline_hook_bytes.data() + prior_page_copy_size, bytes_overflowed);
	}
	else
	{
		memcpy(shadow_page_virtual + page_offset, inline_hook_bytes.data(), inline_hook_bytes.size());
	}

	return 1;
}

static std::uint8_t set_up_hook_handler(const std::uint64_t routine_to_hook_virtual,
                                        std::uint16_t& detour_holder_shadow_offset,
                                        const std::pair<std::vector<std::uint8_t>, std::uint64_t>& original_bytes,
                                        const std::span<const std::uint8_t> extra_assembled_bytes,
                                        const std::span<const std::uint8_t> post_original_assembled_bytes)
{
	std::array<std::uint8_t, 14> return_to_original_bytes = {
		0x68, 0x21, 0x43, 0x65, 0x87, // push   0xffffffff87654321
		0xC7, 0x44, 0x24, 0x04, 0x78, 0x56, 0x34, 0x12, // mov    DWORD PTR [rsp+0x4],0x12345678
		0xC3 // ret
	};

	parted_address_t parted_subroutine_to_jmp_to{};

	parted_subroutine_to_jmp_to.value = routine_to_hook_virtual + original_bytes.second;

	*reinterpret_cast<std::uint32_t*>(&return_to_original_bytes[1]) = parted_subroutine_to_jmp_to.u.low_part;
	*reinterpret_cast<std::uint32_t*>(&return_to_original_bytes[9]) = parted_subroutine_to_jmp_to.u.high_part;

	std::vector<std::uint8_t> hook_handler_bytes(extra_assembled_bytes.begin(), extra_assembled_bytes.end());

	hook_handler_bytes.insert(hook_handler_bytes.end(), original_bytes.first.begin(), original_bytes.first.end());
	hook_handler_bytes.insert(hook_handler_bytes.end(), post_original_assembled_bytes.begin(),
	                          post_original_assembled_bytes.end());
	hook_handler_bytes.insert(hook_handler_bytes.end(), return_to_original_bytes.begin(),
	                          return_to_original_bytes.end());

	void* bytes_buffer = kernel_detour_holder::allocate_memory(static_cast<std::uint16_t>(hook_handler_bytes.size()));

	if (bytes_buffer == nullptr)
	{
		return 0;
	}

	detour_holder_shadow_offset = kernel_detour_holder::get_allocation_offset(bytes_buffer);

	memcpy(bytes_buffer, hook_handler_bytes.data(), hook_handler_bytes.size());
	publish_shadow_bytes(bytes_buffer, hook_handler_bytes.size());

	return 1;
}

static std::vector<std::uint8_t> absolute_jump(const std::uint64_t target)
{
	std::vector<std::uint8_t> bytes = {
		0x68, 0x21, 0x43, 0x65, 0x87, // push   0xffffffff87654321
		0xC7, 0x44, 0x24, 0x04, 0x78, 0x56, 0x34, 0x12, // mov    DWORD PTR [rsp+0x4],0x12345678
		0xC3 // ret
	};

	const parted_address_t parted = {.value = target};

	*reinterpret_cast<std::uint32_t*>(&bytes[1]) = parted.u.low_part;
	*reinterpret_cast<std::uint32_t*>(&bytes[9]) = parted.u.high_part;

	return bytes;
}

static std::vector<std::uint8_t> relative_jump(const std::uint64_t site, const std::uint64_t target)
{
	const std::int64_t displacement = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(site + 5);

	if (displacement > 0x7FFFFFFF || displacement < -static_cast<std::int64_t>(0x80000000))
	{
		return {};
	}

	std::vector<std::uint8_t> bytes = {0xE9, 0x00, 0x00, 0x00, 0x00};

	*reinterpret_cast<std::int32_t*>(&bytes[1]) = static_cast<std::int32_t>(displacement);

	return bytes;
}

static std::uint8_t detour_in_rel32(const std::uint64_t site)
{
	const std::int64_t near_edge = static_cast<std::int64_t>(kernel_detour_holder_base) -
		static_cast<std::int64_t>(site + 5);
	const std::int64_t far_edge = static_cast<std::int64_t>(kernel_detour_holder_base + page_size) -
		static_cast<std::int64_t>(site + 5);

	return static_cast<std::uint8_t>(near_edge >= -static_cast<std::int64_t>(0x80000000) && far_edge <= 0x7FFFFFFF);
}

static std::uint64_t inline_patch_length(const std::uint64_t site)
{
	if (kernel_detour_holder_base != 0 && detour_in_rel32(site) == 1)
	{
		return inline_jump_rel32_size;
	}

	return inline_hook_bytes_size;
}

//
// The shadow page and the next guest page are different EPT pages. An
// instruction that starts on this page and finishes on the next one is fetched
// from both. That fetch stops on the boundary and the leftover byte runs as
// its own instruction. Move the whole instruction into the detour and jump
// back to the byte after it.
//
static std::uint8_t relocate_page_span(std::uint8_t* const shadow_page, const std::uint64_t page_virtual,
                                      const std::uint64_t patch_offset, const std::uint64_t patch_length)
{
	constexpr std::uint64_t tail_bytes = 15;
	const std::uint64_t minimum_steal = detour_in_rel32(page_virtual) == 1 &&
	                                    detour_in_rel32(page_virtual + page_size - 5) == 1
		                                    ? 5
		                                    : inline_hook_bytes_size;
	std::vector<std::uint8_t> bytes(page_size + tail_bytes);
	std::array<std::uint8_t, tail_bytes> tail = {};

	memcpy(bytes.data(), shadow_page, page_size);

	const std::uint64_t read = hypercall::read_guest_virtual_memory(tail.data(), page_virtual + page_size,
	                                                                sys::current_cr3, tail_bytes);

	if (read != tail_bytes)
	{
		return 1;
	}

	memcpy(bytes.data() + page_size, tail.data(), tail_bytes);

	const hook_disasm::page_span_t span = hook_disasm::find_page_span(bytes.data(), page_size, minimum_steal);

	if (span.byte_count == 0)
	{
		return 1;
	}

	if (patch_length != 0 && span.steal_offset < patch_offset + patch_length && patch_offset < page_size)
	{
		return 1;
	}

	const auto relocated = hook_disasm::get_routine_aligned_bytes(bytes.data() + span.steal_offset, span.byte_count,
	                                                              page_virtual + span.steal_offset);

	if (relocated.first.empty() || relocated.second < span.byte_count || relocated.first.size() > 0x7fff)
	{
		return 0;
	}

	std::vector<std::uint8_t> trampoline = relocated.first;
	const std::vector<std::uint8_t> resume = absolute_jump(page_virtual + span.steal_offset + relocated.second);

	trampoline.insert(trampoline.end(), resume.begin(), resume.end());

	void* const buffer = kernel_detour_holder::allocate_memory(static_cast<std::uint16_t>(trampoline.size()));

	if (buffer == nullptr)
	{
		return 0;
	}

	memcpy(buffer, trampoline.data(), trampoline.size());
	publish_shadow_bytes(buffer, trampoline.size());

	const std::uint64_t detour = kernel_detour_holder_base + kernel_detour_holder::get_allocation_offset(buffer);
	std::vector<std::uint8_t> jump = {};

	if (minimum_steal == 5)
	{
		jump = relative_jump(page_virtual + span.steal_offset, detour);
	}

	if (jump.empty())
	{
		if (page_size - span.steal_offset < inline_hook_bytes_size)
		{
			return 0;
		}

		jump = absolute_jump(detour);
	}

	const std::uint64_t room = page_size - span.steal_offset;

	memcpy(shadow_page + span.steal_offset, jump.data(), jump.size());

	if (room > jump.size())
	{
		memset(shadow_page + span.steal_offset + jump.size(), 0x90, static_cast<std::size_t>(room - jump.size()));
	}

	return 1;
}

std::uint8_t hook::add_kernel_hook(const std::uint64_t routine_to_hook_virtual,
                                   const std::span<const std::uint8_t> extra_assembled_bytes,
                                   const std::span<const std::uint8_t> post_original_assembled_bytes)
{
	if (kernel_detour_holder_physical_page == 0 && set_up() == 0)
	{
		LOG_ERR("unable to set up kernel hook helper");

		return 0;
	}

	if (kernel_hook_list.contains(routine_to_hook_virtual))
	{
		LOG_ERR("kernel hook already exists");

		return 0;
	}

	const std::uint64_t routine_to_hook_physical = hypercall::translate_guest_virtual_address(
		routine_to_hook_virtual, sys::current_cr3);

	if (routine_to_hook_physical == 0)
	{
		return 0;
	}

	const std::uint64_t page_offset = routine_to_hook_physical & 0xFFF;
	const std::uint64_t patch_length = inline_patch_length(routine_to_hook_virtual);
	const std::uint64_t hook_end = page_offset + patch_length;

	const std::uint8_t is_overflow_hook = static_cast<const std::uint8_t>(page_size < hook_end);
	const std::uint64_t page_pfn = routine_to_hook_physical >> 12;
	std::uint8_t existing_overflow = 0;
	void* const shared_shadow = shadow_for_page(page_pfn, existing_overflow);

	//
	// The SLAT hook is one entry per 4 KiB page. A second function on that
	// page patches the shadow already installed for the first.
	//
	if (shared_shadow != nullptr && (is_overflow_hook == 1 || existing_overflow == 1))
	{
		LOG_ERR("kernel hook crosses a page that is already hooked");

		return 0;
	}

	void* shadow_page_virtual = shared_shadow;
	std::uint64_t shadow_page_physical = 0;
	std::pair<std::vector<std::uint8_t>, std::uint64_t> original_bytes = {};

	if (shadow_page_virtual == nullptr)
	{
		shadow_page_virtual = sys::user::allocate_locked_memory(is_overflow_hook == 1 ? (page_size * 2) : page_size,
		                                                        PAGE_READWRITE);

		if (shadow_page_virtual == nullptr)
		{
			return 0;
		}

		shadow_page_physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(shadow_page_virtual), sys::directory_for_local_memory());

		if (shadow_page_physical == 0)
		{
			return 0;
		}

		original_bytes = load_original_bytes_into_shadow_page(static_cast<std::uint8_t*>(shadow_page_virtual),
		                                                     routine_to_hook_virtual, is_overflow_hook, patch_length);
	}
	else
	{
		std::vector<std::uint8_t> page(page_size);
		const std::uint64_t page_virtual = routine_to_hook_virtual & ~(static_cast<std::uint64_t>(page_size) - 1);

		if (hypercall::read_guest_virtual_memory(page.data(), page_virtual, sys::current_cr3, page_size) != page_size)
		{
			return 0;
		}

		original_bytes = hook_disasm::get_routine_aligned_bytes(page.data() + page_offset, patch_length,
		                                                     routine_to_hook_virtual);
	}

	if (original_bytes.first.empty())
	{
		return 0;
	}

	std::uint16_t detour_holder_shadow_offset = 0;

	const std::uint8_t status = set_up_hook_handler(routine_to_hook_virtual, detour_holder_shadow_offset,
	                                                original_bytes, extra_assembled_bytes,
	                                                post_original_assembled_bytes);

	if (status == 0)
	{
		return 0;
	}

	const std::uint64_t detour_address = kernel_detour_holder_base + detour_holder_shadow_offset;

	if (original_bytes.second < patch_length)
	{
		LOG_ERR("kernel hook entry is shorter than the jump");

		return 0;
	}

	if (shared_shadow != nullptr &&
	    (page_offset + patch_length > page_size || patch_overlaps(page_pfn, page_offset, patch_length) == 1))
	{
		LOG_ERR("kernel hook overlaps an existing hook");

		return 0;
	}

	auto* const shadow_before_patch = static_cast<std::uint8_t*>(shadow_page_virtual);
	kernel_hook_patch_t saved_patch = {};

	saved_patch.offset = page_offset;
	saved_patch.original.assign(shadow_before_patch + page_offset,
	                            shadow_before_patch + page_offset + patch_length);

	std::uint64_t overflow_shadow_page_physical_address = 0;
	std::uint64_t overflow_page_physical_address = 0;

	std::uint64_t hook_status = set_up_inline_hook(static_cast<std::uint8_t*>(shadow_page_virtual),
	                                               routine_to_hook_virtual, routine_to_hook_physical, detour_address,
	                                               patch_length, is_overflow_hook, overflow_shadow_page_physical_address,
	                                               overflow_page_physical_address);

	if (hook_status == 0)
	{
		return 0;
	}

	kernel_hook_patches[routine_to_hook_virtual] = std::move(saved_patch);

	const std::uint64_t page_virtual = routine_to_hook_virtual & ~(static_cast<std::uint64_t>(page_size) - 1);
	auto* const shadow = static_cast<std::uint8_t*>(shadow_page_virtual);
	const std::uint64_t page_patch = page_offset + patch_length > page_size ? page_size - page_offset : patch_length;

	if (shared_shadow == nullptr && relocate_page_span(shadow, page_virtual, page_offset, page_patch) == 0)
	{
		kernel_hook_patches.erase(routine_to_hook_virtual);

		return 0;
	}

	if (shared_shadow == nullptr && is_overflow_hook == 1)
	{
		const std::uint64_t overflow_patch = page_offset + patch_length - page_size;

		if (relocate_page_span(shadow + page_size, page_virtual + page_size, 0, overflow_patch) == 0)
		{
			kernel_hook_patches.erase(routine_to_hook_virtual);

			return 0;
		}
	}

	publish_shadow_bytes(shadow_page_virtual, is_overflow_hook == 1 ? (page_size * 2) : page_size);

	//
	// Translation includes the byte offset inside the page. The SLAT hook
	// names the 4 KiB page, and a non-zero offset is rejected. A page that
	// already has a hook keeps that entry; the edited shadow is copied again
	// by the flush.
	//
	if (shared_shadow == nullptr)
	{
		hook_status = hypercall::add_slat_code_hook(routine_to_hook_physical & ~0xFFFull,
		                                            shadow_page_physical & ~0xFFFull);

		if (hook_status == 0)
		{
			kernel_hook_patches.erase(routine_to_hook_virtual);

			return 0;
		}
	}
	else if (hypercall::flush_slat_cache() == 0)
	{
		const auto failed = kernel_hook_patches.find(routine_to_hook_virtual);

		if (failed != kernel_hook_patches.end() && failed->second.original.empty() == false)
		{
			memcpy(shadow + failed->second.offset, failed->second.original.data(), failed->second.original.size());
		}

		kernel_hook_patches.erase(routine_to_hook_virtual);

		return 0;
	}

	if (overflow_shadow_page_physical_address != 0)
	{
		hook_status = hypercall::add_slat_code_hook(overflow_page_physical_address & ~0xFFFull,
		                                            overflow_shadow_page_physical_address & ~0xFFFull);

		if (hook_status == 0)
		{
			return 0;
		}
	}

	const kernel_hook_info_t hook_info(routine_to_hook_physical >> 12, overflow_page_physical_address >> 12,
	                                   shadow_page_virtual, detour_holder_shadow_offset);

	kernel_hook_list[routine_to_hook_virtual] = hook_info;

	return 1;
}

std::uint8_t hook::remove_kernel_hook(const std::uint64_t hooked_routine_virtual, const std::uint8_t do_list_erase)
{
	if (!kernel_hook_list.contains(hooked_routine_virtual))
	{
		LOG_ERR("unable to find kernel hook");

		return 0;
	}

	const kernel_hook_info_t hook_info = kernel_hook_list[hooked_routine_virtual];
	const auto patch = kernel_hook_patches.find(hooked_routine_virtual);
	const std::uint8_t keep_page = shadow_still_used(hook_info.mapped_shadow_page(), hooked_routine_virtual);

	if (keep_page == 1)
	{
		if (patch != kernel_hook_patches.end() && patch->second.original.empty() == false)
		{
			auto* const shadow = static_cast<std::uint8_t*>(hook_info.mapped_shadow_page());

			memcpy(shadow + patch->second.offset, patch->second.original.data(), patch->second.original.size());
			publish_shadow_bytes(shadow + patch->second.offset, patch->second.original.size());
			hypercall::flush_slat_cache();
		}
	}
	else
	{
		if (hypercall::remove_slat_code_hook(hook_info.original_page_pfn() << 12) == 0)
		{
			LOG_ERR("unable to remove slat counterpart of kernel hook");

			return 0;
		}

		if (hook_info.overflow_page_pfn() != 0 &&
		    hypercall::remove_slat_code_hook(hook_info.overflow_page_pfn() << 12) == 0)
		{
			LOG_ERR("unable to remove slat counterpart of kernel hook (2)");

			return 0;
		}
	}

	kernel_hook_patches.erase(hooked_routine_virtual);

	if (do_list_erase == 1)
	{
		kernel_hook_list.erase(hooked_routine_virtual);
	}

	void* detour_holder_allocation = kernel_detour_holder::get_allocation_from_offset(
		hook_info.detour_holder_shadow_offset());

	kernel_detour_holder::free_memory(detour_holder_allocation);

	if (keep_page == 0 && sys::user::free_memory(hook_info.mapped_shadow_page()) == 0)
	{
		LOG_ERR("unable to deallocate mapped shadow page");

		return 0;
	}

	return 1;
}

std::uint64_t hook::kernel_hook_info_t::original_page_pfn() const
{
	return original_page_pfn_;
}

void hook::kernel_hook_info_t::set_original_page_pfn(const std::uint64_t original_page_pfn)
{
	original_page_pfn_ = original_page_pfn;
}

std::uint64_t hook::kernel_hook_info_t::overflow_page_pfn() const
{
	return overflow_page_pfn_;
}

void hook::kernel_hook_info_t::set_overflow_page_pfn(const std::uint64_t overflow_page_pfn)
{
	overflow_page_pfn_ = overflow_page_pfn;
}

void* hook::kernel_hook_info_t::mapped_shadow_page() const
{
	return reinterpret_cast<void*>(mapped_shadow_page_);
}

void hook::kernel_hook_info_t::set_mapped_shadow_page(void* const mapped_shadow_page)
{
	mapped_shadow_page_ = reinterpret_cast<std::uint64_t>(mapped_shadow_page);
}

std::uint16_t hook::kernel_hook_info_t::detour_holder_shadow_offset() const
{
	return detour_holder_shadow_offset_;
}

void hook::kernel_hook_info_t::set_detour_holder_shadow_offset(const std::uint64_t detour_holder_shadow_offset)
{
	detour_holder_shadow_offset_ = detour_holder_shadow_offset;
}
