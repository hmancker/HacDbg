#pragma once
#include <vector>

union parted_address_t
{
	struct
	{
		std::uint32_t low_part;
		std::uint32_t high_part;
	} u;

	std::uint64_t value;
};

namespace hook_disasm
{
	struct page_span_t
	{
		std::uint64_t steal_offset;
		std::uint64_t byte_count;
	};

	std::pair<std::vector<std::uint8_t>, std::uint64_t> get_routine_aligned_bytes(
		std::uint8_t* routine, std::uint64_t minimum_size, std::uint64_t routine_runtime_address);

	// steal_offset is where a complete instruction starts on this page.
	// byte_count is the original bytes from there through the instruction that
	// finishes on the next page. byte_count is 0 when nothing crosses.
	page_span_t find_page_span(std::uint8_t* page_and_tail, std::uint64_t page_bytes, std::uint64_t minimum_steal);
}
