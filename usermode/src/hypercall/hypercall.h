#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include <structures/trap_frame.h>

namespace hypercall
{
	std::uint64_t read_guest_physical_memory(void* guest_destination_buffer,
	                                         std::uint64_t guest_source_physical_address, std::uint64_t size);
	std::uint64_t write_guest_physical_memory(const void* guest_source_buffer,
	                                          std::uint64_t guest_destination_physical_address, std::uint64_t size);

	std::uint64_t read_guest_virtual_memory(void* guest_destination_buffer, std::uint64_t guest_source_virtual_address,
	                                        std::uint64_t source_cr3, std::uint64_t size);
	std::uint64_t write_guest_virtual_memory(const void* guest_source_buffer,
	                                         std::uint64_t guest_destination_virtual_address,
	                                         std::uint64_t destination_cr3, std::uint64_t size);

	std::uint64_t translate_guest_virtual_address(std::uint64_t guest_virtual_address, std::uint64_t guest_cr3);

	std::uint64_t read_guest_cr3();
	std::uint64_t log_current_state();

	std::uint8_t query_driver_version(std::uint32_t& major, std::uint32_t& minor, std::uint32_t& patch,
	                                  std::uint32_t& hypercall_abi_version, std::string& version);

	std::uint64_t add_slat_code_hook(std::uint64_t target_guest_physical_address,
	                                 std::uint64_t shadow_page_guest_physical_address);
	std::uint64_t remove_slat_code_hook(std::uint64_t target_guest_physical_address);

	std::uint64_t hide_guest_physical_page(std::uint64_t target_guest_physical_address);

	std::uint64_t flush_logs(std::vector<trap_frame_log_t>& logs);

	std::uint64_t get_heap_free_page_count();

	std::uint64_t flush_slat_cache();

	std::uint64_t breakpoint_resume();
}
