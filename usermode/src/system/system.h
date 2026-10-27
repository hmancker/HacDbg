#pragma once
#include <span>
#include <unordered_map>
#include <string>
#include "system_def.h"

constexpr std::size_t page_size = 0x1000;

namespace sys
{
	struct kernel_module_t;

	std::uint8_t set_up();
	void clean_up();

	namespace kernel
	{
		std::uint8_t parse_modules();
		std::uint8_t dump_module_to_disk(std::string_view target_module_name, std::string_view output_directory);

		std::unordered_map<std::string, std::uint64_t> compile_symbol_list();

		inline std::unordered_map<std::string, kernel_module_t> modules_list = {};
	}

	namespace user
	{
		std::uint32_t query_system_information(std::int32_t information_class, void* information_out,
		                                       std::uint32_t information_size, std::uint32_t* returned_size);

		std::uint32_t adjust_privilege(std::uint32_t privilege, std::uint8_t enable, std::uint8_t current_thread_only,
		                               std::uint8_t* previous_enabled_state);
		std::uint8_t set_debug_privilege(std::uint8_t state, std::uint8_t* previous_state);

		void* allocate_locked_memory(std::uint64_t size, std::uint32_t protection);
		std::uint8_t lock_resident_pages(void* address, std::uint64_t size);
		std::uint8_t free_memory(void* address);

		std::string to_string(std::wstring_view wstring);
	}

	namespace fs
	{
		std::uint8_t exists(std::string_view path);

		std::vector<std::uint8_t> read_from_disk(const std::string& full_path);
		std::uint8_t write_to_disk(const std::string& full_path, std::span<const std::uint8_t> buffer);
	}

	struct kernel_module_t
	{
		std::unordered_map<std::string, std::uint64_t> exports;

		std::uint64_t base_address{};
		std::uint32_t size{};
	};

	inline std::uint64_t current_cr3 = 0;
	inline std::uint64_t local_user_cr3 = 0;

	inline std::uint64_t directory_for_local_memory()
	{
		return local_user_cr3 != 0 ? local_user_cr3 : current_cr3;
	}

	/**
	 * @brief Fill guest bytes that were never faulted in from the matching image file.
	 * @details Reads the headers mapped at the module base. The file is accepted only
	 * when its time stamp and SizeOfImage match those headers. A kernel path is
	 * converted first, then System32 and System32\\drivers are tried. Missing bytes
	 * are copied from the section that contains each RVA. The virtual tail past the
	 * file data is zero.
	 * @param destination Buffer that already holds the guest prefix.
	 * @param guest_address Guest virtual address of destination[0].
	 * @param bytes_present Contiguous prefix already read from the guest.
	 * @param size Size of destination, in bytes.
	 * @param module_base Guest virtual base of the image.
	 * @param read_cr3 Page table used to read the in-memory headers.
	 * @param module_path Loader path of the image. May be empty.
	 * @param module_name File name used for the System32 candidates.
	 * @return Bytes now valid in destination. An unmatched file leaves bytes_present unchanged.
	 */
	std::uint64_t fill_image_bytes_from_disk(std::uint8_t* destination, std::uint64_t guest_address,
	                                         std::uint64_t bytes_present, std::uint64_t size,
	                                         std::uint64_t module_base, std::uint64_t read_cr3,
	                                         std::string_view module_path, std::string_view module_name);
}
