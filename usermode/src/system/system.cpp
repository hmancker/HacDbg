#include "system.h"
#include "nt_offsets.h"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "../hypercall/hypercall.h"
#include "../hook/breakpoint.h"
#include "../hook/hook.h"
#include <symbol_parser.h>
#include "../logs/logs.h"

#include <portable_executable/image.hpp>

#include <vector>
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(std::uint32_t privilege, std::uint8_t enable, std::uint8_t current_thread,
                                             std::uint8_t* previous_enabled_state);

static std::string kernel_path_to_win32(const std::wstring& kernel_path)
{
	std::wstring path = kernel_path;

	if (path.rfind(L"\\??\\", 0) == 0)
	{
		path = path.substr(4);
	}
	else if (path.rfind(L"\\SystemRoot", 0) == 0)
	{
		wchar_t windows[MAX_PATH] = {};
		const UINT length = GetWindowsDirectoryW(windows, MAX_PATH);

		if (length == 0 || length >= MAX_PATH)
		{
			return {};
		}

		path = std::wstring(windows) + path.substr(11);
	}
	else if (path.size() < 2 || path[1] != L':')
	{
		return {};
	}

	return sys::user::to_string(path);
}

static std::uint8_t image_file_matches(const std::vector<std::uint8_t>& file,
                                       const portable_executable::image_t* const memory_image)
{
	if (memory_image == nullptr || file.size() < sizeof(portable_executable::dos_header_t))
	{
		return 0;
	}

	const auto* const dos = reinterpret_cast<const portable_executable::dos_header_t*>(file.data());
	const auto* const memory_nt = memory_image->nt_headers();

	if (dos->e_magic != 0x5a4d || memory_nt == nullptr ||
	    static_cast<std::uint64_t>(dos->e_lfanew) + sizeof(portable_executable::nt_headers_t) > file.size())
	{
		return 0;
	}

	const auto* const file_nt = reinterpret_cast<const portable_executable::nt_headers_t*>(
		file.data() + dos->e_lfanew);

	if (file_nt->signature != 0x4550 ||
	    file_nt->file_header.time_date_stamp != memory_nt->file_header.time_date_stamp ||
	    file_nt->optional_header.size_of_image != memory_nt->optional_header.size_of_image)
	{
		return 0;
	}

	return 1;
}

static std::vector<std::uint8_t> load_matching_kernel_image(const std::wstring& full_name,
                                                            const std::string& module_name,
                                                            const portable_executable::image_t* const memory_image)
{
	std::vector<std::string> candidates;

	const std::string converted = kernel_path_to_win32(full_name);

	if (converted.empty() == false)
	{
		candidates.push_back(converted);
	}

	if (module_name.empty() == false)
	{
		char system_directory[MAX_PATH] = {};
		const UINT length = GetSystemDirectoryA(system_directory, MAX_PATH);

		if (length != 0 && length < MAX_PATH)
		{
			candidates.push_back(std::string(system_directory) + "\\" + module_name);
			candidates.push_back(std::string(system_directory) + "\\drivers\\" + module_name);
		}
	}

	for (const std::string& candidate : candidates)
	{
		if (sys::fs::exists(candidate) == 0)
		{
			continue;
		}

		std::vector<std::uint8_t> file = sys::fs::read_from_disk(candidate);

		if (image_file_matches(file, memory_image) != 0)
		{
			return file;
		}
	}

	return {};
}

static std::uint64_t copy_section_from_file(const std::vector<std::uint8_t>& file,
                                            const portable_executable::section_header_t& section,
                                            const std::uint64_t section_offset,
                                            const std::uint64_t chunk,
                                            std::uint8_t* const destination)
{
	if (section_offset >= section.virtual_size || chunk == 0)
	{
		return 0;
	}

	const std::uint64_t available = (std::min)(chunk, static_cast<std::uint64_t>(section.virtual_size) - section_offset);

	if (section_offset >= section.size_of_raw_data || section.pointer_to_raw_data == 0)
	{
		std::memset(destination, 0, static_cast<std::size_t>(available));
		return available;
	}

	if (file.empty() != false)
	{
		return 0;
	}

	const std::uint64_t raw_left = section.size_of_raw_data - section_offset;
	const std::uint64_t file_offset = static_cast<std::uint64_t>(section.pointer_to_raw_data) + section_offset;

	if (file_offset >= file.size())
	{
		return 0;
	}

	const std::uint64_t from_file = (std::min)(available, (std::min)(raw_left, file.size() - file_offset));

	std::memcpy(destination, file.data() + file_offset, static_cast<std::size_t>(from_file));

	if (from_file < available)
	{
		std::memset(destination + from_file, 0, static_cast<std::size_t>(available - from_file));
	}

	return available;
}

static std::uint8_t image_headers_usable(const std::vector<std::uint8_t>& headers, std::uint64_t* const section_end_out)
{
	*section_end_out = 0;

	if (headers.size() < sizeof(portable_executable::dos_header_t))
	{
		return 0;
	}

	const auto* const dos = reinterpret_cast<const portable_executable::dos_header_t*>(headers.data());

	if (dos->e_magic != 0x5a4d)
	{
		return 0;
	}

	const std::uint64_t nt_offset = dos->e_lfanew;
	constexpr std::uint64_t nt_fixed = sizeof(std::uint32_t) + sizeof(portable_executable::file_header_t);

	if (nt_offset > headers.size() || nt_fixed > headers.size() - nt_offset)
	{
		return 0;
	}

	const auto* const nt = reinterpret_cast<const portable_executable::nt_headers_t*>(headers.data() + nt_offset);

	if (nt->signature != 0x4550 || sizeof(portable_executable::nt_headers_t) > headers.size() - nt_offset)
	{
		return 0;
	}

	const std::uint64_t section_offset = nt_offset + nt_fixed + nt->file_header.sizeof_optional_header;
	const std::uint64_t section_bytes =
		static_cast<std::uint64_t>(nt->file_header.number_of_sections) * sizeof(portable_executable::section_header_t);

	if (section_offset > headers.size() || section_bytes > headers.size() - section_offset)
	{
		*section_end_out = section_offset + section_bytes;

		return 0;
	}

	*section_end_out = section_offset + section_bytes;

	return 1;
}

std::uint64_t sys::fill_image_bytes_from_disk(std::uint8_t* const destination, const std::uint64_t guest_address,
                                              const std::uint64_t bytes_present, const std::uint64_t size,
                                              const std::uint64_t module_base, const std::uint64_t read_cr3,
                                              const std::string_view module_path, const std::string_view module_name)
{
	constexpr std::uint64_t header_limit = 0x10000;

	if (destination == nullptr || module_base == 0 || read_cr3 == 0 || bytes_present >= size ||
	    guest_address < module_base || guest_address + bytes_present < guest_address)
	{
		return bytes_present;
	}

	std::vector<std::uint8_t> headers(page_size);
	const std::uint64_t header_bytes = hypercall::read_guest_virtual_memory(
		headers.data(), module_base, read_cr3, headers.size());

	if (header_bytes < sizeof(portable_executable::dos_header_t))
	{
		return bytes_present;
	}

	headers.resize(static_cast<std::size_t>(header_bytes));

	std::uint64_t section_end = 0;
	std::uint8_t usable = image_headers_usable(headers, &section_end);

	if (usable == 0 && section_end > headers.size() && section_end <= header_limit)
	{
		const std::uint64_t already = headers.size();

		headers.resize(static_cast<std::size_t>(section_end));

		const std::uint64_t more = hypercall::read_guest_virtual_memory(
			headers.data() + already, module_base + already, read_cr3, section_end - already);

		headers.resize(static_cast<std::size_t>(already + more));
		usable = image_headers_usable(headers, &section_end);
	}

	if (usable == 0)
	{
		return bytes_present;
	}

	const auto* const image = reinterpret_cast<const portable_executable::image_t*>(headers.data());
	const std::uint32_t image_size = image->nt_headers()->optional_header.size_of_image;
	const std::uint64_t buffer_rva = guest_address - module_base;

	if (image_size == 0 || buffer_rva >= image_size)
	{
		return bytes_present;
	}

	std::wstring full_name;
	full_name.reserve(module_path.size());

	for (const char character : module_path)
	{
		full_name.push_back(static_cast<wchar_t>(static_cast<unsigned char>(character)));
	}

	const std::vector<std::uint8_t> file = load_matching_kernel_image(
		full_name, std::string(module_name), image);

	if (file.empty() == true)
	{
		return bytes_present;
	}

	const std::uint64_t max_end = (std::min)(size, static_cast<std::uint64_t>(image_size) - buffer_rva);
	std::uint64_t filled = bytes_present;

	while (filled < max_end)
	{
		const std::uint64_t rva = buffer_rva + filled;
		const portable_executable::section_header_t* section = nullptr;

		for (const portable_executable::section_header_t& current : image->sections())
		{
			const std::uint64_t section_limit =
				static_cast<std::uint64_t>(current.virtual_address) + current.virtual_size;

			if (current.virtual_size != 0 && rva >= current.virtual_address && rva < section_limit)
			{
				section = &current;

				break;
			}
		}

		if (section == nullptr)
		{
			break;
		}

		const std::uint64_t copied = copy_section_from_file(
			file, *section, rva - section->virtual_address, max_end - filled, destination + filled);

		if (copied == 0)
		{
			break;
		}

		filled += copied;
	}

	return filled;
}

static std::vector<std::uint8_t> dump_kernel_module(const std::uint64_t module_base_address,
                                                    std::uint32_t* const failed_sections_out = nullptr,
                                                    const std::wstring& full_name = {},
                                                    const std::string& module_name = {})
{
	constexpr std::uint64_t headers_size = page_size;

	std::vector<std::uint8_t> headers(headers_size);
	std::uint32_t failed_sections = 0;

	if (failed_sections_out != nullptr)
	{
		*failed_sections_out = 0;
	}

	std::uint64_t bytes_read = 0;

	while (bytes_read < headers_size)
	{
		const std::uint64_t current_address = module_base_address + bytes_read;
		const std::uint64_t page_left = page_size - (current_address & (page_size - 1));
		const std::uint64_t chunk = (std::min)(headers_size - bytes_read, page_left);

		const std::uint64_t copied = hypercall::read_guest_virtual_memory(
			headers.data() + bytes_read, current_address, sys::current_cr3, chunk);

		if (copied == 0)
		{
			break;
		}

		bytes_read += copied;
	}

	if (bytes_read != headers_size)
	{
		const std::uint64_t source_physical = hypercall::translate_guest_virtual_address(
			module_base_address, sys::current_cr3);
		const std::uint64_t destination_physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(headers.data()), sys::directory_for_local_memory());
		const std::uint64_t physical_bytes_read =
			source_physical == 0
				? 0
				: hypercall::read_guest_physical_memory(headers.data(), source_physical, headers_size);

		LOG_ERR("kernel module header read failed: base=0x{:x} cr3=0x{:x} source_phys=0x{:x} "
		        "destination_phys=0x{:x} virtual_bytes={}/{} physical_bytes={}/{}",
		        module_base_address, sys::current_cr3, source_physical, destination_physical,
		        bytes_read, headers_size, physical_bytes_read, headers_size);

		if (physical_bytes_read != headers_size)
		{
			return {};
		}

		bytes_read = physical_bytes_read;
	}

	const std::uint16_t magic = *reinterpret_cast<std::uint16_t*>(headers.data());

	if (magic != 0x5a4d)
	{
		LOG_ERR("kernel module header has invalid magic: base=0x{:x} magic=0x{:x}",
		        module_base_address, magic);

		return {};
	}

	const portable_executable::image_t* image = reinterpret_cast<portable_executable::image_t*>(headers.data());

	std::vector<std::uint8_t> image_buffer(image->nt_headers()->optional_header.size_of_image);
	std::vector<std::uint8_t> image_file;
	std::uint8_t image_file_checked = 0;

	memcpy(image_buffer.data(), headers.data(), page_size);

	for (const auto& current_section : image->sections())
	{
		if (current_section.virtual_size == 0 || current_section.characteristics.mem_discardable != 0)
		{
			continue;
		}

		const std::uint64_t read_offset = current_section.virtual_address;
		const std::uint64_t read_size = current_section.virtual_size;

		std::uint64_t section_copied = 0;

		while (section_copied < read_size)
		{
			const std::uint64_t current_address = module_base_address + read_offset + section_copied;
			const std::uint64_t page_left = page_size - (current_address & (page_size - 1));
			const std::uint64_t chunk = (std::min)(read_size - section_copied, page_left);

			const std::uint64_t copied = hypercall::read_guest_virtual_memory(
				image_buffer.data() + read_offset + section_copied, current_address, sys::current_cr3, chunk);

			if (copied == 0)
			{
				//
				// A prototype PTE of 0xA0 has no PFN. The page was never
				// faulted in, so the bytes are still in the on-disk image.
				//
				if (image_file_checked == 0)
				{
					image_file_checked = 1;
					image_file = load_matching_kernel_image(full_name, module_name, image);
				}

				const std::uint64_t filled = copy_section_from_file(
					image_file, current_section, section_copied, chunk,
					image_buffer.data() + read_offset + section_copied);

				if (filled == 0)
				{
					break;
				}

				section_copied += filled;
				continue;
			}

			section_copied += copied;
		}

		if (section_copied != read_size)
		{
			std::uint64_t physical_section_copied = 0;

			while (physical_section_copied < read_size)
			{
				const std::uint64_t current_address =
					module_base_address + read_offset + physical_section_copied;
				const std::uint64_t page_left = page_size - (current_address & (page_size - 1));
				const std::uint64_t chunk =
					(std::min)(read_size - physical_section_copied, page_left);
				const std::uint64_t section_physical = hypercall::translate_guest_virtual_address(
					current_address, sys::current_cr3);

				if (section_physical == 0)
				{
					break;
				}

				const std::uint64_t copied = hypercall::read_guest_physical_memory(
					image_buffer.data() + read_offset + physical_section_copied, section_physical,
					chunk);

				physical_section_copied += copied;

				if (copied != chunk)
				{
					break;
				}
			}

			if (physical_section_copied == read_size)
			{
				section_copied = physical_section_copied;
			}

			if (section_copied != read_size)
			{
				failed_sections++;
			}
		}
	}

	if (failed_sections_out != nullptr)
	{
		*failed_sections_out = failed_sections;
	}

	return image_buffer;
}

static std::uint64_t find_kernel_detour_holder_base_address(const portable_executable::image_t* const ntoskrnl,
                                                            const std::uint64_t ntoskrnl_base_address)
{
	for (const auto& current_section : ntoskrnl->sections())
	{
		const std::string_view current_section_name(current_section.name);

		if (current_section.characteristics.mem_execute == 1 && current_section_name.contains("Pad"))
		{
			return ntoskrnl_base_address + current_section.virtual_address;
		}
	}

	return 0;
}

static std::unordered_map<std::string, std::uint64_t> parse_module_exports(
	const portable_executable::image_t* const image, const std::string& module_name,
	const std::uint64_t module_base_address)
{
	std::unordered_map<std::string, std::uint64_t> exports = {};

	for (const auto& current_export : image->exports())
	{
		const std::string current_export_name = module_name + "!" + current_export.name;
		const std::uint64_t delta = reinterpret_cast<std::uint64_t>(current_export.address) - image->as<
			std::uint64_t>();

		exports[current_export_name] = module_base_address + delta;
	}

	return exports;
}

static void add_module_to_list(const std::string& module_name, const std::span<const std::uint8_t> module_dump,
                               const std::uint64_t module_base_address, const std::uint32_t module_size)
{
	sys::kernel_module_t kernel_module = {};

	const auto* const image = reinterpret_cast<const portable_executable::image_t*>(module_dump.data());

	kernel_module.exports = parse_module_exports(image, module_name, module_base_address);
	kernel_module.base_address = module_base_address;
	kernel_module.size = module_size;

	sys::kernel::modules_list[module_name] = kernel_module;
}

static void erase_unused_modules(const std::unordered_map<std::string, sys::kernel_module_t>& modules_not_found)
{
	for (const auto& [module_name, module_info] : modules_not_found)
	{
		sys::kernel::modules_list.erase(module_name);
	}
}

// requires SeDebugPriviledge, use PsLoadedModulesList instead unless if using before ntoskrnl.exe is parsed
static std::vector<rtl_process_module_information_t> get_loaded_modules_priviledged()
{
	std::uint32_t size_of_information = 0;

	sys::user::query_system_information(11, nullptr, 0, &size_of_information);

	if (size_of_information == 0)
	{
		return {};
	}

	std::vector<std::uint8_t> buffer(size_of_information);

	const std::uint32_t status = sys::user::query_system_information(11, buffer.data(), size_of_information,
	                                                                 &size_of_information);

	if (NT_SUCCESS(status) == false)
	{
		return {};
	}

	auto* process_modules = reinterpret_cast<rtl_process_modules_t*>(buffer.data());

	rtl_process_module_information_t* start = &process_modules->modules[0];
	rtl_process_module_information_t* end = start + process_modules->module_count;

	return {start, end};
}

template <class t>
static t read_kernel_virtual_memory(const std::uint64_t address)
{
	t buffer = t();

	hypercall::read_guest_virtual_memory(&buffer, address, sys::current_cr3, sizeof(t));

	return buffer;
}

static std::wstring read_unicode_string(const std::uint64_t address)
{
	const auto length = read_kernel_virtual_memory<std::uint16_t>(address);

	if (length == 0)
	{
		return {};
	}

	const auto buffer_address = read_kernel_virtual_memory<std::uint64_t>(address + 8);

	std::wstring string(length / 2, L'\0');

	hypercall::read_guest_virtual_memory(string.data(), buffer_address, sys::current_cr3, length);

	return string;
}

static std::uint64_t get_ps_loaded_module_list()
{
	const std::string ntoskrnl_name = "ntoskrnl.exe";

	if (static_cast<int>(sys::kernel::modules_list.contains(ntoskrnl_name)) == 0)
	{
		return 0;
	}

	sys::kernel_module_t& ntoskrnl = sys::kernel::modules_list[ntoskrnl_name];

	const std::string ps_loaded_module_list_name = "ntoskrnl.exe!PsLoadedModuleList";

	return ntoskrnl.exports[ps_loaded_module_list_name];
}

std::uint8_t sys::kernel::parse_modules()
{
	const std::uint64_t ps_loaded_module_list = get_ps_loaded_module_list();

	if (ps_loaded_module_list == 0)
	{
		LOG_ERR("can't locate PsLoadedModuleList");

		return 0;
	}

	std::unordered_map<std::string, kernel_module_t> modules_not_found = modules_list;
	std::uint32_t incomplete_modules = 0;
	std::string incomplete_module_names;

	const std::uint64_t start_entry = ps_loaded_module_list;

	auto current_entry = read_kernel_virtual_memory<std::uint64_t>(start_entry); // flink

	while (current_entry != start_entry)
	{
		const kernel_module_t kernel_module = {};

		const auto module_base_address = read_kernel_virtual_memory<std::uint64_t>(current_entry + 0x30); // DllBase
		const auto module_size = read_kernel_virtual_memory<std::uint32_t>(current_entry + 0x40); // SizeOfImage
		const std::wstring module_path = read_unicode_string(current_entry + 0x48); // FullDllName
		const std::string module_name = user::to_string(read_unicode_string(current_entry + 0x58)); // BaseDllName

		// current_entry must not be accessed after this point in this iteration
		current_entry = read_kernel_virtual_memory<std::uint64_t>(current_entry); // flink

		if (modules_list.contains(module_name))
		{
			modules_not_found.erase(module_name);

			const kernel_module_t already_present_module = modules_list[module_name];

			if (already_present_module.base_address == module_base_address && already_present_module.size ==
				module_size)
			{
				continue;
			}
		}

		std::uint32_t failed_sections = 0;
		const std::vector<std::uint8_t> module_dump = dump_kernel_module(
			module_base_address, &failed_sections, module_path, module_name);

		if (module_dump.empty())
		{
			continue;
		}

		if (failed_sections != 0)
		{
			if (incomplete_modules < 8)
			{
				if (incomplete_module_names.empty() == false)
				{
					incomplete_module_names += ", ";
				}

				incomplete_module_names += module_name;
			}

			incomplete_modules++;
		}

		add_module_to_list(module_name, module_dump, module_base_address, module_size);
	}

	if (incomplete_modules != 0)
	{
		LOG_WARN("kernel module dump incomplete: {} modules [{}]", incomplete_modules,
		         incomplete_module_names);
	}

	erase_unused_modules(modules_not_found);

	return 1;
}

static void fix_dump(std::vector<std::uint8_t>& buffer)
{
	auto* image = reinterpret_cast<portable_executable::image_t*>(buffer.data());

	for (auto& current_section : image->sections())
	{
		current_section.pointer_to_raw_data = current_section.virtual_address;
		current_section.size_of_raw_data = current_section.virtual_size;
	}
}

std::uint8_t sys::kernel::dump_module_to_disk(const std::string_view target_module_name,
                                              const std::string_view output_directory)
{
	const auto module_info = modules_list[target_module_name.data()];

	const std::uint64_t module_base_address = module_info.base_address;

	if (module_base_address == 0)
	{
		return 0;
	}

	std::vector<std::uint8_t> buffer = dump_kernel_module(module_base_address);

	if (static_cast<int>(buffer.empty()) == 1)
	{
		return 0;
	}

	fix_dump(buffer);

	const std::string output_path = std::string(output_directory) + "\\" + "dump_" + std::string(target_module_name);

	return fs::write_to_disk(output_path, buffer);
}

std::unordered_map<std::string, std::uint64_t> sys::kernel::compile_symbol_list()
{
	std::unordered_map<std::string, std::uint64_t> aliases = { {"current_cr3", current_cr3} };

	for (auto& [module_name, module_info] : modules_list)
	{
		aliases.insert({ module_name, module_info.base_address });
		aliases.insert(module_info.exports.begin(), module_info.exports.end());
	}

	return aliases;
}

struct ntoskrnl_information_t
{
	std::uint64_t base_address;
	std::uint32_t size;

	std::vector<std::uint8_t> dump;
};

static std::optional<ntoskrnl_information_t> load_ntoskrnl_information()
{
	std::uint8_t desired_privilege_state = 1;
	std::uint8_t previous_privilege_state = 0;

	if (sys::user::set_debug_privilege(desired_privilege_state, &previous_privilege_state) == 0)
	{
		LOG_ERR("unable to acquire necessary privilege");

		return std::nullopt;
	}

	const std::vector<rtl_process_module_information_t> loaded_modules = get_loaded_modules_priviledged();

	sys::user::set_debug_privilege(previous_privilege_state, &desired_privilege_state);

	for (const rtl_process_module_information_t& current_module : loaded_modules)
	{
		const std::string_view current_module_name = reinterpret_cast<const char*>(current_module.full_path_name +
			current_module.offset_to_file_name);

		if (current_module_name == "ntoskrnl.exe")
		{
			std::uint32_t failed_sections = 0;
			const std::vector<std::uint8_t> ntoskrnl_dump =
				dump_kernel_module(current_module.image_base, &failed_sections);

			if (ntoskrnl_dump.empty())
			{
				LOG_ERR("unable to dump ntoskrnl.exe");

				return std::nullopt;
			}

			if (failed_sections != 0)
			{
				LOG_WARN("ntoskrnl.exe dump incomplete: failed_sections={}", failed_sections);
			}

			ntoskrnl_information_t ntoskrnl_info = {};

			ntoskrnl_info.base_address = current_module.image_base;
			ntoskrnl_info.size = current_module.image_size;
			ntoskrnl_info.dump = ntoskrnl_dump;

			return ntoskrnl_info;
		}
	}

	return std::nullopt;
}

static std::uint8_t parse_ntoskrnl()
{
	const std::optional<ntoskrnl_information_t> ntoskrnl_info = load_ntoskrnl_information();

	if (!ntoskrnl_info)
	{
		LOG_ERR("unable to load ntoskrnl.exe's information");

		return 0;
	}

	const std::span<const std::uint8_t> ntoskrnl_dump = ntoskrnl_info->dump;
	const auto* const ntoskrnl_image = reinterpret_cast<const portable_executable::image_t*>(ntoskrnl_dump.data());

	add_module_to_list("ntoskrnl.exe", ntoskrnl_dump, ntoskrnl_info->base_address, ntoskrnl_info->size);

	if (nt_offsets_select_from_image(ntoskrnl_dump) == 0)
	{
		LOG_ERR("unable to select windows kernel offsets");

		return 0;
	}

	const std::uint64_t kernel_detour_holder_base = find_kernel_detour_holder_base_address(
		ntoskrnl_image, ntoskrnl_info->base_address);

	if (kernel_detour_holder_base == 0)
	{
		LOG_ERR("unable to locate kernel hook holder");

		return 0;
	}

	hook::set_kernel_detour_holder_base(kernel_detour_holder_base);

	return 1;
}

static std::uint64_t capture_local_user_cr3()
{
	constexpr std::uint64_t log_capacity = 2048;

	hypercall::log_current_state();

	std::vector<trap_frame_log_t> logs(static_cast<std::size_t>(log_capacity));
	const std::uint64_t flushed = hypercall::flush_logs(logs);

	if (flushed == static_cast<std::uint64_t>(-1) || flushed == 0)
	{
		return 0;
	}

	const std::uint64_t self = reinterpret_cast<std::uint64_t>(&sys::current_cr3);

	for (std::uint64_t index = flushed; index > 0; index--)
	{
		const std::uint64_t cr3 = logs[static_cast<std::size_t>(index - 1)].cr3;

		if (cr3 != 0 && hypercall::translate_guest_virtual_address(self, cr3) != 0)
		{
			return cr3;
		}
	}

	return 0;
}

//
// The system directory does not map session space. This process's kernel
// directory does, so win32k can be translated. Keep the system directory
// when this one cannot translate ntoskrnl.
//
static std::uint64_t capture_session_kernel_directory(const std::uint64_t kernel_base)
{
	const nt_offsets_t* const nt = nt_offsets_current();

	if (nt == nullptr || kernel_base == 0 || sys::kernel::modules_list.contains("ntoskrnl.exe") == 0)
	{
		return 0;
	}

	const auto export_it = sys::kernel::modules_list["ntoskrnl.exe"].exports.find(
		"ntoskrnl.exe!PsInitialSystemProcess");

	if (export_it == sys::kernel::modules_list["ntoskrnl.exe"].exports.end() || export_it->second == 0)
	{
		return 0;
	}

	std::uint64_t eprocess = 0;

	if (hypercall::read_guest_virtual_memory(&eprocess, export_it->second, sys::current_cr3, sizeof(eprocess)) !=
			sizeof(eprocess) || eprocess == 0)
	{
		return 0;
	}

	const std::uint64_t self = GetCurrentProcessId();
	const std::uint64_t first = eprocess;
	std::uint64_t fallback = 0;

	for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
	{
		std::uint64_t directory = 0;
		std::uint64_t pid = 0;

		if (hypercall::read_guest_virtual_memory(&directory, eprocess + nt->eprocess_directory_table_base,
		                                         sys::current_cr3, sizeof(directory)) == sizeof(directory))
		{
			directory &= 0x000FFFFFFFFFF000ull;

			if (directory != 0 && directory != sys::current_cr3 &&
				hypercall::translate_guest_virtual_address(kernel_base, directory) != 0)
			{
				if (hypercall::read_guest_virtual_memory(&pid, eprocess + nt->eprocess_unique_process_id,
				                                         sys::current_cr3, sizeof(pid)) == sizeof(pid) &&
					pid == self)
				{
					return directory;
				}

				if (fallback == 0)
				{
					fallback = directory;
				}
			}
		}

		std::uint64_t flink = 0;

		if (hypercall::read_guest_virtual_memory(&flink, eprocess + nt->eprocess_active_process_links,
		                                         sys::current_cr3, sizeof(flink)) != sizeof(flink) || flink == 0)
		{
			break;
		}

		eprocess = flink - nt->eprocess_active_process_links;

		if (eprocess == first)
		{
			break;
		}
	}

	return fallback;
}

std::uint8_t sys::set_up()
{
	current_cr3 = hypercall::read_guest_cr3();

	if (current_cr3 <= page_size)
	{
		LOG_ERR("hyperv-attachment doesn't seem to be loaded");

		return 0;
	}

	//
	// read_guest_cr3 is the kernel directory. Under KPTI that directory has
	// no user half, so it cannot translate shadow pages allocated in this
	// process. The CR3 at this CPUID exit is the directory that maps them.
	//
	local_user_cr3 = capture_local_user_cr3();

	if (local_user_cr3 == 0)
	{
		LOG_ERR("debugger user directory does not map local memory");
	}

	if (parse_ntoskrnl() == 0)
	{
		LOG_ERR("unable to parse ntoskrnl.exe");

		return 0;
	}

	{
		const std::uint64_t system_directory = current_cr3;
		const std::uint64_t session_directory = capture_session_kernel_directory(
			kernel::modules_list["ntoskrnl.exe"].base_address);

		if (session_directory != 0)
		{
			current_cr3 = session_directory;
			LOG_INFO("kernel directory uses session page tables: system=0x{:x} session=0x{:x}",
			         system_directory, session_directory);
		}
	}

	if (kernel::parse_modules() == 0)
	{
		LOG_ERR("unable to parse kernel modules");

		return 0;
	}

	return 1;
}

void sys::clean_up()
{
	breakpoint::clean_up();
	symbol_parser::unload();
	hook::clean_up();
}

std::uint32_t sys::user::query_system_information(std::int32_t information_class, void* information_out,
                                                  const std::uint32_t information_size, std::uint32_t* returned_size)
{
	return NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(information_class), information_out,
	                                information_size, reinterpret_cast<ULONG*>(returned_size));
}

std::uint32_t sys::user::adjust_privilege(const std::uint32_t privilege, const std::uint8_t enable,
                                          const std::uint8_t current_thread_only, std::uint8_t* previous_enabled_state)
{
	return RtlAdjustPrivilege(privilege, enable, current_thread_only, previous_enabled_state);
}

std::uint8_t sys::user::set_debug_privilege(const std::uint8_t state, std::uint8_t* previous_state)
{
	constexpr std::uint32_t debug_privilege_id = 20;

	const std::uint32_t status = adjust_privilege(debug_privilege_id, state, 0, previous_state);

	return NT_SUCCESS(status);
}

void* sys::user::allocate_locked_memory(const std::uint64_t size, const std::uint32_t protection)
{
	void* allocation_base = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);

	if (allocation_base == nullptr)
	{
		return nullptr;
	}

	const std::int32_t lock_status = VirtualLock(allocation_base, size);

	if (lock_status == 0)
	{
		free_memory(allocation_base);

		return nullptr;
	}

	return allocation_base;
}

std::uint8_t sys::user::free_memory(void* address)
{
	const std::int32_t free_status = VirtualFree(address, 0, MEM_RELEASE);

	return static_cast<std::uint8_t>(free_status != 0);
}

std::string sys::user::to_string(const std::wstring_view wstring)
{
	if (static_cast<int>(wstring.empty()) == 1)
	{
		return {};
	}

	std::string converted_string = {};

	std::ranges::transform(wstring,
	                       std::back_inserter(converted_string), [](const wchar_t character)
	                       {
		                       return static_cast<char>(character);
	                       });

	return converted_string;
}

std::uint8_t sys::fs::exists(const std::string_view path)
{
	return static_cast<std::uint8_t>(std::filesystem::exists(path));
}

std::vector<std::uint8_t> sys::fs::read_from_disk(const std::string& full_path)
{
	std::ifstream file(full_path, std::ios::binary);

	if (file.is_open())
	{
		return { std::istreambuf_iterator(file), { } };
	}

	return { };
}

std::uint8_t sys::fs::write_to_disk(const std::string& full_path, const std::span<const std::uint8_t> buffer)
{
	std::ofstream file(full_path.data(), std::ios::binary);

	if (static_cast<int>(file.is_open()) == 0)
	{
		return 0;
	}

	file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

	return static_cast<std::uint8_t>(file.good());
}
