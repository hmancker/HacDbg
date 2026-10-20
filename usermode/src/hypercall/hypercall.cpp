#include "hypercall.h"
#include <Windows.h>
#include <winioctl.h>
#include <hypercall/hypercall_def.h>
#include <hypercall/control.h>
#include "../logs/logs.h"
#include "../system/system.h"

#include <mutex>

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8,
                                              std::uint64_t r9);

static_assert(sizeof(HACDBG_HYPERCALL_REQUEST) == 0x40, "IOCTL ABI changed");
static_assert(sizeof(HACDBG_VERSION_INFO) == 0x30, "version ABI changed");

static std::mutex g_control_mutex;
static HANDLE g_control_handle = INVALID_HANDLE_VALUE;

static HANDLE get_control_handle_locked()
{
	if (g_control_handle == INVALID_HANDLE_VALUE)
	{
		g_control_handle = CreateFileW(HACDBG_USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
		                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
		                               FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	return g_control_handle;
}

static std::uint64_t make_hypercall(const hypercall_type_t call_type, const std::uint64_t call_reserved_data,
                                    const std::uint64_t rdx, const std::uint64_t r8, const std::uint64_t r9)
{
	HACDBG_HYPERCALL_REQUEST request = {};

	request.Version = HACDBG_HYPERCALL_REQUEST_VERSION;
	request.CallType = static_cast<std::uint64_t>(call_type);
	request.Reserved = call_reserved_data;
	request.ProcessCr3 = sys::current_cr3;
	request.Rdx = rdx;
	request.R8 = r8;
	request.R9 = r9;

	{
		std::lock_guard<std::mutex> lock(g_control_mutex);
		const HANDLE control_handle = get_control_handle_locked();

		if (control_handle != INVALID_HANDLE_VALUE)
		{
			DWORD bytes_returned = 0;

			if (DeviceIoControl(control_handle, HACDBG_IOCTL_HYPERCALL, &request, sizeof(request), &request,
			                    sizeof(request), &bytes_returned, nullptr) != FALSE &&
			    bytes_returned >= sizeof(request) && request.Status == 0)
			{
				return request.Result;
			}

			LOG_ERR("hypercall ioctl failed: type={} status=0x{:x} get_last_error={}", request.CallType,
			        request.Status, GetLastError());

			if (request.Status != 0)
			{
				CloseHandle(g_control_handle);
				g_control_handle = INVALID_HANDLE_VALUE;
			}
		}
	}

	hypercall_info_t hypercall_info;

	LOG_WARN("falling back to CPUID hypercall for type={}", request.CallType);

	hypercall_info.primary_key = hypercall_primary_key;
	hypercall_info.secondary_key = hypercall_secondary_key;
	hypercall_info.call_type = call_type;
	hypercall_info.call_reserved_data = call_reserved_data;

	return launch_raw_hypercall(hypercall_info, rdx, r8, r9);
}

static std::uint8_t offset_wraps(const std::uint64_t address, const std::uint64_t offset)
{
	return static_cast<std::uint8_t>(offset != 0 && address + offset < address);
}

static std::uint8_t request_global_slat_flush()
{
	std::lock_guard<std::mutex> lock(g_control_mutex);

	const HANDLE control_handle = get_control_handle_locked();

	if (control_handle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	DWORD bytes_returned = 0;

	if (DeviceIoControl(control_handle, HACDBG_IOCTL_FLUSH_SLAT, nullptr, 0, nullptr, 0, &bytes_returned,
	                    nullptr) == FALSE)
	{
		CloseHandle(g_control_handle);
		g_control_handle = INVALID_HANDLE_VALUE;
		return 0;
	}

	return 1;
}

static std::uint64_t invoke_chunked_hypercall(const hypercall_type_t call_type, const std::uint64_t call_reserved_data,
                                              const std::uint64_t rdx_address, const std::uint64_t r8_address,
                                              const std::uint64_t size)
{
	std::uint64_t bytes_copied = 0;

	while (bytes_copied < size)
	{
		if (offset_wraps(rdx_address, bytes_copied) == 1 || offset_wraps(r8_address, bytes_copied) == 1)
		{
			break;
		}

		const std::uint64_t remaining = size - bytes_copied;
		const std::uint64_t chunk_size = remaining < hypercall_memory_chunk_size ? remaining : hypercall_memory_chunk_size;

		const std::uint64_t copied = make_hypercall(call_type, call_reserved_data, rdx_address + bytes_copied,
		                                            r8_address + bytes_copied, chunk_size);

		bytes_copied += copied;

		if (copied != chunk_size)
		{
			break;
		}
	}

	return bytes_copied;
}

std::uint64_t hypercall::read_guest_physical_memory(void* const guest_destination_buffer,
                                                    const std::uint64_t guest_source_physical_address,
                                                    const std::uint64_t size)
{
	constexpr auto call_type = hypercall_type_t::guest_physical_memory_operation;

	constexpr auto operation_type = static_cast<std::uint64_t>(memory_operation_t::read_operation);
	const auto guest_destination_virtual_address = reinterpret_cast<std::uint64_t>(guest_destination_buffer);

	return invoke_chunked_hypercall(call_type, operation_type, guest_source_physical_address,
	                                guest_destination_virtual_address, size);
}

std::uint64_t hypercall::write_guest_physical_memory(const void* const guest_source_buffer,
                                                     const std::uint64_t guest_destination_physical_address,
                                                     const std::uint64_t size)
{
	constexpr auto call_type = hypercall_type_t::guest_physical_memory_operation;

	constexpr auto operation_type = static_cast<std::uint64_t>(memory_operation_t::write_operation);
	const auto guest_source_virtual_address = reinterpret_cast<std::uint64_t>(guest_source_buffer);

	return invoke_chunked_hypercall(call_type, operation_type, guest_destination_physical_address,
	                                guest_source_virtual_address, size);
}

std::uint64_t hypercall::read_guest_virtual_memory(void* const guest_destination_buffer,
                                                   const std::uint64_t guest_source_virtual_address,
                                                   const std::uint64_t source_cr3, const std::uint64_t size)
{
	virt_memory_op_hypercall_info_t memory_op_call = {};

	memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
	memory_op_call.memory_operation = memory_operation_t::read_operation;
	memory_op_call.address_of_page_directory = source_cr3 >> 12;

	const hypercall_info_t hypercall_info = {.value = memory_op_call.value};

	const auto guest_destination_virtual_address = reinterpret_cast<std::uint64_t>(guest_destination_buffer);

	return invoke_chunked_hypercall(hypercall_info.call_type, hypercall_info.call_reserved_data,
	                                guest_destination_virtual_address, guest_source_virtual_address, size);
}

std::uint64_t hypercall::write_guest_virtual_memory(const void* const guest_source_buffer,
                                                    const std::uint64_t guest_destination_virtual_address,
                                                    const std::uint64_t destination_cr3, const std::uint64_t size)
{
	virt_memory_op_hypercall_info_t memory_op_call = {};

	memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
	memory_op_call.memory_operation = memory_operation_t::write_operation;
	memory_op_call.address_of_page_directory = destination_cr3 >> 12;

	const hypercall_info_t hypercall_info = {.value = memory_op_call.value};
	const auto guest_source_virtual_address = reinterpret_cast<std::uint64_t>(guest_source_buffer);

	return invoke_chunked_hypercall(hypercall_info.call_type, hypercall_info.call_reserved_data,
	                                guest_source_virtual_address, guest_destination_virtual_address, size);
}

std::uint64_t hypercall::translate_guest_virtual_address(const std::uint64_t guest_virtual_address,
                                                         const std::uint64_t guest_cr3)
{
	constexpr auto call_type = hypercall_type_t::translate_guest_virtual_address;

	return make_hypercall(call_type, 0, guest_virtual_address, guest_cr3, 0);
}

std::uint64_t hypercall::read_guest_cr3()
{
	constexpr auto call_type = hypercall_type_t::read_guest_cr3;

	return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint8_t hypercall::query_driver_version(std::uint32_t& major, std::uint32_t& minor,
                                             std::uint32_t& patch, std::uint32_t& hypercall_abi_version,
                                             std::string& version)
{
	HACDBG_VERSION_INFO info = {};
	std::lock_guard<std::mutex> lock(g_control_mutex);
	const HANDLE control_handle = get_control_handle_locked();

	if (control_handle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	DWORD bytes_returned = 0;

	if (DeviceIoControl(control_handle, HACDBG_IOCTL_QUERY_VERSION, nullptr, 0, &info, sizeof(info),
	                    &bytes_returned, nullptr) == FALSE ||
	    bytes_returned < sizeof(info))
	{
		LOG_WARN("query driver version failed: get_last_error={}", GetLastError());
		return 0;
	}

	major = info.Major;
	minor = info.Minor;
	patch = info.Patch;
	hypercall_abi_version = info.HypercallAbiVersion;
	version = info.VersionString;
	return 1;
}

std::uint64_t hypercall::add_slat_code_hook(const std::uint64_t target_guest_physical_address,
                                            const std::uint64_t shadow_page_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::add_slat_code_hook;

	const std::uint64_t result =
		make_hypercall(call_type, 0, target_guest_physical_address, shadow_page_guest_physical_address, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::remove_slat_code_hook(const std::uint64_t target_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::remove_slat_code_hook;

	const std::uint64_t result = make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::hide_guest_physical_page(const std::uint64_t target_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::hide_guest_physical_page;

	const std::uint64_t result = make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::flush_logs(std::vector<trap_frame_log_t>& logs)
{
	constexpr auto call_type = hypercall_type_t::flush_logs;

	return make_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(logs.data()), logs.size(), 0);
}

std::uint64_t hypercall::get_heap_free_page_count()
{
	constexpr auto call_type = hypercall_type_t::get_heap_free_page_count;

	return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::flush_slat_cache()
{
	if (request_global_slat_flush() == 1)
	{
		return 1;
	}

	constexpr auto call_type = hypercall_type_t::flush_slat_cache;

	return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::breakpoint_resume()
{
	constexpr auto call_type = hypercall_type_t::breakpoint_resume;

	return make_hypercall(call_type, 0, 0, 0, 0);
}
