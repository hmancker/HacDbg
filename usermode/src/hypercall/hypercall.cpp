#include "hypercall.h"
#include <Windows.h>
#include <hypercall/hypercall_def.h>
#include <hypercall/control.h>
#include "../system/system.h"

#include <atomic>
#include <mutex>

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8,
                                              std::uint64_t r9);

static_assert(sizeof(HACDBG_HYPERCALL_REQUEST) == 0x40, "IOCTL ABI changed");
static_assert(sizeof(HACDBG_VERSION_INFO) == 0x30, "version ABI changed");

static std::mutex g_flush_mutex;

alignas(4096) static std::uint8_t g_log_notify_storage[4096];
static std::atomic<std::uint8_t> g_log_notify_armed = 0;
static std::atomic<std::uint64_t> g_log_notify_seen = 0;

static HACDBG_LOG_NOTIFY* log_notify_page()
{
	return reinterpret_cast<HACDBG_LOG_NOTIFY*>(g_log_notify_storage);
}

static std::uint64_t sample_log_notify(std::uint8_t& stable)
{
	const HACDBG_LOG_NOTIFY* const page = log_notify_page();
	stable = 0;

	for (std::uint32_t attempt = 0; attempt < 8; ++attempt)
	{
		const std::uint64_t copy = *reinterpret_cast<const volatile std::uint64_t*>(&page->sequence_copy);
		const std::uint64_t sequence = *reinterpret_cast<const volatile std::uint64_t*>(&page->sequence);

		if (copy == sequence)
		{
			stable = 1;

			return sequence;
		}
	}

	return 0;
}

static std::uint8_t offset_wraps(const std::uint64_t address, const std::uint64_t offset)
{
	return static_cast<std::uint8_t>(offset != 0 && address + offset < address);
}

static std::uint64_t launch_cpuid_hypercall(const hypercall_type_t call_type, const std::uint64_t call_reserved_data,
                                            const std::uint64_t rdx, const std::uint64_t r8, const std::uint64_t r9)
{
	hypercall_info_t hypercall_info = {};

	hypercall_info.primary_key = hypercall_primary_key;
	hypercall_info.secondary_key = hypercall_secondary_key;
	hypercall_info.call_type = call_type;
	hypercall_info.call_reserved_data = call_reserved_data;

	return launch_raw_hypercall(hypercall_info, rdx, r8, r9);
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

		const std::uint64_t copied = launch_cpuid_hypercall(call_type, call_reserved_data, rdx_address + bytes_copied,
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

	return launch_cpuid_hypercall(call_type, 0, guest_virtual_address, guest_cr3, 0);
}

std::uint64_t hypercall::read_guest_cr3()
{
	constexpr auto call_type = hypercall_type_t::read_guest_cr3;

	return launch_cpuid_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::log_current_state()
{
	constexpr auto call_type = hypercall_type_t::log_current_state;

	return launch_cpuid_hypercall(call_type, 0, 0, 0, 0);
}

std::uint8_t hypercall::query_driver_version(std::uint32_t& major, std::uint32_t& minor,
                                             std::uint32_t& patch, std::uint32_t& hypercall_abi_version,
                                             std::string& version)
{
	HACDBG_VERSION_INFO info = {};
	const std::uint64_t written = launch_cpuid_hypercall(hypercall_type_t::query_hypervisor_version, 0,
	                                                     reinterpret_cast<std::uint64_t>(&info), sizeof(info), 0);

	if (written != sizeof(info) || info.VersionString[0] == '\0')
	{
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
		launch_cpuid_hypercall(call_type, 0, target_guest_physical_address, shadow_page_guest_physical_address, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::remove_slat_code_hook(const std::uint64_t target_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::remove_slat_code_hook;

	const std::uint64_t result = launch_cpuid_hypercall(call_type, 0, target_guest_physical_address, 0, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::hide_guest_physical_page(const std::uint64_t target_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::hide_guest_physical_page;

	const std::uint64_t result = launch_cpuid_hypercall(call_type, 0, target_guest_physical_address, 0, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::flush_logs(std::vector<trap_frame_log_t>& logs)
{
	constexpr auto call_type = hypercall_type_t::flush_logs;
	std::uint8_t stable = 0;
	const std::uint8_t armed = g_log_notify_armed.load(std::memory_order_acquire);
	const std::uint64_t observed = armed != 0 ? sample_log_notify(stable) : 0;
	const std::uint64_t result = launch_cpuid_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(logs.data()),
	                                                    logs.size(), 0);

	if (armed != 0 && stable != 0 && result != static_cast<std::uint64_t>(-1))
	{
		g_log_notify_seen.store(observed, std::memory_order_release);
	}

	return result;
}

std::uint64_t hypercall::register_log_notify()
{
	HACDBG_LOG_NOTIFY* const page = log_notify_page();
	std::uint64_t key = (static_cast<std::uint64_t>(GetTickCount64()) << 32) ^
	                    reinterpret_cast<std::uintptr_t>(page) ^ 0x4E474C4F474E5446ull;

	if (key == 0)
	{
		key = 1;
	}

	page->key = key;
	page->sequence = 0;
	page->sequence_copy = 0;
	g_log_notify_seen.store(0, std::memory_order_relaxed);

	// A VM-exit cannot fault this page in. Lock it before the driver translates it.
	if (sys::user::lock_resident_pages(g_log_notify_storage, sizeof(g_log_notify_storage)) == 0)
	{
		g_log_notify_armed.store(0, std::memory_order_release);

		return 0;
	}

	const std::uint64_t registered = launch_cpuid_hypercall(hypercall_type_t::flush_logs, flush_logs_register_notify,
	                                                        reinterpret_cast<std::uint64_t>(page), 0, 0);

	g_log_notify_armed.store(registered == 1 ? 1 : 0, std::memory_order_release);

	return registered == 1 ? 1 : 0;
}

void hypercall::unregister_log_notify()
{
	if (g_log_notify_armed.exchange(0, std::memory_order_acq_rel) == 0)
	{
		return;
	}

	launch_cpuid_hypercall(hypercall_type_t::flush_logs, flush_logs_unregister_notify, 0, 0, 0);
}

std::uint8_t hypercall::log_notify_idle()
{
	std::uint8_t stable = 0;

	if (g_log_notify_armed.load(std::memory_order_acquire) == 0)
	{
		return 0;
	}

	const std::uint64_t sequence = sample_log_notify(stable);

	if (stable == 0)
	{
		return 0;
	}

	return sequence == g_log_notify_seen.load(std::memory_order_acquire) ? 1 : 0;
}

std::uint64_t hypercall::get_heap_free_page_count()
{
	constexpr auto call_type = hypercall_type_t::get_heap_free_page_count;

	return launch_cpuid_hypercall(call_type, 0, 0, 0, 0);
}

static std::uint8_t wait_for_processor(const WORD group, const DWORD number)
{
	for (std::uint32_t spin = 0; spin < 100000; ++spin)
	{
		PROCESSOR_NUMBER current = {};

		GetCurrentProcessorNumberEx(&current);

		if (current.Group == group && current.Number == number)
		{
			return 1;
		}

		SwitchToThread();
	}

	return 0;
}

static std::uint64_t flush_slat_on_every_processor()
{
	std::lock_guard<std::mutex> lock(g_flush_mutex);
	const HANDLE thread = GetCurrentThread();
	GROUP_AFFINITY previous = {};
	std::uint64_t visited = 0;
	const WORD group_count = GetActiveProcessorGroupCount();

	if (GetThreadGroupAffinity(thread, &previous) == FALSE)
	{
		return launch_cpuid_hypercall(hypercall_type_t::flush_slat_cache, 0, 0, 0, 0);
	}

	for (WORD group = 0; group < group_count; ++group)
	{
		const DWORD count = GetActiveProcessorCount(group);

		for (DWORD number = 0; number < count && number < 64; ++number)
		{
			GROUP_AFFINITY affinity = {};

			affinity.Group = group;
			affinity.Mask = 1ull << number;

			if (SetThreadGroupAffinity(thread, &affinity, nullptr) == FALSE ||
			    wait_for_processor(group, number) == 0)
			{
				continue;
			}

			launch_cpuid_hypercall(hypercall_type_t::flush_slat_cache, 0, 0, 0, 0);
			visited += 1;
		}
	}

	SetThreadGroupAffinity(thread, &previous, nullptr);

	if (visited == 0)
	{
		return launch_cpuid_hypercall(hypercall_type_t::flush_slat_cache, 0, 0, 0, 0);
	}

	return 1;
}

std::uint64_t hypercall::flush_slat_cache()
{
	return flush_slat_on_every_processor();
}

std::uint64_t hypercall::breakpoint_resume()
{
	constexpr auto call_type = hypercall_type_t::breakpoint_resume;

	return launch_cpuid_hypercall(call_type, breakpoint_resume_publish, 0, 0, 0);
}

std::uint64_t hypercall::breakpoint_abandon()
{
	constexpr auto call_type = hypercall_type_t::breakpoint_resume;

	return launch_cpuid_hypercall(call_type, breakpoint_resume_abandon, 0, 0, 0);
}

std::uint64_t hypercall::trace_control(const std::uint64_t control_flags, const std::uint32_t sample_rate,
                                       const std::uint32_t event_mask)
{
	constexpr auto call_type = hypercall_type_t::trace_control;

	return launch_cpuid_hypercall(call_type, 0, control_flags, sample_rate, event_mask);
}

std::uint64_t hypercall::trace_read(HACDBG_TRACE_SNAPSHOT& snapshot_out, const std::uint32_t cpu_filter)
{
	constexpr auto call_type = hypercall_type_t::trace_read;

	return launch_cpuid_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(&snapshot_out),
	                              sizeof(snapshot_out), cpu_filter);
}
