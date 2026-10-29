#include "hypercall.h"
#include <Windows.h>
#include <hypercall/hypercall_def.h>
#include <hypercall/control.h>
#include <version.h>
#include "../system/system.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8,
                                              std::uint64_t r9);

static_assert(sizeof(HACDBG_HYPERCALL_REQUEST) == 0x40, "IOCTL ABI changed");
static_assert(sizeof(HACDBG_VERSION_INFO) == 0x30, "version ABI changed");

static std::mutex g_flush_mutex;
static std::recursive_mutex g_guest_mutex;
static std::mutex g_command_wait_mutex;
static std::condition_variable g_command_cv;
static std::atomic<std::uint8_t> g_command_guest = 0;
static std::atomic<std::uint32_t> g_command_cookie = 0;
static std::atomic<std::uint32_t> g_next_thread_cookie = 1;
static thread_local std::uint32_t t_thread_cookie = 0;
static thread_local int t_guest_depth = 0;
static thread_local std::uint8_t t_skip_command_wait = 0;
static void (*g_command_yield)() = nullptr;

static std::uint32_t this_thread_cookie()
{
	if (t_thread_cookie == 0)
	{
		const std::uint32_t cookie = g_next_thread_cookie.fetch_add(1, std::memory_order_relaxed);

		t_thread_cookie = cookie == 0 ? g_next_thread_cookie.fetch_add(1, std::memory_order_relaxed) : cookie;
	}

	return t_thread_cookie;
}

static std::uint8_t command_guest_blocks(const std::uint32_t cookie)
{
	if (t_skip_command_wait != 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(g_command_guest.load(std::memory_order_acquire) != 0 &&
	                                 g_command_cookie.load(std::memory_order_acquire) != cookie);
}

void hypercall::set_command_yield(void (*const yield)())
{
	g_command_yield = yield;
}

void hypercall::begin_command_guest()
{
	const std::lock_guard<std::mutex> wait(g_command_wait_mutex);

	g_command_cookie.store(this_thread_cookie(), std::memory_order_release);
	g_command_guest.store(1, std::memory_order_release);
}

void hypercall::skip_command_guest_wait()
{
	t_skip_command_wait = 1;
}

void hypercall::end_command_guest()
{
	{
		const std::lock_guard<std::mutex> wait(g_command_wait_mutex);

		g_command_guest.store(0, std::memory_order_release);
		g_command_cookie.store(0, std::memory_order_release);
	}

	g_command_cv.notify_all();
}

hypercall::GuestSection::GuestSection()
{
	if (t_guest_depth == 0)
	{
		const std::uint32_t mine = this_thread_cookie();

		for (;;)
		{
			{
				std::unique_lock<std::mutex> wait(g_command_wait_mutex);

				if (command_guest_blocks(mine) != 0)
				{
					if (g_command_yield != nullptr)
					{
						g_command_yield();
					}

					g_command_cv.wait(wait, [mine]
					{
						return command_guest_blocks(mine) == 0;
					});
				}
			}

			g_guest_mutex.lock();

			std::uint8_t blocked = 0;

			{
				const std::lock_guard<std::mutex> wait(g_command_wait_mutex);

				blocked = command_guest_blocks(mine);
			}

			if (blocked != 0)
			{
				g_guest_mutex.unlock();

				continue;
			}

			break;
		}
	}
	else
	{
		g_guest_mutex.lock();
	}

	t_guest_depth += 1;
}

hypercall::GuestSection::~GuestSection()
{
	t_guest_depth -= 1;
	g_guest_mutex.unlock();
}

static HACDBG_LOG_MAILBOX* g_log_mailbox = nullptr;
static std::uint64_t g_log_mailbox_key = 0;
static std::atomic<std::uint8_t> g_log_notify_armed = 0;
static std::atomic<std::uint64_t> g_log_notify_seen = 0;

static std::uint64_t mailbox_key()
{
	if (g_log_mailbox == nullptr)
	{
		return 0;
	}

	return *reinterpret_cast<const volatile std::uint64_t*>(&g_log_mailbox->key);
}

static std::uint64_t launch_cpuid_hypercall(hypercall_type_t call_type, std::uint64_t call_reserved_data,
                                            std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9);

static std::uint8_t mailbox_key_acceptable(const std::uint64_t key, const std::uint8_t allow_cleared)
{
	if (key == g_log_mailbox_key)
	{
		return 1;
	}

	return static_cast<std::uint8_t>(allow_cleared == 1 && key == 0);
}

static std::uint64_t sample_log_mailbox(std::uint8_t& stable, const std::uint8_t allow_cleared)
{
	stable = 0;

	if (g_log_mailbox == nullptr || mailbox_key_acceptable(mailbox_key(), allow_cleared) == 0)
	{
		return 0;
	}

	for (std::uint32_t attempt = 0; attempt < 8; ++attempt)
	{
		const std::uint64_t copy = *reinterpret_cast<const volatile std::uint64_t*>(&g_log_mailbox->producer_copy);
		const std::uint64_t producer = *reinterpret_cast<const volatile std::uint64_t*>(&g_log_mailbox->producer);

		if (copy == producer && mailbox_key_acceptable(mailbox_key(), allow_cleared) == 1)
		{
			stable = 1;

			return producer;
		}
	}

	return 0;
}

static trap_frame_log_t* mailbox_record(const std::uint64_t slot)
{
	return reinterpret_cast<trap_frame_log_t*>(g_log_mailbox->records +
	                                           (slot * sizeof(trap_frame_log_t)));
}

// Copies records the mailbox has published since the last local read.
// give_up is 1 when the mailbox key is no longer the one this process registered.
static std::uint64_t copy_log_mailbox(std::vector<trap_frame_log_t>& logs, std::uint8_t& give_up)
{
	const std::uint64_t key = mailbox_key();
	std::uint8_t stable = 0;
	std::uint64_t producer;
	std::uint64_t cursor;
	std::uint64_t count;

	give_up = 0;

	if (mailbox_key_acceptable(key, 1) == 0)
	{
		give_up = 1;

		return 0;
	}

	producer = sample_log_mailbox(stable, static_cast<std::uint8_t>(key == 0));

	if (stable == 0)
	{
		if (key == 0)
		{
			give_up = 1;
		}

		return 0;
	}

	cursor = g_log_notify_seen.load(std::memory_order_relaxed);

	if (producer < cursor)
	{
		cursor = 0;
	}

	if (producer - cursor > HACDBG_LOG_MAILBOX_CAPACITY)
	{
		cursor = producer - HACDBG_LOG_MAILBOX_CAPACITY;
	}

	count = producer - cursor;

	if (count > logs.size())
	{
		count = logs.size();
	}

	std::atomic_thread_fence(std::memory_order_acquire);

	for (std::uint64_t index = 0; index < count; index++)
	{
		const std::uint64_t slot = (cursor + index) % HACDBG_LOG_MAILBOX_CAPACITY;

		logs[index] = *mailbox_record(slot);
	}

	g_log_notify_seen.store(cursor + count, std::memory_order_release);

	if (mailbox_key() == 0)
	{
		give_up = 1;
	}

	return count;
}

static std::uint64_t flush_logs_hypercall(std::vector<trap_frame_log_t>& logs)
{
	constexpr auto call_type = hypercall_type_t::flush_logs;

	if (logs.empty() == true)
	{
		return 0;
	}

	return launch_cpuid_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(logs.data()), logs.size(), 0);
}

static std::uint8_t driver_has_log_mailbox()
{
	std::uint32_t major = 0;
	std::uint32_t minor = 0;
	std::uint32_t patch = 0;
	std::uint32_t abi = 0;
	std::string version = {};

	if (hypercall::query_driver_version(major, minor, patch, abi, version) == 0)
	{
		return 0;
	}

	// The mailbox was added in 1.1.5. Later minor versions still have it.
	if (major != 1)
	{
		return static_cast<std::uint8_t>(major > 1);
	}

	if (minor > 1)
	{
		return 1;
	}

	if (minor < 1)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(patch >= 5);
}

static std::uint8_t offset_wraps(const std::uint64_t address, const std::uint64_t offset)
{
	return static_cast<std::uint8_t>(offset != 0 && address + offset < address);
}

static std::uint64_t launch_cpuid_hypercall(const hypercall_type_t call_type, const std::uint64_t call_reserved_data,
                                            const std::uint64_t rdx, const std::uint64_t r8, const std::uint64_t r9)
{
	const hypercall::GuestSection guest;
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
	const std::uint64_t written = launch_cpuid_hypercall(hypercall_type_t::flush_logs, flush_logs_query_version,
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
	constexpr auto call_type = hypercall_type_t::slat;

	const std::uint64_t result =
		launch_cpuid_hypercall(call_type, slat_add_hook, target_guest_physical_address,
		                       shadow_page_guest_physical_address, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::remove_slat_code_hook(const std::uint64_t target_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::slat;

	const std::uint64_t result = launch_cpuid_hypercall(call_type, slat_remove_hook, target_guest_physical_address, 0, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::hide_guest_physical_page(const std::uint64_t target_guest_physical_address)
{
	constexpr auto call_type = hypercall_type_t::slat;

	const std::uint64_t result = launch_cpuid_hypercall(call_type, slat_hide_page, target_guest_physical_address, 0, 0);

	if (result == 1)
	{
		flush_slat_cache();
	}

	return result;
}

std::uint64_t hypercall::flush_logs(std::vector<trap_frame_log_t>& logs)
{
	std::lock_guard<std::mutex> guard(g_flush_mutex);

	if (g_log_notify_armed.load(std::memory_order_acquire) != 0 && g_log_mailbox != nullptr)
	{
		std::uint8_t give_up = 0;
		const std::uint64_t copied = copy_log_mailbox(logs, give_up);

		if (give_up == 0)
		{
			return copied;
		}

		g_log_notify_armed.store(0, std::memory_order_release);

		if (copied >= logs.size())
		{
			return copied;
		}

		std::vector<trap_frame_log_t> rest(logs.size() - copied);
		const std::uint64_t kernel = flush_logs_hypercall(rest);

		if (kernel == static_cast<std::uint64_t>(-1))
		{
			return copied == 0 ? kernel : copied;
		}

		const std::uint64_t extra = kernel < rest.size() ? kernel : rest.size();

		for (std::uint64_t index = 0; index < extra; index++)
		{
			logs[copied + index] = rest[index];
		}

		return copied + extra;
	}

	return flush_logs_hypercall(logs);
}

std::uint64_t hypercall::register_log_notify()
{
	std::lock_guard<std::mutex> guard(g_flush_mutex);
	HACDBG_LOG_MAILBOX* mailbox;
	std::uint64_t key;

	if (driver_has_log_mailbox() == 0)
	{
		return 0;
	}

	mailbox = static_cast<HACDBG_LOG_MAILBOX*>(
		sys::user::allocate_locked_memory(sizeof(HACDBG_LOG_MAILBOX), PAGE_READWRITE));

	if (mailbox == nullptr)
	{
		return 0;
	}

	key = (static_cast<std::uint64_t>(GetTickCount64()) << 32) ^
	      reinterpret_cast<std::uintptr_t>(mailbox) ^ 0x4E474C4F474E5446ull;

	if (key == 0)
	{
		key = 1;
	}

	mailbox->key = key;
	mailbox->capacity = HACDBG_LOG_MAILBOX_CAPACITY;
	mailbox->producer = 0;
	mailbox->producer_copy = 0;
	g_log_mailbox = mailbox;
	g_log_mailbox_key = key;
	g_log_notify_seen.store(0, std::memory_order_relaxed);

	// A VM-exit cannot fault these pages in. Lock them before the driver translates them.
	const std::uint64_t registered = launch_cpuid_hypercall(hypercall_type_t::flush_logs, flush_logs_register_mailbox,
	                                                        reinterpret_cast<std::uint64_t>(mailbox), 0, 0);

	if (registered != 1)
	{
		g_log_mailbox = nullptr;
		g_log_mailbox_key = 0;
		g_log_notify_armed.store(0, std::memory_order_release);
		sys::user::free_memory(mailbox);

		return 0;
	}

	g_log_notify_armed.store(1, std::memory_order_release);

	return 1;
}

void hypercall::unregister_log_notify()
{
	std::lock_guard<std::mutex> guard(g_flush_mutex);
	HACDBG_LOG_MAILBOX* mailbox;
	const std::uint8_t armed = g_log_notify_armed.exchange(0, std::memory_order_acq_rel);

	mailbox = g_log_mailbox;
	g_log_mailbox = nullptr;
	g_log_mailbox_key = 0;

	if (armed != 0)
	{
		launch_cpuid_hypercall(hypercall_type_t::flush_logs, flush_logs_unregister_mailbox, 0, 0, 0);
	}

	if (mailbox != nullptr)
	{
		sys::user::free_memory(mailbox);
	}
}

std::uint8_t hypercall::log_notify_idle()
{
	std::lock_guard<std::mutex> guard(g_flush_mutex);
	std::uint8_t stable = 0;

	if (g_log_notify_armed.load(std::memory_order_acquire) == 0 || g_log_mailbox == nullptr)
	{
		return 0;
	}

	if (mailbox_key() != g_log_mailbox_key)
	{
		return 0;
	}

	const std::uint64_t producer = sample_log_mailbox(stable, 0);

	if (stable == 0)
	{
		return 0;
	}

	return producer == g_log_notify_seen.load(std::memory_order_acquire) ? 1 : 0;
}

std::uint64_t hypercall::get_heap_free_page_count()
{
	constexpr auto call_type = hypercall_type_t::slat;

	return launch_cpuid_hypercall(call_type, slat_free_page_count, 0, 0, 0);
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
		return launch_cpuid_hypercall(hypercall_type_t::slat, slat_flush, 0, 0, 0);
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

			launch_cpuid_hypercall(hypercall_type_t::slat, slat_flush, 0, 0, 0);
			visited += 1;
		}
	}

	SetThreadGroupAffinity(thread, &previous, nullptr);

	if (visited == 0)
	{
		return launch_cpuid_hypercall(hypercall_type_t::slat, slat_flush, 0, 0, 0);
	}

	return 1;
}

std::uint64_t hypercall::flush_slat_cache()
{
	return flush_slat_on_every_processor();
}

std::uint64_t hypercall::breakpoint_resume()
{
	constexpr auto call_type = hypercall_type_t::breakpoint;

	return launch_cpuid_hypercall(call_type, breakpoint_resume_publish, 0, 0, 0);
}

std::uint64_t hypercall::breakpoint_abandon()
{
	constexpr auto call_type = hypercall_type_t::breakpoint;

	return launch_cpuid_hypercall(call_type, breakpoint_resume_abandon, 0, 0, 0);
}

std::uint64_t hypercall::trace_control(const std::uint64_t control_flags, const std::uint32_t sample_rate,
                                       const std::uint32_t event_mask)
{
	constexpr auto call_type = hypercall_type_t::trace;

	return launch_cpuid_hypercall(call_type, trace_control_op, control_flags, sample_rate, event_mask);
}

std::uint64_t hypercall::trace_read(HACDBG_TRACE_SNAPSHOT& snapshot_out, const std::uint32_t cpu_filter)
{
	constexpr auto call_type = hypercall_type_t::trace;

	return launch_cpuid_hypercall(call_type, trace_read_op, reinterpret_cast<std::uint64_t>(&snapshot_out),
	                              sizeof(snapshot_out), cpu_filter);
}
