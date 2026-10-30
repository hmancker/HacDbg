/**
 * @file core_api.cpp
 * @brief C ABI session wrapper for the GUI.
 *
 * @author HacDbg
 */

#include "../../api/hacdbg_core_api.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <deque>
#include <exception>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <symbol_parser.h>
#include <version.h>

#include "../commands/commands.h"
#include "../hook/breakpoint.h"
#include "../hypercall/hypercall.h"
#include "../logs/logs.h"
#include "../output/output_sink.h"
#include "../system/system.h"

struct core_view_request_t
{
	std::uint32_t view = 0;
	std::uint64_t id = 0;
	std::uint64_t arg0 = 0;
	std::uint64_t arg1 = 0;
	std::uint32_t arg2 = 0;
	std::uint32_t arg3 = 0;
	std::string text = {};
	std::uint8_t pending = 0;
};

struct core_completion_request_t
{
	std::uint64_t id = 0;
	std::string token = {};
	std::uint8_t pending = 0;
};

struct HACDBG_CORE
{
	std::mutex command_mutex;
	std::condition_variable command_ready;
	std::deque<std::string> commands;
	std::thread worker;
	std::thread view_worker;
	std::thread monitor_worker;
	std::atomic<std::uint8_t> running = 0;
	std::atomic<std::uint8_t> command_active = 0;
	std::uint8_t initialized = 0;
	HACDBG_OUTPUT_CALLBACK output_callback = nullptr;
	void* output_context = nullptr;

	std::mutex state_mutex;
	HACDBG_CORE_STATE state = {};

	std::mutex monitor_mutex;
	std::vector<HACDBG_CORE_MONITOR> monitors = {};
	std::vector<HACDBG_CORE_MONITOR_HIT> monitor_hit_slots = {};
	std::size_t monitor_hit_head = 0;
	std::size_t monitor_hit_count = 0;
	std::uint64_t monitor_newest_sequence = 0;

	std::mutex view_mutex;
	std::array<core_view_request_t, static_cast<std::size_t>(HacDbgViewCount)> view_requests = {};
	std::array<HACDBG_CORE_VIEW_STATUS, static_cast<std::size_t>(HacDbgViewCount)> view_status = {};
	std::uint64_t next_view_request_id = 1;
	core_completion_request_t completion_request = {};
	HACDBG_CORE_COMPLETION_STATUS completion_status = {};
	std::vector<std::string> completion_matches = {};
	std::uint32_t completion_total = 0;
	std::uint64_t next_completion_request_id = 1;

	HACDBG_CORE_MODULE modules[HACDBG_CORE_MAX_MODULES] = {};
	std::uint32_t module_count = 0;
	std::uint32_t module_truncated = 0;

	HACDBG_CORE_PROCESS processes[HACDBG_CORE_MAX_PROCESSES] = {};
	std::uint32_t process_count = 0;
	std::uint32_t process_truncated = 0;

	HACDBG_CORE_THREAD threads[HACDBG_CORE_MAX_THREADS] = {};
	std::uint32_t thread_count = 0;
	std::uint32_t thread_truncated = 0;

	HACDBG_CORE_STACK_FRAME stack[HACDBG_CORE_MAX_STACK_FRAMES] = {};
	std::uint32_t stack_count = 0;
	std::uint32_t stack_truncated = 0;
	HACDBG_CORE_STACK_WINDOW stack_window = {};

	HACDBG_CORE_MEMORY memory = {};
	HACDBG_CORE_INSTRUCTION disassembly[HACDBG_CORE_MAX_DISASSEMBLY_LINES] = {};
	std::uint32_t disassembly_count = 0;
	std::uint32_t disassembly_truncated = 0;
	HACDBG_CORE_RESOLVED_ADDRESS resolved_address = {};

	std::mutex trace_mutex;
	HACDBG_CORE_TRACE_STATUS trace_status = {};
	std::uint32_t trace_sample_rate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
	std::uint32_t trace_event_mask = HACDBG_TRACE_EVENT_MASK_ALL;
	std::uint32_t trace_control_flags = 0;
	std::uint32_t trace_control_sample_rate = 0;
	std::uint32_t trace_control_event_mask = 0;
	std::uint8_t trace_control_pending = 0;
	std::uint8_t trace_read_pending = 0;
	std::array<HACDBG_TRACE_SNAPSHOT, 2> trace_snapshots = {};
	std::uint32_t trace_snapshot_active = 0;
	std::uint32_t trace_snapshot_write = 1;
	std::chrono::steady_clock::time_point trace_last_read = {};
	std::uint8_t trace_last_read_valid = 0;
	std::uint32_t commands_completed = 0;
};

namespace
{
	constexpr std::size_t max_queued_commands = 64;
	constexpr std::chrono::milliseconds breakpoint_poll_interval(100);
	constexpr std::size_t monitor_hit_queue_limit = 8192;

	static_assert(HACDBG_CORE_MONITOR_STACK == trap_frame_log_stack_data_count, "monitor stack width changed");

	void fill_monitor_hit(HACDBG_CORE_MONITOR_HIT& item, const breakpoint::monitor_hit_t& hit)
	{
		item = {};
		item.Address = hit.address;
		item.Rip = hit.log.rip;
		item.Rax = hit.log.rax;
		item.Rcx = hit.log.rcx;
		item.Rdx = hit.log.rdx;
		item.Rbx = hit.log.rbx;
		item.Rsp = hit.log.rsp;
		item.Rbp = hit.log.rbp;
		item.Rsi = hit.log.rsi;
		item.Rdi = hit.log.rdi;
		item.R8 = hit.log.r8;
		item.R9 = hit.log.r9;
		item.R10 = hit.log.r10;
		item.R11 = hit.log.r11;
		item.R12 = hit.log.r12;
		item.R13 = hit.log.r13;
		item.R14 = hit.log.r14;
		item.R15 = hit.log.r15;
		item.Cr3 = hit.log.cr3;
		item.Sequence = hit.sequence;

		for (std::size_t index = 0; index < HACDBG_CORE_MONITOR_STACK; index++)
		{
			item.Stack[index] = hit.log.stack_data[index];
		}
	}

	void push_monitor_hit(HACDBG_CORE* const core, const HACDBG_CORE_MONITOR_HIT& item)
	{
		std::vector<HACDBG_CORE_MONITOR_HIT>& slots = core->monitor_hit_slots;
		const std::size_t capacity = slots.size();

		if (capacity == 0)
		{
			return;
		}

		if (core->monitor_hit_count == capacity)
		{
			slots[core->monitor_hit_head] = item;
			core->monitor_hit_head = (core->monitor_hit_head + 1) % capacity;
		}
		else
		{
			const std::size_t index = (core->monitor_hit_head + core->monitor_hit_count) % capacity;
			slots[index] = item;
			core->monitor_hit_count += 1;
		}

		if (item.Sequence > core->monitor_newest_sequence)
		{
			core->monitor_newest_sequence = item.Sequence;
		}
	}

	void publish_monitor_sites(HACDBG_CORE* const core)
	{
		const std::vector<breakpoint::monitor_site_t> sites = breakpoint::monitor_sites();

		std::lock_guard<std::mutex> lock(core->monitor_mutex);

		core->monitors.clear();

		for (const breakpoint::monitor_site_t& site : sites)
		{
			if (core->monitors.size() >= HACDBG_CORE_MAX_MONITORS)
			{
				break;
			}

			HACDBG_CORE_MONITOR item = {};
			item.Address = site.address;
			item.Hits = site.hits;

			const std::size_t symbol_length = (std::min)(site.symbol.size(), sizeof(item.Symbol) - 1);
			std::memcpy(item.Symbol, site.symbol.data(), symbol_length);
			item.Symbol[symbol_length] = '\0';
			core->monitors.push_back(item);
		}
	}

	//
	// Hits leave the ring only on the monitor thread. The command thread used
	// to drain the same ring and could push an older batch after a newer one.
	// The GUI then counted the sequence hole and those late rows.
	//
	void publish_monitor_hits(HACDBG_CORE* const core)
	{
		breakpoint::monitor_hit_t batch[128] = {};

		for (;;)
		{
			std::uint64_t newest = 0;
			const std::size_t count = breakpoint::copy_monitor_hits(batch, 128, &newest);

			std::lock_guard<std::mutex> lock(core->monitor_mutex);

			if (newest > core->monitor_newest_sequence)
			{
				core->monitor_newest_sequence = newest;
			}

			for (std::size_t index = 0; index < count; index++)
			{
				HACDBG_CORE_MONITOR_HIT item = {};
				fill_monitor_hit(item, batch[index]);
				push_monitor_hit(core, item);
			}

			if (count < 128)
			{
				break;
			}
		}
	}

	void publish_monitors(HACDBG_CORE* const core)
	{
		publish_monitor_sites(core);
		publish_monitor_hits(core);
	}
	constexpr std::chrono::milliseconds trace_poll_interval(33);
	constexpr std::chrono::milliseconds trace_minimum_read_interval(20);

	HACDBG_CORE* core_from_context(void* const context)
	{
		return static_cast<HACDBG_CORE*>(context);
	}

	template <std::size_t Size>
	void copy_text(char (&destination)[Size], const std::string_view source)
	{
		const std::size_t length = (std::min)(source.size(), static_cast<std::size_t>(Size - 1));
		std::memcpy(destination, source.data(), length);
		destination[length] = '\0';
	}

	void copy_version(char (&destination)[HACDBG_CORE_VERSION_STRING_SIZE], const std::string& source)
	{
		copy_text(destination, source);
	}

	bool has_pending_view(HACDBG_CORE* const core)
	{
		std::lock_guard<std::mutex> lock(core->view_mutex);

		for (const core_view_request_t& request : core->view_requests)
		{
			if (request.pending != 0)
			{
				return true;
			}
		}

		return false;
	}

	bool has_pending_completion(HACDBG_CORE* const core)
	{
		std::lock_guard<std::mutex> lock(core->view_mutex);

		return core->completion_request.pending != 0;
	}

	bool take_view_request(HACDBG_CORE* const core, core_view_request_t& request_out)
	{
		std::lock_guard<std::mutex> lock(core->view_mutex);

		for (core_view_request_t& request : core->view_requests)
		{
			if (request.pending == 0)
			{
				continue;
			}

			request_out = std::move(request);
			request.pending = 0;

			return true;
		}

		return false;
	}

	void complete_view_locked(HACDBG_CORE* const core, const core_view_request_t& request,
	                          const std::uint32_t count, const std::uint32_t truncated,
	                          const std::string& error)
	{
		HACDBG_CORE_VIEW_STATUS& status = core->view_status[request.view];

		status.CompletedRequestId = request.id;
		status.Pending = core->view_requests[request.view].pending;
		status.Failed = error.empty() == true ? 0 : 1;
		status.Count = count;
		status.Truncated = truncated;
		copy_text(status.Message, error);
	}

	HACDBG_CORE* g_preempt_core = nullptr;

	std::uint8_t view_command_pending()
	{
		if (g_preempt_core == nullptr)
		{
			return 0;
		}

		if (g_preempt_core->running.load(std::memory_order_acquire) == 0 ||
		    g_preempt_core->command_active.load(std::memory_order_acquire) != 0)
		{
			return 1;
		}

		std::lock_guard<std::mutex> lock(g_preempt_core->command_mutex);

		return g_preempt_core->commands.empty() == true ? 0 : 1;
	}

	void requeue_preempted_view(HACDBG_CORE* const core, const core_view_request_t& request)
	{
		std::lock_guard<std::mutex> lock(core->view_mutex);
		core_view_request_t& slot = core->view_requests[request.view];

		if (slot.pending != 0 && slot.id != request.id)
		{
			return;
		}

		slot = request;
		slot.pending = 1;

		HACDBG_CORE_VIEW_STATUS& status = core->view_status[request.view];
		status.RequestId = request.id;
		status.Pending = 1;
		status.Failed = 0;
		status.Message[0] = '\0';
	}

	void publish_view_error(HACDBG_CORE* const core, const core_view_request_t& request, const std::string& error)
	{
		//
		// A step was queued while this view was still reading the guest.
		// Keep the same request id pending so the step runs first.
		//
		if (commands::view_was_preempted() != 0)
		{
			requeue_preempted_view(core, request);

			return;
		}

		std::lock_guard<std::mutex> lock(core->view_mutex);
		complete_view_locked(core, request, 0, 0, error);
	}

	void execute_view_request(HACDBG_CORE* const core, const core_view_request_t& request)
	{
		std::string error = {};

		switch (request.view)
		{
		case HacDbgViewModules:
		{
			std::vector<commands::views::module_t> modules = {};

			if (commands::views::modules(modules, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			const std::uint32_t count = static_cast<std::uint32_t>(
				(std::min)(modules.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_MODULES)));

			std::lock_guard<std::mutex> lock(core->view_mutex);

			for (std::uint32_t index = 0; index < count; index++)
			{
				HACDBG_CORE_MODULE& destination = core->modules[index];
				const commands::views::module_t& source = modules[index];

				destination = {};
				destination.Base = source.base;
				destination.Size = source.size;
				destination.Cr3 = source.cr3;
				destination.Kernel = source.kernel;
				destination.SymbolsLoaded = source.symbols_loaded;
				copy_text(destination.Name, source.name);
				copy_text(destination.SymbolPath, source.symbol_path);
			}

			core->module_count = count;
			core->module_truncated = static_cast<std::uint32_t>(modules.size() > count);
			complete_view_locked(core, request, count, core->module_truncated, error);

			return;
		}

		case HacDbgViewProcesses:
		{
			std::vector<commands::views::process_t> processes = {};

			if (commands::views::processes(processes, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			const std::uint32_t count = static_cast<std::uint32_t>(
				(std::min)(processes.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_PROCESSES)));

			std::lock_guard<std::mutex> lock(core->view_mutex);

			for (std::uint32_t index = 0; index < count; index++)
			{
				HACDBG_CORE_PROCESS& destination = core->processes[index];
				const commands::views::process_t& source = processes[index];

				destination = {};
				destination.Eprocess = source.eprocess;
				destination.Pid = source.pid;
				destination.ParentPid = source.parent_pid;
				destination.Peb = source.peb;
				destination.Directory = source.directory;
				destination.UserCr3 = source.user_cr3;
				copy_text(destination.Image, source.image);
			}

			core->process_count = count;
			core->process_truncated = static_cast<std::uint32_t>(processes.size() > count);
			complete_view_locked(core, request, count, core->process_truncated, error);

			return;
		}

		case HacDbgViewThreads:
		{
			std::vector<commands::views::thread_t> threads = {};
			std::uint8_t truncated = 0;

			if (commands::views::threads(request.arg0, threads, truncated, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			const std::uint32_t count = static_cast<std::uint32_t>(
				(std::min)(threads.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_THREADS)));

			std::lock_guard<std::mutex> lock(core->view_mutex);

			for (std::uint32_t index = 0; index < count; index++)
			{
				HACDBG_CORE_THREAD& destination = core->threads[index];
				const commands::views::thread_t& source = threads[index];

				destination = {};
				destination.Ethread = source.ethread;
				destination.Eprocess = source.eprocess;
				destination.Pid = source.pid;
				destination.Tid = source.tid;
				destination.Teb = source.teb;
				destination.Trap = source.trap;
				destination.Win32Start = source.win32_start;
				destination.StackBase = source.stack_base;
				destination.StackLimit = source.stack_limit;
				destination.KernelStack = source.kernel_stack;
				destination.InstructionPointer = source.instruction_pointer;
				destination.Cr3 = source.cr3;
				destination.ContextSwitches = source.context_switches;
				destination.WaitTime = source.wait_time;
				destination.State = source.state;
				destination.Priority = static_cast<std::uint32_t>(source.priority);
				destination.SuspendCount = static_cast<std::uint32_t>(source.suspend_count);
				destination.WaitReason = source.wait_reason;
				destination.WaitMode = source.wait_mode;
				destination.SystemThread = source.system_thread;
				destination.HasRegisters = source.has_registers;
				destination.KernelMode = source.kernel;
				copy_text(destination.Image, source.image);
				copy_text(destination.StateName, source.state_name);
				copy_text(destination.WaitReasonName, source.wait_reason_name);
			}

			core->thread_count = count;
			core->thread_truncated = truncated;
			complete_view_locked(core, request, count, core->thread_truncated, error);

			return;
		}

		case HacDbgViewStack:
		{
			std::vector<commands::views::stack_frame_t> frames = {};
			commands::views::memory_t window = {};
			std::uint64_t rsp = 0;

			if (commands::views::stack(request.arg2, frames, window, rsp, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			const std::uint32_t count = static_cast<std::uint32_t>(
				(std::min)(frames.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_STACK_FRAMES)));

			std::lock_guard<std::mutex> lock(core->view_mutex);

			for (std::uint32_t index = 0; index < count; index++)
			{
				HACDBG_CORE_STACK_FRAME& destination = core->stack[index];
				const commands::views::stack_frame_t& source = frames[index];

				destination = {};
				destination.ChildSp = source.child_sp;
				destination.ReturnAddress = source.return_address;
				destination.InstructionPointer = source.instruction_pointer;
				std::memcpy(destination.Args, source.args, sizeof(destination.Args));
				destination.ArgsValidMask = source.args_valid_mask;
				destination.HasReturn = source.has_return;
				copy_text(destination.Symbol, source.symbol);
			}

			core->stack_count = count;
			core->stack_truncated = static_cast<std::uint32_t>(frames.size() > count);
			core->stack_window = {};
			core->stack_window.Address = window.address;
			core->stack_window.Rsp = rsp;
			const std::uint32_t window_bytes = static_cast<std::uint32_t>(
				(std::min)(window.bytes.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_MEMORY_BYTES)));
			core->stack_window.BytesValid = window_bytes;

			if (window_bytes != 0)
			{
				std::memcpy(core->stack_window.Data, window.bytes.data(), window_bytes);
			}

			complete_view_locked(core, request, count, core->stack_truncated, error);

			return;
		}

		case HacDbgViewMemory:
		{
			commands::views::memory_t memory = {};

			if (commands::views::read_memory(request.arg0, request.arg1, request.arg2, memory, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			const std::uint32_t count = static_cast<std::uint32_t>(
				(std::min)(memory.bytes.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_MEMORY_BYTES)));

			std::lock_guard<std::mutex> lock(core->view_mutex);

			core->memory = {};
			core->memory.Address = memory.address;
			core->memory.Cr3 = memory.cr3;
			core->memory.Requested = request.arg2;
			core->memory.BytesValid = count;
			std::memcpy(core->memory.Data, memory.bytes.data(), count);
			complete_view_locked(core, request, count, 0, error);

			return;
		}

		case HacDbgViewDisassembly:
		{
			std::vector<commands::views::instruction_t> instructions = {};
			std::uint64_t next_address = 0;

			if (commands::views::disassemble(request.arg0, request.arg1, request.arg2, instructions, next_address, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			(void)next_address;

			const std::uint32_t count = static_cast<std::uint32_t>(
				(std::min)(instructions.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_DISASSEMBLY_LINES)));

			std::lock_guard<std::mutex> lock(core->view_mutex);

			for (std::uint32_t index = 0; index < count; index++)
			{
				HACDBG_CORE_INSTRUCTION& destination = core->disassembly[index];
				const commands::views::instruction_t& source = instructions[index];

				destination = {};
				destination.Address = source.address;
				destination.Length = static_cast<std::uint32_t>(source.length);
				destination.Invalid = source.invalid;
				copy_text(destination.Bytes, source.bytes);
				copy_text(destination.Text, source.text);
				copy_text(destination.Symbol, source.symbol);
			}

			core->disassembly_count = count;
			core->disassembly_truncated = static_cast<std::uint32_t>(instructions.size() > count);
			complete_view_locked(core, request, count, core->disassembly_truncated, error);

			return;
		}

		case HacDbgViewResolve:
		{
			commands::views::resolved_address_t resolved = {};

			if (commands::views::resolve(request.text, resolved, error) == 0)
			{
				publish_view_error(core, request, error);

				return;
			}

			std::lock_guard<std::mutex> lock(core->view_mutex);

			core->resolved_address = {};
			core->resolved_address.Address = resolved.address;
			copy_text(core->resolved_address.Symbol, resolved.symbol);
			complete_view_locked(core, request, 1, 0, error);

			return;
		}

		default:
			publish_view_error(core, request, "unknown view");
			return;
		}
	}

	std::uint64_t queue_view_request(HACDBG_CORE* const core, const std::uint32_t view,
	                                 const std::uint64_t arg0 = 0, const std::uint64_t arg1 = 0,
	                                 const std::uint32_t arg2 = 0, const std::uint32_t arg3 = 0,
	                                 const std::string_view text = {})
	{
		if (core == nullptr || core->running.load() == 0 ||
		    view >= static_cast<std::uint32_t>(HacDbgViewCount))
		{
			return 0;
		}

		std::uint64_t id = 0;

		{
			std::lock_guard<std::mutex> lock(core->view_mutex);
			core_view_request_t& request = core->view_requests[view];
			HACDBG_CORE_VIEW_STATUS& status = core->view_status[view];

			if (core->next_view_request_id == 0)
			{
				core->next_view_request_id = 1;
			}

			id = core->next_view_request_id++;
			request = {};
			request.view = view;
			request.id = id;
			request.arg0 = arg0;
			request.arg1 = arg1;
			request.arg2 = arg2;
			request.arg3 = arg3;
			request.text = std::string(text);
			request.pending = 1;

			status.RequestId = id;
			status.Pending = 1;
			status.Failed = 0;
			status.Count = 0;
			status.Truncated = 0;
			status.Message[0] = '\0';
		}

		//
		// Taking the waiter mutex closes the gap between the worker's
		// predicate check and the start of its wait.
		//
		{
			std::lock_guard<std::mutex> lock(core->command_mutex);
		}

		core->command_ready.notify_all();

		return id;
	}

	void fill_registers(HACDBG_CORE_REGISTERS& destination, const breakpoint::registers_t& source)
	{
		destination.Rax = source.rax;
		destination.Rcx = source.rcx;
		destination.Rdx = source.rdx;
		destination.Rbx = source.rbx;
		destination.Rsp = source.rsp;
		destination.Rbp = source.rbp;
		destination.Rsi = source.rsi;
		destination.Rdi = source.rdi;
		destination.R8 = source.r8;
		destination.R9 = source.r9;
		destination.R10 = source.r10;
		destination.R11 = source.r11;
		destination.R12 = source.r12;
		destination.R13 = source.r13;
		destination.R14 = source.r14;
		destination.R15 = source.r15;
		destination.Rip = source.rip;
		destination.Rflags = source.rflags;
		destination.Cr3 = source.cr3;
		destination.RflagsKnown = source.rflags_known;
	}

	void update_state(HACDBG_CORE* const core)
	{
		HACDBG_CORE_STATE state = {};

		state.Initialized = core->initialized;
		state.Running = core->running.load();
		state.Paused = breakpoint::has_paused_thread();

		{
			std::lock_guard<std::mutex> lock(core->state_mutex);
			state.HypercallAbiVersion = core->state.HypercallAbiVersion;
			std::memcpy(state.UserVersion, core->state.UserVersion, sizeof(state.UserVersion));
			std::memcpy(state.DriverVersion, core->state.DriverVersion, sizeof(state.DriverVersion));
		}

		if (state.Paused != 0)
		{
			breakpoint::registers_t registers = {};

			if (breakpoint::paused_registers(registers) != 0)
			{
				fill_registers(state.Registers, registers);
			}
		}
		else
		{
			state.Registers.Cr3 = commands::context_cr3();
		}

		const std::vector<breakpoint::info_t> breakpoints = breakpoint::list();
		const std::size_t count = (std::min)(breakpoints.size(), static_cast<std::size_t>(HACDBG_CORE_MAX_BREAKPOINTS));

		for (std::size_t index = 0; index < count; index++)
		{
			state.Breakpoints[index].Id = breakpoints[index].id;
			state.Breakpoints[index].Address = breakpoints[index].address;
			state.Breakpoints[index].Cr3 = breakpoints[index].cr3;
			state.Breakpoints[index].Enabled = breakpoints[index].enabled;
			state.Breakpoints[index].PausesThread = breakpoints[index].pauses_thread;
		}

		state.BreakpointCount = static_cast<std::uint32_t>(count);
		state.CommandSequence = core->commands_completed;

		std::lock_guard<std::mutex> lock(core->state_mutex);
		core->state = state;
	}

	void output_callback(const output::kind_t kind, const char* const text, const std::size_t size, void* const context)
	{
		HACDBG_CORE* const core = core_from_context(context);

		if (core == nullptr || core->output_callback == nullptr)
		{
			return;
		}

		const std::uint32_t length = static_cast<std::uint32_t>(
			(std::min)(size, static_cast<std::size_t>(UINT32_MAX)));

		core->output_callback(static_cast<std::uint32_t>(kind), text, length, core->output_context);
	}

	bool has_pending_trace(HACDBG_CORE* const core)
	{
		std::lock_guard<std::mutex> lock(core->trace_mutex);

		return core->trace_control_pending != 0 || core->trace_read_pending != 0;
	}

	std::chrono::milliseconds worker_wait_interval(HACDBG_CORE* const core)
	{
		std::lock_guard<std::mutex> lock(core->trace_mutex);

		return core->trace_status.Capturing != 0 ? trace_poll_interval : breakpoint_poll_interval;
	}

	void apply_pending_trace_control(HACDBG_CORE* const core)
	{
		std::uint32_t flags = 0;
		std::uint32_t sample_rate = 0;
		std::uint32_t event_mask = 0;
		std::uint8_t supported = 0;

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);

			if (core->trace_control_pending == 0)
			{
				return;
			}

			flags = core->trace_control_flags;
			sample_rate = core->trace_control_sample_rate;
			event_mask = core->trace_control_event_mask;
			supported = static_cast<std::uint8_t>(core->trace_status.Supported != 0);
			core->trace_control_pending = 0;
		}

		if (supported == 0)
		{
			return;
		}

		const std::uint64_t result = hypercall::trace_control(flags, sample_rate, event_mask);

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);

			if (result == 0)
			{
				core->trace_status.LastError = HACDBG_CORE_TRACE_ERROR_CONTROL_FAILED;
				return;
			}

			if ((flags & HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE) != 0)
			{
				core->trace_sample_rate = sample_rate == 0
				                              ? HACDBG_TRACE_DEFAULT_SAMPLE_RATE
				                              : sample_rate;
			}

			if ((flags & HACDBG_TRACE_CONTROL_SET_EVENT_MASK) != 0)
			{
				core->trace_event_mask = event_mask & HACDBG_TRACE_EVENT_MASK_ALL;
			}

			if ((flags & HACDBG_TRACE_CONTROL_DISABLE) != 0)
			{
				core->trace_status.Capturing = 0;
				core->trace_status.EventsEnabled = 0;
			}
			else if ((flags & (HACDBG_TRACE_CONTROL_ENABLE_COUNTERS |
			                   HACDBG_TRACE_CONTROL_ENABLE_EVENTS)) != 0)
			{
				core->trace_status.Capturing = 1;
				core->trace_status.EventsEnabled =
					(flags & HACDBG_TRACE_CONTROL_ENABLE_EVENTS) != 0 ? 1u : 0u;
			}
			else if ((flags & HACDBG_TRACE_CONTROL_RESET) != 0)
			{
				core->trace_status.Capturing = 0;
				core->trace_status.EventsEnabled = 0;
			}

			core->trace_status.SampleRate = core->trace_sample_rate;
			core->trace_status.EventMask = core->trace_event_mask;
			core->trace_status.LastError = HACDBG_CORE_TRACE_ERROR_NONE;

			if (flags != 0)
			{
				core->trace_read_pending = 1;
			}
		}
	}

	bool perform_trace_read(HACDBG_CORE* const core)
	{
		std::uint32_t snapshot_index = 0;

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);

			if (core->trace_status.Supported == 0)
			{
				core->trace_read_pending = 0;
				return false;
			}

			const bool forced = core->trace_read_pending != 0;
			core->trace_read_pending = 0;
			const auto now = std::chrono::steady_clock::now();

			if (forced == false)
			{
				if (core->trace_status.Capturing == 0)
				{
					return false;
				}

				if (core->trace_last_read_valid != 0 &&
				    now - core->trace_last_read < trace_minimum_read_interval)
				{
					return false;
				}
			}

			snapshot_index = core->trace_snapshot_write;
		}

		HACDBG_TRACE_SNAPSHOT& destination = core->trace_snapshots[snapshot_index];

		sys::user::lock_resident_pages(&destination, sizeof(destination));

		const std::uint64_t copied = hypercall::trace_read(destination, HACDBG_TRACE_ALL_CPUS);
		const auto now = std::chrono::steady_clock::now();

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);
			core->trace_last_read = now;
			core->trace_last_read_valid = 1;

			if (copied != sizeof(destination) ||
			    destination.Version != HACDBG_TRACE_VERSION ||
			    destination.CpuCount > HACDBG_TRACE_MAX_CPUS ||
			    destination.EventCount > HACDBG_TRACE_MAX_EVENTS)
			{
				core->trace_status.LastError = HACDBG_CORE_TRACE_ERROR_READ_FAILED;
				return false;
			}

			core->trace_snapshot_active = snapshot_index;
			core->trace_snapshot_write = snapshot_index == 0 ? 1u : 0u;
			core->trace_status.SnapshotSequence += 1;
			core->trace_status.SnapshotVersion = destination.Version;
			core->trace_status.CpuCount = destination.CpuCount;
			core->trace_status.SnapshotEventCount = destination.EventCount;
			core->trace_status.TotalExits = destination.TotalExits;
			core->trace_status.DroppedEvents = destination.DroppedEvents;
			core->trace_status.CapturedTsc = destination.CapturedTsc;
			core->trace_status.Capturing =
				(destination.Flags & HACDBG_TRACE_FLAG_COUNTERS_ENABLED) != 0 ? 1u : 0u;
			core->trace_status.EventsEnabled =
				(destination.Flags & HACDBG_TRACE_FLAG_EVENTS_ENABLED) != 0 ? 1u : 0u;
			core->trace_status.LastError = HACDBG_CORE_TRACE_ERROR_NONE;
		}

		return true;
	}

	void stop_trace_capture(HACDBG_CORE* const core)
	{
		bool disable = false;

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);
			disable = core->trace_status.Supported != 0;
			core->trace_control_pending = 0;
			core->trace_read_pending = 0;
		}

		if (disable == false)
		{
			return;
		}

		hypercall::trace_control(HACDBG_TRACE_CONTROL_DISABLE, 0, 0);

		std::lock_guard<std::mutex> lock(core->trace_mutex);
		core->trace_status.Capturing = 0;
		core->trace_status.EventsEnabled = 0;
	}

	void view_loop(HACDBG_CORE* const core)
	{
		while (core->running.load(std::memory_order_acquire) != 0)
		{
			{
				std::unique_lock<std::mutex> lock(core->command_mutex);
				core->command_ready.wait_for(lock, std::chrono::milliseconds(100), [core]
				{
					return core->running.load(std::memory_order_acquire) == 0 ||
					       (core->command_active.load(std::memory_order_acquire) == 0 && core->commands.empty() &&
					        has_pending_view(core));
				});
			}

			if (core->running.load(std::memory_order_acquire) == 0)
			{
				break;
			}

			if (view_command_pending() != 0)
			{
				continue;
			}

			core_view_request_t view_request = {};

			if (take_view_request(core, view_request) == false)
			{
				continue;
			}

			if (view_command_pending() != 0)
			{
				requeue_preempted_view(core, view_request);
				continue;
			}

			commands::clear_view_preempted();

			try
			{
				execute_view_request(core, view_request);
			}
			catch (const std::exception& error)
			{
				if (commands::view_was_preempted() == 0)
				{
					publish_view_error(core, view_request, error.what());
				}
				else
				{
					requeue_preempted_view(core, view_request);
				}
			}
			catch (...)
			{
				if (commands::view_was_preempted() == 0)
				{
					publish_view_error(core, view_request, "view request failed");
				}
				else
				{
					requeue_preempted_view(core, view_request);
				}
			}

			commands::clear_view_preempted();
		}
	}

	std::uint8_t command_is_symbol_reload(const std::string& command)
	{
		std::size_t index = 0;

		while (index < command.size() && (command[index] == ' ' || command[index] == '\t'))
		{
			index += 1;
		}

		const std::string_view text(command.data() + index, command.size() - index);
		constexpr std::string_view prefix = ".reload";

		if (text.size() < prefix.size())
		{
			return 0;
		}

		for (std::size_t cursor = 0; cursor < prefix.size(); cursor++)
		{
			char character = text[cursor];

			if (character >= 'A' && character <= 'Z')
			{
				character = static_cast<char>(character - 'A' + 'a');
			}

			if (character != prefix[cursor])
			{
				return 0;
			}
		}

		if (text.size() == prefix.size())
		{
			return 1;
		}

		const char next = text[prefix.size()];

		return static_cast<std::uint8_t>(next == ' ' || next == '\t');
	}

	void monitor_loop(HACDBG_CORE* const core)
	{
		hypercall::skip_command_guest_wait();

		while (core->running.load(std::memory_order_acquire) != 0)
		{
			std::uint8_t again = 0;

			try
			{
				again = breakpoint::drain_monitor_mailbox();
				publish_monitors(core);
			}
			catch (const std::exception&)
			{
			}

			if (again != 0)
			{
				continue;
			}

			std::unique_lock<std::mutex> lock(core->command_mutex);
			core->command_ready.wait_for(lock, std::chrono::milliseconds(50), [core]
			{
				return core->running.load(std::memory_order_acquire) == 0;
			});
		}
	}

	void worker_loop(HACDBG_CORE* const core)
	{
		commands::mark_command_thread();

		while (true)
		{
			std::string command;
			const std::chrono::milliseconds wait_interval = worker_wait_interval(core);

			{
				std::unique_lock<std::mutex> lock(core->command_mutex);
				core->command_ready.wait_for(lock, wait_interval, [core]
				{
					return core->running.load() == 0 || core->commands.empty() == false ||
					       has_pending_completion(core) || has_pending_trace(core);
				});

				if (core->running.load() == 0)
				{
					break;
				}

				if (core->commands.empty() == false)
				{
					command = std::move(core->commands.front());
					core->commands.pop_front();
					core->command_active.store(1, std::memory_order_release);
				}
			}

			if (command.empty() == false)
			{
				commands::clear_cancel();
				hypercall::begin_command_guest();

				try
				{
					//
					// Hold the guest section for the whole command. The view
					// thread waits out this section instead of starting another
					// guest read, including the process walk after a breakpoint.
					// dbghelp does not take the section, so a step does not wait
					// for it. A symbol reload does not hold the section: the
					// monitor thread keeps flushing the log mailbox while PDBs
					// download.
					//
					if (command_is_symbol_reload(command) == 0)
					{
						const hypercall::GuestSection guest;

						commands::process(command);
					}
					else
					{
						commands::process(command);
					}
				}
				catch (const std::exception& error)
				{
					output::write(output::kind_t::error, error.what());
				}

				hypercall::end_command_guest();

				core->command_active.store(0, std::memory_order_release);
				core->command_ready.notify_all();
				core->commands_completed += 1;

				if (core->commands_completed == 0)
				{
					core->commands_completed = 1;
				}

				update_state(core);
				publish_monitor_sites(core);

				if (commands::is_quit_command(command) != 0)
				{
					output::write(output::kind_t::quit, {});
					core->running.store(0);
					break;
				}

				continue;
			}

			if (has_pending_completion(core) == true)
			{
				std::string token = {};
				std::uint64_t request_id = 0;

				{
					std::lock_guard<std::mutex> lock(core->view_mutex);

					if (core->completion_request.pending != 0)
					{
						token = core->completion_request.token;
						request_id = core->completion_request.id;
						core->completion_request.pending = 0;
					}
				}

				if (request_id != 0)
				{
					std::vector<std::string> matches = {};
					std::string error = {};

					try
					{
						commands::collect_completions(token, matches);
					}
					catch (const std::exception& exception)
					{
						error = exception.what();
					}
					catch (...)
					{
						error = "completion failed";
					}

					std::lock_guard<std::mutex> lock(core->view_mutex);

					if (core->completion_request.id == request_id)
					{
						core->completion_matches.clear();
						core->completion_total = static_cast<std::uint32_t>(
							(std::min)(matches.size(), static_cast<std::size_t>(0xffffffffu)));

						for (const std::string& match : matches)
						{
							if (core->completion_matches.size() >= HACDBG_CORE_MAX_COMPLETIONS)
							{
								break;
							}

							if (match.size() >= HACDBG_CORE_COMPLETION_SIZE)
							{
								continue;
							}

							core->completion_matches.push_back(match);
						}

						core->completion_status.CompletedRequestId = request_id;
						core->completion_status.Pending = core->completion_request.pending;
						core->completion_status.Failed = error.empty() == true ? 0u : 1u;
						core->completion_status.Count = static_cast<std::uint32_t>(core->completion_matches.size());
						core->completion_status.Total = core->completion_total;
					}
				}

				continue;
			}

			apply_pending_trace_control(core);

			// Trace reads used to skip this poll. A hit logged by the first
			// pause CPUID then never reached the disassembly view. The poll
			// reads the log mailbox and copies new records locally.
			if (commands::poll_breakpoint() != 0)
			{
				update_state(core);
			}

			publish_monitor_sites(core);

			if (perform_trace_read(core) != false)
			{
				continue;
			}
		}

		stop_trace_capture(core);
	}
}

uint32_t HacDbgCoreApiVersion(void)
{
	return HACDBG_CORE_API_VERSION;
}

uint32_t HacDbgCoreStateSize(void)
{
	return static_cast<uint32_t>(sizeof(HACDBG_CORE_STATE));
}

uint32_t HacDbgCoreStructureSize(const uint32_t structure)
{
	switch (structure)
	{
	case HacDbgStructureViewStatus:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_VIEW_STATUS));

	case HacDbgStructureModule:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_MODULE));

	case HacDbgStructureProcess:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_PROCESS));

	case HacDbgStructureThread:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_THREAD));

	case HacDbgStructureStackFrame:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_STACK_FRAME));

	case HacDbgStructureMemory:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_MEMORY));

	case HacDbgStructureInstruction:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_INSTRUCTION));

	case HacDbgStructureResolvedAddress:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_RESOLVED_ADDRESS));

	case HacDbgStructureTraceStatus:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_TRACE_STATUS));

	case HacDbgStructureTraceSnapshot:
		return static_cast<uint32_t>(sizeof(HACDBG_TRACE_SNAPSHOT));

	case HacDbgStructureCompletion:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_COMPLETION));

	case HacDbgStructureCompletionStatus:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_COMPLETION_STATUS));

	case HacDbgStructureMonitor:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_MONITOR));

	case HacDbgStructureMonitorHit:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_MONITOR_HIT));

	case HacDbgStructureStackWindow:
		return static_cast<uint32_t>(sizeof(HACDBG_CORE_STACK_WINDOW));

	default:
		return 0;
	}
}

HACDBG_CORE* HacDbgCoreCreate(const HACDBG_OUTPUT_CALLBACK output_callback, void* const context)
{
	try
	{
		HACDBG_CORE* const core = new HACDBG_CORE();
		core->monitor_hit_slots.resize(monitor_hit_queue_limit);
		core->output_callback = output_callback;
		core->output_context = context;
		copy_version(core->state.UserVersion, HACDBG_VERSION_STRING);
		sys::user::lock_resident_pages(core->trace_snapshots.data(), sizeof(core->trace_snapshots));

		return core;
	}
	catch (const std::exception&)
	{
		return nullptr;
	}
}

void HacDbgCoreDestroy(HACDBG_CORE* const core)
{
	if (core == nullptr)
	{
		return;
	}

	HacDbgCoreStop(core);
	delete core;
}

uint32_t HacDbgCoreStart(HACDBG_CORE* const core)
{
	if (core == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	if (core->initialized != 0)
	{
		return HacDbgCoreStatusState;
	}

	try
	{
		output::set_sink(output_callback, core);
		logs::set_up();
		symbol_parser::set_interrupt_check(commands::interrupt_requested);

		if (sys::set_up() == 0)
		{
			output::set_sink(nullptr, nullptr);

			return HacDbgCoreStatusDriver;
		}

		core->initialized = 1;
		core->running.store(1);

		{
			std::lock_guard<std::mutex> lock(core->state_mutex);
			core->state.Initialized = 1;
			core->state.Running = 1;
		}

		{
			std::lock_guard<std::mutex> lock(core->view_mutex);
			core->view_requests = {};
			core->view_status = {};
			core->next_view_request_id = 1;
			core->completion_request = {};
			core->completion_status = {};
			core->completion_matches.clear();
			core->completion_total = 0;
			core->next_completion_request_id = 1;
		}

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);
			core->trace_status = {};
			core->trace_sample_rate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
			core->trace_event_mask = HACDBG_TRACE_EVENT_MASK_ALL;
			core->trace_control_flags = 0;
			core->trace_control_sample_rate = 0;
			core->trace_control_event_mask = 0;
			core->trace_control_pending = 0;
			core->trace_read_pending = 0;
			core->trace_snapshot_active = 0;
			core->trace_snapshot_write = 1;
			core->trace_last_read = {};
			core->trace_last_read_valid = 0;
			core->trace_status.SampleRate = core->trace_sample_rate;
			core->trace_status.EventMask = core->trace_event_mask;
		}

		const std::uint64_t trace_supported = hypercall::trace_control(0, 0, 0);

		{
			std::lock_guard<std::mutex> lock(core->trace_mutex);
			core->trace_status.Supported = trace_supported != 0 ? 1u : 0u;
			core->trace_status.LastError = trace_supported != 0
			                                  ? HACDBG_CORE_TRACE_ERROR_NONE
			                                  : HACDBG_CORE_TRACE_ERROR_UNSUPPORTED;

			if (trace_supported != 0)
			{
				core->trace_read_pending = 1;
			}
		}

		std::uint32_t major = 0;
		std::uint32_t minor = 0;
		std::uint32_t patch = 0;
		std::uint32_t abi = 0;
		std::string version;

		if (hypercall::query_driver_version(major, minor, patch, abi, version) != 0)
		{
			std::lock_guard<std::mutex> lock(core->state_mutex);
			core->state.HypercallAbiVersion = abi;
			copy_version(core->state.DriverVersion, version);
		}

		commands::set_view_preempt(view_command_pending);
		hypercall::set_command_yield(commands::latch_view_preempt);
		g_preempt_core = core;
		core->worker = std::thread(worker_loop, core);
		core->view_worker = std::thread(view_loop, core);
		core->monitor_worker = std::thread(monitor_loop, core);
		update_state(core);

		return HacDbgCoreStatusOk;
	}
	catch (const std::exception&)
	{
		core->running.store(0);
		core->command_ready.notify_all();

		if (core->worker.joinable() != false)
		{
			core->worker.join();
		}

		if (core->view_worker.joinable() != false)
		{
			core->view_worker.join();
		}

		if (core->monitor_worker.joinable() != false)
		{
			core->monitor_worker.join();
		}

		g_preempt_core = nullptr;

		if (core->initialized != 0)
		{
			sys::clean_up();
			core->initialized = 0;
			core->running.store(0);
		}

		output::set_sink(nullptr, nullptr);

		return HacDbgCoreStatusException;
	}
}

uint32_t HacDbgCoreStop(HACDBG_CORE* const core)
{
	if (core == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	core->running.store(0);
	commands::cancel();
	core->command_ready.notify_all();

	if (core->worker.joinable() != false)
	{
		core->worker.join();
	}

	if (core->view_worker.joinable() != false)
	{
		core->view_worker.join();
	}

	if (core->monitor_worker.joinable() != false)
	{
		core->monitor_worker.join();
	}

	g_preempt_core = nullptr;

	if (core->initialized != 0)
	{
		sys::clean_up();
		core->initialized = 0;
	}

	{
		std::lock_guard<std::mutex> lock(core->state_mutex);
		core->state.Initialized = 0;
		core->state.Running = 0;
	}

	{
		std::lock_guard<std::mutex> lock(core->view_mutex);
		core->view_requests = {};

		for (HACDBG_CORE_VIEW_STATUS& status : core->view_status)
		{
			status.Pending = 0;
		}

		core->completion_request.pending = 0;
		core->completion_status.Pending = 0;
	}

	output::set_sink(nullptr, nullptr);

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreExecute(HACDBG_CORE* const core, const char* const utf8_command)
{
	if (core == nullptr || utf8_command == nullptr || utf8_command[0] == '\0')
	{
		return HacDbgCoreStatusArgument;
	}

	if (core->running.load() == 0)
	{
		return HacDbgCoreStatusState;
	}

	try
	{
		{
			std::lock_guard<std::mutex> lock(core->command_mutex);

			if (core->commands.size() >= max_queued_commands)
			{
				return HacDbgCoreStatusState;
			}

			core->commands.emplace_back(utf8_command);
		}

		core->command_ready.notify_all();

		return HacDbgCoreStatusOk;
	}
	catch (const std::exception&)
	{
		return HacDbgCoreStatusException;
	}
}

void HacDbgCoreCancel(HACDBG_CORE* const core)
{
	if (core != nullptr && core->running.load() != 0)
	{
		commands::cancel();
	}
}

uint32_t HacDbgCoreGetState(HACDBG_CORE* const core, HACDBG_CORE_STATE* const state_out)
{
	if (core == nullptr || state_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->state_mutex);
	*state_out = core->state;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyMonitors(HACDBG_CORE* const core, HACDBG_CORE_MONITOR* const items, const uint32_t capacity,
                              uint32_t* const count_out)
{
	if (core == nullptr || count_out == nullptr || (items == nullptr && capacity != 0))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->monitor_mutex);
	const uint32_t count = static_cast<uint32_t>(
		(std::min)(core->monitors.size(), static_cast<std::size_t>(capacity)));

	for (uint32_t index = 0; index < count; index++)
	{
		items[index] = core->monitors[index];
	}

	*count_out = count;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyMonitorHits(HACDBG_CORE* const core, HACDBG_CORE_MONITOR_HIT* const items, const uint32_t capacity,
                                   uint32_t* const count_out, uint64_t* const newest_sequence)
{
	if (core == nullptr || count_out == nullptr || (items == nullptr && capacity != 0))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->monitor_mutex);
	const std::size_t available = core->monitor_hit_count;
	const uint32_t count = static_cast<uint32_t>(
		(std::min)(available, static_cast<std::size_t>(capacity)));
	const std::size_t slots = core->monitor_hit_slots.size();

	for (uint32_t index = 0; index < count; index++)
	{
		items[index] = core->monitor_hit_slots[(core->monitor_hit_head + index) % slots];
	}

	if (count != 0 && slots != 0)
	{
		core->monitor_hit_head = (core->monitor_hit_head + count) % slots;
		core->monitor_hit_count -= count;
	}

	*count_out = count;

	if (newest_sequence != nullptr)
	{
		*newest_sequence = core->monitor_newest_sequence;
	}

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreGetSymbolProgress(HACDBG_CORE* const core, HACDBG_CORE_SYMBOL_PROGRESS* const progress_out)
{
	if (core == nullptr || progress_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	const commands::symbol_load_progress_t progress = commands::symbol_load_progress();

	progress_out->Active = progress.active;
	progress_out->Completed = progress.completed;
	progress_out->Total = progress.total;

	return HacDbgCoreStatusOk;
}

uint64_t HacDbgCoreRequestModules(HACDBG_CORE* const core)
{
	try
	{
		return queue_view_request(core, HacDbgViewModules);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint64_t HacDbgCoreRequestProcesses(HACDBG_CORE* const core)
{
	try
	{
		return queue_view_request(core, HacDbgViewProcesses);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint64_t HacDbgCoreRequestThreads(HACDBG_CORE* const core, const uint64_t eprocess)
{
	if (eprocess == 0)
	{
		return 0;
	}

	try
	{
		return queue_view_request(core, HacDbgViewThreads, eprocess);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint64_t HacDbgCoreRequestStack(HACDBG_CORE* const core, uint32_t frame_count)
{
	if (frame_count == 0)
	{
		frame_count = 20;
	}
	else if (frame_count > HACDBG_CORE_MAX_STACK_FRAMES)
	{
		frame_count = HACDBG_CORE_MAX_STACK_FRAMES;
	}

	try
	{
		return queue_view_request(core, HacDbgViewStack, 0, 0, frame_count);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint64_t HacDbgCoreRequestMemory(HACDBG_CORE* const core, const uint64_t address, const uint64_t cr3,
                                 const uint32_t size)
{
	if (size == 0 || size > HACDBG_CORE_MAX_MEMORY_BYTES)
	{
		return 0;
	}

	try
	{
		return queue_view_request(core, HacDbgViewMemory, address, cr3, size);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint64_t HacDbgCoreRequestDisassembly(HACDBG_CORE* const core, const uint64_t address, const uint64_t cr3,
                                      const uint32_t instruction_count)
{
	if (instruction_count == 0 || instruction_count > HACDBG_CORE_MAX_DISASSEMBLY_LINES)
	{
		return 0;
	}

	try
	{
		return queue_view_request(core, HacDbgViewDisassembly, address, cr3, instruction_count);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint64_t HacDbgCoreRequestResolve(HACDBG_CORE* const core, const char* const utf8_text)
{
	if (utf8_text == nullptr || utf8_text[0] == '\0')
	{
		return 0;
	}

	try
	{
		return queue_view_request(core, HacDbgViewResolve, 0, 0, 0, 0, utf8_text);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint32_t HacDbgCoreGetViewStatus(HACDBG_CORE* const core, const uint32_t view,
                                 HACDBG_CORE_VIEW_STATUS* const status_out)
{
	if (core == nullptr || status_out == nullptr || view >= static_cast<uint32_t>(HacDbgViewCount))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	*status_out = core->view_status[view];

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyModules(HACDBG_CORE* const core, HACDBG_CORE_MODULE* const modules,
                               const uint32_t capacity, uint32_t* const count_out)
{
	if (core == nullptr || count_out == nullptr || (capacity != 0 && modules == nullptr))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	const uint32_t count = (std::min)(core->module_count, capacity);

	if (count != 0)
	{
		std::memcpy(modules, core->modules, static_cast<std::size_t>(count) * sizeof(HACDBG_CORE_MODULE));
	}

	*count_out = count;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyProcesses(HACDBG_CORE* const core, HACDBG_CORE_PROCESS* const processes,
                                 const uint32_t capacity, uint32_t* const count_out)
{
	if (core == nullptr || count_out == nullptr || (capacity != 0 && processes == nullptr))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	const uint32_t count = (std::min)(core->process_count, capacity);

	if (count != 0)
	{
		std::memcpy(processes, core->processes, static_cast<std::size_t>(count) * sizeof(HACDBG_CORE_PROCESS));
	}

	*count_out = count;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyThreads(HACDBG_CORE* const core, HACDBG_CORE_THREAD* const threads,
                               const uint32_t capacity, uint32_t* const count_out)
{
	if (core == nullptr || count_out == nullptr || (capacity != 0 && threads == nullptr))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	const uint32_t count = (std::min)(core->thread_count, capacity);

	if (count != 0)
	{
		std::memcpy(threads, core->threads, static_cast<std::size_t>(count) * sizeof(HACDBG_CORE_THREAD));
	}

	*count_out = count;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyStack(HACDBG_CORE* const core, HACDBG_CORE_STACK_FRAME* const frames,
                             const uint32_t capacity, uint32_t* const count_out)
{
	if (core == nullptr || count_out == nullptr || (capacity != 0 && frames == nullptr))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	const uint32_t count = (std::min)(core->stack_count, capacity);

	if (count != 0)
	{
		std::memcpy(frames, core->stack, static_cast<std::size_t>(count) * sizeof(HACDBG_CORE_STACK_FRAME));
	}

	*count_out = count;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyStackWindow(HACDBG_CORE* const core, HACDBG_CORE_STACK_WINDOW* const window_out)
{
	if (core == nullptr || window_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	*window_out = core->stack_window;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyMemory(HACDBG_CORE* const core, HACDBG_CORE_MEMORY* const memory_out)
{
	if (core == nullptr || memory_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	*memory_out = core->memory;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyDisassembly(HACDBG_CORE* const core, HACDBG_CORE_INSTRUCTION* const instructions,
                                   const uint32_t capacity, uint32_t* const count_out)
{
	if (core == nullptr || count_out == nullptr || (capacity != 0 && instructions == nullptr))
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	const uint32_t count = (std::min)(core->disassembly_count, capacity);

	if (count != 0)
	{
		std::memcpy(instructions, core->disassembly,
		            static_cast<std::size_t>(count) * sizeof(HACDBG_CORE_INSTRUCTION));
	}

	*count_out = count;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyResolvedAddress(HACDBG_CORE* const core, HACDBG_CORE_RESOLVED_ADDRESS* const address_out)
{
	if (core == nullptr || address_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	*address_out = core->resolved_address;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreTraceControl(HACDBG_CORE* const core, const uint32_t flags, const uint32_t sample_rate,
                                const uint32_t event_mask)
{
	if (core == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	constexpr std::uint32_t allowed_flags =
		HACDBG_TRACE_CONTROL_ENABLE_COUNTERS |
		HACDBG_TRACE_CONTROL_ENABLE_EVENTS |
		HACDBG_TRACE_CONTROL_RESET |
		HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE |
		HACDBG_TRACE_CONTROL_SET_EVENT_MASK |
		HACDBG_TRACE_CONTROL_DISABLE;

	if ((flags & ~allowed_flags) != 0 || core->running.load() == 0)
	{
		return HacDbgCoreStatusArgument;
	}

	{
		std::lock_guard<std::mutex> lock(core->trace_mutex);

		if (core->trace_status.Supported == 0)
		{
			core->trace_status.LastError = HACDBG_CORE_TRACE_ERROR_UNSUPPORTED;
			return HacDbgCoreStatusDriver;
		}

		core->trace_control_flags = flags;
		core->trace_control_sample_rate = sample_rate;
		core->trace_control_event_mask = event_mask & HACDBG_TRACE_EVENT_MASK_ALL;
		core->trace_control_pending = 1;
	}

	{
		std::lock_guard<std::mutex> lock(core->command_mutex);
	}

	core->command_ready.notify_all();

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreRequestTraceRead(HACDBG_CORE* const core)
{
	if (core == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	if (core->running.load() == 0)
	{
		return HacDbgCoreStatusState;
	}

	{
		std::lock_guard<std::mutex> lock(core->trace_mutex);

		if (core->trace_status.Supported == 0)
		{
			return HacDbgCoreStatusDriver;
		}

		if (core->trace_status.Capturing == 0)
		{
			return HacDbgCoreStatusState;
		}

		core->trace_read_pending = 1;
	}

	{
		std::lock_guard<std::mutex> lock(core->command_mutex);
	}

	core->command_ready.notify_all();

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreGetTraceStatus(HACDBG_CORE* const core, HACDBG_CORE_TRACE_STATUS* const status_out)
{
	if (core == nullptr || status_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->trace_mutex);
	*status_out = core->trace_status;
	status_out->ControlPending = core->trace_control_pending;
	status_out->ReadPending = core->trace_read_pending;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyTraceSnapshot(HACDBG_CORE* const core, HACDBG_TRACE_SNAPSHOT* const snapshot_out)
{
	if (core == nullptr || snapshot_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->trace_mutex);

	if (core->trace_status.SnapshotSequence == 0)
	{
		return HacDbgCoreStatusState;
	}

	*snapshot_out = core->trace_snapshots[core->trace_snapshot_active];

	return HacDbgCoreStatusOk;
}

namespace
{
	std::uint32_t copy_completion_matches(const std::vector<std::string>& matches,
	                                      HACDBG_CORE_COMPLETION* const items, const std::uint32_t capacity)
	{
		std::uint32_t copied = 0;

		for (const std::string& match : matches)
		{
			if (copied >= capacity)
			{
				break;
			}

			if (match.size() >= HACDBG_CORE_COMPLETION_SIZE)
			{
				continue;
			}

			copy_text(items[copied].Text, match);
			copied += 1;
		}

		return copied;
	}
}

uint32_t HacDbgCoreCompleteCommands(const char* const utf8_token, HACDBG_CORE_COMPLETION* const items,
                                    const uint32_t capacity, uint32_t* const count_out)
{
	if (utf8_token == nullptr || items == nullptr || count_out == nullptr || capacity == 0)
	{
		return HacDbgCoreStatusArgument;
	}

	if (std::strchr(utf8_token, '!') != nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	try
	{
		std::vector<std::string> matches = {};
		commands::collect_completions(utf8_token, matches);
		*count_out = copy_completion_matches(matches, items, capacity);

		return HacDbgCoreStatusOk;
	}
	catch (const std::exception&)
	{
		return HacDbgCoreStatusException;
	}
}

uint64_t HacDbgCoreRequestCompletions(HACDBG_CORE* const core, const char* const utf8_token)
{
	if (core == nullptr || utf8_token == nullptr || core->running.load() == 0)
	{
		return 0;
	}

	std::uint64_t id = 0;

	try
	{
		{
			std::lock_guard<std::mutex> lock(core->view_mutex);

			if (core->next_completion_request_id == 0)
			{
				core->next_completion_request_id = 1;
			}

			id = core->next_completion_request_id++;
			core->completion_request.id = id;
			core->completion_request.token = utf8_token;
			core->completion_request.pending = 1;
			core->completion_status.RequestId = id;
			core->completion_status.Pending = 1;
			core->completion_status.Failed = 0;
		}

		{
			std::lock_guard<std::mutex> lock(core->command_mutex);
		}

		core->command_ready.notify_all();

		return id;
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

uint32_t HacDbgCoreGetCompletionStatus(HACDBG_CORE* const core, HACDBG_CORE_COMPLETION_STATUS* const status_out)
{
	if (core == nullptr || status_out == nullptr)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);
	*status_out = core->completion_status;

	return HacDbgCoreStatusOk;
}

uint32_t HacDbgCoreCopyCompletions(HACDBG_CORE* const core, const uint64_t request_id,
                                   HACDBG_CORE_COMPLETION* const items, const uint32_t capacity,
                                   uint32_t* const count_out)
{
	if (core == nullptr || items == nullptr || count_out == nullptr || request_id == 0 || capacity == 0)
	{
		return HacDbgCoreStatusArgument;
	}

	std::lock_guard<std::mutex> lock(core->view_mutex);

	if (core->completion_status.Pending != 0 || core->completion_status.CompletedRequestId != request_id)
	{
		return HacDbgCoreStatusState;
	}

	*count_out = copy_completion_matches(core->completion_matches, items, capacity);

	return HacDbgCoreStatusOk;
}
