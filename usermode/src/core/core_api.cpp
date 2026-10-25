/**
 * @file core_api.cpp
 * @brief C ABI session wrapper for the WPF GUI.
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

struct HACDBG_CORE
{
	std::mutex command_mutex;
	std::condition_variable command_ready;
	std::deque<std::string> commands;
	std::thread worker;
	std::atomic<std::uint8_t> running = 0;
	std::uint8_t initialized = 0;
	HACDBG_OUTPUT_CALLBACK output_callback = nullptr;
	void* output_context = nullptr;

	std::mutex state_mutex;
	HACDBG_CORE_STATE state = {};

	std::mutex view_mutex;
	std::array<core_view_request_t, static_cast<std::size_t>(HacDbgViewCount)> view_requests = {};
	std::array<HACDBG_CORE_VIEW_STATUS, static_cast<std::size_t>(HacDbgViewCount)> view_status = {};
	std::uint64_t next_view_request_id = 1;

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

	HACDBG_CORE_MEMORY memory = {};
	HACDBG_CORE_INSTRUCTION disassembly[HACDBG_CORE_MAX_DISASSEMBLY_LINES] = {};
	std::uint32_t disassembly_count = 0;
	std::uint32_t disassembly_truncated = 0;
	HACDBG_CORE_RESOLVED_ADDRESS resolved_address = {};
};

namespace
{
	constexpr std::size_t max_queued_commands = 64;
	constexpr std::chrono::milliseconds breakpoint_poll_interval(100);

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

	void publish_view_error(HACDBG_CORE* const core, const core_view_request_t& request, const std::string& error)
	{
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

			if (commands::views::stack(request.arg2, frames, error) == 0)
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

		core->command_ready.notify_one();

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

	void worker_loop(HACDBG_CORE* const core)
	{
		while (true)
		{
			std::string command;

			{
				std::unique_lock<std::mutex> lock(core->command_mutex);
				core->command_ready.wait_for(lock, breakpoint_poll_interval, [core]
				{
					return core->running.load() == 0 || core->commands.empty() == false ||
					       has_pending_view(core);
				});

				if (core->running.load() == 0)
				{
					break;
				}

				if (core->commands.empty() == false)
				{
					command = std::move(core->commands.front());
					core->commands.pop_front();
				}
			}

			if (command.empty() == false)
			{
				commands::clear_cancel();

				try
				{
					commands::process(command);
				}
				catch (const std::exception& error)
				{
					output::write(output::kind_t::error, error.what());
				}

				update_state(core);

				if (commands::is_quit_command(command) != 0)
				{
					output::write(output::kind_t::quit, {});
					core->running.store(0);
					break;
				}

				continue;
			}

			core_view_request_t view_request = {};

			if (take_view_request(core, view_request) == true)
			{
				try
				{
					execute_view_request(core, view_request);
				}
				catch (const std::exception& error)
				{
					publish_view_error(core, view_request, error.what());
				}
				catch (...)
				{
					publish_view_error(core, view_request, "view request failed");
				}

				continue;
			}

			if (commands::poll_breakpoint() != 0)
			{
				update_state(core);
			}
		}
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

	default:
		return 0;
	}
}

HACDBG_CORE* HacDbgCoreCreate(const HACDBG_OUTPUT_CALLBACK output_callback, void* const context)
{
	try
	{
		HACDBG_CORE* const core = new HACDBG_CORE();
		core->output_callback = output_callback;
		core->output_context = context;
		copy_version(core->state.UserVersion, HACDBG_VERSION_STRING);

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

		core->worker = std::thread(worker_loop, core);
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

		core->command_ready.notify_one();

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
