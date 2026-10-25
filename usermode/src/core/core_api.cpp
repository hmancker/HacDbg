/**
 * @file core_api.cpp
 * @brief C ABI session wrapper for the WPF GUI.
 *
 * @author HacDbg
 */

#include "../../api/hacdbg_core_api.h"

#include <algorithm>
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
};

namespace
{
	constexpr std::size_t max_queued_commands = 64;
	constexpr std::chrono::milliseconds breakpoint_poll_interval(100);

	HACDBG_CORE* core_from_context(void* const context)
	{
		return static_cast<HACDBG_CORE*>(context);
	}

	void copy_version(char (&destination)[HACDBG_CORE_VERSION_STRING_SIZE], const std::string& source)
	{
		const std::size_t length = (std::min)(source.size(), static_cast<std::size_t>(HACDBG_CORE_VERSION_STRING_SIZE - 1));
		std::memcpy(destination, source.data(), length);
		destination[length] = '\0';
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
					return core->running.load() == 0 || core->commands.empty() == false;
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
