/**
 * @file trace_abi.cpp
 * @brief Exported C ABI for the embedded trace renderer.
 *
 * @author HacDbg
 */

#include "trace_internal.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <new>

namespace
{
	std::atomic<uint32_t> g_last_error = 0;

	bool valid_theme(const HACDBG_TRACE_THEME* const theme)
	{
		return theme != nullptr && theme->Size == sizeof(HACDBG_TRACE_THEME) &&
		       theme->Version == HACDBG_TRACE_THEME_VERSION;
	}
}

HACDBG_TRACE_THEME trace_default_theme()
{
	HACDBG_TRACE_THEME theme = {};

	theme.Size = sizeof(theme);
	theme.Version = HACDBG_TRACE_THEME_VERSION;
	theme.Background = 0xFF111418;
	theme.Surface = 0xFF181D23;
	theme.SurfaceRaised = 0xFF20262E;
	theme.Border = 0xFF303842;
	theme.Text = 0xFFE6EDF3;
	theme.Muted = 0xFF8B98A5;
	theme.Accent = 0xFF4CC2FF;
	theme.Warning = 0xFFE3B341;
	theme.Error = 0xFFFF7B72;

	return theme;
}

uint32_t trace_hresult_code(const HRESULT result)
{
	return static_cast<uint32_t>(result);
}

void trace_notify(HACDBG_TRACE* const trace)
{
	const HWND child = trace != nullptr ? trace->child.load() : nullptr;

	if (child != nullptr)
	{
		PostMessageW(child, trace_wake_message, 0, 0);
	}
}

void trace_invoke_action(HACDBG_TRACE* const trace, const uint32_t action)
{
	if (trace == nullptr)
	{
		return;
	}

	HACDBG_TRACE_ACTION_CALLBACK callback = nullptr;
	void* context = nullptr;

	{
		const std::lock_guard<std::mutex> lock(trace->action_mutex);
		callback = trace->action_callback;
		context = trace->action_context;
	}

	if (callback != nullptr)
	{
		callback(action, context);
	}
}

void trace_report_failure(HACDBG_TRACE* const trace, const uint32_t error)
{
	if (trace == nullptr)
	{
		return;
	}

	trace->last_error.store(error);
	g_last_error.store(error);
	trace->stopping.store(true);

	HACDBG_TRACE_ACTION_CALLBACK callback = nullptr;
	void* context = nullptr;

	{
		const std::lock_guard<std::mutex> lock(trace->action_mutex);
		trace->failure_pending = true;

		if (trace->action_callback != nullptr && trace->failure_reported == false)
		{
			trace->failure_reported = true;
			callback = trace->action_callback;
			context = trace->action_context;
		}
	}

	if (callback != nullptr)
	{
		callback(HacDbgTraceActionDeviceError, context);
	}
}

void trace_snapshot_mailbox::publish(const HACDBG_TRACE_SNAPSHOT& snapshot)
{
	const std::lock_guard<std::mutex> publish_lock(publish_mutex_);
	const uint32_t next = active_.load(std::memory_order_relaxed) == 0 ? 1u : 0u;

	std::memcpy(&buffers_[next], &snapshot, sizeof(snapshot));

	{
		const std::unique_lock<std::shared_mutex> lock(mutex_);
		active_.store(next, std::memory_order_relaxed);
		generation_ += 1;
	}
}

bool trace_snapshot_mailbox::copy_latest(HACDBG_TRACE_SNAPSHOT& snapshot_out, uint64_t& generation_out,
                                         const uint64_t seen_generation) const
{
	const std::shared_lock<std::shared_mutex> lock(mutex_);

	if (generation_ == seen_generation || generation_ == 0)
	{
		return false;
	}

	const uint32_t active = active_.load(std::memory_order_relaxed);
	std::memcpy(&snapshot_out, &buffers_[active], sizeof(snapshot_out));
	generation_out = generation_;

	return true;
}

bool trace_snapshot_mailbox::copy_current(HACDBG_TRACE_SNAPSHOT& snapshot_out) const
{
	const std::shared_lock<std::shared_mutex> lock(mutex_);

	if (generation_ == 0)
	{
		return false;
	}

	const uint32_t active = active_.load(std::memory_order_relaxed);
	std::memcpy(&snapshot_out, &buffers_[active], sizeof(snapshot_out));

	return true;
}

HACDBG_TRACE::HACDBG_TRACE(const HWND host_window, const HINSTANCE module, const HACDBG_TRACE_THEME* const theme)
	: host(host_window),
	  instance(module),
	  view(valid_theme(theme) == true ? *theme : trace_default_theme())
{
	window.theme = valid_theme(theme) == true ? *theme : trace_default_theme();

	RECT client = {};
	if (GetClientRect(host_window, &client) != FALSE)
	{
		window.width = static_cast<uint32_t>((std::max)(client.right - client.left, 1L));
		window.height = static_cast<uint32_t>((std::max)(client.bottom - client.top, 1L));
	}

	const UINT dpi = GetDpiForWindow(host_window);
	window.dpi = dpi >= 48 ? dpi : 96;
	view.set_dpi(window.dpi);
}

uint32_t HACDBG_TRACE_CALL HacDbgTraceApiVersion(void)
{
	return HACDBG_TRACE_API_VERSION;
}

uint32_t HACDBG_TRACE_CALL HacDbgTraceThemeSize(void)
{
	return static_cast<uint32_t>(sizeof(HACDBG_TRACE_THEME));
}

uint32_t HACDBG_TRACE_CALL HacDbgTraceLastError(void)
{
	return g_last_error.load();
}

HACDBG_TRACE* HACDBG_TRACE_CALL HacDbgTraceAttach(const HWND host, const HINSTANCE instance,
                                                   const HACDBG_TRACE_THEME* const theme)
{
	if (host == nullptr || instance == nullptr || IsWindow(host) == FALSE)
	{
		g_last_error.store(trace_hresult_code(E_INVALIDARG));
		return nullptr;
	}

	HACDBG_TRACE* trace = nullptr;

	try
	{
		trace = new (std::nothrow) HACDBG_TRACE(host, instance, theme);
	}
	catch (...)
	{
		trace = nullptr;
	}

	if (trace == nullptr)
	{
		g_last_error.store(trace_hresult_code(E_OUTOFMEMORY));
		return nullptr;
	}

	g_last_error.store(0);

	if (trace_host_start(trace) == false)
	{
		const uint32_t error = trace->last_error.load();
		g_last_error.store(error != 0 ? error : trace_hresult_code(E_FAIL));
		delete trace;
		return nullptr;
	}

	return trace;
}

void HACDBG_TRACE_CALL HacDbgTracePublishSnapshot(HACDBG_TRACE* const trace,
                                                   const HACDBG_TRACE_SNAPSHOT* const snapshot)
{
	if (trace == nullptr || snapshot == nullptr)
	{
		g_last_error.store(trace_hresult_code(E_INVALIDARG));
		return;
	}

	if (snapshot->Version != HACDBG_TRACE_VERSION ||
	    snapshot->CpuCount > HACDBG_TRACE_MAX_CPUS ||
	    snapshot->EventCount > HACDBG_TRACE_MAX_EVENTS)
	{
		g_last_error.store(trace_hresult_code(E_INVALIDARG));
		return;
	}

	trace->snapshots.publish(*snapshot);
}

void HACDBG_TRACE_CALL HacDbgTraceSetTheme(HACDBG_TRACE* const trace, const HACDBG_TRACE_THEME* const theme)
{
	if (trace == nullptr || valid_theme(theme) == false)
	{
		g_last_error.store(trace_hresult_code(E_INVALIDARG));
		return;
	}

	{
		const std::lock_guard<std::mutex> lock(trace->command_mutex);
		trace->window.theme = *theme;
		trace->command_serial += 1;
	}

	trace_notify(trace);
}

void HACDBG_TRACE_CALL HacDbgTraceSetDpi(HACDBG_TRACE* const trace, const uint32_t dpi)
{
	if (trace == nullptr)
	{
		return;
	}

	{
		const std::lock_guard<std::mutex> lock(trace->command_mutex);
		trace->window.dpi = (std::max)(dpi, 48u);
		trace->command_serial += 1;
	}

	trace_notify(trace);
}

void HACDBG_TRACE_CALL HacDbgTraceSetVisible(HACDBG_TRACE* const trace, const uint32_t visible)
{
	if (trace == nullptr)
	{
		return;
	}

	{
		const std::lock_guard<std::mutex> lock(trace->command_mutex);
		trace->window.visible = visible != 0 ? 1u : 0u;
		trace->command_serial += 1;
	}

	trace_notify(trace);
}

void HACDBG_TRACE_CALL HacDbgTraceResize(HACDBG_TRACE* const trace, const uint32_t width, const uint32_t height)
{
	if (trace == nullptr)
	{
		return;
	}

	{
		const std::lock_guard<std::mutex> lock(trace->command_mutex);
		trace->window.width = (std::max)(width, 1u);
		trace->window.height = (std::max)(height, 1u);
		trace->command_serial += 1;
	}

	trace_notify(trace);
}

void HACDBG_TRACE_CALL HacDbgTraceSetActionCallback(HACDBG_TRACE* const trace,
                                                     const HACDBG_TRACE_ACTION_CALLBACK callback,
                                                     void* const context)
{
	if (trace == nullptr)
	{
		return;
	}

	HACDBG_TRACE_ACTION_CALLBACK pending_callback = nullptr;
	void* pending_context = nullptr;

	{
		const std::lock_guard<std::mutex> lock(trace->action_mutex);
		trace->action_callback = callback;
		trace->action_context = context;

		if (callback != nullptr && trace->failure_pending != false &&
		    trace->failure_reported == false)
		{
			trace->failure_reported = true;
			pending_callback = callback;
			pending_context = context;
		}
	}

	if (pending_callback != nullptr)
	{
		pending_callback(HacDbgTraceActionDeviceError, pending_context);
	}
}

uint32_t HACDBG_TRACE_CALL HacDbgTraceExportCsv(HACDBG_TRACE* const trace, const wchar_t* const path)
{
	if (trace == nullptr || path == nullptr || path[0] == L'\0')
	{
		g_last_error.store(trace_hresult_code(E_INVALIDARG));
		return trace_hresult_code(E_INVALIDARG);
	}

	HACDBG_TRACE_SNAPSHOT snapshot = {};

	if (trace->snapshots.copy_current(snapshot) == false)
	{
		const uint32_t result = trace_hresult_code(HRESULT_FROM_WIN32(ERROR_NOT_FOUND));
		g_last_error.store(result);
		return result;
	}

	try
	{
		std::ofstream stream(std::filesystem::path(path),
		                     std::ios::binary | std::ios::trunc);

		if (!stream)
		{
			const uint32_t result = trace_hresult_code(HRESULT_FROM_WIN32(ERROR_WRITE_FAULT));
			g_last_error.store(result);
			return result;
		}

		stream << "section,index,cpu,reason,tsc,rip,cr3,info1,info2,duration_tsc,total,dropped\n";

		for (uint32_t index = 0; index < snapshot.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
		{
			const HACDBG_TRACE_CPU& cpu = snapshot.Cpu[index];

			stream << "cpu," << index << ',' << cpu.CpuIndex << ",,0,0,0,0,0,0,"
			       << static_cast<unsigned long long>(cpu.TotalExits) << ','
			       << cpu.DroppedEvents << '\n';
		}

		for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
		{
			uint64_t total = 0;

			for (uint32_t index = 0; index < snapshot.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
			{
				total += snapshot.Cpu[index].ReasonCounts[reason];
			}

			stream << "reason," << reason << ",0," << reason << ",0,0,0,0,0,0,"
			       << static_cast<unsigned long long>(total) << ",0\n";
		}

		for (uint32_t index = 0; index < snapshot.EventCount && index < HACDBG_TRACE_MAX_EVENTS; index++)
		{
			const HACDBG_TRACE_EVENT& event = snapshot.Events[index];

			stream << "event," << index << ',' << event.CpuIndex << ',' << event.Reason << ','
			       << static_cast<unsigned long long>(event.Tsc) << ','
			       << static_cast<unsigned long long>(event.Rip) << ','
			       << static_cast<unsigned long long>(event.Cr3) << ','
			       << static_cast<unsigned long long>(event.ExitInfo1) << ','
			       << static_cast<unsigned long long>(event.ExitInfo2) << ','
			       << static_cast<unsigned long long>(event.DurationTsc) << ",0,0\n";
		}

		if (!stream.good())
		{
			const uint32_t result = trace_hresult_code(HRESULT_FROM_WIN32(ERROR_WRITE_FAULT));
			g_last_error.store(result);
			return result;
		}
	}
	catch (const std::exception&)
	{
		const uint32_t result = trace_hresult_code(HRESULT_FROM_WIN32(ERROR_WRITE_FAULT));
		g_last_error.store(result);
		return result;
	}

	g_last_error.store(0);
	return 0;
}

void HACDBG_TRACE_CALL HacDbgTraceDetach(HACDBG_TRACE* const trace)
{
	if (trace == nullptr)
	{
		return;
	}

	trace_host_detach(trace);
	delete trace;
}
