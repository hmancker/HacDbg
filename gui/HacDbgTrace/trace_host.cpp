/**
 * @file trace_host.cpp
 * @brief Native child window and render-thread lifecycle for the trace panel.
 *
 * @author HacDbg
 */

#include "trace_internal.h"

#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <string>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace
{
	constexpr wchar_t trace_window_class[] = L"HacDbgTraceRenderWindow";

	std::once_flag g_window_class_once;
	std::atomic<bool> g_window_class_ready = false;

	LRESULT CALLBACK trace_window_proc(const HWND window, const UINT message, const WPARAM wparam,
	                                   const LPARAM lparam)
	{
		HACDBG_TRACE* trace = reinterpret_cast<HACDBG_TRACE*>(GetWindowLongPtrW(window, GWLP_USERDATA));

		if (message == WM_NCCREATE)
		{
			const CREATESTRUCTW* const create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
			trace = static_cast<HACDBG_TRACE*>(create->lpCreateParams);
			SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(trace));
			return TRUE;
		}

		if (trace != nullptr && message == WM_ERASEBKGND)
		{
			return 1;
		}

		if (trace != nullptr && message == WM_PAINT)
		{
			ValidateRect(window, nullptr);
			return 0;
		}

		if (trace != nullptr && message == WM_LBUTTONDOWN)
		{
			SetFocus(window);
		}

		if (trace != nullptr && message == WM_KEYDOWN)
		{
			const bool control = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
			const bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;

			if (control)
			{
				switch (wparam)
				{
				case VK_TAB:
					trace_invoke_action(trace, shift ? HacDbgTraceActionPreviousDocument
					                                 : HacDbgTraceActionNextDocument);
					return 0;

				case 'L':
					trace_invoke_action(trace, HacDbgTraceActionClearOutput);
					return 0;

				case '1':
				case '2':
				case '3':
				case '4':
					trace_invoke_action(
						trace,
						static_cast<uint32_t>(HacDbgTraceActionDocument1) +
							(static_cast<uint32_t>(wparam) - '1'));
					return 0;

				case VK_NUMPAD1:
				case VK_NUMPAD2:
				case VK_NUMPAD3:
				case VK_NUMPAD4:
					trace_invoke_action(
						trace,
						static_cast<uint32_t>(HacDbgTraceActionDocument1) +
							(static_cast<uint32_t>(wparam) - VK_NUMPAD1));
					return 0;

				default:
					break;
				}
			}

			switch (wparam)
			{
			case VK_F5:
				trace_invoke_action(trace, HacDbgTraceActionContinue);
				return 0;

			case VK_F10:
				trace_invoke_action(trace, HacDbgTraceActionStepOver);
				return 0;

			case VK_F11:
				trace_invoke_action(trace, HacDbgTraceActionStepInto);
				return 0;

			case VK_ESCAPE:
				// Let ImGui close popups or edit text before returning focus to the GUI.
				if (ImGui::GetCurrentContext() != nullptr &&
				    ImGui::GetIO().WantTextInput == false &&
				    ImGui::IsPopupOpen(nullptr,
				                       ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel) == false)
				{
					trace_invoke_action(trace, HacDbgTraceActionFocusCommand);
					return 0;
				}
				break;

			default:
				break;
			}
		}

		if (trace != nullptr && (message == WM_CLOSE || message == WM_DESTROY))
		{
			trace->stopping.store(true);
		}

		if (trace != nullptr && ImGui::GetCurrentContext() != nullptr &&
		    ImGui_ImplWin32_WndProcHandler(window, message, wparam, lparam) != 0)
		{
			return 0;
		}

		if (message == WM_NCDESTROY && trace != nullptr)
		{
			trace->child.store(nullptr);
			SetWindowLongPtrW(window, GWLP_USERDATA, 0);
		}

		return DefWindowProcW(window, message, wparam, lparam);
	}

	void register_window_class(const HINSTANCE instance)
	{
		std::call_once(g_window_class_once, [instance]
		{
			WNDCLASSEXW window_class = {};

			window_class.cbSize = sizeof(window_class);
			window_class.style = CS_HREDRAW | CS_VREDRAW;
			window_class.lpfnWndProc = trace_window_proc;
			window_class.hInstance = instance;
			window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
			window_class.lpszClassName = trace_window_class;

			const ATOM atom = RegisterClassExW(&window_class);

			if (atom != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS)
			{
				g_window_class_ready.store(true);
			}
		});
	}

	std::string wide_to_utf8(const wchar_t* const text)
	{
		if (text == nullptr || text[0] == L'\0')
		{
			return {};
		}

		const int length = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);

		if (length <= 1)
		{
			return {};
		}

		std::string result(static_cast<std::size_t>(length), '\0');
		WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), length, nullptr, nullptr);
		result.resize(static_cast<std::size_t>(length - 1));

		return result;
	}

	bool font_exists(const wchar_t* const path)
	{
		const DWORD attributes = GetFileAttributesW(path);

		return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
	}

	ImFont* load_monospace_font(const float pixel_size)
	{
		wchar_t windows_directory[MAX_PATH] = {};
		const UINT length = GetWindowsDirectoryW(windows_directory, static_cast<UINT>(std::size(windows_directory)));

		if (length == 0 || static_cast<std::size_t>(length) >= std::size(windows_directory))
		{
			return ImGui::GetIO().Fonts->AddFontDefault();
		}

		const wchar_t* const candidates[] = {
			L"\\Fonts\\CascadiaMono.ttf",
			L"\\Fonts\\consola.ttf",
			L"\\Fonts\\lucon.ttf"
		};

		for (const wchar_t* const candidate : candidates)
		{
			wchar_t path[MAX_PATH] = {};
			const int written = swprintf_s(path, L"%ls%ls", windows_directory, candidate);

			if (written <= 0 || font_exists(path) == false)
			{
				continue;
			}

			const std::string utf8_path = wide_to_utf8(path);
			ImFont* const font = ImGui::GetIO().Fonts->AddFontFromFileTTF(utf8_path.c_str(), pixel_size);

			if (font != nullptr)
			{
				return font;
			}
		}

		return ImGui::GetIO().Fonts->AddFontDefault();
	}

	trace_window_state current_window_state(HACDBG_TRACE* const trace, uint64_t& serial_out)
	{
		const std::lock_guard<std::mutex> lock(trace->command_mutex);
		serial_out = trace->command_serial;
		return trace->window;
	}

	double monotonic_seconds()
	{
		static const auto origin = std::chrono::steady_clock::now();
		const auto now = std::chrono::steady_clock::now();

		return std::chrono::duration<double>(now - origin).count();
	}

	void request_device_error(HACDBG_TRACE* const trace)
	{
		trace_report_failure(trace, trace_hresult_code(E_FAIL));
	}

	void render_thread_main(HACDBG_TRACE* const trace)
	{
		trace->render_thread_id.store(GetCurrentThreadId());

		register_window_class(trace->instance);

		if (g_window_class_ready.load() == false)
		{
			trace_report_failure(trace, trace_hresult_code(E_FAIL));
			return;
		}

		uint64_t serial = 0;
		const trace_window_state initial = current_window_state(trace, serial);
		const DWORD style = WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN;

		const HWND child = CreateWindowExW(
			0,
			trace_window_class,
			L"HacDbg trace",
			style,
			0,
			0,
			static_cast<int>(initial.width),
			static_cast<int>(initial.height),
			trace->host,
			nullptr,
			trace->instance,
			trace);

		if (child == nullptr)
		{
			trace_report_failure(trace, trace_hresult_code(HRESULT_FROM_WIN32(GetLastError())));
			return;
		}

		trace->child.store(child);

		if (trace->renderer.initialize(child, initial.width, initial.height) == false)
		{
			trace_report_failure(trace, trace_hresult_code(E_FAIL));
			DestroyWindow(child);
			return;
		}

		ImGuiContext* const context = ImGui::CreateContext();

		if (context == nullptr)
		{
			trace_report_failure(trace, trace_hresult_code(E_OUTOFMEMORY));
			trace->renderer.shutdown();
			DestroyWindow(child);
			return;
		}

		ImGui::SetCurrentContext(context);

		ImGuiIO& io = ImGui::GetIO();
		io.IniFilename = nullptr;
		io.LogFilename = nullptr;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
		io.ConfigDpiScaleFonts = false;

		ImFont* const font = load_monospace_font(15.0f);

		if (font != nullptr)
		{
			io.FontDefault = font;
		}

		const bool win32_ready = ImGui_ImplWin32_Init(child);
		const bool dx11_ready = win32_ready && ImGui_ImplDX11_Init(
			trace->renderer.device(), trace->renderer.context());

		if (win32_ready == false || dx11_ready == false)
		{
			if (win32_ready != false)
			{
				ImGui_ImplWin32_Shutdown();
			}

			ImGui::DestroyContext();
			trace_report_failure(trace, trace_hresult_code(E_FAIL));
			trace->renderer.shutdown();
			DestroyWindow(child);
			return;
		}

		trace->view.set_theme(initial.theme);
		trace->view.set_dpi(initial.dpi);

		if (initial.visible != 0)
		{
			ShowWindow(child, SW_SHOWNA);
		}

		uint64_t applied_serial = serial;
		bool running = true;
		HACDBG_TRACE_SNAPSHOT snapshot = {};

		while (running && trace->stopping.load() == false)
		{
			MSG message = {};

			while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE)
			{
				if (message.message == WM_QUIT)
				{
					running = false;
					break;
				}

				TranslateMessage(&message);
				DispatchMessageW(&message);
			}

			if (running == false || trace->stopping.load() != false)
			{
				break;
			}

			trace_window_state state = current_window_state(trace, serial);

			if (serial != applied_serial)
			{
				if (state.width != trace->renderer.width() || state.height != trace->renderer.height())
				{
					SetWindowPos(child, nullptr, 0, 0, static_cast<int>(state.width),
					             static_cast<int>(state.height), SWP_NOZORDER | SWP_NOACTIVATE);

					if (trace->renderer.resize(state.width, state.height) == false)
					{
						request_device_error(trace);
						break;
					}
				}

				ShowWindow(child, state.visible != 0 ? SW_SHOWNA : SW_HIDE);
				trace->view.set_theme(state.theme);
				trace->view.set_dpi(state.dpi);
				applied_serial = serial;
			}

			if (state.visible == 0)
			{
				MsgWaitForMultipleObjectsEx(0, nullptr, 50, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
				continue;
			}

			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();

			uint64_t generation = 0;

			if (trace->view.display_paused() == false &&
			    trace->snapshots.copy_latest(snapshot, generation, trace->view.generation()) != false)
			{
				trace->view.ingest(snapshot, generation, monotonic_seconds());
			}

			trace->view.draw();
			ImGui::Render();

			if (trace->renderer.render(state.theme) == false)
			{
				request_device_error(trace);
				break;
			}
		}

		ImGui_ImplDX11_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();
		trace->renderer.shutdown();

		if (IsWindow(child) != FALSE)
		{
			DestroyWindow(child);
		}

		trace->child.store(nullptr);
	}
}

bool trace_host_start(HACDBG_TRACE* const trace)
{
	try
	{
		// The render thread creates a child of the GUI-owned host window. Do
		// not wait here: the UI thread must remain free to answer the window
		// manager messages raised while that child is created.
		trace->render_thread = std::thread(render_thread_main, trace);
	}
	catch (...)
	{
		trace->last_error.store(trace_hresult_code(E_OUTOFMEMORY));
		return false;
	}

	return true;
}

void trace_host_detach(HACDBG_TRACE* const trace)
{
	trace->stopping.store(true);

	const HWND child = trace->child.load();

	if (child != nullptr)
	{
		PostMessageW(child, trace_stop_message, 0, 0);
	}

	if (trace->render_thread.joinable() != false)
	{
		trace->render_thread.join();
	}
}
