#include "mapper.h"

#include <Windows.h>
#include <commdlg.h>
#include <string>

void mapper_set_log(void (*log)(int, const char*, void*), void* context);

namespace
{
	constexpr int IdPath = 1001;
	constexpr int IdBrowse = 1002;
	constexpr int IdFree = 1003;
	constexpr int IdIndependentPages = 1004;
	constexpr int IdCopyHeader = 1005;
	constexpr int IdPassAllocation = 1006;
	constexpr int IdMap = 1007;
	constexpr int IdLog = 1008;
	constexpr UINT WmMapLog = WM_APP + 1;
	constexpr UINT WmMapDone = WM_APP + 2;
	constexpr wchar_t kWindowClass[] = L"HacDbgMapperWindow";

	HWND g_window = nullptr;
	bool g_mapping = false;

	struct MAP_JOB
	{
		HWND Window;
		wchar_t Path[MAX_PATH];
		MAP_REQUEST Request;
	};

	void append_log(HWND window, const wchar_t* text)
	{
		const HWND log = GetDlgItem(window, IdLog);
		if (log == nullptr || text == nullptr)
		{
			return;
		}

		const int length = GetWindowTextLengthW(log);
		SendMessageW(log, EM_SETSEL, length, length);
		SendMessageW(log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text));
		SendMessageW(log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));
	}

	void append_log_utf8(HWND window, const char* text)
	{
		if (text == nullptr)
		{
			return;
		}

		wchar_t wide[1024] = {};
		MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, 1024);
		append_log(window, wide);
	}

	void window_log(int, const char* text, void* context)
	{
		if (text == nullptr || context == nullptr)
		{
			return;
		}

		const auto copy = new std::string(text);
		if (PostMessageW(static_cast<HWND>(context), WmMapLog, 0, reinterpret_cast<LPARAM>(copy)) == FALSE)
		{
			delete copy;
		}
	}

	DWORD WINAPI map_thread(LPVOID parameter)
	{
		const auto job = static_cast<MAP_JOB*>(parameter);
		mapper_set_log(window_log, job->Window);
		const std::uint8_t mapped = mapper::map_driver_file(job->Path, job->Request);
		mapper_set_log(nullptr, nullptr);
		PostMessageW(job->Window, WmMapDone, mapped, 0);
		delete job;
		return 0;
	}

	void start_map(HWND window)
	{
		if (g_mapping)
		{
			return;
		}

		wchar_t path[MAX_PATH] = {};
		GetDlgItemTextW(window, IdPath, path, MAX_PATH);
		if (path[0] == L'\0')
		{
			append_log(window, L"请选择一个驱动文件。");
			return;
		}

		auto* job = new MAP_JOB{};
		job->Window = window;
		wcsncpy_s(job->Path, path, _TRUNCATE);
		job->Request.FreeMemory = SendMessageW(GetDlgItem(window, IdFree), BM_GETCHECK, 0, 0) == BST_CHECKED;
		job->Request.IndependentPages =
			SendMessageW(GetDlgItem(window, IdIndependentPages), BM_GETCHECK, 0, 0) == BST_CHECKED;
		job->Request.CopyHeader = SendMessageW(GetDlgItem(window, IdCopyHeader), BM_GETCHECK, 0, 0) == BST_CHECKED;
		job->Request.PassAllocation =
			SendMessageW(GetDlgItem(window, IdPassAllocation), BM_GETCHECK, 0, 0) == BST_CHECKED;

		g_mapping = true;
		EnableWindow(GetDlgItem(window, IdMap), FALSE);
		append_log(window, L"开始映射。");

		const HANDLE thread = CreateThread(nullptr, 0, map_thread, job, 0, nullptr);
		if (thread == nullptr)
		{
			delete job;
			g_mapping = false;
			EnableWindow(GetDlgItem(window, IdMap), TRUE);
			append_log(window, L"无法启动映射线程。");
			return;
		}

		CloseHandle(thread);
	}

	void browse_driver(HWND window)
	{
		wchar_t path[MAX_PATH] = {};
		GetDlgItemTextW(window, IdPath, path, MAX_PATH);

		OPENFILENAMEW dialog = {};
		dialog.lStructSize = sizeof(dialog);
		dialog.hwndOwner = window;
		dialog.lpstrFilter = L"驱动文件 (*.sys)\0*.sys\0所有文件 (*.*)\0*.*\0";
		dialog.lpstrFile = path;
		dialog.nMaxFile = MAX_PATH;
		dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
		dialog.lpstrTitle = L"选择驱动";
		if (GetOpenFileNameW(&dialog) != FALSE)
		{
			SetDlgItemTextW(window, IdPath, path);
		}
	}

	HWND add_control(HWND parent, const wchar_t* class_name, const wchar_t* text, DWORD style, int x, int y, int width,
	                 int height, int id)
	{
		return CreateWindowExW(0, class_name, text, WS_CHILD | WS_VISIBLE | style, x, y, width, height, parent,
		                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
	}

	LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
	{
		switch (message)
		{
		case WM_CREATE:
			add_control(window, L"STATIC", L"驱动文件", 0, 12, 14, 64, 20, 0);
			add_control(window, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 80, 12, 470, 24, IdPath);
			add_control(window, L"BUTTON", L"浏览...", 0, 558, 12, 90, 24, IdBrowse);
			add_control(window, L"BUTTON", L"映射后释放", BS_AUTOCHECKBOX, 12, 48, 110, 22, IdFree);
			add_control(window, L"BUTTON", L"独立页", BS_AUTOCHECKBOX, 132, 48, 80, 22, IdIndependentPages);
			add_control(window, L"BUTTON", L"保留 PE 头", BS_AUTOCHECKBOX, 220, 48, 110, 22, IdCopyHeader);
			add_control(window, L"BUTTON", L"分配地址作为入口参数", BS_AUTOCHECKBOX, 340, 48, 180, 22, IdPassAllocation);
			add_control(window, L"BUTTON", L"映射驱动", 0, 12, 80, 100, 26, IdMap);
			add_control(window, L"EDIT", L"",
			            WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 12, 116, 636, 280, IdLog);
			return 0;

		case WM_COMMAND:
			if (LOWORD(wparam) == IdBrowse)
			{
				browse_driver(window);
			}
			else if (LOWORD(wparam) == IdMap)
			{
				start_map(window);
			}
			return 0;

		case WmMapLog:
		{
			const auto text = reinterpret_cast<std::string*>(lparam);
			if (text != nullptr)
			{
				append_log_utf8(window, text->c_str());
				delete text;
			}
			return 0;
		}

		case WmMapDone:
			g_mapping = false;
			EnableWindow(GetDlgItem(window, IdMap), TRUE);
			append_log(window, wparam == 0 ? L"映射失败。" : L"映射完成。");
			return 0;

		case WM_CLOSE:
			if (g_mapping)
			{
				append_log(window, L"映射尚未结束。");
				return 0;
			}
			DestroyWindow(window);
			return 0;

		case WM_DESTROY:
			g_window = nullptr;
			return 0;

		default:
			return DefWindowProcW(window, message, wparam, lparam);
		}
	}
}

extern "C" void
HacDbgMapperShow(HWND owner)
{
	if (g_window != nullptr)
	{
		ShowWindow(g_window, SW_SHOW);
		SetForegroundWindow(g_window);
		return;
	}

	WNDCLASSW window_class = {};
	window_class.lpfnWndProc = window_proc;
	window_class.hInstance = GetModuleHandleW(nullptr);
	window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	window_class.lpszClassName = kWindowClass;
	RegisterClassW(&window_class);

	g_window = CreateWindowExW(WS_EX_APPWINDOW, kWindowClass, L"驱动映射",
	                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
	                           680, 460, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
	if (g_window == nullptr)
	{
		return;
	}

	ShowWindow(g_window, SW_SHOW);
	UpdateWindow(g_window);
}
