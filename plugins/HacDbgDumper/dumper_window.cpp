#include "include/hacdbg_dumper_api.h"

#include "ProcessDumper.h"
#include "driver_um_lib.h"

#include <Windows.h>
#include <commdlg.h>

#include <atomic>
#include <stdio.h>
#include <string>

void AppendLogMessageA(const char* text);

namespace
{
	constexpr int IdPid = 1001;
	constexpr int IdThreshold = 1002;
	constexpr int IdPath = 1003;
	constexpr int IdBrowse = 1004;
	constexpr int IdConnect = 1005;
	constexpr int IdAttach = 1006;
	constexpr int IdSuspend = 1007;
	constexpr int IdResume = 1008;
	constexpr int IdStart = 1009;
	constexpr int IdStop = 1010;
	constexpr int IdStatus = 1011;
	constexpr int IdProgress = 1012;
	constexpr int IdLog = 1013;
	constexpr UINT WmLog = WM_APP + 1;
	constexpr UINT WmJobDone = WM_APP + 2;
	constexpr int JobConnect = 1;
	constexpr int JobAttach = 2;
	constexpr int JobSuspend = 3;
	constexpr int JobResume = 4;
	constexpr int JobStop = 5;
	constexpr wchar_t kWindowClass[] = L"HacDbgDumperWindow";
	constexpr int kPathChars = 1024;

	HWND g_window = nullptr;
	HWND g_log_window = nullptr;
	ProcessDumper g_dumper;
	std::atomic<bool> g_busy{false};
	std::atomic<bool> g_closing{false};
	bool g_connected = false;
	bool g_attached = false;
	bool g_monitoring = false;
	HANDLE g_worker = nullptr;
	DWORD g_pid = 0;

	struct JOB
	{
		int Kind;
		DWORD Pid;
		float Threshold;
		char Output[kPathChars];
	};

	struct JOB_RESULT
	{
		int Kind;
		int Ok;
		wchar_t Status[256];
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
		const size_t length = wcslen(wide);
		if (length > 0 && wide[length - 1] == L'\n')
		{
			wide[length - 1] = L'\0';
			if (length > 1 && wide[length - 2] == L'\r')
			{
				wide[length - 2] = L'\0';
			}
		}
		append_log(window, wide);
	}

	void set_status(HWND window, const wchar_t* text)
	{
		SetDlgItemTextW(window, IdStatus, text);
	}

	void update_buttons(HWND window)
	{
		const BOOL busy = g_busy.load() ? TRUE : FALSE;
		EnableWindow(GetDlgItem(window, IdConnect), !busy);
		EnableWindow(GetDlgItem(window, IdAttach), !busy && g_connected && !g_attached && !g_monitoring);
		EnableWindow(GetDlgItem(window, IdSuspend), !busy && g_connected);
		EnableWindow(GetDlgItem(window, IdResume), !busy && g_connected);
		EnableWindow(GetDlgItem(window, IdStart), !busy && g_attached && !g_monitoring);
		EnableWindow(GetDlgItem(window, IdStop), !busy && g_monitoring);
		EnableWindow(GetDlgItem(window, IdBrowse), !busy);
	}

	bool read_pid(HWND window, DWORD* pid)
	{
		wchar_t text[32] = {};
		GetDlgItemTextW(window, IdPid, text, 32);
		if (text[0] == L'\0')
		{
			append_log(window, L"请输入目标 PID。");
			return false;
		}

		wchar_t* end = nullptr;
		const unsigned long value = wcstoul(text, &end, 10);
		if (end == text || *end != L'\0' || value == 0 || value > 0xFFFFFFFFUL)
		{
			append_log(window, L"PID 无效。");
			return false;
		}

		*pid = static_cast<DWORD>(value);
		return true;
	}

	float read_threshold(HWND window)
	{
		wchar_t text[32] = {};
		GetDlgItemTextW(window, IdThreshold, text, 32);
		if (text[0] == L'\0')
		{
			return 1.0f;
		}

		float threshold = static_cast<float>(_wtof(text));
		if (threshold < 0.0f)
		{
			threshold = 0.0f;
		}
		if (threshold > 1.0f)
		{
			threshold = 1.0f;
		}
		return threshold;
	}

	bool wide_to_acp(const wchar_t* wide, std::string* out)
	{
		if (wide == nullptr || wide[0] == L'\0' || out == nullptr)
		{
			return false;
		}

		BOOL used_default = FALSE;
		const int bytes = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide, -1, nullptr, 0, nullptr, &used_default);
		if (bytes <= 1 || used_default != FALSE)
		{
			return false;
		}

		std::string text(static_cast<size_t>(bytes - 1), '\0');
		used_default = FALSE;
		if (WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide, -1, text.data(), bytes, nullptr, &used_default) == 0 ||
		    used_default != FALSE)
		{
			return false;
		}

		*out = text;
		return true;
	}

	bool ensure_output_path(HWND window, char* output, size_t output_chars)
	{
		wchar_t path[kPathChars] = {};
		GetDlgItemTextW(window, IdPath, path, kPathChars);
		if (path[0] == L'\0')
		{
			wchar_t exe[kPathChars] = {};
			const DWORD exe_length = GetModuleFileNameW(nullptr, exe, kPathChars);
			if (exe_length == 0 || exe_length >= kPathChars)
			{
				append_log(window, L"请选择输出文件。");
				return false;
			}

			wchar_t* slash = wcsrchr(exe, L'\\');
			if (slash != nullptr)
			{
				*(slash + 1) = L'\0';
			}
			swprintf_s(path, L"%sdumped_%lu.exe", exe, g_pid);
			SetDlgItemTextW(window, IdPath, path);
			append_log(window, L"未选择输出文件，使用程序目录下的默认名称。");
		}

		std::string narrow;
		if (!wide_to_acp(path, &narrow) || narrow.size() >= output_chars)
		{
			append_log(window, L"输出路径无法用当前代码页保存。");
			return false;
		}

		strcpy_s(output, output_chars, narrow.c_str());
		return true;
	}

	void post_result(HWND window, int kind, bool ok, const wchar_t* status)
	{
		if (g_closing.load())
		{
			return;
		}

		auto* result = new JOB_RESULT{};
		result->Kind = kind;
		result->Ok = ok ? 1 : 0;
		wcscpy_s(result->Status, status);
		if (PostMessageW(window, WmJobDone, 0, reinterpret_cast<LPARAM>(result)) == FALSE)
		{
			delete result;
		}
	}

	DWORD WINAPI job_thread(LPVOID parameter)
	{
		const auto job = static_cast<JOB*>(parameter);
		const HWND window = g_window;
		bool ok = false;
		const wchar_t* status = L"操作失败。";

		switch (job->Kind)
		{
		case JobConnect:
			ok = ioctl::init_roseware_lib();
			status = ok ? L"已连接通信驱动。" : L"未能打开 \\\\.\\PdIoctl。请先映射 ProcessIoctlDrv.sys，并勾选分配地址作为入口参数。";
			break;

		case JobAttach:
			g_dumper.SetDecryptionThreshold(job->Threshold);
			ok = g_dumper.Attach(job->Pid);
			status = ok ? L"已附加。" : L"附加失败。";
			break;

		case JobSuspend:
			ok = ioctl::suspend_process(job->Pid);
			status = ok ? L"已挂起目标进程。" : L"挂起失败。";
			break;

		case JobResume:
			ok = ioctl::resume_process(job->Pid);
			status = ok ? L"已恢复目标进程。" : L"恢复失败。";
			break;

		case JobStop:
			g_dumper.DumpCurrent();
			ok = g_dumper.Rebuild(job->Output);
			status = ok ? L"已保存转储。" : L"PE 重建失败。";
			break;

		default:
			break;
		}

		post_result(window, job->Kind, ok, status);
		delete job;
		return 0;
	}

	void start_job(HWND window, JOB* job)
	{
		if (g_busy.load() || g_worker != nullptr)
		{
			delete job;
			return;
		}

		g_busy.store(true);
		update_buttons(window);
		const HANDLE thread = CreateThread(nullptr, 0, job_thread, job, 0, nullptr);
		if (thread == nullptr)
		{
			delete job;
			g_busy.store(false);
			update_buttons(window);
			append_log(window, L"无法启动工作线程。");
			return;
		}

		g_worker = thread;
	}

	void browse_output(HWND window)
	{
		wchar_t path[kPathChars] = {};
		GetDlgItemTextW(window, IdPath, path, kPathChars);

		OPENFILENAMEW dialog = {};
		dialog.lStructSize = sizeof(dialog);
		dialog.hwndOwner = window;
		dialog.lpstrFilter = L"可执行文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0";
		dialog.lpstrFile = path;
		dialog.nMaxFile = kPathChars;
		dialog.Flags = OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
		dialog.lpstrTitle = L"选择转储输出";
		dialog.lpstrDefExt = L"exe";
		if (GetSaveFileNameW(&dialog) != FALSE)
		{
			SetDlgItemTextW(window, IdPath, path);
		}
	}

	void start_connect(HWND window)
	{
		append_log(window, L"正在连接 \\\\.\\PdIoctl。");
		auto* job = new JOB{};
		job->Kind = JobConnect;
		start_job(window, job);
	}

	void start_attach(HWND window)
	{
		DWORD pid = 0;
		if (!read_pid(window, &pid))
		{
			return;
		}

		g_pid = pid;
		auto* job = new JOB{};
		job->Kind = JobAttach;
		job->Pid = pid;
		job->Threshold = read_threshold(window);
		append_log(window, L"正在附加。");
		start_job(window, job);
	}

	void start_process_state(HWND window, bool suspend)
	{
		DWORD pid = 0;
		if (!read_pid(window, &pid))
		{
			return;
		}

		auto* job = new JOB{};
		job->Kind = suspend ? JobSuspend : JobResume;
		job->Pid = pid;
		start_job(window, job);
	}

	void start_monitor(HWND window)
	{
		if (!g_attached || g_monitoring)
		{
			return;
		}

		if (!g_dumper.StartMonitoring())
		{
			set_status(window, L"状态：监控启动失败");
			append_log(window, L"监控启动失败。");
			return;
		}

		g_monitoring = true;
		set_status(window, L"状态：正在监控");
		SetTimer(window, 1, 200, nullptr);
		update_buttons(window);
	}

	void start_stop(HWND window)
	{
		if (!g_monitoring)
		{
			return;
		}

		char output[kPathChars] = {};
		if (!ensure_output_path(window, output, kPathChars))
		{
			return;
		}

		KillTimer(window, 1);
		auto* job = new JOB{};
		job->Kind = JobStop;
		strcpy_s(job->Output, output);
		append_log(window, L"正在停止监控并重建 PE。");
		start_job(window, job);
	}

	void refresh_progress(HWND window)
	{
		const float progress = g_dumper.GetDecryptionProgress();
		wchar_t text[160] = {};
		swprintf_s(text, L"已解密 %llu / %llu 页 (%.1f%%)", g_dumper.GetDecryptedCount(), g_dumper.GetTotalPages(),
		           progress * 100.0f);
		SetDlgItemTextW(window, IdProgress, text);
		set_status(window, text);

		if (!g_dumper.IsMonitoring())
		{
			KillTimer(window, 1);
			append_log(window, L"监控已结束。可以停止并保存。");
			return;
		}

		const float threshold = read_threshold(window);
		if (threshold < 1.0f && progress >= threshold)
		{
			append_log(window, L"解密进度达到阈值，开始保存。");
			start_stop(window);
		}
	}

	void finish_job(HWND window, const JOB_RESULT* result)
	{
		if (g_worker != nullptr)
		{
			CloseHandle(g_worker);
			g_worker = nullptr;
		}

		g_busy.store(false);
		set_status(window, result->Status);
		append_log(window, result->Status);

		switch (result->Kind)
		{
		case JobConnect:
			g_connected = result->Ok != 0;
			break;

		case JobAttach:
			g_attached = result->Ok != 0;
			if (g_attached)
			{
				wchar_t text[160] = {};
				swprintf_s(text, L"映像 0x%llX，大小 0x%llX", g_dumper.GetImageBase(), g_dumper.GetImageSize());
				append_log(window, text);
			}
			break;

		case JobStop:
			g_monitoring = false;
			g_attached = false;
			SetDlgItemTextW(window, IdProgress, L"");
			break;

		default:
			break;
		}

		update_buttons(window);
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
			g_log_window = window;
			add_control(window, L"STATIC", L"PID", 0, 12, 16, 32, 20, 0);
			add_control(window, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 48, 12, 110, 24, IdPid);
			add_control(window, L"STATIC", L"阈值", 0, 172, 16, 36, 20, 0);
			add_control(window, L"EDIT", L"1.0", WS_BORDER | ES_AUTOHSCROLL, 212, 12, 70, 24, IdThreshold);
			add_control(window, L"STATIC", L"输出", 0, 12, 48, 36, 20, 0);
			add_control(window, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 48, 44, 560, 24, IdPath);
			add_control(window, L"BUTTON", L"浏览...", 0, 616, 44, 90, 24, IdBrowse);
			add_control(window, L"BUTTON", L"连接驱动", 0, 12, 80, 90, 26, IdConnect);
			add_control(window, L"BUTTON", L"附加", 0, 110, 80, 70, 26, IdAttach);
			add_control(window, L"BUTTON", L"挂起", 0, 188, 80, 70, 26, IdSuspend);
			add_control(window, L"BUTTON", L"恢复", 0, 266, 80, 70, 26, IdResume);
			add_control(window, L"BUTTON", L"开始监控", 0, 344, 80, 90, 26, IdStart);
			add_control(window, L"BUTTON", L"停止并保存", 0, 442, 80, 110, 26, IdStop);
			add_control(window, L"STATIC", L"状态：通信驱动未连接", 0, 12, 116, 500, 20, IdStatus);
			add_control(window, L"STATIC", L"", 0, 12, 140, 690, 20, IdProgress);
			add_control(window, L"EDIT", L"", WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 12, 168,
			            710, 300, IdLog);
			update_buttons(window);
			append_log(window, L"进程转储不会自动附加。先映射 ProcessIoctlDrv.sys，勾选分配地址作为入口参数，再连接驱动。");
			return 0;

		case WM_COMMAND:
			if (g_busy.load())
			{
				return 0;
			}
			switch (LOWORD(wparam))
			{
			case IdBrowse:
				browse_output(window);
				break;
			case IdConnect:
				start_connect(window);
				break;
			case IdAttach:
				start_attach(window);
				break;
			case IdSuspend:
				start_process_state(window, true);
				break;
			case IdResume:
				start_process_state(window, false);
				break;
			case IdStart:
				start_monitor(window);
				break;
			case IdStop:
				start_stop(window);
				break;
			default:
				break;
			}
			return 0;

		case WM_TIMER:
			if (wparam == 1 && !g_busy.load())
			{
				refresh_progress(window);
			}
			return 0;

		case WmLog:
		{
			const auto text = reinterpret_cast<std::string*>(lparam);
			if (text != nullptr)
			{
				append_log_utf8(window, text->c_str());
				delete text;
			}
			return 0;
		}

		case WmJobDone:
		{
			const auto result = reinterpret_cast<JOB_RESULT*>(lparam);
			if (result != nullptr)
			{
				finish_job(window, result);
				delete result;
			}
			return 0;
		}

		case WM_CLOSE:
			if (g_busy.load())
			{
				append_log(window, L"操作尚未结束。");
				return 0;
			}
			if (g_monitoring)
			{
				append_log(window, L"请先停止并保存。");
				return 0;
			}
			DestroyWindow(window);
			return 0;

		case WM_DESTROY:
			g_closing.store(true);
			g_log_window = nullptr;
			KillTimer(window, 1);
			if (g_worker != nullptr)
			{
				WaitForSingleObject(g_worker, INFINITE);
				CloseHandle(g_worker);
				g_worker = nullptr;
			}
			g_dumper.DumpCurrent();
			g_monitoring = false;
			g_window = nullptr;
			return 0;

		default:
			return DefWindowProcW(window, message, wparam, lparam);
		}
	}
}

void AppendLogMessageA(const char* text)
{
	if (text == nullptr || g_log_window == nullptr || g_closing.load())
	{
		return;
	}

	auto* copy = new std::string(text);
	if (PostMessageW(g_log_window, WmLog, 0, reinterpret_cast<LPARAM>(copy)) == FALSE)
	{
		delete copy;
	}
}

extern "C" void
HacDbgDumperShow(HWND owner)
{
	if (g_window != nullptr)
	{
		ShowWindow(g_window, SW_SHOW);
		SetForegroundWindow(g_window);
		return;
	}

	g_closing.store(false);
	WNDCLASSW window_class = {};
	window_class.lpfnWndProc = window_proc;
	window_class.hInstance = GetModuleHandleW(nullptr);
	window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	window_class.lpszClassName = kWindowClass;
	RegisterClassW(&window_class);

	g_window = CreateWindowExW(WS_EX_APPWINDOW, kWindowClass, L"进程转储",
	                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
	                           760, 540, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
	if (g_window == nullptr)
	{
		return;
	}

	ShowWindow(g_window, SW_SHOW);
	UpdateWindow(g_window);
}
