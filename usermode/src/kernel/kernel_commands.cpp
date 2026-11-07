#include "kernel_commands.h"

#include "kernel_channel.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <cctype>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "../logs/logs.h"
#include "../hypercall/hypercall.h"

namespace
{
std::uint8_t same_text(const std::string_view left, const std::string_view right)
{
	if (left.size() != right.size())
	{
		return 0;
	}

	for (std::size_t index = 0; index < left.size(); ++index)
	{
		if (std::tolower(static_cast<unsigned char>(left[index])) !=
		    std::tolower(static_cast<unsigned char>(right[index])))
		{
			return 0;
		}
	}

	return 1;
}

std::string_view skip_space(std::string_view text)
{
	while (text.empty() == false && (text.front() == ' ' || text.front() == '\t'))
	{
		text.remove_prefix(1);
	}

	return text;
}

std::uint8_t take_token(std::string_view& text, std::string& token_out)
{
	text = skip_space(text);

	if (text.empty() == true)
	{
		return 0;
	}

	const std::size_t end = text.find_first_of(" \t");

	token_out = std::string(text.substr(0, end));
	text = end == std::string_view::npos ? std::string_view() : text.substr(end);

	return 1;
}

std::uint8_t parse_pid(const std::string& text, std::uint32_t& pid_out, const std::uint8_t allow_zero = 0)
{
	char* end = nullptr;
	const int base = text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X') ? 16 : 10;
	const char* const start = base == 16 ? text.c_str() + 2 : text.c_str();
	const unsigned long value = std::strtoul(start, &end, base);

	if (end == start || *end != '\0' || (allow_zero == 0 && value == 0) || value > 0xFFFFFFFFul)
	{
		return 0;
	}

	pid_out = static_cast<std::uint32_t>(value);

	return 1;
}

void print_status(const char* const action, const bool ok, const std::int32_t status)
{
	if (ok == true && status >= 0)
	{
		output::print("{} ok\n", action);
	}
	else
	{
		output::print("err, {} failed: 0x{:08x}\n", action, static_cast<std::uint32_t>(status));
	}

	output::flush();
}

std::uint8_t enable_debug_privilege()
{
	HANDLE token = nullptr;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == FALSE)
	{
		return 0;
	}

	TOKEN_PRIVILEGES privileges = {};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &privileges.Privileges[0].Luid) == FALSE)
	{
		CloseHandle(token);

		return 0;
	}

	AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
	const DWORD error = GetLastError();

	CloseHandle(token);

	return error == ERROR_SUCCESS ? 1 : 0;
}

std::uint8_t user_end_process(const std::uint32_t pid, std::int32_t& status_out)
{
	enable_debug_privilege();

	const HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

	if (process == nullptr)
	{
		status_out = static_cast<std::int32_t>(GetLastError());

		return 0;
	}

	const BOOL ended = TerminateProcess(process, 1);

	status_out = ended != FALSE ? 0 : static_cast<std::int32_t>(GetLastError());
	CloseHandle(process);

	return ended != FALSE ? 1 : 0;
}

std::uint8_t user_force_process(const std::uint32_t pid, std::int32_t& status_out)
{
	if (user_end_process(pid, status_out) == 1)
	{
		return 1;
	}

	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(entry);

	if (Thread32First(snapshot, &entry) != FALSE)
	{
		do
		{
			if (entry.th32OwnerProcessID != pid)
			{
				continue;
			}

			const HANDLE thread = OpenThread(THREAD_TERMINATE, FALSE, entry.th32ThreadID);

			if (thread != nullptr)
			{
				TerminateThread(thread, 1);
				CloseHandle(thread);
			}
		} while (Thread32Next(snapshot, &entry) != FALSE);
	}

	CloseHandle(snapshot);

	return user_end_process(pid, status_out);
}

std::uint8_t user_suspend_process(const std::uint32_t pid, const std::uint8_t resume, std::int32_t& status_out)
{
	using nt_process_t = long(__stdcall*)(HANDLE process);
	const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	const auto routine = ntdll == nullptr
		                     ? nullptr
		                     : reinterpret_cast<nt_process_t>(
		                           GetProcAddress(ntdll, resume != 0 ? "NtResumeProcess" : "NtSuspendProcess"));

	if (routine == nullptr)
	{
		status_out = static_cast<std::int32_t>(ERROR_PROC_NOT_FOUND);

		return 0;
	}

	enable_debug_privilege();

	const HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);

	if (process == nullptr)
	{
		status_out = static_cast<std::int32_t>(GetLastError());

		return 0;
	}

	status_out = routine(process);
	CloseHandle(process);

	return status_out >= 0 ? 1 : 0;
}

std::wstring widen_path(const std::string& text)
{
	if (text.empty() == true)
	{
		return {};
	}

	const int chars = MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, nullptr, 0);

	if (chars <= 0)
	{
		return {};
	}

	std::wstring wide(static_cast<std::size_t>(chars), L'\0');
	MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, wide.data(), chars);

	if (wide.empty() == false && wide.back() == L'\0')
	{
		wide.pop_back();
	}

	return wide;
}

void report_process(const char* const action, const bool sent, const HACDBG_PROCESS_REQUEST& request)
{
	print_status(action, sent, sent == true ? request.Status : static_cast<std::int32_t>(0xC0000225));
}

std::uint8_t command_kill(std::string_view body, const std::uint32_t operation, const char* const action,
                          const std::uint8_t user_force)
{
	std::string pid_text = {};
	std::string extra = {};
	std::uint32_t pid = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HACDBG_PROCESS_REQUEST request = {};
	const bool sent = kernel_process_request(operation, pid, 0, 0, nullptr, request);

	if (sent == true && request.Status >= 0)
	{
		print_status(action, true, 0);

		return 1;
	}

	if (user_force != 0)
	{
		std::int32_t status = 0;

		print_status(action, user_force_process(pid, status) == 1, status);

		return 1;
	}

	report_process(action, sent, request);

	return 1;
}

std::uint8_t command_state(std::string_view body, const std::uint8_t resume)
{
	std::string pid_text = {};
	std::string extra = {};
	std::uint32_t pid = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HACDBG_PROCESS_REQUEST request = {};
	const bool sent = kernel_process_request(resume != 0 ? HACDBG_PROCESS_RESUME : HACDBG_PROCESS_SUSPEND, pid, 0, 0,
	                                        nullptr, request);

	if (sent == true && request.Status >= 0)
	{
		print_status(resume != 0 ? "resume" : "suspend", true, 0);

		return 1;
	}

	std::int32_t status = 0;

	print_status(resume != 0 ? "resume" : "suspend", user_suspend_process(pid, resume, status) == 1, status);

	return 1;
}

std::uint8_t command_one_pid(std::string_view body, const std::uint32_t operation, const std::uint32_t parameter,
                             const char* const action)
{
	std::string pid_text = {};
	std::string extra = {};
	std::uint32_t pid = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HACDBG_PROCESS_REQUEST request = {};
	const bool sent = kernel_process_request(operation, pid, parameter, 0, nullptr, request);

	report_process(action, sent, request);

	return 1;
}

std::uint8_t ppl_value(const std::string& text, std::uint32_t& value_out)
{
	if (same_text(text, "none") == 1)
	{
		value_out = HACDBG_PPL_NONE;
	}
	else if (same_text(text, "am") == 1)
	{
		value_out = HACDBG_PPL_ANTIMALWARE;
	}
	else if (same_text(text, "windows") == 1)
	{
		value_out = HACDBG_PPL_WINDOWS;
	}
	else if (same_text(text, "light") == 1)
	{
		value_out = HACDBG_PPL_WINTCB_LIGHT;
	}
	else if (same_text(text, "tcb") == 1)
	{
		value_out = HACDBG_PPL_WINTCB;
	}
	else
	{
		return 0;
	}

	return 1;
}

std::uint8_t command_ppl(std::string_view body)
{
	std::string pid_text = {};
	std::string level = {};
	std::string extra = {};
	std::uint32_t pid = 0;
	std::uint32_t level_value = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, level) == 0 ||
	    ppl_value(level, level_value) == 0 || take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HACDBG_PROCESS_REQUEST request = {};
	const bool sent = kernel_process_request(HACDBG_PROCESS_SET_PPL, pid, level_value, 0, nullptr, request);

	report_process("ppl", sent, request);

	return 1;
}

std::uint8_t command_handle(std::string_view body)
{
	std::string pid_text = {};
	std::string mode = {};
	std::uint32_t pid = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, mode) == 0)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	std::uint32_t parameter = 0;
	std::wstring actor = {};
	std::wstring victim = {};

	if (same_text(mode, "stop") == 1)
	{
		std::string extra = {};

		if (take_token(body, extra) == 1)
		{
			LOG_ERR("invalid syntax");

			return 1;
		}

		parameter = HACDBG_HANDLE_STOP;
	}
	else if (same_text(mode, "down") == 1 || same_text(mode, "up") == 1)
	{
		std::string actor_text = {};
		std::string victim_text = {};
		const std::uint8_t upgrade = same_text(mode, "up");

		if (take_token(body, actor_text) == 0)
		{
			LOG_ERR("invalid syntax");

			return 1;
		}

		if (same_text(actor_text, "all") == 1)
		{
			std::string name = {};
			std::string extra = {};

			if (take_token(body, name) == 0 || take_token(body, extra) == 1)
			{
				LOG_ERR("invalid syntax");

				return 1;
			}

			parameter = upgrade != 0 ? HACDBG_HANDLE_UPGRADE_ALL : HACDBG_HANDLE_DOWNGRADE_ALL;
			actor = widen_path(name);
		}
		else
		{
			if (take_token(body, victim_text) == 0)
			{
				LOG_ERR("invalid syntax");

				return 1;
			}

			parameter = upgrade != 0 ? HACDBG_HANDLE_UPGRADE_NAME : HACDBG_HANDLE_DOWNGRADE_NAME;
			actor = widen_path(actor_text);
			victim = widen_path(victim_text);
		}
	}
	else
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HACDBG_PROCESS_REQUEST request = {};
	request.Operation = HACDBG_PROCESS_HANDLE_PROTECT;
	request.Pid = pid;
	request.Parameter = parameter;

	if (actor.empty() == false)
	{
		wcsncpy_s(reinterpret_cast<wchar_t*>(request.Path), HACDBG_HANDLE_NAME_CHARS, actor.c_str(), _TRUNCATE);
	}

	if (victim.empty() == false)
	{
		wcsncpy_s(reinterpret_cast<wchar_t*>(request.Path) + HACDBG_HANDLE_NAME_CHARS, HACDBG_HANDLE_NAME_CHARS,
		          victim.c_str(), _TRUNCATE);
	}

	const bool sent = kernel_send_process(request);

	report_process("handle", sent, request);

	return 1;
}

std::uint8_t command_inject(std::string_view body)
{
	std::string pid_text = {};
	std::string path_text = {};
	std::uint32_t pid = 0;
	std::uint32_t flags = 0;
	std::uint8_t pte = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, path_text) == 0)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	std::string option = {};

	while (take_token(body, option) == 1)
	{
		if (same_text(option, "pte") == 1)
		{
			pte = 1;
		}
		else if (same_text(option, "poison") == 1)
		{
			flags |= HACDBG_PROCESS_FLAG_POISON;
		}
		else
		{
			LOG_ERR("invalid syntax");

			return 1;
		}
	}

	if ((flags & HACDBG_PROCESS_FLAG_POISON) != 0 && pte == 0)
	{
		LOG_ERR("poison requires pte");

		return 1;
	}

	const std::wstring path = widen_path(path_text);
	HACDBG_PROCESS_REQUEST request = {};
	const bool sent = kernel_process_request(pte != 0 ? HACDBG_PROCESS_INJECT_PTE : HACDBG_PROCESS_INJECT_APC, pid, 0,
	                                        flags, path.c_str(), request);

	report_process("inject", sent, request);

	return 1;
}

std::uint8_t command_image(std::string_view body)
{
	std::string pid_text = {};
	std::string extra = {};
	std::uint32_t pid = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HACDBG_PROCESS_REQUEST request = {};
	const bool sent = kernel_process_request(HACDBG_PROCESS_QUERY_IMAGE, pid, 0, 0, nullptr, request);

	if (sent == false || request.Status < 0)
	{
		report_process("image", sent, request);

		return 1;
	}

	char narrow[HACDBG_PROCESS_PATH_CHARS * 2] = {};

	WideCharToMultiByte(CP_ACP, 0, reinterpret_cast<const wchar_t*>(request.Path), -1, narrow, sizeof(narrow), nullptr,
	                    nullptr);
	output::print("{}\n", narrow);
	output::flush();

	return 1;
}

#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

using set_affinity_t = BOOL(__stdcall*)(HWND window, DWORD affinity);
using get_affinity_t = BOOL(__stdcall*)(HWND window, DWORD* affinity);

set_affinity_t set_affinity()
{
	const HMODULE user32 = GetModuleHandleW(L"user32.dll");

	if (user32 == nullptr)
	{
		return nullptr;
	}

	return reinterpret_cast<set_affinity_t>(GetProcAddress(user32, "SetWindowDisplayAffinity"));
}

get_affinity_t get_affinity()
{
	const HMODULE user32 = GetModuleHandleW(L"user32.dll");

	if (user32 == nullptr)
	{
		return nullptr;
	}

	return reinterpret_cast<get_affinity_t>(GetProcAddress(user32, "GetWindowDisplayAffinity"));
}

std::uint8_t query_affinity(const HWND window, DWORD& affinity_out)
{
	const get_affinity_t query = get_affinity();
	DWORD value = WDA_NONE;

	if (window == nullptr || query == nullptr || query(window, &value) == FALSE)
	{
		return 0;
	}

	affinity_out = value;

	return 1;
}

void prepare_window(const HWND window)
{
	if (IsWindow(window) == FALSE)
	{
		return;
	}

	const LONG extra = GetWindowLongW(window, GWL_EXSTYLE);

	if ((extra & WS_EX_LAYERED) != 0)
	{
		SetLayeredWindowAttributes(window, 0, 255, LWA_ALPHA);
	}
}

std::uint8_t try_set_affinity(const HWND window, const DWORD affinity)
{
	const set_affinity_t set = set_affinity();

	if (set == nullptr)
	{
		return 0;
	}

	prepare_window(window);

	if (set(window, affinity) != FALSE)
	{
		return 1;
	}

	if (affinity != WDA_EXCLUDEFROMCAPTURE)
	{
		return 0;
	}

	set(window, WDA_MONITOR);

	if (set(window, WDA_EXCLUDEFROMCAPTURE) != FALSE)
	{
		return 1;
	}

	Sleep(0);
	prepare_window(window);

	return set(window, affinity) != FALSE ? 1 : 0;
}

std::uint8_t allow_caller(const std::uint32_t pid)
{
	HACDBG_WINDOW_REQUEST request = {};

	request.Operation = HACDBG_WINDOW_ALLOW;
	request.CalibratePid = pid;

	if (kernel_window_request(request) == false || request.Status < 0)
	{
		return 0;
	}

	return 1;
}

std::uint8_t syscall_number(DWORD& number_out)
{
	HMODULE module = GetModuleHandleW(L"win32u.dll");
	const unsigned char* stub = nullptr;

	if (module == nullptr)
	{
		module = LoadLibraryW(L"win32u.dll");
	}

	if (module == nullptr)
	{
		return 0;
	}

	stub = reinterpret_cast<const unsigned char*>(GetProcAddress(module, "NtUserSetWindowDisplayAffinity"));

	if (stub == nullptr || stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8)
	{
		return 0;
	}

	std::memcpy(&number_out, stub + 4, sizeof(number_out));

	return 1;
}

void mark_call_target(const HANDLE process, void* const address, const SIZE_T size)
{
	using set_vm_t = long(__stdcall*)(HANDLE process, unsigned long kind, std::uintptr_t count, void* ranges,
	                                  void* target, unsigned long target_bytes);
	struct range_t
	{
		void* address;
		SIZE_T bytes;
	};
	struct target_t
	{
		std::uintptr_t offset;
		std::uintptr_t flags;
	};
	const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	const auto set_vm = ntdll == nullptr ? nullptr
	                                     : reinterpret_cast<set_vm_t>(GetProcAddress(ntdll, "NtSetInformationVirtualMemory"));
	range_t range = {address, size};
	target_t target = {0, 1};

	if (set_vm == nullptr)
	{
		return;
	}

	set_vm(process, 2, 1, &range, &target, sizeof(target));
}

void release_remote(const HANDLE process, void* const remote, const HANDLE thread)
{
	if (thread != nullptr)
	{
		CloseHandle(thread);
	}

	if (remote != nullptr && process != nullptr)
	{
		VirtualFreeEx(process, remote, 0, MEM_RELEASE);
	}

	if (process != nullptr)
	{
		CloseHandle(process);
	}
}

std::uint8_t run_in_process(const DWORD pid, const HWND window, const DWORD affinity)
{
	HANDLE process = nullptr;
	void* remote = nullptr;
	HANDLE thread = nullptr;
	DWORD syscall = 0;
	DWORD exit_code = 0;
	BOOL wow64 = FALSE;
	unsigned char code[32] = {};
	std::size_t length = 0;
	const auto hwnd = static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(window));
	std::uint8_t allowed = 0;

	if (pid == 0 || pid == 4 || syscall_number(syscall) == 0)
	{
		return 0;
	}

	process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
	                          PROCESS_VM_READ,
	                      FALSE, pid);

	if (process == nullptr)
	{
		return 0;
	}

	if (IsWow64Process(process, &wow64) == FALSE || wow64 != FALSE)
	{
		release_remote(process, nullptr, nullptr);

		return 0;
	}

	code[length++] = 0x48;
	code[length++] = 0xB9;
	std::memcpy(code + length, &hwnd, sizeof(hwnd));
	length += sizeof(hwnd);
	code[length++] = 0xBA;
	std::memcpy(code + length, &affinity, sizeof(affinity));
	length += sizeof(affinity);
	code[length++] = 0x4C;
	code[length++] = 0x8B;
	code[length++] = 0xD1;
	code[length++] = 0xB8;
	std::memcpy(code + length, &syscall, sizeof(syscall));
	length += sizeof(syscall);
	code[length++] = 0x0F;
	code[length++] = 0x05;
	code[length++] = 0xC3;

	remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (remote == nullptr || WriteProcessMemory(process, remote, code, length, nullptr) == FALSE)
	{
		release_remote(process, remote, nullptr);

		return 0;
	}

	FlushInstructionCache(process, remote, length);
	mark_call_target(process, remote, 0x1000);
	allowed = allow_caller(pid);
	thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote), nullptr, 0,
	                            nullptr);

	if (thread == nullptr)
	{
		if (allowed != 0)
		{
			allow_caller(0);
		}

		release_remote(process, remote, nullptr);

		return 0;
	}

	if (WaitForSingleObject(thread, 3000) != WAIT_OBJECT_0 || GetExitCodeThread(thread, &exit_code) == FALSE ||
	    exit_code == STILL_ACTIVE)
	{
		if (allowed != 0)
		{
			allow_caller(0);
		}

		CloseHandle(thread);
		CloseHandle(process);

		return 0;
	}

	if (allowed != 0)
	{
		allow_caller(0);
	}

	release_remote(process, remote, thread);

	return exit_code == 0 ? 0 : 1;
}

std::uint8_t set_one_window(const HWND window, const std::uint8_t enable)
{
	const DWORD target = enable != 0 ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;
	DWORD current = WDA_NONE;
	DWORD pid = 0;

	if (window == nullptr || IsWindow(window) == FALSE)
	{
		return 0;
	}

	if (query_affinity(window, current) == 1 && current == target)
	{
		return 1;
	}

	GetWindowThreadProcessId(window, &pid);

	if (pid != 0 && pid != GetCurrentProcessId())
	{
		if (enable == 0)
		{
			return run_in_process(pid, window, WDA_NONE);
		}

		if (run_in_process(pid, window, WDA_EXCLUDEFROMCAPTURE) == 1)
		{
			return 1;
		}

		run_in_process(pid, window, WDA_MONITOR);

		return run_in_process(pid, window, WDA_EXCLUDEFROMCAPTURE);
	}

	return try_set_affinity(window, target);
}

struct window_edit_t
{
	std::uint32_t pid;
	std::uint8_t enable;
	int changed;
};

BOOL __stdcall edit_window(const HWND window, const LPARAM parameter)
{
	auto* const state = reinterpret_cast<window_edit_t*>(parameter);
	DWORD pid = 0;

	GetWindowThreadProcessId(window, &pid);

	if (pid == state->pid && set_one_window(window, state->enable) == 1)
	{
		state->changed += 1;
	}

	return TRUE;
}

int edit_pid_windows(const std::uint32_t pid, const std::uint8_t enable)
{
	window_edit_t state = {pid, enable, 0};

	EnumWindows(edit_window, reinterpret_cast<LPARAM>(&state));

	return state.changed;
}

struct listed_window_t
{
	unsigned long long hwnd;
	std::uint32_t pid;
	unsigned long affinity;
	std::uint8_t known;
	std::wstring title;
};

struct window_list_t
{
	std::vector<listed_window_t>* rows;
};

BOOL __stdcall collect_window(const HWND window, const LPARAM parameter)
{
	auto* const state = reinterpret_cast<window_list_t*>(parameter);
	listed_window_t row = {};
	wchar_t title[256] = {};
	DWORD pid = 0;
	DWORD affinity = WDA_NONE;

	GetWindowThreadProcessId(window, &pid);
	GetWindowTextW(window, title, static_cast<int>(sizeof(title) / sizeof(title[0])));
	row.hwnd = static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(window));
	row.pid = pid;
	row.known = query_affinity(window, affinity);
	row.affinity = affinity;
	row.title = title;
	state->rows->push_back(std::move(row));

	return TRUE;
}

void list_windows()
{
	std::vector<listed_window_t> rows;
	window_list_t state = {&rows};

	EnumWindows(collect_window, reinterpret_cast<LPARAM>(&state));
	output::print("window list count={}\n", rows.size());

	for (const listed_window_t& row : rows)
	{
		char title[512] = {};

		WideCharToMultiByte(CP_ACP, 0, row.title.c_str(), -1, title, static_cast<int>(sizeof(title)), nullptr, nullptr);

		if (row.known != 0)
		{
			output::print("  hwnd={:x} pid={} affinity={:x} {}\n", row.hwnd, row.pid, row.affinity, title);
		}
		else
		{
			output::print("  hwnd={:x} pid={} affinity=- {}\n", row.hwnd, row.pid, title);
		}
	}

	output::flush();
}

std::uint32_t find_dwm_pid()
{
	const HWND window = FindWindowW(L"Dwm", L"DWM Notification Window");
	DWORD pid = 0;

	if (window == nullptr)
	{
		return 0;
	}

	GetWindowThreadProcessId(window, &pid);

	return pid;
}

struct affinity_sample_t
{
	HWND window;
	DWORD pid;
};

BOOL __stdcall find_excluded(const HWND window, const LPARAM parameter)
{
	auto* const sample = reinterpret_cast<affinity_sample_t*>(parameter);
	DWORD affinity = WDA_NONE;
	DWORD pid = 0;

	if (query_affinity(window, affinity) == 1 && affinity == WDA_EXCLUDEFROMCAPTURE)
	{
		GetWindowThreadProcessId(window, &pid);
		sample->window = window;
		sample->pid = pid;

		return FALSE;
	}

	return TRUE;
}

void print_window_result(const HACDBG_WINDOW_REQUEST& request)
{
	output::print("window ok armed={} owner={} dwm={} rows={}\n", request.HookArmed, request.OwnerPid, request.DwmPid,
	              request.RowCount);

	for (unsigned int index = 0; index < request.RowCount && index < HACDBG_WINDOW_MAX_ROWS; ++index)
	{
		output::print("  pid={} hwnd={:x}\n", request.Rows[index].Pid, request.Rows[index].Hwnd);
	}

	output::flush();
}

std::uint8_t command_window(std::string_view body)
{
	std::string action = {};

	if (take_token(body, action) == 0)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	if (same_text(action, "list") == 1)
	{
		std::string extra = {};

		if (take_token(body, extra) == 1)
		{
			LOG_ERR("invalid syntax");

			return 1;
		}

		list_windows();

		return 1;
	}

	if (same_text(action, "protect") == 1 || same_text(action, "clear") == 1)
	{
		std::string pid_text = {};
		std::string extra = {};
		std::uint32_t pid = 0;
		const std::uint8_t enable = same_text(action, "protect");

		if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, extra) == 1)
		{
			LOG_ERR("invalid syntax");

			return 1;
		}

		const int changed = edit_pid_windows(pid, enable);

		if (enable != 0)
		{
			HACDBG_WINDOW_REQUEST request = {};

			request.Operation = HACDBG_WINDOW_ARM;
			const bool armed = kernel_window_request(request);

			if (armed == false || request.Status < 0)
			{
				const std::uint32_t status = armed == false ? 0xC0000225u : static_cast<std::uint32_t>(request.Status);

				output::print("err, window protect changed={} arm=0x{:08x}\n", changed, status);
				output::flush();

				return 1;
			}

			output::print("window protect changed={} armed={}\n", changed, request.HookArmed);
			output::flush();

			return 1;
		}

		output::print("window clear changed={}\n", changed);
		output::flush();

		return 1;
	}

	HACDBG_WINDOW_REQUEST request = {};
	std::uint8_t scanning = 0;

	if (same_text(action, "query") == 1)
	{
		request.Operation = HACDBG_WINDOW_QUERY;
	}
	else if (same_text(action, "arm") == 1)
	{
		request.Operation = HACDBG_WINDOW_ARM;
	}
	else if (same_text(action, "disarm") == 1)
	{
		request.Operation = HACDBG_WINDOW_DISARM;
	}
	else if (same_text(action, "scan") == 1)
	{
		std::string flag = {};

		request.Operation = HACDBG_WINDOW_SCAN;
		scanning = 1;

		if (take_token(body, flag) == 1)
		{
			if (same_text(flag, "recal") == 0)
			{
				LOG_ERR("invalid syntax");

				return 1;
			}

			request.Flags = HACDBG_WINDOW_FLAG_RECALIBRATE;
		}
	}
	else if (same_text(action, "allow") == 1)
	{
		std::string pid_text = {};
		std::uint32_t pid = 0;

		if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid, 1) == 0)
		{
			LOG_ERR("invalid syntax");

			return 1;
		}

		request.Operation = HACDBG_WINDOW_ALLOW;
		request.CalibratePid = pid;
	}
	else
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	std::string extra = {};

	if (take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	HWND sample = nullptr;
	DWORD sample_previous = WDA_NONE;
	std::uint8_t restore_sample = 0;

	if (scanning != 0)
	{
		affinity_sample_t excluded = {};

		request.DwmPid = find_dwm_pid();

		if (request.DwmPid == 0 || request.DwmPid == 4)
		{
			output::print("err, window scan did not find dwm\n");
			output::flush();

			return 1;
		}

		EnumWindows(find_excluded, reinterpret_cast<LPARAM>(&excluded));

		if (excluded.window != nullptr)
		{
			request.CalibrateHwnd = static_cast<unsigned int>(reinterpret_cast<std::uintptr_t>(excluded.window));
			request.CalibratePid = excluded.pid;
		}
		else
		{
			sample = GetConsoleWindow();

			if (sample != nullptr)
			{
				query_affinity(sample, sample_previous);

				if (sample_previous != WDA_EXCLUDEFROMCAPTURE && try_set_affinity(sample, WDA_EXCLUDEFROMCAPTURE) == 1)
				{
					restore_sample = 1;
				}

				request.CalibrateHwnd = static_cast<unsigned int>(reinterpret_cast<std::uintptr_t>(sample));
				request.CalibratePid = GetCurrentProcessId();
			}
		}

		Sleep(50);
	}

	const bool sent = kernel_window_request(request);

	if (restore_sample != 0 && sample != nullptr)
	{
		try_set_affinity(sample, sample_previous);
	}

	if (sent == false)
	{
		output::print("err, window failed: 0x{:08x}\n", 0xC0000225u);
		output::flush();

		return 1;
	}

	if (request.Status < 0)
	{
		output::print("err, window failed: 0x{:08x}\n", static_cast<std::uint32_t>(request.Status));
		output::flush();

		return 1;
	}

	print_window_result(request);

	return 1;
}

std::uint8_t command_trace(std::string_view body)
{
	std::string action = {};

	if (take_token(body, action) == 0)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	std::uint64_t flags = 0;
	std::uint32_t rate = HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
	std::string rate_text = {};

	if (same_text(action, "off") == 1)
	{
		flags = HACDBG_TRACE_CONTROL_DISABLE;
	}
	else if (same_text(action, "reset") == 1)
	{
		flags = HACDBG_TRACE_CONTROL_RESET;
	}
	else if (same_text(action, "counters") == 1 || same_text(action, "events") == 1)
	{
		flags = same_text(action, "counters") == 1 ? HACDBG_TRACE_CONTROL_ENABLE_COUNTERS
		                                           : HACDBG_TRACE_CONTROL_ENABLE_EVENTS;
		flags |= HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE | HACDBG_TRACE_CONTROL_SET_EVENT_MASK;

		if (take_token(body, rate_text) == 1)
		{
			char* end = nullptr;
			const unsigned long value = std::strtoul(rate_text.c_str(), &end, 10);

			if (end == rate_text.c_str() || *end != '\0' || value == 0 || value > 1000000ul)
			{
				LOG_ERR("invalid syntax");

				return 1;
			}

			rate = static_cast<std::uint32_t>(value);
		}
	}
	else
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	std::string extra = {};

	if (take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	const std::uint64_t result = hypercall::trace_control(flags, rate, HACDBG_TRACE_EVENT_MASK_ALL);

	print_status("trace", result != 0, result != 0 ? 0 : static_cast<std::int32_t>(0xC0000001));

	return 1;
}

std::uint8_t command_user_kill(std::string_view body)
{
	std::string pid_text = {};
	std::string extra = {};
	std::uint32_t pid = 0;

	if (take_token(body, pid_text) == 0 || parse_pid(pid_text, pid) == 0 || take_token(body, extra) == 1)
	{
		LOG_ERR("invalid syntax");

		return 1;
	}

	std::int32_t status = 0;

	print_status("kill", user_end_process(pid, status) == 1, status);

	return 1;
}

std::wstring callback_dos_path(const wchar_t* kernel_path)
{
	const std::wstring path = kernel_path != nullptr ? kernel_path : L"";
	const std::wstring root = L"\\SystemRoot";

	if (path.size() >= root.size() && _wcsnicmp(path.c_str(), root.c_str(), root.size()) == 0)
	{
		wchar_t windows[MAX_PATH] = {};
		const UINT chars = GetWindowsDirectoryW(windows, MAX_PATH);

		if (chars == 0 || chars >= MAX_PATH)
		{
			return path;
		}

		return std::wstring(windows) + path.substr(root.size());
	}

	if (path.rfind(L"\\??\\", 0) == 0)
	{
		return path.substr(4);
	}

	return path;
}

std::string callback_version_string(const void* block, const std::wstring& key)
{
	void* value = nullptr;
	unsigned int bytes = 0;

	if (VerQueryValueW(block, key.c_str(), &value, &bytes) == FALSE || value == nullptr || bytes < sizeof(wchar_t))
	{
		return {};
	}

	char narrow[256] = {};

	WideCharToMultiByte(CP_ACP, 0, static_cast<const wchar_t*>(value), -1, narrow, static_cast<int>(sizeof(narrow)),
	                    nullptr, nullptr);

	return narrow;
}

void callback_file_details(const std::wstring& path, std::string& company, std::string& version, std::string& description)
{
	const DWORD bytes = GetFileVersionInfoSizeW(path.c_str(), nullptr);

	if (bytes == 0)
	{
		return;
	}

	std::vector<unsigned char> data(bytes);

	if (GetFileVersionInfoW(path.c_str(), 0, bytes, data.data()) == FALSE)
	{
		return;
	}

	struct translation_t
	{
		unsigned short language;
		unsigned short code_page;
	}* translation = nullptr;
	unsigned int translation_bytes = 0;

	if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translation),
	                   &translation_bytes) == FALSE ||
	    translation == nullptr || translation_bytes < sizeof(translation_t))
	{
		return;
	}

	wchar_t root[64] = {};

	swprintf_s(root, L"\\StringFileInfo\\%04x%04x\\", translation->language, translation->code_page);
	company = callback_version_string(data.data(), std::wstring(root) + L"CompanyName");
	version = callback_version_string(data.data(), std::wstring(root) + L"FileVersion");
	description = callback_version_string(data.data(), std::wstring(root) + L"FileDescription");
}

std::string_view trim_edge(std::string_view text)
{
	text = skip_space(text);

	while (text.empty() == false && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n'))
	{
		text.remove_suffix(1);
	}

	return text;
}

std::uint8_t callback_type_id(const std::string_view name, unsigned int& type_out)
{
	for (unsigned int type = HACDBG_CALLBACK_CREATE_PROCESS; type <= HACDBG_CALLBACK_POWER_SETTING; ++type)
	{
		if (same_text(name, HacDbgCallbackTypeName(type)) == 1)
		{
			type_out = type;

			return 1;
		}
	}

	return 0;
}

std::uint8_t callback_type_span(const std::string_view name, unsigned int& first_out, unsigned int& last_out, const char*& label_out)
{
	const struct
	{
		const char* label;
		unsigned int first;
		unsigned int last;
	} groups[] = {
	    {"CreateProcess", HACDBG_CALLBACK_CREATE_PROCESS, HACDBG_CALLBACK_CREATE_PROCESS_EX2},
	    {"CreateThread", HACDBG_CALLBACK_CREATE_THREAD, HACDBG_CALLBACK_CREATE_THREAD_EX},
	    {"LoadImage", HACDBG_CALLBACK_LOAD_IMAGE, HACDBG_CALLBACK_LOAD_IMAGE_EX},
	    {"ProcessObCallback", HACDBG_CALLBACK_PROCESS_OB_PRE, HACDBG_CALLBACK_PROCESS_OB_POST},
	    {"ThreadObCallback", HACDBG_CALLBACK_THREAD_OB_PRE, HACDBG_CALLBACK_THREAD_OB_POST},
	    {"DesktopObCallback", HACDBG_CALLBACK_DESKTOP_OB_PRE, HACDBG_CALLBACK_DESKTOP_OB_POST},
	    {"ImageVerification", HACDBG_CALLBACK_IMAGE_VERIFICATION, HACDBG_CALLBACK_IMAGE_VERIFICATION},
	    {"BugCheck", HACDBG_CALLBACK_BUGCHECK, HACDBG_CALLBACK_BUGCHECK_REASON},
	    {"Shutdown", HACDBG_CALLBACK_SHUTDOWN, HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN},
	    {"CmpCallback", HACDBG_CALLBACK_REGISTRY, HACDBG_CALLBACK_REGISTRY},
	    {"FsNotifyChange", HACDBG_CALLBACK_FS_NOTIFY, HACDBG_CALLBACK_FS_NOTIFY},
	    {"LogonSessionTerminated", HACDBG_CALLBACK_LOGON_TERMINATED, HACDBG_CALLBACK_LOGON_TERMINATED_EX},
	    {"PowerSetting", HACDBG_CALLBACK_POWER_SETTING, HACDBG_CALLBACK_POWER_SETTING},
	};

	for (const auto& group : groups)
	{
		if (same_text(name, group.label) == 1)
		{
			first_out = group.first;
			last_out = group.last;
			label_out = group.label;

			return 1;
		}
	}

	unsigned int type = 0;

	if (callback_type_id(name, type) == 0)
	{
		return 0;
	}

	first_out = type;
	last_out = type;
	label_out = HacDbgCallbackTypeName(type);

	return 1;
}

std::uint8_t parse_callback_address(const std::string& text, std::uint64_t& value_out)
{
	if (text.size() < 3 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X'))
	{
		return 0;
	}

	char* end = nullptr;
	const unsigned long long value = std::strtoull(text.c_str(), &end, 16);

	if (end == text.c_str() || *end != '\0')
	{
		return 0;
	}

	value_out = static_cast<std::uint64_t>(value);

	return 1;
}

std::uint8_t command_callback_edit(const std::vector<std::string>& tokens)
{
	unsigned int operation = HACDBG_CALLBACK_OP_SCAN;

	if (same_text(tokens[0], "remove") == 1)
	{
		operation = HACDBG_CALLBACK_OP_REMOVE;
	}
	else if (same_text(tokens[0], "disable") == 1)
	{
		operation = HACDBG_CALLBACK_OP_DISABLE;
	}
	else if (same_text(tokens[0], "enable") == 1)
	{
		operation = HACDBG_CALLBACK_OP_ENABLE;
	}
	else
	{
		return 0;
	}

	if (tokens.size() < 3)
	{
		output::print("err, invalid syntax\n");
		output::flush();

		return 1;
	}

	std::uint64_t entry = 0;
	std::uint64_t extra = 0;
	std::size_t type_end = tokens.size() - 1;

	if (parse_callback_address(tokens.back(), entry) == 0)
	{
		output::print("err, invalid syntax\n");
		output::flush();

		return 1;
	}

	if (tokens.size() >= 4 && parse_callback_address(tokens[tokens.size() - 2], entry) == 1)
	{
		if (parse_callback_address(tokens.back(), extra) == 0)
		{
			output::print("err, invalid syntax\n");
			output::flush();

			return 1;
		}

		type_end = tokens.size() - 2;
	}

	std::string type_name = {};

	for (std::size_t index = 1; index < type_end; ++index)
	{
		if (type_name.empty() == false)
		{
			type_name.push_back(' ');
		}

		type_name += tokens[index];
	}

	unsigned int selected_type = 0;

	if (type_name.empty() == true || callback_type_id(type_name, selected_type) == 0)
	{
		output::print("err, callback type was not found\n");
		output::flush();

		return 1;
	}

	auto* request = new HACDBG_CALLBACK_REQUEST();
	const bool sent = kernel_callback_request(*request);

	if (sent == false || request->Status < 0)
	{
		output::print("err, callback failed: 0x{:08x}\n",
		              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		output::flush();
		delete request;

		return 1;
	}

	const HACDBG_CALLBACK_ROW* match = nullptr;
	unsigned int matches = 0;

	for (unsigned int index = 0; index < request->Count && index < HACDBG_CALLBACK_MAX_ROWS; ++index)
	{
		const HACDBG_CALLBACK_ROW& row = request->Rows[index];

		if (row.Type != selected_type || row.Entry != entry)
		{
			continue;
		}

		if (extra != 0 && row.Extra != extra)
		{
			continue;
		}

		match = &row;
		matches += 1;
	}

	if (matches == 0)
	{
		output::print("err, callback entry was not found\n");
		output::flush();
		delete request;

		return 1;
	}

	if (matches != 1)
	{
		output::print("err, callback entry is not unique\n");
		output::flush();
		delete request;

		return 1;
	}

	HACDBG_CALLBACK_REQUEST edit = {};
	const std::uint64_t printed_entry = match->Entry;
	const std::uint64_t printed_extra = match->Extra;

	edit.Reserved = operation;
	edit.Rows[0] = *match;
	delete request;

	const bool edited = kernel_callback_request(edit);

	if (edited == false || edit.Status < 0)
	{
		output::print("err, callback failed: 0x{:08x}\n",
		              edited == false ? 0xC0000225u : static_cast<std::uint32_t>(edit.Status));
		output::flush();

		return 1;
	}

	output::print("callback {} type={} entry={:016x} extra={:016x}\n", tokens[0], HacDbgCallbackTypeName(selected_type),
	              printed_entry, printed_extra);
	output::flush();

	return 1;
}

std::uint8_t command_callback(std::string_view body)
{
	std::vector<std::string> tokens = {};
	std::string token = {};
	std::string_view remaining = trim_edge(body);

	while (take_token(remaining, token) == 1)
	{
		tokens.push_back(token);
	}

	if (tokens.empty() == false &&
	    (same_text(tokens[0], "remove") == 1 || same_text(tokens[0], "disable") == 1 || same_text(tokens[0], "enable") == 1))
	{
		return command_callback_edit(tokens);
	}

	const std::string_view type_name = trim_edge(body);
	unsigned int first_type = 0;
	unsigned int last_type = 0;
	const char* type_label = "";
	const std::uint8_t filter_type = type_name.empty() == false ? 1 : 0;

	if (filter_type == 1 && callback_type_span(type_name, first_type, last_type, type_label) == 0)
	{
		output::print("err, callback type was not found\n");
		output::flush();

		return 1;
	}

	auto* request = new HACDBG_CALLBACK_REQUEST();
	const bool sent = kernel_callback_request(*request);

	if (sent == false || request->Status < 0)
	{
		output::print("err, callback failed: 0x{:08x}\n",
		              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		output::flush();
		delete request;

		return 1;
	}

	unsigned int shown = 0;

	for (unsigned int index = 0; index < request->Count && index < HACDBG_CALLBACK_MAX_ROWS; ++index)
	{
		if (filter_type == 0 || (request->Rows[index].Type >= first_type && request->Rows[index].Type <= last_type))
		{
			++shown;
		}
	}

	if (filter_type == 1)
	{
		output::print("callback count={} truncated={} type={} shown={}\n", request->Count, request->Truncated, type_label,
		              shown);
	}
	else
	{
		output::print("callback count={} truncated={}\n", request->Count, request->Truncated);
	}

	for (unsigned int index = 0; index < request->Count && index < HACDBG_CALLBACK_MAX_ROWS; ++index)
	{
		const HACDBG_CALLBACK_ROW& row = request->Rows[index];

		if (filter_type == 1 && (row.Type < first_type || row.Type > last_type))
		{
			continue;
		}

		const std::wstring path = callback_dos_path(row.Path);
		std::string company = {};
		std::string version = {};
		std::string description = {};
		char narrow[HACDBG_CALLBACK_PATH_CHARS * 2] = {};

		callback_file_details(path, company, version, description);
		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
		const char* state = "正常";
		if (row.Reserved == HACDBG_CALLBACK_STATE_DISABLED)
		{
			state = "禁用";
		}
		else if (row.Reserved == HACDBG_CALLBACK_STATE_REMOVED)
		{
			state = "移除";
		}
		else if (row.Reserved == HACDBG_CALLBACK_STATE_ENABLED)
		{
			state = "启用";
		}

		output::print("  {} {} entry={:016x} extra={:016x} {} | {} | {} | {}\n", HacDbgCallbackTypeName(row.Type), state,
		              row.Entry, row.Extra, narrow, company, version, description);
	}

	output::flush();
	delete request;

	return 1;
}

std::uint8_t command_filter_operate(unsigned int operation, std::uint64_t driver, std::uint64_t device, std::uint64_t host)
{
	auto* request = new HACDBG_FILTER_REQUEST();

	request->Reserved = operation;
	request->Rows[0].DriverObject = driver;
	request->Rows[0].DeviceObject = device;
	request->Rows[0].HostDeviceObject = host;
	const bool sent = kernel_filter_request(*request);

	if (sent == false || request->Status < 0)
	{
		output::print("err, filter failed: 0x{:08x}\n",
		              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		output::flush();
		delete request;

		return 1;
	}

	if (operation == HACDBG_FILTER_OP_DETACH)
	{
		output::print("filter removed dev={:016x} host={:016x}\n", device, host);
		output::flush();
		delete request;

		return 1;
	}

	output::print("filter count={}\n", request->Count);
	for (unsigned int index = 0; index < request->Count && index < HACDBG_FILTER_MAX_ROWS; ++index)
	{
		const HACDBG_FILTER_ROW& row = request->Rows[index];
		const std::wstring path = callback_dos_path(row.DriverPath);
		char narrow[HACDBG_FILTER_PATH_CHARS] = {};
		char name[HACDBG_FILTER_NAME_CHARS] = {};

		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
		WideCharToMultiByte(CP_ACP, 0, operation == HACDBG_FILTER_OP_DEVICES ? row.DeviceName : row.DriverName, -1, name,
		                    static_cast<int>(sizeof(name)), nullptr, nullptr);
		if (operation == HACDBG_FILTER_OP_DEVICES)
		{
			output::print("  dev={:016x} {} {}\n", row.DeviceObject, name[0] != 0 ? name : "-", narrow);
		}
		else
		{
			output::print("  {:2} {:016x} {}\n", row.Depth, row.DeviceObject, narrow);
		}
	}

	output::flush();
	delete request;

	return 1;
}

std::uint8_t command_filter(std::string_view body)
{
	std::string operation = {};
	std::string_view arguments = trim_edge(body);

	if (take_token(arguments, operation) == 1 &&
	    (same_text(operation, "remove") == 1 || same_text(operation, "devices") == 1 || same_text(operation, "dispatch") == 1))
	{
		std::string first = {};
		std::string second = {};
		std::uint64_t driver = 0;
		std::uint64_t device = 0;
		std::uint64_t host = 0;

		if (take_token(arguments, first) == 0 || parse_callback_address(first, device) == 0)
		{
			output::print("err, invalid syntax\n");
			output::flush();

			return 1;
		}

		if (same_text(operation, "remove") == 1)
		{
			if (take_token(arguments, second) == 0 || parse_callback_address(second, host) == 0)
			{
				output::print("err, invalid syntax\n");
				output::flush();

				return 1;
			}

			return command_filter_operate(HACDBG_FILTER_OP_DETACH, 0, device, host);
		}

		driver = device;
		return command_filter_operate(same_text(operation, "devices") == 1 ? HACDBG_FILTER_OP_DEVICES
		                                                                   : HACDBG_FILTER_OP_DISPATCH,
		                              driver, 0, 0);
	}

	const std::string_view type_name = trim_edge(body);
	unsigned int selected_type = 0;
	const std::uint8_t filter_type = type_name.empty() == false ? 1 : 0;

	if (filter_type == 1)
	{
		for (unsigned int type = HACDBG_FILTER_FILE; type <= HACDBG_FILTER_PNP; ++type)
		{
			if (same_text(type_name, HacDbgFilterTypeName(type)) == 1)
			{
				selected_type = type;
				break;
			}
		}

		if (selected_type == 0)
		{
			output::print("err, filter type was not found\n");
			output::flush();

			return 1;
		}
	}

	auto* request = new HACDBG_FILTER_REQUEST();
	const bool sent = kernel_filter_request(*request);

	if (sent == false || request->Status < 0)
	{
		output::print("err, filter failed: 0x{:08x}\n",
		              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		output::flush();
		delete request;

		return 1;
	}

	unsigned int shown = 0;

	for (unsigned int index = 0; index < request->Count && index < HACDBG_FILTER_MAX_ROWS; ++index)
	{
		if (filter_type == 0 || request->Rows[index].Type == selected_type)
		{
			++shown;
		}
	}

	if (filter_type == 1)
	{
		output::print("filter count={} truncated={} type={} shown={}\n", request->Count, request->Truncated,
		              HacDbgFilterTypeName(selected_type), shown);
	}
	else
	{
		output::print("filter count={} truncated={}\n", request->Count, request->Truncated);
	}

	for (unsigned int index = 0; index < request->Count && index < HACDBG_FILTER_MAX_ROWS; ++index)
	{
		const HACDBG_FILTER_ROW& row = request->Rows[index];

		if (filter_type == 1 && row.Type != selected_type)
		{
			continue;
		}

		const std::wstring path = callback_dos_path(row.DriverPath);
		std::string company = {};
		std::string version = {};
		std::string description = {};
		char narrow[HACDBG_FILTER_PATH_CHARS * 2] = {};
		char device[HACDBG_FILTER_NAME_CHARS * 2] = {};
		char driver[HACDBG_FILTER_NAME_CHARS * 2] = {};
		char host[HACDBG_FILTER_NAME_CHARS * 2] = {};

		callback_file_details(path, company, version, description);
		(void)version;
		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
		WideCharToMultiByte(CP_ACP, 0, row.DriverName, -1, driver, static_cast<int>(sizeof(driver)), nullptr, nullptr);
		WideCharToMultiByte(CP_ACP, 0, row.DeviceName, -1, device, static_cast<int>(sizeof(device)), nullptr, nullptr);
		WideCharToMultiByte(CP_ACP, 0, row.HostDriverName, -1, host, static_cast<int>(sizeof(host)), nullptr, nullptr);
		const std::string indent(static_cast<std::size_t>(row.Depth) * 2u, ' ');
		output::print("{}{} {} drv={:016x} dev={:016x} device={} host={} hostdrv={:016x} hostdev={:016x} {} | {} | {}\n",
		              indent, HacDbgFilterTypeName(row.Type), driver[0] != 0 ? driver : "-", row.DriverObject,
		              row.DeviceObject, device[0] != 0 ? device : "-", host[0] != 0 ? host : "-", row.HostDriverObject,
		              row.HostDeviceObject, narrow, company, description);
	}

	output::flush();
	delete request;

	return 1;
}

std::uint8_t command_minifilter(std::string_view body)
{
	std::string operation = {};
	std::string_view arguments = trim_edge(body);
	unsigned int action = HACDBG_MINIFILTER_OP_SCAN;

	if (take_token(arguments, operation) == 1 &&
	    (same_text(operation, "disable") == 1 || same_text(operation, "enable") == 1))
	{
		std::string address = {};
		std::uint64_t filter = 0;

		if (take_token(arguments, address) == 0 || parse_callback_address(address, filter) == 0)
		{
			output::print("err, invalid syntax\n");
			output::flush();

			return 1;
		}

		action = same_text(operation, "disable") == 1 ? HACDBG_MINIFILTER_OP_DISABLE : HACDBG_MINIFILTER_OP_ENABLE;
		auto* request = new HACDBG_MINIFILTER_REQUEST();
		request->Reserved = action;
		request->Rows[0].Filter = filter;
		const bool sent = kernel_minifilter_request(*request);
		if (sent == false || request->Status < 0)
		{
			output::print("err, minifilter failed: 0x{:08x}\n",
			              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		}
		else
		{
			output::print("minifilter {} filter={:016x}\n", operation, filter);
		}

		output::flush();
		delete request;

		return 1;
	}

	auto* request = new HACDBG_MINIFILTER_REQUEST();
	const bool sent = kernel_minifilter_request(*request);
	if (sent == false || request->Status < 0)
	{
		output::print("err, minifilter failed: 0x{:08x}\n",
		              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		output::flush();
		delete request;

		return 1;
	}

	output::print("minifilter count={} truncated={}\n", request->Count, request->Truncated);
	for (unsigned int index = 0; index < request->Count && index < HACDBG_MINIFILTER_MAX_ROWS; ++index)
	{
		const HACDBG_MINIFILTER_ROW& row = request->Rows[index];
		const std::wstring path = callback_dos_path(row.Path);
		std::string company = {};
		std::string version = {};
		std::string description = {};
		char narrow[HACDBG_MINIFILTER_PATH_CHARS] = {};
		char name[HACDBG_MINIFILTER_NAME_CHARS] = {};
		char altitude[HACDBG_MINIFILTER_ALTITUDE_CHARS] = {};

		callback_file_details(path, company, version, description);
		(void)version;
		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
		WideCharToMultiByte(CP_ACP, 0, row.Name, -1, name, static_cast<int>(sizeof(name)), nullptr, nullptr);
		WideCharToMultiByte(CP_ACP, 0, row.Altitude, -1, altitude, static_cast<int>(sizeof(altitude)), nullptr, nullptr);
		const std::string indent(static_cast<std::size_t>(row.Depth) * 2u, ' ');
		output::print("{}{} callback={:016x} filter={:016x} altitude={} {} | {} | {}\n", indent,
		              name[0] != 0 ? name : "-", row.Callback, row.Filter, altitude[0] != 0 ? altitude : "-", narrow, company,
		              description);
	}

	output::flush();
	delete request;

	return 1;
}

std::uint8_t command_timer(std::string_view body)
{
	std::string operation = {};
	std::string_view arguments = trim_edge(body);

	if (take_token(arguments, operation) == 1 && same_text(operation, "remove") == 1)
	{
		std::string kind = {};
		std::string address = {};
		std::uint64_t timer = 0;
		unsigned int type = 0;

		if (take_token(arguments, kind) == 0 || take_token(arguments, address) == 0 || parse_callback_address(address, timer) == 0)
		{
			output::print("err, invalid syntax\n");
			output::flush();

			return 1;
		}

		if (same_text(kind, "io") == 1)
		{
			type = HACDBG_TIMER_IO;
		}
		else if (same_text(kind, "dpc") == 1)
		{
			type = HACDBG_TIMER_DPC;
		}
		else
		{
			output::print("err, timer type was not found\n");
			output::flush();

			return 1;
		}

		auto* request = new HACDBG_TIMER_REQUEST();
		request->Reserved = HACDBG_TIMER_OP_REMOVE;
		request->Rows[0].Type = type;
		request->Rows[0].Timer = timer;
		const bool sent = kernel_timer_request(*request);
		if (sent == false || request->Status < 0)
		{
			output::print("err, timer failed: 0x{:08x}\n",
			              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		}
		else
		{
			output::print("timer removed type={} timer={:016x}\n", kind, timer);
		}

		output::flush();
		delete request;

		return 1;
	}

	auto* request = new HACDBG_TIMER_REQUEST();
	const bool sent = kernel_timer_request(*request);
	if (sent == false || request->Status < 0)
	{
		output::print("err, timer failed: 0x{:08x}\n",
		              sent == false ? 0xC0000225u : static_cast<std::uint32_t>(request->Status));
		output::flush();
		delete request;

		return 1;
	}

	output::print("timer count={} truncated={}\n", request->Count, request->Truncated);
	for (unsigned int index = 0; index < request->Count && index < HACDBG_TIMER_MAX_ROWS; ++index)
	{
		const HACDBG_TIMER_ROW& row = request->Rows[index];
		const std::wstring path = callback_dos_path(row.Path);
		std::string company = {};
		std::string version = {};
		std::string description = {};
		char narrow[HACDBG_TIMER_PATH_CHARS] = {};

		callback_file_details(path, company, version, description);
		(void)version;
		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
		output::print("  callback={:016x} {} period={} {} dpc={:016x} timer={:016x} {} | {} | {}\n", row.Callback,
		              row.Type == HACDBG_TIMER_IO ? "IO Timer" : "DPC Timer", row.Period,
		              row.Running != 0 ? "running" : "stopped", row.Dpc, row.Timer, narrow, company, description);
	}

	output::flush();
	delete request;

	return 1;
}
}

std::uint8_t dispatch_gui_command(const std::string& command)
{
	std::string_view body = skip_space(command);
	std::string name = {};

	if (take_token(body, name) == 0)
	{
		return 0;
	}

	if (same_text(name, "kill") == 1)
	{
		return command_user_kill(body);
	}

	if (same_text(name, "killk") == 1)
	{
		return command_kill(body, HACDBG_PROCESS_TERMINATE_KERNEL, "killk", 0);
	}

	if (same_text(name, "killf") == 1)
	{
		return command_kill(body, HACDBG_PROCESS_TERMINATE_FORCE, "killf", 1);
	}

	if (same_text(name, "suspend") == 1)
	{
		return command_state(body, 0);
	}

	if (same_text(name, "resume") == 1)
	{
		return command_state(body, 1);
	}

	if (same_text(name, "hide") == 1)
	{
		return command_one_pid(body, HACDBG_PROCESS_HIDE, 0, "hide");
	}

	if (same_text(name, "ppl") == 1)
	{
		return command_ppl(body);
	}

	if (same_text(name, "handle") == 1)
	{
		return command_handle(body);
	}

	if (same_text(name, "inject") == 1)
	{
		return command_inject(body);
	}

	if (same_text(name, "image") == 1)
	{
		return command_image(body);
	}

	if (same_text(name, "window") == 1)
	{
		return command_window(body);
	}

	if (same_text(name, ".trace") == 1)
	{
		return command_trace(body);
	}

	if (same_text(name, "callback") == 1)
	{
		return command_callback(body);
	}

	if (same_text(name, "filter") == 1)
	{
		return command_filter(body);
	}

	if (same_text(name, "minifilter") == 1)
	{
		return command_minifilter(body);
	}

	if (same_text(name, "timer") == 1)
	{
		return command_timer(body);
	}

	return 0;
}
