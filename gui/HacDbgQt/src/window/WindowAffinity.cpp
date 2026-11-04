#include "WindowAffinity.h"

#include "WindowDriver.h"

#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace
{
using SetAffinity = BOOL(WINAPI*)(HWND, DWORD);
using GetAffinity = BOOL(WINAPI*)(HWND, DWORD*);

SetAffinity setAffinity()
{
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr)
    {
        return nullptr;
    }

    return reinterpret_cast<SetAffinity>(GetProcAddress(user32, "SetWindowDisplayAffinity"));
}

GetAffinity getAffinity()
{
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr)
    {
        return nullptr;
    }

    return reinterpret_cast<GetAffinity>(GetProcAddress(user32, "GetWindowDisplayAffinity"));
}

void prepareWindow(HWND window)
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

BOOL trySetAffinity(HWND window, DWORD affinity)
{
    const SetAffinity set = setAffinity();
    if (set == nullptr)
    {
        return FALSE;
    }

    prepareWindow(window);
    if (set(window, affinity) != FALSE)
    {
        return TRUE;
    }

    if (affinity != WDA_EXCLUDEFROMCAPTURE)
    {
        return FALSE;
    }

    set(window, WDA_MONITOR);
    if (set(window, WDA_EXCLUDEFROMCAPTURE) != FALSE)
    {
        return TRUE;
    }

    Sleep(0);
    prepareWindow(window);
    return set(window, affinity);
}

bool allowCaller(unsigned long pid)
{
    HACDBG_WINDOW_REQUEST request = {};
    request.Operation = HACDBG_WINDOW_ALLOW;
    request.CalibratePid = pid;
    return windowDriverExecute(&request);
}

bool syscallNumber(DWORD* number)
{
    HMODULE module = GetModuleHandleW(L"win32u.dll");
    const unsigned char* stub;

    if (module == nullptr)
    {
        module = LoadLibraryW(L"win32u.dll");
    }
    if (module == nullptr || number == nullptr)
    {
        return false;
    }

    stub = reinterpret_cast<const unsigned char*>(GetProcAddress(module, "NtUserSetWindowDisplayAffinity"));
    if (stub == nullptr || stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8)
    {
        return false;
    }

    CopyMemory(number, stub + 4, sizeof(*number));
    return true;
}

void markCallTarget(HANDLE process, void* address, SIZE_T size)
{
    using SetVm = LONG(NTAPI*)(HANDLE, ULONG, ULONG_PTR, void*, void*, ULONG);
    struct Range
    {
        void* VirtualAddress;
        SIZE_T NumberOfBytes;
    };
    struct Target
    {
        ULONG_PTR Offset;
        ULONG_PTR Flags;
    };
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto setVm = ntdll == nullptr
                           ? nullptr
                           : reinterpret_cast<SetVm>(GetProcAddress(ntdll, "NtSetInformationVirtualMemory"));
    Range range{address, size};
    Target target{0, 1};

    if (setVm == nullptr)
    {
        return;
    }

    setVm(process, 2, 1, &range, &target, sizeof(target));
}

void releaseRemote(HANDLE process, void* remote, HANDLE thread)
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

//
// SetWindowDisplayAffinity only accepts a window owned by the caller.
// The stub runs in the owner process and issues the same syscall. The
// bytes are the native x64 sequence, so a 32-bit process is refused.
//
bool runInProcess(DWORD pid, HWND window, DWORD affinity)
{
    HANDLE process = nullptr;
    void* remote = nullptr;
    HANDLE thread = nullptr;
    DWORD syscall = 0;
    DWORD exitCode = 0;
    DWORD error = ERROR_ACCESS_DENIED;
    BOOL wow64 = FALSE;
    unsigned char code[32] = {};
    unsigned int length = 0;
    const auto hwnd = static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(window));
    bool allowed = false;
    DWORD wait = WAIT_FAILED;

    if (pid == 0 || pid == 4 || syscallNumber(&syscall) == false)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ,
                          FALSE, pid);
    if (process == nullptr)
    {
        return false;
    }

    if (IsWow64Process(process, &wow64) == FALSE || wow64 != FALSE)
    {
        releaseRemote(process, nullptr, nullptr);
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    code[length++] = 0x48;
    code[length++] = 0xB9;
    CopyMemory(code + length, &hwnd, sizeof(hwnd));
    length += sizeof(hwnd);
    code[length++] = 0xBA;
    CopyMemory(code + length, &affinity, sizeof(affinity));
    length += sizeof(affinity);
    code[length++] = 0x4C;
    code[length++] = 0x8B;
    code[length++] = 0xD1;
    code[length++] = 0xB8;
    CopyMemory(code + length, &syscall, sizeof(syscall));
    length += sizeof(syscall);
    code[length++] = 0x0F;
    code[length++] = 0x05;
    code[length++] = 0xC3;

    remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote == nullptr || WriteProcessMemory(process, remote, code, length, nullptr) == FALSE)
    {
        error = GetLastError();
        releaseRemote(process, remote, nullptr);
        SetLastError(error);
        return false;
    }

    FlushInstructionCache(process, remote, length);
    markCallTarget(process, remote, 0x1000);
    allowed = allowCaller(pid);
    thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote), nullptr, 0,
                                nullptr);
    if (thread == nullptr)
    {
        error = GetLastError();
        if (allowed)
        {
            allowCaller(0);
        }
        releaseRemote(process, remote, nullptr);
        SetLastError(error);
        return false;
    }

    wait = WaitForSingleObject(thread, 3000);
    if (wait != WAIT_OBJECT_0 || GetExitCodeThread(thread, &exitCode) == FALSE || exitCode == STILL_ACTIVE)
    {
        error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        if (allowed)
        {
            allowCaller(0);
        }
        //
        // The thread may still be inside the stub. Leave the page mapped.
        //
        CloseHandle(thread);
        CloseHandle(process);
        SetLastError(error == 0 ? ERROR_TIMEOUT : error);
        return false;
    }

    if (allowed)
    {
        allowCaller(0);
    }
    releaseRemote(process, remote, thread);
    if (exitCode == 0)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    return true;
}
}

bool setWindowAntiCapture(HWND window, bool enable)
{
    DWORD current = WDA_NONE;
    DWORD pid = 0;
    const DWORD target = enable ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;

    if (window == nullptr || IsWindow(window) == FALSE)
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return false;
    }

    if (queryWindowAffinity(window, &current) && current == target)
    {
        return true;
    }

    GetWindowThreadProcessId(window, &pid);
    if (pid != 0 && pid != GetCurrentProcessId())
    {
        if (enable == false)
        {
            return runInProcess(pid, window, WDA_NONE);
        }

        if (runInProcess(pid, window, WDA_EXCLUDEFROMCAPTURE))
        {
            return true;
        }

        runInProcess(pid, window, WDA_MONITOR);
        return runInProcess(pid, window, WDA_EXCLUDEFROMCAPTURE);
    }

    return trySetAffinity(window, target) != FALSE;
}

bool queryWindowAffinity(HWND window, unsigned long* affinity)
{
    const GetAffinity get = getAffinity();
    DWORD value = WDA_NONE;

    if (affinity == nullptr || window == nullptr || get == nullptr)
    {
        return false;
    }

    if (get(window, &value) == FALSE)
    {
        return false;
    }

    *affinity = value;
    return true;
}

unsigned long dwmProcessId()
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
