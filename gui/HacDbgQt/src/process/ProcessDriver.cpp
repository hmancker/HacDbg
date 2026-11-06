#include "ProcessDriver.h"

#include "../Config.h"
#if HACDBG_COMM_WOB
#include "../WobChannel.h"
#endif
#include "process_control.h"

#include <Windows.h>
#include <winioctl.h>

#define HACDBG_PROCESS_DEVICE L"\\\\.\\HacDbg"
#define HACDBG_PROCESS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool processDriverCall(std::uint32_t operation, std::uint32_t pid, std::uint32_t parameter, std::uint32_t flags,
                       const wchar_t* path, std::int32_t* status)
{
    HACDBG_PROCESS_REQUEST request = {};

    request.Operation = operation;
    request.Pid = pid;
    request.Parameter = parameter;
    request.Flags = flags;
    if (path != nullptr)
    {
        wcsncpy_s(reinterpret_cast<wchar_t*>(request.Path), HACDBG_PROCESS_PATH_CHARS, path, _TRUNCATE);
    }

#if HACDBG_COMM_WOB
    if (!wobExchange(HACDBG_WOB_KIND_PROCESS, &request, sizeof(request)))
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(0xC0000225);
        }
        return false;
    }

    if (status != nullptr)
    {
        *status = request.Status;
    }
    return request.Status >= 0;
#else
    DWORD returned = 0;
    HANDLE device = CreateFileW(HACDBG_PROCESS_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(GetLastError());
        }
        return false;
    }

    const BOOL ok = DeviceIoControl(device, HACDBG_PROCESS_IOCTL, &request, sizeof(request), &request, sizeof(request),
                                    &returned, nullptr);
    CloseHandle(device);
    if (ok == FALSE)
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(GetLastError());
        }
        return false;
    }

    if (status != nullptr)
    {
        *status = request.Status;
    }
    return request.Status >= 0;
#endif
}

bool processDriverImagePath(std::uint32_t pid, wchar_t* path, std::uint32_t pathChars, std::int32_t* status)
{
    HACDBG_PROCESS_REQUEST request = {};

    if (path == nullptr || pathChars == 0)
    {
        return false;
    }

    path[0] = L'\0';
    request.Operation = HACDBG_PROCESS_QUERY_IMAGE;
    request.Pid = pid;
#if HACDBG_COMM_WOB
    if (!wobExchange(HACDBG_WOB_KIND_PROCESS, &request, sizeof(request)))
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(0xC0000225);
        }
        return false;
    }

    if (status != nullptr)
    {
        *status = request.Status;
    }
    if (request.Status < 0)
    {
        return false;
    }

    wcsncpy_s(path, pathChars, reinterpret_cast<const wchar_t*>(request.Path), _TRUNCATE);
    return path[0] != L'\0';
#else
    DWORD returned = 0;
    HANDLE device = CreateFileW(HACDBG_PROCESS_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(GetLastError());
        }
        return false;
    }

    const BOOL ok = DeviceIoControl(device, HACDBG_PROCESS_IOCTL, &request, sizeof(request), &request, sizeof(request),
                                    &returned, nullptr);
    CloseHandle(device);
    if (ok == FALSE)
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(GetLastError());
        }
        return false;
    }

    if (status != nullptr)
    {
        *status = request.Status;
    }
    if (request.Status < 0)
    {
        return false;
    }

    wcsncpy_s(path, pathChars, reinterpret_cast<const wchar_t*>(request.Path), _TRUNCATE);
    return path[0] != L'\0';
#endif
}

bool processDriverHandleCall(std::uint32_t parameter, std::uint32_t pid, const wchar_t* actor, const wchar_t* victim,
                             std::int32_t* status)
{
    HACDBG_PROCESS_REQUEST request = {};
    auto* path = reinterpret_cast<wchar_t*>(request.Path);

    request.Operation = HACDBG_PROCESS_HANDLE_PROTECT;
    request.Pid = pid;
    request.Parameter = parameter;
    if (actor != nullptr)
    {
        wcsncpy_s(path, HACDBG_HANDLE_NAME_CHARS, actor, _TRUNCATE);
    }
    if (victim != nullptr)
    {
        wcsncpy_s(path + HACDBG_HANDLE_NAME_CHARS, HACDBG_HANDLE_NAME_CHARS, victim, _TRUNCATE);
    }

#if HACDBG_COMM_WOB
    if (!wobExchange(HACDBG_WOB_KIND_PROCESS, &request, sizeof(request)))
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(0xC0000225);
        }
        return false;
    }

    if (status != nullptr)
    {
        *status = request.Status;
    }
    return request.Status >= 0;
#else
    DWORD returned = 0;
    HANDLE device = CreateFileW(HACDBG_PROCESS_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(GetLastError());
        }
        return false;
    }

    const BOOL ok = DeviceIoControl(device, HACDBG_PROCESS_IOCTL, &request, sizeof(request), &request, sizeof(request),
                                    &returned, nullptr);
    CloseHandle(device);
    if (ok == FALSE)
    {
        if (status != nullptr)
        {
            *status = static_cast<std::int32_t>(GetLastError());
        }
        return false;
    }

    if (status != nullptr)
    {
        *status = request.Status;
    }
    return request.Status >= 0;
#endif
}
