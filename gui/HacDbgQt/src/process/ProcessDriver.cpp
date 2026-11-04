#include "ProcessDriver.h"

#include "process_control.h"

#include <Windows.h>
#include <winioctl.h>

#define HACDBG_PROCESS_DEVICE L"\\\\.\\HacDbg"
#define HACDBG_PROCESS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool processDriverCall(std::uint32_t operation, std::uint32_t pid, std::uint32_t parameter, std::uint32_t flags,
                       const wchar_t* path, std::int32_t* status)
{
    HACDBG_PROCESS_REQUEST request = {};
    DWORD returned = 0;
    HANDLE device;

    request.Operation = operation;
    request.Pid = pid;
    request.Parameter = parameter;
    request.Flags = flags;
    if (path != nullptr)
    {
        wcsncpy_s(reinterpret_cast<wchar_t*>(request.Path), HACDBG_PROCESS_PATH_CHARS, path, _TRUNCATE);
    }

    device = CreateFileW(HACDBG_PROCESS_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
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
}

bool processDriverHandleCall(std::uint32_t parameter, std::uint32_t pid, const wchar_t* actor, const wchar_t* victim,
                             std::int32_t* status)
{
    HACDBG_PROCESS_REQUEST request = {};
    DWORD returned = 0;
    HANDLE device;
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

    device = CreateFileW(HACDBG_PROCESS_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
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
}
