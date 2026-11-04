#include "WindowDriver.h"

#include <Windows.h>
#include <winioctl.h>

#define HACDBG_WINDOW_DEVICE L"\\\\.\\HacDbg"
#define HACDBG_WINDOW_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool windowDriverExecute(HACDBG_WINDOW_REQUEST* request)
{
    HANDLE device;
    DWORD returned = 0;
    BOOL ok;

    if (request == nullptr)
    {
        return false;
    }

    device = CreateFileW(HACDBG_WINDOW_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    ok = DeviceIoControl(device, HACDBG_WINDOW_IOCTL, request, sizeof(*request), request, sizeof(*request), &returned,
                         nullptr);
    CloseHandle(device);
    if (ok == FALSE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    return request->Status >= 0;
}
