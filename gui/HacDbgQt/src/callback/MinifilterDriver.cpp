#include "MinifilterDriver.h"

#include "../Config.h"
#if HACDBG_COMM_WOB
#include "../WobChannel.h"
#endif

#include <Windows.h>
#include <winioctl.h>

#define HACDBG_MINIFILTER_DEVICE L"\\\\.\\HacDbg"
#define HACDBG_MINIFILTER_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool minifilterDriverSend(HACDBG_MINIFILTER_REQUEST* request)
{
    if (request == nullptr)
    {
        return false;
    }

#if HACDBG_COMM_WOB
    if (!wobExchange(HACDBG_WOB_KIND_MINIFILTER, request, sizeof(*request)))
    {
        request->Status = static_cast<int>(0xC0000225);
        return false;
    }

    return request->Status >= 0;
#else
    DWORD returned = 0;
    HANDLE device = CreateFileW(HACDBG_MINIFILTER_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    const BOOL ok = DeviceIoControl(device, HACDBG_MINIFILTER_IOCTL, request, sizeof(*request), request, sizeof(*request),
                                    &returned, nullptr);
    CloseHandle(device);
    if (ok == FALSE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    return request->Status >= 0;
#endif
}

bool minifilterDriverQuery(HACDBG_MINIFILTER_REQUEST* request)
{
    if (request == nullptr)
    {
        return false;
    }

    *request = {};
    return minifilterDriverSend(request);
}

bool minifilterDriverOperate(unsigned int operation, unsigned long long filter, HACDBG_MINIFILTER_REQUEST* request,
                             int* status)
{
    if (request == nullptr)
    {
        return false;
    }

    *request = {};
    request->Reserved = operation;
    request->Rows[0].Filter = filter;
    const bool sent = minifilterDriverSend(request);
    if (status != nullptr)
    {
        *status = request->Status;
    }

    return sent && request->Status >= 0;
}
