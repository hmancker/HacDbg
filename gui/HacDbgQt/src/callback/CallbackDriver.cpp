#include "CallbackDriver.h"

#include "../Config.h"
#if HACDBG_COMM_WOB
#include "../WobChannel.h"
#endif

#include <Windows.h>
#include <winioctl.h>

#define HACDBG_CALLBACK_DEVICE L"\\\\.\\HacDbg"
#define HACDBG_CALLBACK_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool callbackDriverSend(HACDBG_CALLBACK_REQUEST* request)
{
#if HACDBG_COMM_WOB
    if (!wobExchange(HACDBG_WOB_KIND_CALLBACK, request, sizeof(*request)))
    {
        request->Status = static_cast<int>(0xC0000225);
        return false;
    }

    return request->Status >= 0;
#else
    DWORD returned = 0;
    HANDLE device = CreateFileW(HACDBG_CALLBACK_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    const BOOL ok = DeviceIoControl(device, HACDBG_CALLBACK_IOCTL, request, sizeof(*request), request, sizeof(*request),
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

bool callbackDriverQuery(HACDBG_CALLBACK_REQUEST* request)
{
    if (request == nullptr)
    {
        return false;
    }

    *request = {};
    return callbackDriverSend(request);
}

bool callbackDriverEdit(unsigned int operation, unsigned int type, unsigned long long entry, unsigned long long extra,
                        int* status)
{
    auto* request = new HACDBG_CALLBACK_REQUEST();
    request->Reserved = operation;
    request->Rows[0].Type = type;
    request->Rows[0].Entry = entry;
    request->Rows[0].Extra = extra;
    const bool sent = callbackDriverSend(request);
    if (status != nullptr)
    {
        *status = request->Status;
    }

    const bool ok = sent && request->Status >= 0;
    delete request;
    return ok;
}
