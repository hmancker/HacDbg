#include "TimerDriver.h"

#include "../Config.h"
#if HACDBG_COMM_WOB
#include "../WobChannel.h"
#endif

#include <Windows.h>
#include <winioctl.h>

#define HACDBG_TIMER_DEVICE L"\\\\.\\HacDbg"
#define HACDBG_TIMER_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool timerDriverSend(HACDBG_TIMER_REQUEST* request)
{
    if (request == nullptr)
    {
        return false;
    }

#if HACDBG_COMM_WOB
    if (!wobExchange(HACDBG_WOB_KIND_TIMER, request, sizeof(*request)))
    {
        request->Status = static_cast<int>(0xC0000225);
        return false;
    }

    return request->Status >= 0;
#else
    DWORD returned = 0;
    HANDLE device = CreateFileW(HACDBG_TIMER_DEVICE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    const BOOL ok =
        DeviceIoControl(device, HACDBG_TIMER_IOCTL, request, sizeof(*request), request, sizeof(*request), &returned, nullptr);
    CloseHandle(device);
    if (ok == FALSE)
    {
        request->Status = static_cast<int>(GetLastError());
        return false;
    }

    return request->Status >= 0;
#endif
}

bool timerDriverQuery(HACDBG_TIMER_REQUEST* request)
{
    if (request == nullptr)
    {
        return false;
    }

    *request = {};
    return timerDriverSend(request);
}

bool timerDriverRemove(unsigned int type, unsigned long long timer, int* status)
{
    auto* request = new HACDBG_TIMER_REQUEST();
    request->Reserved = HACDBG_TIMER_OP_REMOVE;
    request->Rows[0].Type = type;
    request->Rows[0].Timer = timer;
    const bool sent = timerDriverSend(request);
    if (status != nullptr)
    {
        *status = request->Status;
    }

    const bool ok = sent && request->Status >= 0;
    delete request;
    return ok;
}
