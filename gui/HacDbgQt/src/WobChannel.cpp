#include "WobChannel.h"

#include "Config.h"

#include <Windows.h>

#include <cstring>

#if HACDBG_COMM_WOB
namespace
{
using ManageWobTicket = long(__stdcall*)(unsigned long informationClass, void* buffer, unsigned long length,
                                         unsigned long* returned);

const unsigned char kMagic[16] = {0x48, 0x44, 0x42, 0x47, 0x57, 0x4F, 0x42, 0x31, 0, 0, 0, 0, 0, 0, 0, 0};

ManageWobTicket manageWobTicket()
{
    static ManageWobTicket function = nullptr;
    static bool resolved = false;
    if (resolved == false)
    {
        const auto module = GetModuleHandleW(L"ntdll.dll");
        if (module != nullptr)
        {
            function = reinterpret_cast<ManageWobTicket>(GetProcAddress(module, "NtManageWobTicket"));
        }
        resolved = true;
    }
    return function;
}
} // namespace

bool wobExchange(const std::uint32_t kind, void* const body, const std::uint32_t bodyBytes)
{
    const auto function = manageWobTicket();
    if (function == nullptr || body == nullptr || bodyBytes == 0)
    {
        return false;
    }

    struct Packet
    {
        HACDBG_WOB_HEADER header;
        unsigned char body[sizeof(HACDBG_WINDOW_REQUEST)];
    } packet = {};

    if (bodyBytes > sizeof(packet.body))
    {
        return false;
    }

    std::memcpy(packet.header.Magic, kMagic, sizeof(kMagic));
    packet.header.Version = HACDBG_WOB_VERSION;
    packet.header.Kind = kind;
    packet.header.BodyBytes = bodyBytes;
    std::memcpy(packet.body, body, bodyBytes);

    unsigned long returned = 0;
    const auto length = static_cast<unsigned long>(sizeof(packet.header) + bodyBytes);
    const long status = function(0, &packet, length, &returned);
    if (status < 0)
    {
        return false;
    }

    std::memcpy(body, packet.body, bodyBytes);
    return true;
}
#endif
