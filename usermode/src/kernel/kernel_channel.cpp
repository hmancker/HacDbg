#include "kernel_channel.h"

#include "../Config.h"
#include "wob_comm.h"

#include <Windows.h>
#if !HACDBG_COMM_WOB
#include <winioctl.h>
#endif

#include <cstring>
#include <vector>

#if HACDBG_COMM_WOB
namespace
{
using manage_wob_ticket_t = long(__stdcall*)(unsigned long information_class, void* buffer, unsigned long length,
                                            unsigned long* returned);

const unsigned char k_magic[16] = {0x48, 0x44, 0x42, 0x47, 0x57, 0x4F, 0x42, 0x31, 0, 0, 0, 0, 0, 0, 0, 0};

manage_wob_ticket_t manage_wob_ticket()
{
	static manage_wob_ticket_t function = nullptr;
	static bool resolved = false;

	if (resolved == false)
	{
		const HMODULE module = GetModuleHandleW(L"ntdll.dll");

		if (module != nullptr)
		{
			function = reinterpret_cast<manage_wob_ticket_t>(GetProcAddress(module, "NtManageWobTicket"));
		}

		resolved = true;
	}

	return function;
}

bool exchange(const std::uint32_t kind, void* const body, const std::uint32_t body_bytes)
{
	const manage_wob_ticket_t function = manage_wob_ticket();

	if (function == nullptr || body == nullptr || body_bytes == 0 || body_bytes > 1024u * 1024u)
	{
		return false;
	}

	std::vector<unsigned char> packet(sizeof(HACDBG_WOB_HEADER) + body_bytes);
	auto* header = reinterpret_cast<HACDBG_WOB_HEADER*>(packet.data());

	std::memcpy(header->Magic, k_magic, sizeof(k_magic));
	header->Version = HACDBG_WOB_VERSION;
	header->Kind = kind;
	header->BodyBytes = body_bytes;
	std::memcpy(packet.data() + sizeof(HACDBG_WOB_HEADER), body, body_bytes);

	unsigned long returned = 0;
	const long status = function(0, packet.data(), static_cast<unsigned long>(packet.size()), &returned);

	if (status < 0)
	{
		return false;
	}

	std::memcpy(body, packet.data() + sizeof(HACDBG_WOB_HEADER), body_bytes);

	return true;
}
}
#endif

#if !HACDBG_COMM_WOB
namespace
{
bool ioctl_exchange(const unsigned long code, void* const body, const unsigned long body_bytes)
{
	const HANDLE device = CreateFileW(L"\\\\.\\HacDbg", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
	                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (device == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	DWORD returned = 0;
	const BOOL ok = DeviceIoControl(device, code, body, body_bytes, body, body_bytes, &returned, nullptr);

	CloseHandle(device);

	return ok != FALSE;
}
}
#endif

bool kernel_send_process(HACDBG_PROCESS_REQUEST& request)
{
#if HACDBG_COMM_WOB
	return exchange(HACDBG_WOB_KIND_PROCESS, &request, sizeof(request));
#else
	return ioctl_exchange(CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS), &request,
	                      sizeof(request));
#endif
}

bool kernel_process_request(const std::uint32_t operation, const std::uint32_t pid, const std::uint32_t parameter,
                            const std::uint32_t flags, const wchar_t* const path, HACDBG_PROCESS_REQUEST& request_out)
{
	request_out = {};
	request_out.Operation = operation;
	request_out.Pid = pid;
	request_out.Parameter = parameter;
	request_out.Flags = flags;

	if (path != nullptr)
	{
		wcsncpy_s(reinterpret_cast<wchar_t*>(request_out.Path), HACDBG_PROCESS_PATH_CHARS, path, _TRUNCATE);
	}

	return kernel_send_process(request_out);
}

bool kernel_window_request(HACDBG_WINDOW_REQUEST& request)
{
#if HACDBG_COMM_WOB
	return exchange(HACDBG_WOB_KIND_WINDOW, &request, sizeof(request));
#else
	return ioctl_exchange(CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS), &request,
	                      sizeof(request));
#endif
}

bool kernel_callback_request(HACDBG_CALLBACK_REQUEST& request)
{
#if HACDBG_COMM_WOB
	return exchange(HACDBG_WOB_KIND_CALLBACK, &request, sizeof(request));
#else
	return ioctl_exchange(CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS), &request,
	                      sizeof(request));
#endif
}

bool kernel_filter_request(HACDBG_FILTER_REQUEST& request)
{
#if HACDBG_COMM_WOB
	return exchange(HACDBG_WOB_KIND_FILTER, &request, sizeof(request));
#else
	return ioctl_exchange(CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS), &request,
	                      sizeof(request));
#endif
}

bool kernel_minifilter_request(HACDBG_MINIFILTER_REQUEST& request)
{
#if HACDBG_COMM_WOB
	return exchange(HACDBG_WOB_KIND_MINIFILTER, &request, sizeof(request));
#else
	return ioctl_exchange(CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS), &request,
	                      sizeof(request));
#endif
}
