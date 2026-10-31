#include "mapper.h"

#include "include/hacdbg_mapper_api.h"
#include "intel_driver.h"
#include "kdmapper.h"
#include "kdm_utils.h"

#include <filesystem>
#include <string>
#include <vector>
#include <Windows.h>

namespace
{
	HACDBG_MAPPER_LOG g_log = nullptr;
	void* g_log_context = nullptr;

	std::string to_utf8(const std::wstring& text)
	{
		if (text.empty())
		{
			return {};
		}

		const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (size <= 1)
		{
			return {};
		}

		std::string utf8(static_cast<std::size_t>(size - 1), '\0');
		WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, utf8.data(), size, nullptr, nullptr);
		return utf8;
	}
}

void mapper_set_log(HACDBG_MAPPER_LOG log, void* context)
{
	g_log = log;
	g_log_context = context;
}

void mapper_log_write(const std::string& text)
{
	if (g_log == nullptr || text.empty())
	{
		return;
	}

	const int level = (text.rfind("[-]", 0) == 0 || text.rfind("[!]", 0) == 0) ? 1 : 0;
	g_log(level, text.c_str(), g_log_context);
}

std::uint8_t mapper::map_driver_file(const wchar_t* path, const MAP_REQUEST& request)
{
	if (path == nullptr || path[0] == L'\0' || !std::filesystem::exists(path))
	{
		mapper_log_write("[-] select a driver file");
		return 0;
	}

	mapper_log_write("[+] mapping " + to_utf8(path));

	if (!NT_SUCCESS(intel_driver::Load()))
	{
		mapper_log_write("[-] failed to load vulnerable intel driver");
		return 0;
	}

	std::vector<BYTE> raw_image;
	if (!kdmUtils::ReadFileToMemory(path, &raw_image) || raw_image.empty())
	{
		intel_driver::Unload();
		mapper_log_write("[-] failed to read driver file");
		return 0;
	}

	NTSTATUS exit_code = 0;
	const ULONG64 base = kdmapper::MapDriver(raw_image.data(),
	                                         0,
	                                         0,
	                                         request.FreeMemory,
	                                         !request.CopyHeader,
	                                         request.IndependentPages
	                                             ? kdmapper::AllocationMode::AllocateIndependentPages
	                                             : kdmapper::AllocationMode::AllocatePool,
	                                         request.PassAllocation,
	                                         nullptr,
	                                         &exit_code);

	intel_driver::Unload();

	if (base == 0)
	{
		mapper_log_write("[-] failed to map driver");
		return 0;
	}

	if (!NT_SUCCESS(exit_code))
	{
		char status_text[64] = {};
		sprintf_s(status_text, "[-] DriverEntry returned 0x%08X", static_cast<unsigned>(exit_code));
		mapper_log_write(status_text);
		return 0;
	}

	char mapped_text[80] = {};
	sprintf_s(mapped_text, "[+] driver mapped at 0x%llX", static_cast<unsigned long long>(base));
	mapper_log_write(mapped_text);
	return 1;
}

extern "C" uint32_t
HacDbgMapperMap(const wchar_t* driver_path, HACDBG_MAPPER_LOG log, void* context)
{
	g_log = log;
	g_log_context = context;

	MAP_REQUEST request = {};
	const std::uint8_t mapped = mapper::map_driver_file(driver_path, request);
	g_log = nullptr;
	g_log_context = nullptr;
	return mapped;
}
