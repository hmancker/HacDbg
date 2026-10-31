#pragma once

#include <cstdint>

struct MAP_REQUEST
{
	bool FreeMemory;
	bool IndependentPages;
	bool CopyHeader;
	bool PassAllocation;
};

namespace mapper
{
	std::uint8_t map_driver_file(const wchar_t* path, const MAP_REQUEST& request);
}
