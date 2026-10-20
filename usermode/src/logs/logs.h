#pragma once
#include <spdlog/spdlog.h>

#define LOG_PRINTNOLINE(...) fmt::print(__VA_ARGS__)
#define LOG_INFO(...) spdlog::info(__VA_ARGS__)
#define LOG_WARN(...) spdlog::warn(__VA_ARGS__)
#define LOG_ERR(...) spdlog::error(__VA_ARGS__)

namespace logs
{
	void set_up();
}
