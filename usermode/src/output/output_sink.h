#pragma once

/**
 * @file output_sink.h
 * @brief Process-wide output sink shared by the CLI and GUI core.
 *
 * @author HacDbg
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/format.h>

namespace output
{
	enum class kind_t : std::uint32_t
	{
		text = 0,
		info = 1,
		warning = 2,
		error = 3,
		progress = 4,
		clear = 5,
		quit = 6
	};

	using sink_t = void (*)(kind_t kind, const char* text, std::size_t size, void* context);

	/**
	 * @brief Installs the process-wide output sink. A null sink writes to the
	 * console.
	 */
	void set_sink(sink_t sink, void* context);

	/**
	 * @brief Writes one output event. Safe to call from multiple threads.
	 */
	void write(kind_t kind, std::string_view text);

	/**
	 * @brief Emits a console clear or a GUI clear event.
	 */
	void clear();

	/**
	 * @brief Flushes the console output. A custom sink receives no flush call.
	 */
	void flush();

	/**
	 * @brief Formats text and writes it as a text event.
	 */
	template <typename... args_t>
	void print(fmt::format_string<args_t...> format, args_t&&... args)
	{
		write(kind_t::text, fmt::format(format, std::forward<args_t>(args)...));
	}
}
