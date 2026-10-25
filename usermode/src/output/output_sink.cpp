/**
 * @file output_sink.cpp
 * @brief Console and GUI output sink implementation.
 *
 * @author HacDbg
 */

#include "output_sink.h"

#include <cstdio>
#include <mutex>

#include <Windows.h>

namespace
{
	std::mutex g_output_mutex;
	output::sink_t g_sink = nullptr;
	void* g_sink_context = nullptr;

	void clear_console_screen()
	{
		const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO info = {};

		if (GetConsoleScreenBufferInfo(output, &info) == 0)
		{
			std::fputc('\n', stdout);
			std::fflush(stdout);

			return;
		}

		const DWORD cells = static_cast<DWORD>(info.dwSize.X) * static_cast<DWORD>(info.dwSize.Y);
		DWORD written = 0;
		const COORD origin = { 0, 0 };

		FillConsoleOutputCharacterA(output, ' ', cells, origin, &written);
		FillConsoleOutputAttribute(output, info.wAttributes, cells, origin, &written);
		SetConsoleCursorPosition(output, origin);
	}

	WORD level_color(const output::kind_t kind)
	{
		if (kind == output::kind_t::info)
		{
			return FOREGROUND_GREEN;
		}

		if (kind == output::kind_t::warning)
		{
			return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		}

		return FOREGROUND_RED | FOREGROUND_INTENSITY;
	}

	const char* level_name(const output::kind_t kind)
	{
		if (kind == output::kind_t::info)
		{
			return "info";
		}

		if (kind == output::kind_t::warning)
		{
			return "warning";
		}

		return "error";
	}

	void write_level_prefix(const output::kind_t kind)
	{
		const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO info = {};
		const bool is_console = GetConsoleScreenBufferInfo(output, &info) != 0;

		std::fputc('[', stdout);

		if (is_console == true)
		{
			std::fflush(stdout);

			const WORD color = static_cast<WORD>(level_color(kind) | (info.wAttributes & 0xfff0));
			SetConsoleTextAttribute(output, color);
		}

		std::fputs(level_name(kind), stdout);

		if (is_console == true)
		{
			std::fflush(stdout);
			SetConsoleTextAttribute(output, info.wAttributes);
		}

		std::fputs("] ", stdout);
	}

	void write_console(const output::kind_t kind, const char* const text, const std::size_t size)
	{
		if (kind == output::kind_t::clear)
		{
			clear_console_screen();

			return;
		}

		if (kind == output::kind_t::info || kind == output::kind_t::warning || kind == output::kind_t::error)
		{
			write_level_prefix(kind);
		}

		if (size != 0)
		{
			std::fwrite(text, 1, size, stdout);
		}

		if (kind == output::kind_t::info || kind == output::kind_t::warning || kind == output::kind_t::error)
		{
			std::fputc('\n', stdout);
		}
	}
}

void output::set_sink(const sink_t sink, void* const context)
{
	std::lock_guard<std::mutex> lock(g_output_mutex);

	g_sink = sink;
	g_sink_context = context;
}

void output::write(const kind_t kind, const std::string_view text)
{
	std::lock_guard<std::mutex> lock(g_output_mutex);

	if (g_sink != nullptr)
	{
		g_sink(kind, text.data(), text.size(), g_sink_context);

		return;
	}

	write_console(kind, text.data(), text.size());
}

void output::clear()
{
	write(kind_t::clear, {});
}

void output::flush()
{
	std::fflush(stdout);
}
