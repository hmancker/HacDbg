#pragma once
#include <string>

namespace commands
{
	void process(const std::string& command);
	std::uint8_t read_command(std::string& command_out);
	std::uint8_t is_quit_command(const std::string& command);
}
