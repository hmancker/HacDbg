#include <iostream>
#include <string>

#include <Windows.h>

#include "commands/commands.h"
#include "hook/hook.h"
#include "logs/logs.h"
#include "system/system.h"

std::int32_t main()
{
	logs::set_up();

	if (sys::set_up() == 0)
	{
		std::system("pause");

		return 1;
	}

	sys::kernel::parse_modules();

	while (true)
	{
		std::string command;

		if (commands::read_command(command) == 0 || commands::is_quit_command(command) == 1)
		{
			break;
		}

		commands::process(command);
	}

	sys::clean_up();

	return 0;
}
