#pragma once

#include <Windows.h>
#include <stdio.h>

void AppendLogMessageA(const char* text);

#define FILENAMES_ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : \
    (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__))

#define logging(fmt, ...)                                                                 \
	do                                                                                    \
	{                                                                                     \
		char _logbuf[4096];                                                              \
		_snprintf_s(_logbuf, sizeof(_logbuf), _TRUNCATE,                                 \
		            "[Usermode] - [%s:%d] " fmt "\n", FILENAMES_, __LINE__ __VA_OPT__(,) \
		                __VA_ARGS__);                                                    \
		AppendLogMessageA(_logbuf);                                                      \
	} while (0)
