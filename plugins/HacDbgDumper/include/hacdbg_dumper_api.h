#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open the process-dump window. Does not attach or dump by itself.
 * @param owner Owner window. May be null.
 */
void
HacDbgDumperShow(HWND owner);

#ifdef __cplusplus
}
#endif
