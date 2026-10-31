#pragma once

#include <stdint.h>
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Log callback supplied by the host.
 * @param level 0 is informational. 1 is an error.
 * @param text One line, without a trailing newline.
 * @param context Value passed to HacDbgMapperMap.
 */
typedef void (*HACDBG_MAPPER_LOG)(int level, const char* text, void* context);

/**
 * @brief Map one selected driver image through the embedded Intel driver.
 * @param driver_path Full path of the .sys file. Empty fails.
 * @param log Host log callback. May be null.
 * @param context Passed unchanged to log.
 * @return 1 when DriverEntry returns success.
 */
uint32_t
HacDbgMapperMap(const wchar_t* driver_path, HACDBG_MAPPER_LOG log, void* context);

/**
 * @brief Open the driver-selection window. Does not map a driver by itself.
 * @param owner Owner window. May be null.
 */
void
HacDbgMapperShow(HWND owner);

#ifdef __cplusplus
}
#endif
