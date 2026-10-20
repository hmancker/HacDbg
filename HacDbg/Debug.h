/**
 * @file Debug.h
 * @brief Kernel debug output switch.
 *
 * @author HacDbg
 */

#pragma once

#include <ntddk.h>
#include "Config.h"

//
// 开关在 Config.h。置 1 后全部 HACDBG_LOG 调用编译为空，不再向
// DebugView 输出；断点日志环不属于调试输出，仍然保留。
//
#if HACDBG_DISABLE_DEBUG_LOG
#define HACDBG_LOG(...) ((VOID)0)
#else
#define HACDBG_LOG(...) DbgPrint(__VA_ARGS__)
#endif
