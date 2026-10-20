/**
 * @file Config.h
 * @brief Compile-time switches for the driver.
 *
 * @author HacDbg
 */

#pragma once

//
// 调试与诊断总开关：
//   0 - 保留 DbgPrint 输出和注册表加载诊断（默认）
//   1 - 全部关闭，生成静默驱动
//
#ifndef HACDBG_DISABLE_DEBUG_LOG
#define HACDBG_DISABLE_DEBUG_LOG 1
#endif

//
// 注册表诊断（LastLoadStage / LastLoadStatus / LastLoadDetail）
// 跟随调试开关一起关闭。
//
#if HACDBG_DISABLE_DEBUG_LOG
#define HACDBG_DIAGNOSTICS 0
#else
#define HACDBG_DIAGNOSTICS 1
#endif
