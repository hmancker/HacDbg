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
#define HACDBG_DISABLE_DEBUG_LOG 0
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

//
// 0: 编译 AMD SVM。1: 编译 Intel VT-x。一次只链接一种后端。
// Visual Studio 里编 Debug / Release 时以这个值为准，工程会按它
// 排除另一边的源文件。DebugIntel / ReleaseIntel 由工程传入 1。
//
#ifndef HACDBG_BACKEND_INTEL
#define HACDBG_BACKEND_INTEL 0
#endif
