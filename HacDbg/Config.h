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

//
// 客户是否看到虚拟化能力。
//   1 - 隐藏（默认）。Intel 清掉 CPUID.1 ECX[5]，CR4 读影子不带 VMXE，
//       IA32_FEATURE_CONTROL 显示为已锁定且不允许 VMX，0x480-0x4FF 注入 #GP，
//       并对 Processor Trace 隐藏 VMX。AMD 的 EFER 读结果不带 SVME。
//   0 - 不隐藏。上述位按真实状态返回。
// 两种取值都不把 VMCS、VMCB 和 MSR 位图映射进客户，也不模拟嵌套 VMX。
// VMX 指令仍然注入 #UD。
//
#ifndef HACDBG_HIDE_VIRTUALIZATION
#define HACDBG_HIDE_VIRTUALIZATION 1
#endif
