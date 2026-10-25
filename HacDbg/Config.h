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
#define HACDBG_BACKEND_INTEL 1
#endif

//
// 客户是否看到虚拟化能力。
//   1 - 隐藏。Intel 清掉 CPUID.1 ECX[5]，CR4 读影子不带 VMXE，
//       IA32_FEATURE_CONTROL 显示为已锁定且不允许 VMX，0x480-0x493 注入 #GP。
//       AMD 清掉 CPUID Fn8000_0001 ECX[2]，Fn8000_000A 返回全 0，EFER 读结果
//       不带 SVME，VM_CR 与 VM_HSAVE_PA 注入 #GP，SVM 指令注入 #UD。
//       没有外层 hypervisor 时，不拦截 RDTSC。AMD 按处理器扣退出开销。
//       Intel 把短退出的宿主采样和校准出的硬件过渡记入补偿。VMX-preemption
//       timer 可用时最多累加 160000 个 TSC 拍，timer 仍按约 10000 拍清回 0。
//       timer 不可用时累加上限仍是 10000。长退出和 VMX-preemption timer
//       退出把补偿清回 0，避免各核 TSC 被拉开。
//       两边都拦截 IA32_TSC_DEADLINE，把客户写入的虚拟 TSC 换算成主机 TSC。
//       CPUID.1 ECX[31] 已置位时不做这项补偿，也不打开 PERF_GLOBAL_CTRL
//       保存/加载和对 Processor Trace 隐藏 VMX。
//   0 - 不隐藏。上述位按真实状态返回。AMD 上 VMRUN 仍被拦截，该退出停止当前处理器。
// 两种取值都不把 VMCS、VMCB、MSR 位图和宿主栈映射进客户，也不模拟嵌套虚拟化。
// VMX 指令仍然注入 #UD。
//
#ifndef HACDBG_HIDE_VIRTUALIZATION
#define HACDBG_HIDE_VIRTUALIZATION 1
#endif
