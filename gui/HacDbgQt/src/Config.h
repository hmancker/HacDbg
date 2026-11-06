#pragma once

//
// 三环和内核驱动之间的请求通道。一次只编译一种。
// 必须和 HacDbg/Config.h 里的 HACDBG_COMM_WOB 取同一个值。
//   1 - 只调用 NtManageWobTicket。
//   0 - 只调用 \\.\HacDbg 的 DeviceIoControl。
// CPUID hypercall 不受这个开关影响。
//
#ifndef HACDBG_COMM_WOB
#define HACDBG_COMM_WOB 1
#endif
