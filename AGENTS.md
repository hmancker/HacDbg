# AGENTS.md — HacDbg

在本仓库写代码或改代码之前，先读完本文件。下面每条都是硬性规则。当前对话里的明确指示优先于本文件。更深层目录里的 `AGENTS.md` 优先于本文件。

本文件不是项目介绍。它规定代理必须怎样做事，以及代码必须长什么样。

HacDbg 是 x86-64 上以 Windows 驱动启动的 hypervisor，同时支持 AMD SVM 和 Intel VT-x。AMD 路径写 SVM、VMCB、`VMRUN`、NPT。Intel 路径写 VT-x、VMCS、`VMXON`、`VMLAUNCH`、`VMRESUME`、EPT。两套术语按本机 CPU 厂商分开写，不把一种厂商的结构写成另一种。新写的驱动代码用 C。从 hyper-reV 搬入的三环调试器保持原来的 C++。三环命令和 hypercall 协议两套平台共用同一套。

生产编译环境是 Visual Studio 2026（路径在D:\vs2026）、Windows SDK 和 WDK。生产要交付 `.sys` 驱动，以及配套的三环调试程序。驱动加载之后，在逻辑处理器上按 CPU 厂商进入客户：AMD 上启用 SVM 并执行 `VMRUN`，Intel 上启用 VMX、执行 `VMXON` 后 `VMLAUNCH`。当前这套 Windows 作为客户。AMD 的启动方式对照 SimpleSvm。Intel 的启动方式对照 HyperDbg 的 `hyperhv`，再按仓库里的 Intel SDM 写。

主要对照：

* \- `D:\\Project\\github\\HyperDbg`：Intel VT-x 的参考实现。对照 `hyperdbg/hyperhv` 里的 VMX、VMCS、EPT 和 VM-exit。不把它的调试器、脚本引擎或三环程序搬进来。三环仍用 hyper-reV 那一套。
* \- `D:\\Project\\github\\SimpleSvm`：用 WDK 写的 AMD SVM 教学驱动，含 VMCB、`VMRUN` 循环和 NPT。本仓库的驱动启动对照它。
* \- `D:\\Project\\github\\hyper-reV`：用户自己的项目，优先深度复用三环调试器、符号解析和 hypercall。不复用它的 `uefi-boot`。它把附件挂进 Hyper-V 的启动链不是本仓库的启动方式。
* \- `D:\\Project\\github\\pulzar-hypervisor-main`：Rust 写的 UEFI Type-1。只在需要对照 VMCB、NPT 或 VMEXIT 分工时阅读。不把它的固件启动搬进本仓库。

## 1\. 最高规则

1. **硬件行为以仓库 `doc/` 里的手册为准。** 不理解的机制先查对应厂商的那一版 PDF，再写进代码。字段偏移、拦截位、指令的隐式操作数、异常条件都从该修订版读出来。记忆、博客、其他项目和更新的网络版本都不能覆盖仓库里的这几份文件。手册没写清楚时停下来问，不要补一种「合理」行为。可以读公开实现来理解做法，见第 8 节，但不能用它们代替手册。

   * AMD 的最高依据是 `doc/24593\_3.45\_APM\_Vol2\_PUB.pdf`（系统编程，SVM 在第 15 章）和 `doc/24594\_3.38\_APM\_Vol3\_PUB.pdf`（指令说明）。
   * Intel 的最高依据是 Intel SDM 修订 093（2026 年 9 月），不是 HyperDbg，也不是别的实现。基本架构查 `doc/253665-093-sdm-vol-1.pdf`。VMX 指令查 `doc/325383-093-sdm-vol-2abcd.pdf`。系统编程和 VMX 查 `doc/325384-093-sdm-vol-3abcd.pdf`。MSR 索引查 `doc/335592-093-sdm-vol-4.pdf`。
2. **有歧义就停下来问。** 任务、需求或你自己的理解存在多于一种合理解释时，先列出这些解释以及各自会改到什么，等用户选择。自己挑一个「更合理」的做法，即使结果碰巧正确，也是失败。
3. **只改任务要求的范围。** 不修改、不「改进」、不重排、不重构任务之外的代码。每一行改动都要能直接对应到用户的请求。看到无关的死代码、缺陷或难看的接口时，报告它们，不要顺手修。
4. **先复用，再写新代码。** 顺序是：本仓库已有的函数、类型和模块；然后 hyper-reV 里可以搬进来的调试器和 hypercall 源文件；最后才新写。已有的地址类型、寄存器包装、位定义、hypercall 布局和调试器命令，禁止再写一套，也禁止按 AMD 和 Intel 各写一套。SimpleSvm 用来对照驱动里的 SVM，HyperDbg 的 `hyperhv` 用来对照驱动里的 VT-x，都不整文件搬进来。已有设施不够用时，说明原因，问过之后再替换。
5. **提交进仓库的代码必须是完成的。** 禁止 `TODO`、`FIXME`、空函数、返回成功的桩、默默跳过的分支、注释掉的实现。工作要么做完，要么把剩余部分作为明确的、有名字的问题告诉用户。
6. **不靠关掉警告让构建通过。** 禁止压低、禁止或屏蔽警告和静态检查。低层代码里某条警告确实不适用于这次合法写法、而且没有合规改法时，按第 7 节处理。
7. **按资深 C 系统工程师的标准写。** 简单优先，不重复，符合本文件的风格，能用于生产，并且在意性能。资深工程师会认为方案过重时，先改到简单再交给用户。
8. **Windows 内核开发只写代码，不自己测试。** 驱动、SVM、VT-x 和任何会加载进内核的路径，都由用户手工做实机验证。代理不加载 `.sys`，不安装驱动，不在宿主或虚拟机里执行 `VMRUN`、`VMXON`、`VMLAUNCH` 或 `VMRESUME`，也不代跑这些测试。代码写完后，把手工步骤写进 `doc/test/` 并交给用户。

## 2\. 仓库里已经有的和还没有的

已经有的：

```
HacDbg/
├── AGENTS.md
├── HacDbg.slnx
├── LICENSE-hyper-reV
├── LICENSE-SimpleSvm
├── HacDbg/                  ← WDK 驱动。已有 AMD SVM、NPT，Intel VMX、EPT 和 hypercall
│   ├── HacDbg.inf
│   ├── HacDbg.vcxproj       ← WindowsKernelModeDriver10.0，x64 与 ARM64
│   ├── HacDbg.vcxproj.filters
│   └── HacDbg.vcxproj.user
├── usermode/                ← 三环调试器。命令两套平台共用
├── symbol-parser/
├── shared/                  ← 驱动和调试器共用的 hypercall 和数据结构
└── doc/                     ← 不进 Git
    ├── 24593\_3.45\_APM\_Vol2\_PUB.pdf
    ├── 24594\_3.38\_APM\_Vol3\_PUB.pdf
    ├── 253665-093-sdm-vol-1.pdf
    ├── 325383-093-sdm-vol-2abcd.pdf
    ├── 325384-093-sdm-vol-3abcd.pdf
    └── 335592-093-sdm-vol-4.pdf
```

`HacDbg/` 是生产用的 WDK 驱动工程。它编出 `.sys`。AMD 的 SVM、VMCB 和 `VMRUN` 写在 `Svm.c`、`Svm.h`、`SvmAsm.asm`、`Npt.c` 和 `Npt.h`。Intel 的 VMX、VMCS、`VMXON`、`VMLAUNCH` 和 EPT 写在 `Vmx.c`、`Vmx.h`、`VmxAsm.asm`、`Ept.c` 和 `Ept.h`。没有用户的明确指示时，不删除这个工程，不改它的 ARM64 配置。生产目标只编 x64。

不要为了「补齐结构」预先建空目录或空文件。`doc/README.md`、`doc/dev/`、`doc/test/` 已经在。

各目录的职责：

* `HacDbg/` 是 WDK 驱动。它在加载后按 CPU 厂商把当前 Windows 变成客户。AMD 上启用 SVM，用 `VMRUN`。主机侧写法对照 SimpleSvm 的 `SimpleSvm.cpp`、`SimpleSvm.hpp` 和 `x64.asm`，再按仓库里的 AMD 手册写。Intel 上启用 VMX，用 `VMXON` 和 `VMLAUNCH`。主机侧写法对照 HyperDbg 的 `hyperdbg/hyperhv/code/vmm/vmx`、`hyperdbg/hyperhv/code/vmm/ept` 和 `hyperdbg/hyperhv/code/assembly` 里的 `AsmVmxOperation.asm`、`AsmVmxContextState.asm`、`AsmVmexitHandler.asm`，再按仓库里的 Intel SDM 写。
* `usermode/` 是配套的三环调试程序。AMD 和 Intel 共用第 4 节那一套命令。整份命令实现、符号和 hypercall 客户从 `D:\\Project\\github\\hyper-reV` 的 `usermode/`、`symbol-parser/` 和 `shared/` 复用。不另设计一套协议，也不在搬入时删掉表里的命令。
* 设备拦截、指令模拟和多处理器是驱动里的后继模块。当前任务没有点名时不要创建。

需要新工程时，加进现有的 `HacDbg.slnx`。驱动和三环调试器都在这个解决方案里。没有任务需要时，不预先建空工程。

以下事项写「未确认」，不要猜：

* 已经验证可用的 MSBuild 命令。
* SimpleSvm 在本机的路径。
* pulzar 在本机的路径。

## 3\. 工具链与构建

生产编译器是 Visual Studio 2026 自带的 MSVC。不改用 gcc、clang 或 Rust 做生产构建。

* **驱动**用 WDK。平台工具集是 `WindowsKernelModeDriver10.0`，配置类型是 Driver，`DriverType` 是 WDM，平台是 x64，输出 `.sys`。现存的 `HacDbg.vcxproj` 就是这个工程。
* **三环调试器**用 Visual Studio 2026 和 Windows SDK，配置类型是 Application，平台是 x64，输出 `.exe`。新建这个工程时，桌面平台工具集用 `v145`。
* 不把本机的 Visual Studio 安装路径写进仓库。用已经配置好的开发者命令提示符里的 `msbuild`。

仓库里还没有一条验证过的构建命令。在它真实存在之前：

* 不编造 `cmake`、`ninja`、`gcc`、`clang`、`cargo` 或 `qemu` 命令，也不把猜出来的命令写进 `doc/dev/` 当作已经可用。
* 只运行仓库里真实存在的命令，或用户在当前对话里明确给出的命令。先查本文件、`doc/dev/` 和已经存在的工程文件。找不到 `msbuild` 就停下来问，不要换编译器。
* 与本次改动相关的检查要跑完。失败时修原因。能缩小范围时，先跑受影响的工程，再跑完整检查。
* 编译是开发的一部分，可以在本机编译。编译通过不等于测试通过。不加载 `.sys`，不安装驱动。
* 不擅自启动会一直占住终端的监视器，除非用户要求。

格式化用 clang-format，只处理本次改过的 C 和头文件。仓库根目录有 `.clang-format` 时用它。没有时，使用 [HyperDbg 的 .clang-format](https://github.com/HyperDbg/HyperDbg/blob/master/hyperdbg/.clang-format)。把这份配置添进仓库属于新增文件，先问。不格式化未改动的文件。

## 4\. 编码风格

本仓库新写的 C 按本节写。依据是 [HyperDbg Style Guide](https://docs.hyperdbg.org/contribution/style-guide)。从 hyper-reV 搬入的文件保持原来的语言、文件名和命名，不在搬入的同一次改动里改成 C 或重命名。仓库里已经有同类文件时，沿用那个文件的缩进。不为了这一处改动引入新的框架、分层或工具。不顺手格式化、重排或重命名无关代码。

### 命名

* 函数和变量用大驼峰，每个单词首字母大写，名字里不用下划线。例如 `MathPower`、`SvmRunGuest`。
* 结构体、枚举和地址类型的名字全部大写，单词之间只用一个下划线。例如 `GUEST\_STATE`、`GUEST\_PHYSICAL\_ADDRESS`。
* 全局变量以 `g\_` 开头。例如 `g\_HostSaveArea`。
* 宏和枚举常量与结构体一样，全部大写，单词之间一个下划线。

### 文件和目录

* 驱动目录里新写的源文件名以大写字母开头，例如 `Svm.c`、`Vmx.c`。
* `usermode/` 里新写的 C 源文件名以小写字母开头。
* 目录名全部小写，不用空格，需要分隔时用 `-`。`symbol-parser` 和 `shared` 沿用 hyper-reV 的目录名。
* 头文件用 `#pragma once`。

### 格式

函数返回类型单独占一行，左花括号换行。

```c
int
MathPower(int Base, int Exp)
{
    ...
}
```

块注释：

```c
//
// This is my comment line 1
// This is my comment line 2
//
```

### 打印和错误

* 驱动、VMEXIT 和 VM-exit 路径上打出的消息，首字母大写。
* 用户态工具打出的消息，首字母小写。
* 错误用来源前缀区分。用户态以 `err,` 开头。驱动、VMEXIT 和 VM-exit 路径以 `Err,` 开头。

### 命令

* 三环调试器必须支持下面这张表里的全部命令。这张表就是 hyper-reV 命令支持表「系列总览」里已支持的命令。AMD 和 Intel 共用这一套，不按厂商拆开。本机 `D:\\Project\\github\\hyper-reV` 这份克隆没有 `doc/命令支持表.md`。实现以本仓库 `usermode/src/commands` 为准。命令名不区分大小写。一行只执行一条命令。地址、数量、`L` 上限和各条命令的限制以这张表为准。不平行再做一套命令，也不在搬入时只留下其中几条。

已支持、必须保留的命令：

|系列|命令|
|-|-|
|显示内存|`db` `dw` `dd` `dq` `dp` `dc` `da` `du` `dds` `dps` `dqs`|
|修改内存|`eb` `ew` `ed` `eq` `ep` `ea` `eu` `eza` `ezu`|
|反汇编|`u`|
|执行断点|`bp` `bl` `bc` `bd` `be`|
|继续和单步|`g` `t` `p` `tc` `tt` `tct` `pc` `pt` `pct`|
|调用栈|`k` `kb` `kd` `kp` `kv`|
|寄存器|`r` `.thread`|
|模块和符号|`.sympath` `.sympath+` `.symfix` `.symfix+` `.reload` `.symopt` `lm` `lmi` `ld` `x` `ln` `dt`|
|进程|`!process` `.process`|
|线程|`!thread` `.thread`|
|客户机内存和钩子|`rgpm` `wgpm` `cgpm` `gvat` `rgvm` `wgvm` `cgvm` `akh` `rkh` `hgpp` `fl` `hfpc` `lkm` `kme` `dkm` `gva`|
|杂项|`.cls` `cls` `.echo` `.printf` `.formats` `?` `.time` `version` `.help` `q` `.quit` `exit`|

那份表「还没有的常见 WinDbg 系列」里的命令不要自行补上，除非用户要求。这包括 `ba`、`bu`、`bm`、`.frame`、`gu`、`wt`、`ub`、线程调用栈回溯、`dt -r`，以及用 `.symopt` 改选项。

驱动侧必须回答上表里会进入客户的每一条命令所依赖的 hypercall。

新命令按 WinDbg 的三类来归类。来源是 [Command style](https://docs.hyperdbg.org/contribution/style-guide/command-style)。写进 `doc/dev/` 时用 Command、Syntax、Description、Parameters、Examples。和上表冲突时，沿用上表的拼法。

|种类|前缀|作用|
|-|-|-|
|regular|无|作用于调试会话，控制和查看被调试目标。例如 `db`、`u`、`bp`、`g`|
|meta|`.`|作用于调试器自身，不作用于被调试目标。例如 `.reload`、`.sympath`|
|extension|`!`|定义在扩展里。例如 `!process`、`!thread`|

参数写法固定。小写单词是必须原样出现的关键字。大写开头的单词是参数名，类型写在括号里。末尾写了 `(optional)` 的参数可以省略。每一项参数单独成段。

### Doxygen

公开的函数、结构体、枚举和全局变量用 Javadoc 形式的注释块。来源是 [Doxygen style](https://docs.hyperdbg.org/contribution/style-guide/doxygen-style)。

只用这些标签：`@brief`、`@details`、`@param`、`@return`、`@see`、`@warning`。文件开头用 `@author HacDbg`，除非用户指定了人名。不要编造人名。

硬件包装函数在 `@details` 里写清调用前必须成立的条件，在 `@warning` 里写清条件不成立时的后果，例如 `#UD`、客户状态错误或宿主寄存器丢失。

## 5\. C 与驱动 hypervisor 的硬规则

* **不用分节横幅注释。** 不写 `// ----- VMCB -----` 这类横幅。公开入口在前，内部辅助函数在后。
* **注释自洽。** 代码注释、工程文件、文档和提交说明里，不引用本文件、评审意见、PR 或对话记录。把技术原因本身写在那里。
* **注释只写读者从代码里看不出来的事。**
* **不留脏代码。** 不留死代码、注释掉的代码、调试残留和无人使用的包含。本次改动造成的无用代码要删掉。改动之前就存在的死代码，只报告，不删，除非用户要求。
* **有语义的整数不用裸整数穿过接口。** 客户物理地址、宿主物理地址、宿主虚拟地址、页帧号、MSR 索引、向量号，各自用全部大写的结构体包装。
* **整数宽度要明确。** 使用固定宽度类型。不在同一模块里为同一种宽度再起一个新的 typedef。驱动工程使用 WDK 头。三环调试器使用 Windows SDK 头。共用结构放在 `shared/`，不把只在某一侧合法的头泄漏到另一侧。
* **VMEXIT 和 VM-exit 路径上不分配内存、不复制可以避免的缓冲区。** 驱动在进入客户之前可以使用 WDK 提供的内存。热路径上不再调用会阻塞或分页的内核 API。
* **魔法数要变成有名字的常量或枚举。** 常量的数值来自第 1 节里对应厂商的手册，并在声明旁用块注释写上手册里的字段名。VMCB、VMCS 和拦截控制块的布局用编译期断言检查大小和关键偏移。
* **特权操作收到窄的模块里。** MSR、控制寄存器、端口 I/O、SVM 指令、VMX 指令，以及把整数变成硬件结构指针的转换，放在专门的文件里。
* **每处特权操作上面都有一块 `INVARIANT:` 注释。** 紧挨着调用，说明对齐、映射和谁保证这块内存不是客户可见的。

```c
//
// INVARIANT: VmcbPa is the 4 KiB-aligned host physical address of this
// processor's VMCB. The page is writable in the host map and is not
// reachable through the guest's nested page tables.
//
SvmVmrun(VmcbPa);
```

* **客户已经在跑之后，热路径不主动蓝屏。** VMEXIT 和 VM-exit 的正常处理用返回值把错误交回去。驱动尚未执行第一次 `VMRUN` 或 `VMLAUNCH` 时，不变量已经破坏，失败返回是正确反应。
* **没有被明确处理的 VMEXIT 或 VM-exit 不得当作成功重新进入客户。**
* **性能是要求，但不拿正确性或可读性去换没有测量过的速度。**
* **一个逻辑处理器一份它独占的宿主状态，以及一份 VMCB 或一份 VMCS。** 厂商由本机 CPU 决定，一个逻辑处理器不同时持有两条路径。

## 6\. SVM、VT-x 与驱动启动

这些约束约束的是写法。字段和指令的精确定义仍以第 1 节里对应厂商的 PDF 为准，本文件故意不抄录偏移和 MSR 号。

* 同一个驱动按 CPU 厂商选择一条路径。AMD 走 SVM。Intel 走 VT-x。不在 Intel 处理器上执行 SVM 指令，也不在 AMD 处理器上执行 VMX 指令。两条路径共用第 4 节的三环命令和同一套 hypercall。
* AMD 启动顺序对照 SimpleSvm：驱动加载后启用 SVM，准备宿主保存区和 VMCB，再在逻辑处理器上 `VMRUN`。当前 Windows 成为客户。
* 先读卷二第 15 章里启用 SVM 的那一节，以及卷三里实际要执行的那条指令，再写启用顺序。`EFER.SVME` 未按手册置位时，SVM 指令会 `#UD`。
* `VMRUN` 的 VMCB 物理地址由 rAX 隐式给出，并且 4 KiB 对齐。客户的 RAX 在 VMCB 状态保存区里。不要假设 `VMRUN` 之后宿主的 RAX 仍是那个指针。
* `VMRUN` 在 SMM 处理程序里的行为是未定义的。不要在 SMM 上下文里执行它。
* `CLGI` 与 `STGI` 划定的是宿主不能随便受中断的窗口。改变 GIF 时，`INVARIANT:` 注释要写明这段窗口保护的是什么。
* 客户物理地址不是宿主物理地址。嵌套页表打开之后，两者都用第 5 节的地址类型。
* 事件注入按手册处理注入字段和退出中断信息。
* 卸载驱动时，先让全部逻辑处理器离开客户，再关闭 SVM。卸载顺序没有按手册和 SimpleSvm 的约束写清时，停下来问，不要留下仍在 `VMRUN` 中的处理器。
* 真实的中断控制器可以屏蔽、应答或复位宿主的处理器。用户没有明确要求改变中断投递之前，沿用 SimpleSvm 已有的宿主中断处理方式，不要另写一套 APIC 模拟。
* 客户的设备默认就是机器上的设备。只在任务点名的设备上做拦截。上面这条对 AMD 和 Intel 都适用。

Intel VT-x 与上面的 AMD 规则并列，不替换它们：

* Intel 启动对照 HyperDbg 的 `hyperdbg/hyperhv`：`code/vmm/vmx`、`code/vmm/ept`，以及 `code/assembly/AsmVmxOperation.asm`、`AsmVmxContextState.asm`、`AsmVmexitHandler.asm`。再按仓库里的 Intel SDM 写进 `HacDbg/`。不把 HyperDbg 的调试器、脚本引擎、`hwdbg` 或三环程序搬进来。
* 先读卷三里启用 VMX 的章节，以及卷二里 `VMXON`、`VMLAUNCH`、`VMRESUME`、`VMXOFF` 的指令说明，再写启用顺序。进入条件不成立时的异常以手册为准。
* `VMXON` 区域和 VMCS 的物理地址按手册对齐。客户通用寄存器的保存位置以手册为准。不要假设 `VMLAUNCH` 或 `VMRESUME` 之后宿主通用寄存器仍是调用前的值。
* 不要在 SMM 上下文里执行手册未允许的 VMX 操作。
* EPT 打开之后，客户物理地址不是宿主物理地址。两者都用第 5 节的地址类型。
* 事件注入按手册处理 VM-entry 与 VM-exit 的中断信息字段。
* 卸载驱动时，先让全部逻辑处理器离开客户，再执行 `VMXOFF` 并关闭 VMX。卸载顺序没有按手册和 HyperDbg 的约束写清时，停下来问，不要留下仍在 VMX 操作中的处理器。
* 用户没有明确要求改变中断投递之前，沿用 HyperDbg 已有的宿主中断处理方式，不要另写一套 APIC 模拟。

## 7\. 警告

构建命令一旦存在，警告就是错误。一次发出任何警告的构建都是失败的构建。

* 不使用 `/wd`、`-Wno-`、`#pragma warning(disable: ...)` 或编译器对等写法来放过一个警告，除非本节允许。
* 某条警告对这次合法的低层写法确实是错的，而且没有合规改法时：把抑制放在尽可能小的范围，紧挨着那一行或那一个函数，并用块注释写出一行理由。禁止文件级或工程级的成组关闭。在交给用户的说明里写上关掉了哪一条、为什么。
* 用抑制来掩盖真实问题、省时间，或因为改起来麻烦，都禁止。
* SimpleSvm 和 HyperDbg 工程里关闭过的警告号，不整组抄进本仓库。

## 8\. 依赖、参考项目与复用

硬件行为仍以第 1 节里对应厂商的手册为准。

### hyper-reV：深度复用调试器

* 路径是 `D:\\Project\\github\\hyper-reV`。这是用户自己的代码，复用优先于新写。三环命令两套平台共用，不按厂商拆开。

|hyper-reV|搬到 HacDbg|条件|
|-|-|-|
|`usermode/`|`usermode/`|整份三环调试器，含命令支持表里已支持的全部命令、hypercall 客户和日志。不删命令|
|`symbol-parser/`|`symbol-parser/`|调试器要解析 PDB 或导出时|
|`shared/hypercall/`、`shared/structures/`|`shared/`|驱动和调试器共用的 hypercall 与陷阱帧。改布局时两侧一起改|
|`hyperv-attachment` 里的 SLAT、hypercall、堆|驱动内的对应文件|先去掉「代码跑在 Hyper-V 地址空间里」的假设。AMD 的 NPT 接到本驱动自己的 VMCB 和 NPT。Intel 的 EPT 不从这里搬|

这些不搬：

* `uefi-boot/` 整棵目录，包括 `bootmgfw`、`winload`、`hvloader` 和已经编出的 `.efi`。
* `build/`、`vcpkg\_installed/`、已经编出的 `.dll`、`.exe`、`.pdb`。
* `uefi-boot/ext/edk2` 和 `uefi-boot/ext/openssl`。
* hyper-reV 的 Intel SLAT 和 `\_INTELMACHINE` 分支。那份代码假设附件跑在 Hyper-V 里。本驱动的 VT-x 对照 HyperDbg，再按第 1 节的 Intel SDM 写。

搬入时保持原文件的语言和命名，改掉旧的包含路径，保留版权和许可证声明。hyper-reV 仓库根许可证是 GPL-3.0。要换许可证时先问。不在同一次改动里为了符合第 4 节去重排刚搬入的文件。

### SimpleSvm、HyperDbg 和 pulzar

* SimpleSvm 许可证是 MIT。本机路径未确认。本仓库的 AMD 驱动启动、SVM 启用、宿主保存区、VMCB、`VMRUN` 循环和 NPT 对照它，再按 AMD 手册写进 `HacDbg/`。复制了实质片段时，保留其版权声明。
* HyperDbg 位于 `D:\\Project\\github\\HyperDbg`，仓库根许可证是 GPL-3.0。本仓库的 Intel 驱动启动、VMX 启用、VMCS、`VMXON`、`VMLAUNCH`、`VMRESUME` 循环和 EPT 对照 `hyperdbg/hyperhv`，再按 Intel SDM 写进 `HacDbg/`。复制了实质片段时，保留其版权声明。不搬 `libhyperdbg`、`hyperkd`、脚本引擎和 `hwdbg`。
* pulzar 本机路径未确认。只在对照 NPT 或 VMEXIT 分工时阅读。不把它的 UEFI loader、handoff 或固件客户搬进本仓库，也不把 Rust 译成 C。

### kdmapper

三环可以把 `HacDbg.sys` 手工映射进内核。实现是独立插件 `plugins/HacDbgMapper/`，生成 `HacDbgMapper.dll`。来源是公开的 kdmapper，以及本机 `DriverTools` 里那份 Intel 漏洞驱动封装。保留原文件语言和命名。不把漏洞驱动当生产签名方案，也不把它写进 WDK 驱动工程。三环只 `LoadLibrary` 这个插件，不静态链接它。

* 调试器启动时不映射驱动。`HacDbgQt.exe` 的「文件 → 驱动映射」打开插件窗口，由用户选择要映射的 `.sys`。
* 映射时 `DriverEntry` 的 `DRIVER_OBJECT` 为空，驱动用 `IoCreateDriver` 再建对象。
* 这条路径需要管理员，并且本机允许加载嵌入的 Intel 漏洞驱动。Memory Integrity / HVCI 会让它失败。

### 其他依赖

* 引入第三方库之前，先确认 hyper-reV 和本仓库都没有同样的功能，说明许可证。用户同意之后再加。
* 依赖一旦加入，只打开这次需要的部分。

## 9\. 工作顺序

1. 用一两句话复述任务。范围不清楚，或有两种差异很大的做法时，先问。
2. 先读要改的文件，以及同目录里的同类实现。调试器或 hypercall 先按第 8 节读 hyper-reV。涉及 SVM、VT-x、页表、描述符、APIC 或指令编码时，先查第 1 节里对应厂商的手册，再写。驱动里的 `VMRUN` 对照 SimpleSvm。驱动里的 `VMXON`、`VMLAUNCH` 和 EPT 对照 HyperDbg。
3. 动手前把假设写出来。有更简单的做法时，先说，再写代码。
4. 小改动直接做。其余先给出短步骤，每步对应一个可检查的结果。
5. 只改完成任务所需要的代码。
6. 用最少的代码解决指定的问题。不加猜测性的功能。
7. 跑第 3 节里真实存在、且与本次改动相关的检查。失败就修原因，然后重跑。没跑的检查写明原因。
8. 行为、命令、接口、目录或测试步骤有变化时，按第 10 节更新 `doc/`。
9. 说明改了什么、为什么，以及用户如何在实机上验证。
10. 停在这里。不要提交，不要推送。

边界：

|情况|做法|
|-|-|
|改任务范围内的代码、补已有测试、修本次引入的检查失败|直接做|
|往 `HacDbg.slnx` 添加任务需要的驱动或三环工程|直接加进这个解决方案|
|新增或删除第三方依赖、改 CI、改公开的 hypercall 布局、改权限或发布配置|先说明影响，等用户同意|
|任务有两种差异很大的做法|先问|
|密钥、令牌、`.env`、证书、私钥|不写入代码、提交、日志或本文件|
|发现仓库里已经提交了密钥|停下来告诉用户|

* 不用 `--no-verify` 跳过钩子，除非用户明确要求。
* 不删除或覆盖不认识的文件、分支和本地修改。
* 不执行 `reset --hard`、`clean -fd`、强推，也不改写已经推送的历史，除非用户明确要求并指出目标。

## 10\. 文档

文档放在 `doc/`。`doc/` 不暂存、不提交。其中的 AMD 手册和 Intel SDM 同样不暂存、不提交，也不要替换。

* `doc/dev/`：开发文档。
* `doc/test/`：测试方式。
* `doc/README.md`：索引，只链接上述两类文档。

改了对外行为、命令、接口、目录或测试步骤时，同时改 `doc/` 里的对应文档。只改内部实现、对外行为不变时，不改文档。

开发文档写清这些事实，不确定就写「未确认」：模块做什么，入口文件在哪，依赖什么；公开接口、数据布局和错误码；构建命令必须是仓库里真实存在的，或是本次用户明确给出的。新命令按第 4 节写 Command、Syntax、Description、Parameters、Examples。Windows 内核路径由用户手工实机验证，代理不代跑。

测试方式文档写清：测什么，在用户态还是驱动里；前置条件；步骤和期望输出；通过标准和失败时看哪里。代理不加载驱动，不执行 SVM，也不执行 VT-x。只写步骤，由用户手工在实机上做。

文档里不写密钥、令牌、证书、私钥和本机个人绝对路径。

## 11\. Git

仓库已经在用 Git 时，沿用它的分支、远程和提交习惯。没有用户的明确要求，不新建仓库，不改远程，不改写历史。

* 用户没有明确要求时，不执行 `git init`，不添加或修改 remote。
* 建库前先放好 `.gitignore`。排除构建产物、依赖目录、`.env`、密钥、证书、私钥、本地 IDE 配置和调试符号。`doc/` 整目录排除。
* 一次提交只包含当前任务的文件。提交前看 `git status` 和 `git diff`。
* `doc/` 下的文件不要提交。
* 标题格式是 `<area>: <imperative summary>`。英文，祈使语气，小写开头，不加句号，整行不超过 72 个字符。例如 `driver: enable svm on load`。
* 区域只用这些名字：`driver`、`usermode`、`workspace`。`driver` 指 `HacDbg/` 里的 WDK 驱动。`workspace` 用于本文件、解决方案和格式配置。`symbol-parser` 和 `shared` 用各自的目录名。
* 正文与标题之间空一行，72 列换行。写清改了什么、为什么。提交说明不引用本文件、评审或对话。
* 一次提交只包含一个逻辑改动。
* 只有用户明确说实机验证通过之后，才执行 `git commit` 和 `git push`。
* 用户只说「提交」但没说实机已通过时，先问是否已在实机验证通过。
* 真正执行提交前，把文件列表和提交说明草稿发给用户。用户确认后再执行。
* 推送前确认当前分支。不强推。不推到 `main` 或 `master`，除非用户在同一条消息里点名那条分支。

## 12\. 测试

* **Windows 内核开发不自主测试。** 驱动、SVM 和 VT-x 路径，代理只负责写代码。不加载，不安装，不在本机或虚拟机里运行，也不把编译成功写成测试通过。
* 实机验证由用户手工做。代理把步骤写进 `doc/test/`，并在回复里给出：在哪一台机器或虚拟机上做、操作顺序、期望看到什么、失败时看哪里。写完步骤就停，等用户验证。
* 三环调试器里不接触驱动、不发 hypercall、不读内核的纯界面或命令解析，只有用户明确要求运行时才可以运行。会连上内核的调试命令同样只写步骤。
* 这块代码已有、且属于用户态纯逻辑的测试时，为本次行为补上或改好对应测试。内核路径不为了这次任务新搭测试框架，也不自己跑。
* 仓库没有测试框架时，不要为了这一次任务新搭一套。
* 声称某项编译检查通过之前，先实际运行并把结果写出来。内核验证没有跑，就写明交给用户手工验证。

## 13\. 回复

* 用户用中文时用中文回复。
* 先给结果：改了哪些文件、检查跑了什么、结果是什么。
* 接着给实机验证步骤。
* 文档有更新时，写出更新了哪份文档。
* 关掉过警告时，写出警告号和理由。

## 14\. 完成的定义

可以称为做完，仅当下面全部成立：

1. 改动范围与用户要求一致。diff 里没有无关改动，也没有 `.efi` 或 UEFI 加载代码。
2. 仓库里已经有、且与本次改动相关的构建或检查已经运行，警告为零，并把结果写了出来。还没有这样的命令时，明确写出「未构建」，不声称能编译。
3. 本仓库新写的 C 符合第 4 节和第 5 节。从 hyper-reV 搬入且按第 8 节保持原样的文件不按第 4 节重写。
4. 没有引入 `TODO`、桩、死代码或注释掉的代码。
5. 本次若抑制了警告，抑制范围是最小的，旁边有理由，并且已在回复里说明。
6. 行为、命令、接口或测试步骤有变化时，`doc/` 里对应文档已更新，且没有把 `doc/` 放进暂存区。
7. 已经写清交给用户手工做的实机验证步骤。代理没有代跑驱动、SVM 或 VT-x。
8. 还没有 commit，也没有 push。

任何一条不成立，任务就没有完成，要明确说出来。

