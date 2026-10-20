/**
 * @file Svm.h
 * @brief SVM definitions and processor lifecycle interfaces.
 *
 * @author HacDbg
 */

#pragma once

#include "Types.h"

//
// See "SVM Related MSRs".
//
#define SVM_MSR_VM_CR                         0xc0010114
#define SVM_MSR_VM_HSAVE_PA                   0xc0010117

#define SVM_VM_CR_SVMDIS                      (1ull << 4)

//
// See "VMCB Layout, Control Area".
//
#define SVM_INTERCEPT_MISC1_CPUID             (1ull << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT          (1ull << 28)
#define SVM_INTERCEPT_MISC2_VMRUN              (1ull << 0)

//
// See "VMCB Layout, State Save Area".
//
#define SVM_NP_ENABLE                          (1ull << 0)

#define SVM_EXIT_CPUID                        0x0072ull
#define SVM_EXIT_MSR                          0x007cull
#define SVM_EXIT_NPF                          0x0400ull

#define SVM_TLB_CONTROL_FLUSH_GUEST           3ull

#define HACDBG_STOP_CPUID_LEAF                0x48444300u
#define HACDBG_STOP_CPUID_SUBLEAF             0x44424748u
#define HACDBG_FLUSH_CPUID_LEAF               0x48444301u
#define HACDBG_FLUSH_CPUID_SUBLEAF            0x464C5348u

#pragma pack(push, 1)

typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;
    UINT16 InterceptCrWrite;
    UINT16 InterceptDrRead;
    UINT16 InterceptDrWrite;
    UINT32 InterceptException;
    UINT32 InterceptMisc1;
    UINT32 InterceptMisc2;
    UINT8 Reserved1[0x3c - 0x14];
    UINT16 PauseFilterThreshold;
    UINT16 PauseFilterCount;
    UINT64 IopmBasePa;
    UINT64 MsrpmBasePa;
    UINT64 TscOffset;
    UINT32 GuestAsid;
    UINT32 TlbControl;
    UINT64 VIntr;
    UINT64 InterruptShadow;
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT64 ExitIntInfo;
    UINT64 NpEnable;
    UINT64 AvicApicBar;
    UINT64 GuestPaOfGhcb;
    UINT64 EventInj;
    UINT64 NCr3;
    UINT64 LbrVirtualizationEnable;
    UINT64 VmcbClean;
    UINT64 NRip;
    UINT8 NumOfBytesFetched;
    UINT8 GuestInstructionBytes[15];
    UINT64 AvicApicBackingPagePointer;
    UINT64 Reserved2;
    UINT64 AvicLogicalTablePointer;
    UINT64 AvicPhysicalTablePointer;
    UINT64 Reserved3;
    UINT64 VmcbSaveStatePointer;
    UINT8 Reserved4[0x400 - 0x110];
} VMCB_CONTROL_AREA;

typedef struct _VMCB_STATE_SAVE_AREA
{
    UINT16 EsSelector;
    UINT16 EsAttrib;
    UINT32 EsLimit;
    UINT64 EsBase;
    UINT16 CsSelector;
    UINT16 CsAttrib;
    UINT32 CsLimit;
    UINT64 CsBase;
    UINT16 SsSelector;
    UINT16 SsAttrib;
    UINT32 SsLimit;
    UINT64 SsBase;
    UINT16 DsSelector;
    UINT16 DsAttrib;
    UINT32 DsLimit;
    UINT64 DsBase;
    UINT16 FsSelector;
    UINT16 FsAttrib;
    UINT32 FsLimit;
    UINT64 FsBase;
    UINT16 GsSelector;
    UINT16 GsAttrib;
    UINT32 GsLimit;
    UINT64 GsBase;
    UINT16 GdtrSelector;
    UINT16 GdtrAttrib;
    UINT32 GdtrLimit;
    UINT64 GdtrBase;
    UINT16 LdtrSelector;
    UINT16 LdtrAttrib;
    UINT32 LdtrLimit;
    UINT64 LdtrBase;
    UINT16 IdtrSelector;
    UINT16 IdtrAttrib;
    UINT32 IdtrLimit;
    UINT64 IdtrBase;
    UINT16 TrSelector;
    UINT16 TrAttrib;
    UINT32 TrLimit;
    UINT64 TrBase;
    UINT8 Reserved1[0x0cb - 0x0a0];
    UINT8 Cpl;
    UINT32 Reserved2;
    UINT64 Efer;
    UINT8 Reserved3[0x148 - 0x0d8];
    UINT64 Cr4;
    UINT64 Cr3;
    UINT64 Cr0;
    UINT64 Dr7;
    UINT64 Dr6;
    UINT64 Rflags;
    UINT64 Rip;
    UINT8 Reserved4[0x1d8 - 0x180];
    UINT64 Rsp;
    UINT8 Reserved5[0x1f8 - 0x1e0];
    UINT64 Rax;
    UINT64 Star;
    UINT64 LStar;
    UINT64 CStar;
    UINT64 SfMask;
    UINT64 KernelGsBase;
    UINT64 SysenterCs;
    UINT64 SysenterEsp;
    UINT64 SysenterEip;
    UINT64 Cr2;
    UINT8 Reserved6[0x268 - 0x248];
    UINT64 GPat;
    UINT64 DbgCtl;
    UINT64 BrFrom;
    UINT64 BrTo;
    UINT64 LastExcepFrom;
    UINT64 LastExcepTo;
} VMCB_STATE_SAVE_AREA;

typedef struct _VMCB
{
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UINT8 Reserved[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB;

#pragma pack(pop)

C_ASSERT(sizeof(VMCB_CONTROL_AREA) == 0x400);
C_ASSERT(sizeof(VMCB_STATE_SAVE_AREA) == 0x298);
C_ASSERT(sizeof(VMCB) == 0x1000);
C_ASSERT(FIELD_OFFSET(VMCB, StateSaveArea) == 0x400);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, ExitCode) == 0x070);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NpEnable) == 0x090);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NCr3) == 0x0b0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NRip) == 0x0c8);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Efer) == 0x0d0);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cr3) == 0x150);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rflags) == 0x170);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rip) == 0x178);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rsp) == 0x1d8);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rax) == 0x1f8);

/**
 * @brief Architecturally defined general-purpose register state.
 */
typedef struct _SVM_GUEST_REGISTERS
{
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rsp;
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
} SVM_GUEST_REGISTERS;

typedef struct _SVM_GUEST_CONTEXT
{
    VMCB* Vmcb;
    SVM_GUEST_REGISTERS* Registers;
    struct _SVM_PROCESSOR_CONTEXT* ProcessorContext;
    UINT8 Reserved[8];
} SVM_GUEST_CONTEXT;

/**
 * @brief Per-logical-processor SVM state.
 */
typedef struct _SVM_PROCESSOR_CONTEXT
{
    VMCB* GuestVmcb;
    VMCB* HostVmcb;
    VOID* HostSaveArea;
    VOID* HostStack;
    VOID* GuestVmcbAllocation;
    VOID* HostVmcbAllocation;
    VOID* HostSaveAreaAllocation;
    VOID* HostStackAllocation;
    UINT64 GuestVmcbPa;
    UINT64 HostVmcbPa;
    UINT8 Virtualized;
    UINT8 StopRequested;
    UINT8 LaunchCompleted;
    UINT8 Reserved[5];
    SVM_GUEST_REGISTERS Registers;
    volatile LONG TlbFlushRequested;
} SVM_PROCESSOR_CONTEXT;

NTSTATUS
/**
 * @brief Allocates this processor's VMCB, host save area, and host stack.
 *
 * @param ProcessorContext Receives the initialized context.
 * @param NptRootPa Physical address of the primary NPT root.
 * @param GuestAsid ASID assigned to this guest.
 *
 * @return STATUS_SUCCESS on success; otherwise an NTSTATUS error.
 */
SvmInitialize(
    _Out_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT64 NptRootPa,
    _In_ UINT64 GuestAsid
    );

VOID
/**
 * @brief Saves the current processor state into the guest VMCB.
 *
 * @param ProcessorContext Processor context to prepare.
 * @param Context Captured guest state that VMRUN resumes.
 */
SvmPrepareLaunch(
    _Inout_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ const CONTEXT* Context
    );

BOOLEAN
/**
 * @brief Handles one VMEXIT.
 *
 * @param GuestContext Current guest context.
 *
 * @return TRUE to leave the VMRUN loop; FALSE to resume the guest.
 */
SvmHandleVmExit(
    _Inout_ SVM_GUEST_CONTEXT* GuestContext
    );

NTSTATUS
/**
 * @brief Checks AMD SVM, NPT, and VM_CR requirements on this processor.
 *
 * @return STATUS_SUCCESS when SVM can be enabled.
 */
SvmCheckSupport(
    VOID
    );

NTSTATUS
/**
 * @brief Allocates and initializes the shared MSR permissions map.
 *
 * @return STATUS_SUCCESS on success; otherwise an NTSTATUS error.
 */
SvmInitializeShared(
    VOID
    );

VOID
/**
 * @brief Releases the shared MSR permissions map.
 */
SvmCleanupShared(
    VOID
    );

ULONG
/**
 * @brief Returns the shared-initialization failure detail.
 *
 * @return 0 on success, or the failed sub-step from SvmInitializeShared.
 */
SvmGetSharedFailureDetail(
    VOID
    );

VOID
/**
 * @brief Sets EFER.SVME on the current processor.
 */
SvmEnable(
    VOID
    );

VOID
/**
 * @brief Clears EFER.SVME and VM_HSAVE_PA on the current processor.
 */
SvmDisable(
    VOID
    );

VOID
/**
 * @brief Requests a TLB flush on every registered processor.
 */
SvmFlushAllProcessors(
    VOID
    );
