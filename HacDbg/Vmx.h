/**
 * @file Vmx.h
 * @brief VT-x definitions and processor lifecycle interfaces.
 *
 * @author HacDbg
 */

#pragma once

#include "Guest.h"

//
// VMX capability MSRs. IA32_VMX_BASIC bit 55 selects the TRUE_* control MSRs.
//
#define VMX_MSR_BASIC                    0x480ull
//
// IA32_VMX_EXIT_CTLS2. The next architectural MSR is IA32_A_PMC0 at 4C1H.
//
#define VMX_MSR_VMX_LAST                 0x493ull
#define VMX_MSR_PINBASED_CTLS            0x481ull
#define VMX_MSR_PROCBASED_CTLS           0x482ull
#define VMX_MSR_EXIT_CTLS                0x483ull
#define VMX_MSR_ENTRY_CTLS               0x484ull
#define VMX_MSR_MISC                     0x485ull
#define VMX_MSR_CR0_FIXED0               0x486ull
#define VMX_MSR_CR0_FIXED1               0x487ull
#define VMX_MSR_CR4_FIXED0               0x488ull
#define VMX_MSR_CR4_FIXED1               0x489ull
#define VMX_MSR_PROCBASED_CTLS2          0x48Bull
#define VMX_MSR_EPT_VPID_CAP             0x48Cull
#define VMX_MSR_TRUE_PINBASED_CTLS       0x48Dull
#define VMX_MSR_TRUE_PROCBASED_CTLS      0x48Eull
#define VMX_MSR_TRUE_EXIT_CTLS           0x48Full
#define VMX_MSR_TRUE_ENTRY_CTLS          0x490ull
#define VMX_MSR_FEATURE_CONTROL          0x3Aull
#define VMX_MSR_TIME_STAMP_COUNTER       0x10ull
#define VMX_MSR_TSC_ADJUST               0x3Bull
#define VMX_MSR_TSC_DEADLINE             0x6E0ull
#define VMX_MSR_PERF_GLOBAL_CTRL         0x38Full

#define VMX_BASIC_TRUE_CONTROLS          (1ull << 55)
#define VMX_BASIC_MEMORY_TYPE_SHIFT      50
#define VMX_BASIC_MEMORY_TYPE_WB         6ull
#define VMX_FEATURE_CONTROL_LOCK         (1ull << 0)
#define VMX_FEATURE_CONTROL_OUTSIDE_SMX  (1ull << 2)
#define VMX_CR4_VMXE                     (1ull << 13)

//
// Primary processor-based VM-execution controls.
//
#define VMX_PROC_USE_TSC_OFFSETTING      (1u << 3)

//
// Primary VM-exit controls. Bit 12 loads IA32_PERF_GLOBAL_CTRL from the
// host field. Bit 30 saves it into the guest field.
//
#define VMX_EXIT_LOAD_PERF_GLOBAL        (1u << 12)
#define VMX_EXIT_SAVE_PERF_GLOBAL        (1u << 30)

//
// VM-entry control. Bit 13 loads IA32_PERF_GLOBAL_CTRL from the guest field.
//
#define VMX_ENTRY_LOAD_PERF_GLOBAL       (1u << 13)
#define VMX_PROC_HLT_EXITING             (1u << 7)
#define VMX_PROC_INVLPG_EXITING          (1u << 9)
#define VMX_PROC_RDTSC_EXITING           (1u << 12)
#define VMX_PROC_CR3_LOAD_EXITING        (1u << 15)
#define VMX_PROC_CR3_STORE_EXITING       (1u << 16)
#define VMX_PROC_IO_EXITING              (1u << 24)
#define VMX_PROC_USE_IO_BITMAPS          (1u << 25)
#define VMX_PROC_MONITOR_TRAP_FLAG       (1u << 27)
#define VMX_PROC_USE_MSR_BITMAPS         (1u << 28)
#define VMX_PROC_ACTIVATE_SECONDARY      (1u << 31)

//
// Secondary processor-based VM-execution controls.
//
#define VMX_PROC2_ENABLE_EPT             (1u << 1)
#define VMX_PROC2_ENABLE_RDTSCP          (1u << 3)
#define VMX_PROC2_ENABLE_VPID            (1u << 5)
#define VMX_PROC2_ENABLE_INVPCID         (1u << 12)
#define VMX_PROC2_CONCEAL_VMX_FROM_PT    (1u << 19)
#define VMX_PROC2_ENABLE_XSAVES          (1u << 20)

#define VMX_PIN_EXTERNAL_INT_EXITING     (1u << 0)
#define VMX_PIN_NMI_EXITING              (1u << 3)
#define VMX_PIN_PREEMPTION_TIMER         (1u << 6)

#define VMX_EXIT_SAVE_DEBUG              (1u << 2)
#define VMX_EXIT_HOST_ADDR_SPACE_SIZE    (1u << 9)
#define VMX_EXIT_SAVE_EFER               (1u << 20)
#define VMX_EXIT_LOAD_EFER               (1u << 21)
#define VMX_EXIT_CONCEAL_VMX_FROM_PT     (1u << 24)
#define VMX_EXIT_LOAD_CET                (1u << 28)

#define VMX_ENTRY_LOAD_DEBUG             (1u << 2)
#define VMX_ENTRY_IA32E_MODE_GUEST       (1u << 9)
#define VMX_ENTRY_LOAD_EFER              (1u << 15)
#define VMX_ENTRY_CONCEAL_VMX_FROM_PT    (1u << 17)
#define VMX_ENTRY_LOAD_CET               (1u << 20)

//
// VMCS field encodings from Appendix B.
//
#define VMCS_CTRL_VPID                   0x00000000ull
#define VMCS_GUEST_ES_SELECTOR           0x00000800ull
#define VMCS_GUEST_CS_SELECTOR           0x00000802ull
#define VMCS_GUEST_SS_SELECTOR           0x00000804ull
#define VMCS_GUEST_DS_SELECTOR           0x00000806ull
#define VMCS_GUEST_FS_SELECTOR           0x00000808ull
#define VMCS_GUEST_GS_SELECTOR           0x0000080Aull
#define VMCS_GUEST_LDTR_SELECTOR         0x0000080Cull
#define VMCS_GUEST_TR_SELECTOR           0x0000080Eull
#define VMCS_HOST_ES_SELECTOR            0x00000C00ull
#define VMCS_HOST_CS_SELECTOR            0x00000C02ull
#define VMCS_HOST_SS_SELECTOR            0x00000C04ull
#define VMCS_HOST_DS_SELECTOR            0x00000C06ull
#define VMCS_HOST_FS_SELECTOR            0x00000C08ull
#define VMCS_HOST_GS_SELECTOR            0x00000C0Aull
#define VMCS_HOST_TR_SELECTOR            0x00000C0Cull
#define VMCS_CTRL_MSR_BITMAP             0x00002004ull
#define VMCS_CTRL_TSC_OFFSET             0x00002010ull
#define VMCS_GUEST_PERF_GLOBAL_CTRL      0x00002808ull
#define VMCS_HOST_PERF_GLOBAL_CTRL       0x00002C04ull
#define VMCS_CTRL_EPT_POINTER            0x0000201Aull
#define VMCS_GUEST_VMCS_LINK_POINTER     0x00002800ull
#define VMCS_GUEST_DEBUGCTL              0x00002802ull
#define VMCS_GUEST_PAT                   0x00002804ull
#define VMCS_GUEST_EFER                  0x00002806ull
#define VMCS_HOST_PAT                    0x00002C00ull
#define VMCS_HOST_EFER                   0x00002C02ull
#define VMCS_CTRL_PIN_BASED              0x00004000ull
#define VMCS_CTRL_PROCESSOR_BASED        0x00004002ull
#define VMCS_CTRL_EXCEPTION_BITMAP       0x00004004ull
#define VMCS_CTRL_VMEXIT                 0x0000400Cull
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT 0x0000400Eull
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT  0x00004010ull
#define VMCS_CTRL_VMENTRY                0x00004012ull
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT 0x00004014ull
#define VMCS_CTRL_VMENTRY_INTERRUPTION   0x00004016ull
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERROR 0x00004018ull
#define VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH 0x0000401Aull
#define VMCS_CTRL_PROCESSOR_BASED2       0x0000401Eull
#define VMCS_VM_INSTRUCTION_ERROR        0x00004400ull
#define VMCS_EXIT_REASON                 0x00004402ull
#define VMCS_EXIT_INSTRUCTION_LENGTH     0x0000440Cull
#define VMCS_GUEST_ES_LIMIT              0x00004800ull
#define VMCS_GUEST_CS_LIMIT              0x00004802ull
#define VMCS_GUEST_SS_LIMIT              0x00004804ull
#define VMCS_GUEST_DS_LIMIT              0x00004806ull
#define VMCS_GUEST_FS_LIMIT              0x00004808ull
#define VMCS_GUEST_GS_LIMIT              0x0000480Aull
#define VMCS_GUEST_LDTR_LIMIT            0x0000480Cull
#define VMCS_GUEST_TR_LIMIT              0x0000480Eull
#define VMCS_GUEST_GDTR_LIMIT            0x00004810ull
#define VMCS_GUEST_IDTR_LIMIT            0x00004812ull
#define VMCS_GUEST_ES_ACCESS             0x00004814ull
#define VMCS_GUEST_CS_ACCESS             0x00004816ull
#define VMCS_GUEST_SS_ACCESS             0x00004818ull
#define VMCS_GUEST_DS_ACCESS             0x0000481Aull
#define VMCS_GUEST_FS_ACCESS             0x0000481Cull
#define VMCS_GUEST_GS_ACCESS             0x0000481Eull
#define VMCS_GUEST_LDTR_ACCESS           0x00004820ull
#define VMCS_GUEST_TR_ACCESS             0x00004822ull
#define VMCS_GUEST_INTERRUPTIBILITY      0x00004824ull
#define VMCS_GUEST_ACTIVITY_STATE        0x00004826ull
#define VMCS_GUEST_PREEMPTION_TIMER      0x0000482Eull
#define VMCS_GUEST_SYSENTER_CS           0x0000482Aull
#define VMCS_CTRL_CR0_MASK               0x00006000ull
#define VMCS_CTRL_CR4_MASK               0x00006002ull
#define VMCS_CTRL_CR0_READ_SHADOW        0x00006004ull
#define VMCS_CTRL_CR4_READ_SHADOW        0x00006006ull
#define VMCS_EXIT_QUALIFICATION          0x00006400ull
#define VMCS_GUEST_PHYSICAL_ADDRESS      0x00002400ull
#define VMCS_GUEST_CR0                   0x00006800ull
#define VMCS_GUEST_CR3                   0x00006802ull
#define VMCS_GUEST_CR4                   0x00006804ull
#define VMCS_GUEST_ES_BASE               0x00006806ull
#define VMCS_GUEST_CS_BASE               0x00006808ull
#define VMCS_GUEST_SS_BASE               0x0000680Aull
#define VMCS_GUEST_DS_BASE               0x0000680Cull
#define VMCS_GUEST_FS_BASE               0x0000680Eull
#define VMCS_GUEST_GS_BASE               0x00006810ull
#define VMCS_GUEST_LDTR_BASE             0x00006812ull
#define VMCS_GUEST_TR_BASE               0x00006814ull
#define VMCS_GUEST_GDTR_BASE             0x00006816ull
#define VMCS_GUEST_IDTR_BASE             0x00006818ull
#define VMCS_GUEST_DR7                   0x0000681Aull
#define VMCS_GUEST_RSP                   0x0000681Cull
#define VMCS_GUEST_RIP                   0x0000681Eull
#define VMCS_GUEST_RFLAGS                0x00006820ull
#define VMCS_GUEST_PENDING_DEBUG         0x00006822ull
#define VMCS_GUEST_SYSENTER_ESP          0x00006824ull
#define VMCS_GUEST_SYSENTER_EIP          0x00006826ull
#define VMCS_HOST_CR0                    0x00006C00ull
#define VMCS_HOST_CR3                    0x00006C02ull
#define VMCS_HOST_CR4                    0x00006C04ull
#define VMCS_HOST_FS_BASE                0x00006C06ull
#define VMCS_HOST_GS_BASE                0x00006C08ull
#define VMCS_HOST_TR_BASE                0x00006C0Aull
#define VMCS_HOST_GDTR_BASE              0x00006C0Cull
#define VMCS_HOST_IDTR_BASE              0x00006C0Eull
#define VMCS_HOST_SYSENTER_CS            0x00004C00ull
#define VMCS_HOST_SYSENTER_ESP           0x00006C10ull
#define VMCS_HOST_SYSENTER_EIP           0x00006C12ull
#define VMCS_HOST_RSP                    0x00006C14ull
#define VMCS_HOST_RIP                    0x00006C16ull

//
// Basic exit reasons from Appendix C.
//
#define VMX_EXIT_CPUID                   10u
#define VMX_EXIT_GETSEC                  11u
#define VMX_EXIT_INVD                    13u
#define VMX_EXIT_VMCALL                  18u
#define VMX_EXIT_VMCLEAR                 19u
#define VMX_EXIT_VMLAUNCH                20u
#define VMX_EXIT_VMPTRLD                 21u
#define VMX_EXIT_VMPTRST                 22u
#define VMX_EXIT_VMREAD                  23u
#define VMX_EXIT_VMRESUME                24u
#define VMX_EXIT_VMWRITE                 25u
#define VMX_EXIT_VMXOFF                  26u
#define VMX_EXIT_VMXON                   27u
#define VMX_EXIT_CR_ACCESS               28u
#define VMX_EXIT_RDMSR                   31u
#define VMX_EXIT_WRMSR                   32u
#define VMX_EXIT_MONITOR_TRAP            37u
#define VMX_EXIT_EPT_VIOLATION           48u
#define VMX_EXIT_EPT_MISCONFIG           49u
#define VMX_EXIT_INVEPT                  50u
#define VMX_EXIT_PREEMPTION_TIMER        52u
#define VMX_EXIT_INVVPID                 53u
#define VMX_EXIT_XSETBV                  55u
#define VMX_EXIT_REASON_MASK             0xFFFFu
#define VMX_EXIT_ENTRY_FAILURE           (1u << 31)

#define VMX_INTERRUPTION_VALID           (1ull << 31)
#define VMX_INTERRUPTION_HARDWARE        (3ull << 8)
#define VMX_INTERRUPTION_ERROR_CODE      (1ull << 11)
#define VMX_VECTOR_UD                    6u
#define VMX_VECTOR_GP                    13u

#define VMX_EPT_CAP_WALK4                (1ull << 6)
#define VMX_EPT_CAP_WB                   (1ull << 14)
#define VMX_EPT_CAP_2MB                  (1ull << 16)
#define VMX_EPT_CAP_INVEPT               (1ull << 20)
#define VMX_EPT_CAP_INVEPT_SINGLE        (1ull << 25)
#define VMX_INVEPT_SINGLE_CONTEXT        1u
#define VMX_INVEPT_ALL_CONTEXT           2u

/**
 * @brief Per-logical-processor VT-x state.
 *
 * @details Register storage starts at offset 0 so the exit stub can save
 * general-purpose registers without a second indirection.
 */
typedef struct _VMX_PROCESSOR_CONTEXT
{
    HACDBG_GUEST_REGISTERS Registers;
    UINT64 GuestCr3;
    UINT64 GuestRip;
    UINT64 GuestRsp;
    UINT64 GuestRflags;
    UINT64 HostRsp;
    UINT64 VmxonPa;
    UINT64 VmcsPa;
    UINT64 MsrBitmapPa;
    PVOID Vmxon;
    PVOID Vmcs;
    PVOID MsrBitmap;
    PVOID HostStack;
    PVOID VmxonAllocation;
    PVOID VmcsAllocation;
    PVOID MsrBitmapAllocation;
    PVOID HostStackAllocation;
    UINT64 TscBeforeVmxon;
    UINT64 TscAfterVmxon;
    UINT64 VpRuntime;
    volatile LONG InveptRequested;
    UINT16 Vpid;
    UINT8 Virtualized;
    UINT8 StopRequested;
    UINT8 LaunchCompleted;
    UINT8 EptEnabled;
    UINT32 InstructionError;
    UINT64 TscAtExit;
    UINT64 TscOffset;
    UINT64 LastGuestTsc;
    UINT64 NativeCpuidCost;
    UINT64 HardwareTransition;
    UINT64 GuestTscAdjust;
    UINT8 TscOffsetting;
    UINT8 TscDeadlineArmed;
    UINT8 HostDeadlineValid;
    UINT64 GuestTscDeadline;
    UINT64 HostTscDeadline;
    UINT16 SavedGdtrLimit;
    UINT16 SavedIdtrLimit;
    UINT64 SavedGdtrBase;
    UINT64 SavedIdtrBase;
    UINT8 DescriptorTablesSaved;
    UINT64 GuestTscOffset;
    UINT64 TscBias;
    UINT8 PreemptionTimerArmed;
} VMX_PROCESSOR_CONTEXT;

NTSTATUS
/**
 * @brief Checks Intel VMX, EPT, and IA32_FEATURE_CONTROL on this processor.
 *
 * @return STATUS_SUCCESS when VT-x can be enabled.
 */
VmxCheckSupport(
    VOID
    );

NTSTATUS
/**
 * @brief Reserves shared VT-x state. The MSR bitmap is per processor.
 *
 * @return STATUS_SUCCESS. There is no cross-processor allocation.
 */
VmxInitializeShared(
    VOID
    );

VOID
/**
 * @brief Releases shared VT-x state.
 */
VmxCleanupShared(
    VOID
    );

ULONG
/**
 * @brief Returns the shared-initialization failure detail.
 *
 * @return Always 0. MSR bitmaps are allocated with each processor.
 */
VmxGetSharedFailureDetail(
    VOID
    );

NTSTATUS
/**
 * @brief Virtualizes every active logical processor.
 *
 * @return STATUS_SUCCESS when every processor entered VMX non-root operation.
 */
VmxStartAllProcessors(
    VOID
    );

VOID
/**
 * @brief Brings every virtualized processor out of VMX non-root operation.
 */
VmxStopAllProcessors(
    VOID
    );

NTSTATUS
/**
 * @brief Enters VMX non-root operation again after the processors were stopped.
 *
 * @return STATUS_SUCCESS when every processor resumed as a guest.
 */
VmxRestartAllProcessors(
    VOID
    );

VOID
/**
 * @brief Frees every processor context allocated by VmxStartAllProcessors.
 */
VmxFreeAllProcessors(
    VOID
    );

VOID
/**
 * @brief Asks every processor to invalidate EPT translations on its next exit.
 */
VmxFlushAllProcessors(
    VOID
    );

VOID
/**
 * @brief Clears CPUID.1 ECX[5] when virtualization hiding is enabled.
 *
 * @param Leaf CPUID leaf that produced Registers.
 * @param Registers Guest EAX/EBX/ECX/EDX to edit.
 */
VmxConcealCpuid(
    _In_ UINT32 Leaf,
    _Inout_ HACDBG_GUEST_REGISTERS* Registers
    );

BOOLEAN
/**
 * @brief Handles one VM exit on the current processor.
 *
 * @param ProcessorContext State of the processor that exited.
 *
 * @return TRUE when the processor has left VMX operation.
 */
VmxHandleVmExit(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    );

VMX_PROCESSOR_CONTEXT*
/**
 * @brief Leaves VMX after VMRESUME failed and prepares the guest return frame.
 *
 * @param ProcessorContext State of the processor that failed to resume.
 *
 * @return ProcessorContext, so the exit stub can keep using it in RAX.
 */
VmxAbortToGuest(
    _Inout_ VMX_PROCESSOR_CONTEXT* ProcessorContext
    );

EXTERN_C VOID
VmxLaunchVm(
    _In_ VMX_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ UINT64 HostRsp
    );

EXTERN_C VOID
VmxExitEntry(
    VOID
    );

EXTERN_C UINT8
HacDbgVmxOn(
    _In_ UINT64* VmxonPa
    );

EXTERN_C UINT8
VmxClear(
    _In_ UINT64* VmcsPa
    );

EXTERN_C UINT8
VmxPtrld(
    _In_ UINT64* VmcsPa
    );

EXTERN_C VOID
HacDbgVmxOff(
    VOID
    );

EXTERN_C VOID
/**
 * @brief Loads a 10-byte GDTR image captured before the first VM-exit.
 *
 * @param TableRegister Pointer to a packed limit followed by a 64-bit base.
 */
VmxWriteGdtr(
    _In_ const VOID* TableRegister
    );

EXTERN_C VOID
/**
 * @brief Loads a 10-byte IDTR image captured before the first VM-exit.
 *
 * @param TableRegister Pointer to a packed limit followed by a 64-bit base.
 */
VmxWriteIdtr(
    _In_ const VOID* TableRegister
    );

EXTERN_C UINT8
VmxInvept(
    _In_ UINT64 Type,
    _In_ UINT64 Eptp
    );

EXTERN_C UINT16
VmxReadTr(
    VOID
    );

EXTERN_C UINT16
VmxReadLdtr(
    VOID
    );
