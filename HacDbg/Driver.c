/**
 * @file Driver.c
 * @brief Driver entry point and processor lifecycle.
 *
 * @author HacDbg
 */

#include <ntifs.h>

#include "Config.h"
#include "Hypercall.h"
#include "Logs.h"
#include "PhysicalMemory.h"
#include "Debug.h"
#include "../shared/hypercall/control.h"
#if HACDBG_BACKEND_INTEL
#include "Vmx.h"
#include "Ept.h"
#define HACDBG_CHECK_SUPPORT     VmxCheckSupport
#define HACDBG_PAGING_INITIALIZE EptInitialize
#define HACDBG_PAGING_CLEANUP    EptCleanup
#define HACDBG_SHARED_INITIALIZE VmxInitializeShared
#define HACDBG_SHARED_CLEANUP    VmxCleanupShared
#define HACDBG_SHARED_DETAIL     VmxGetSharedFailureDetail
#define HACDBG_START_ALL         VmxStartAllProcessors
#define HACDBG_STOP_ALL          VmxStopAllProcessors
#define HACDBG_RESTART_ALL       VmxRestartAllProcessors
#define HACDBG_FREE_ALL          VmxFreeAllProcessors
#define HACDBG_VENDOR_NAME       "Intel VT-x"
#else
#include "Svm.h"
#include "Npt.h"
#define HACDBG_CHECK_SUPPORT     SvmCheckSupport
#define HACDBG_PAGING_INITIALIZE NptInitialize
#define HACDBG_PAGING_CLEANUP    NptCleanup
#define HACDBG_SHARED_INITIALIZE SvmInitializeShared
#define HACDBG_SHARED_CLEANUP    SvmCleanupShared
#define HACDBG_SHARED_DETAIL     SvmGetSharedFailureDetail
#define HACDBG_START_ALL         SvmStartAllProcessors
#define HACDBG_STOP_ALL          SvmStopAllProcessors
#define HACDBG_RESTART_ALL       SvmRestartAllProcessors
#define HACDBG_FREE_ALL          SvmFreeAllProcessors
#define HACDBG_VENDOR_NAME       "AMD SVM"
#endif

#define HACDBG_MAX_PROCESSORS 256

C_ASSERT(sizeof(HACDBG_VERSION_INFO) == 0x30);
C_ASSERT(sizeof(HACDBG_VERSION_STRING) <= HACDBG_VERSION_STRING_SIZE);

#if HACDBG_DIAGNOSTICS
#define HACDBG_LOAD_STAGE_START          0
#define HACDBG_LOAD_STAGE_SVM_SUPPORT    1
#define HACDBG_LOAD_STAGE_PHYSICAL_MEMORY 2
#define HACDBG_LOAD_STAGE_NPT            3
#define HACDBG_LOAD_STAGE_LOGS           4
#define HACDBG_LOAD_STAGE_MSRPM          5
#define HACDBG_LOAD_STAGE_DEVICE         6
#define HACDBG_LOAD_STAGE_POWER          7
#define HACDBG_LOAD_STAGE_PROCESSORS     8
#define HACDBG_LOAD_STAGE_COMPLETE       9
#define HACDBG_REGISTRY_PATH_CHARS       512
#endif

static PVOID g_PowerCallbackRegistration;
static BOOLEAN g_VirtualizationSuspended;
static PDEVICE_OBJECT g_DeviceObject;

#if !HACDBG_BACKEND_INTEL
EXTERN_C VOID
SvmLaunchVm(
    _In_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ PVOID HostStackTop
    );

static SVM_PROCESSOR_CONTEXT* g_Contexts[HACDBG_MAX_PROCESSORS];
static ULONG g_ProcessorCount;
#endif

DRIVER_INITIALIZE DriverEntry;

#if HACDBG_DIAGNOSTICS
// 把加载阶段和状态写入服务注册表，便于失败后定位。
static VOID
HacDbgWriteRegistryDword(
    _In_ PCUNICODE_STRING RegistryPath,
    _In_ PCWSTR ValueName,
    _In_ ULONG Value
    )
{
    WCHAR path[HACDBG_REGISTRY_PATH_CHARS];

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL ||
        RegistryPath->Length >= sizeof(path))
    {
        return;
    }

    RtlCopyMemory(path, RegistryPath->Buffer, RegistryPath->Length);
    path[RegistryPath->Length / sizeof(WCHAR)] = L'\0';

    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, path, ValueName,
                          REG_DWORD, &Value, sizeof(Value));
}

// 记录当前阶段和 NTSTATUS。
static VOID
HacDbgRecordLoadStatus(
    _In_ PCUNICODE_STRING RegistryPath,
    _In_ ULONG Stage,
    _In_ NTSTATUS Status
    )
{
    HacDbgWriteRegistryDword(RegistryPath, L"LastLoadStage", Stage);
    HacDbgWriteRegistryDword(RegistryPath, L"LastLoadStatus", (ULONG)Status);
}

// 记录阶段内部的细分失败原因。
static VOID
HacDbgRecordLoadDetail(
    _In_ PCUNICODE_STRING RegistryPath,
    _In_ ULONG Detail
    )
{
    HacDbgWriteRegistryDword(RegistryPath, L"LastLoadDetail", Detail);
}

// 记录失败阶段并原样返回状态码。
static NTSTATUS
HacDbgRecordFailure(
    _In_ PCUNICODE_STRING RegistryPath,
    _In_ ULONG Stage,
    _In_ NTSTATUS Status
    )
{
    HacDbgRecordLoadStatus(RegistryPath, Stage, Status);
    return Status;
}
#else
//
// 诊断关闭时，这三个记录点编译为空；失败路径仍然原样返回状态码。
//
#define HacDbgRecordLoadStatus(...) ((VOID)0)
#define HacDbgRecordLoadDetail(...) ((VOID)0)
#define HacDbgRecordFailure(RegistryPath, Stage, Status) (Status)
#endif

#if !HACDBG_BACKEND_INTEL
// 在当前逻辑处理器上启用 SVM，并切入 VMRUN 循环。
static VOID
SvmVirtualizeProcessor(
    _Inout_ SVM_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    CONTEXT context;

    RtlCaptureContext(&context);

    if (ProcessorContext->Virtualized != FALSE || ProcessorContext->LaunchCompleted != FALSE)
    {
        return;
    }

    if (!NT_SUCCESS(SvmCheckSupport()))
    {
        HACDBG_LOG("HacDbg: Err, SVM support disappeared on processor %u.\n",
                 KeGetCurrentProcessorNumber());
        ProcessorContext->LaunchCompleted = TRUE;
        return;
    }

    ProcessorContext->StopRequested = FALSE;
    ProcessorContext->Virtualized = TRUE;
    // 关中断，避免切换宿主栈期间被中断打断。
    _disable();
    //
    // INVARIANT: The per-processor VMCB and host save area are 4 KiB-aligned,
    // NPT is enabled, and this logical processor is not already in a guest.
    //
    SvmEnable();
    SvmPrepareLaunch(ProcessorContext, &context);
    //
    // INVARIANT: SVM is enabled and this processor is not in a guest. Keep
    // external events out until VMRUN installs the guest state and sets GIF.
    //
    __svm_clgi();

    // HostStack 是本处理器独占的 32 KiB 非分页栈。
    // 进入客户前关掉 MmCopyMemory。它发出的 TLB IPI 会被仍在客户里的处理器接走。
    PhysicalMemorySetGuestRunning(TRUE);
    SvmLaunchVm(ProcessorContext,
                (PVOID)((ULONG_PTR)ProcessorContext->HostStack + 0x8000));
}

// 用停止 CPUID 让当前处理器退出 VMRUN。
static VOID
SvmStopProcessor(
    _Inout_ SVM_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    int registers[4];

    if (ProcessorContext->Virtualized == FALSE)
    {
        return;
    }

    ProcessorContext->StopRequested = TRUE;
    __cpuidex(registers, HACDBG_STOP_CPUID_LEAF, HACDBG_STOP_CPUID_SUBLEAF);
}

// 释放单个处理器的 VMCB、宿主保存区和宿主栈。
static VOID
SvmFreeProcessorContext(
    _Inout_ SVM_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    if (ProcessorContext->GuestVmcbAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->GuestVmcbAllocation, 'VcaH');
    }
    if (ProcessorContext->HostVmcbAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->HostVmcbAllocation, 'VcaH');
    }
    if (ProcessorContext->HostSaveAreaAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->HostSaveAreaAllocation, 'VcaH');
    }
    if (ProcessorContext->HostStackAllocation != NULL)
    {
        ExFreePoolWithTag(ProcessorContext->HostStackAllocation, 'VcaH');
    }

    ExFreePoolWithTag(ProcessorContext, 'VcaH');
}

// 先建好全部处理器上下文，再逐个进入 VMRUN。
static NTSTATUS
SvmStartAllProcessors(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index;

    g_ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (g_ProcessorCount > HACDBG_MAX_PROCESSORS)
    {
        return STATUS_NOT_SUPPORTED;
    }

    // 隐藏 VMCB 页会分配 NPT 拆分页，必须在任何客户运行前完成。
    for (index = 0; index < g_ProcessorCount; index++)
    {
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY affinity;
        GROUP_AFFINITY oldAffinity;
        SVM_PROCESSOR_CONTEXT* context;

        status = KeGetProcessorNumberFromIndex(index, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ull << processorNumber.Number;
        affinity.Reserved[0] = 0;
        affinity.Reserved[1] = 0;
        affinity.Reserved[2] = 0;

        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        context = (SVM_PROCESSOR_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                          sizeof(*context),
                                                          'VcaH');
        if (context != NULL)
        {
            g_Contexts[index] = context;
            status = SvmInitialize(context, NptMainRootPa(), 1);
        }
        else
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
        {
            break;
        }
    }

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (index = 0; index < g_ProcessorCount; index++)
    {
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY affinity;
        GROUP_AFFINITY oldAffinity;

        status = KeGetProcessorNumberFromIndex(index, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ull << processorNumber.Number;
        affinity.Reserved[0] = 0;
        affinity.Reserved[1] = 0;
        affinity.Reserved[2] = 0;

        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);
        SvmVirtualizeProcessor(g_Contexts[index]);
        if (g_Contexts[index]->Virtualized == FALSE)
        {
            status = STATUS_UNSUCCESSFUL;
        }
        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
        {
            break;
        }
    }

    return status;
}

// 让所有已虚拟化的处理器退出客户。
static VOID
SvmStopAllProcessors(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < g_ProcessorCount; index++)
    {
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY affinity;
        GROUP_AFFINITY oldAffinity;

        if (g_Contexts[index] == NULL)
        {
            continue;
        }

        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(index, &processorNumber)))
        {
            continue;
        }

        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ull << processorNumber.Number;
        affinity.Reserved[0] = 0;
        affinity.Reserved[1] = 0;
        affinity.Reserved[2] = 0;

        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);
        SvmStopProcessor(g_Contexts[index]);
        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }

    for (index = 0; index < g_ProcessorCount; index++)
    {
        if (g_Contexts[index] != NULL && g_Contexts[index]->Virtualized != FALSE)
        {
            return;
        }
    }

    PhysicalMemorySetGuestRunning(FALSE);
}

// 恢复 S0 后重新虚拟化所有处理器。
static NTSTATUS
SvmRestartAllProcessors(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < g_ProcessorCount; index++)
    {
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY affinity;
        GROUP_AFFINITY oldAffinity;
        NTSTATUS status;

        if (g_Contexts[index] == NULL)
        {
            continue;
        }

        status = KeGetProcessorNumberFromIndex(index, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            SvmStopAllProcessors();
            return status;
        }

        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ull << processorNumber.Number;
        affinity.Reserved[0] = 0;
        affinity.Reserved[1] = 0;
        affinity.Reserved[2] = 0;

        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        g_Contexts[index]->StopRequested = FALSE;
        g_Contexts[index]->LaunchCompleted = FALSE;
        g_Contexts[index]->Virtualized = FALSE;
        SvmVirtualizeProcessor(g_Contexts[index]);

        if (g_Contexts[index]->Virtualized == FALSE)
        {
            KeRevertToUserGroupAffinityThread(&oldAffinity);
            SvmStopAllProcessors();
            return STATUS_UNSUCCESSFUL;
        }

        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }

    return STATUS_SUCCESS;
}

static VOID
SvmFreeAllProcessors(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < HACDBG_MAX_PROCESSORS; index++)
    {
        if (g_Contexts[index] != NULL)
        {
            if (g_Contexts[index]->Virtualized != FALSE)
            {
                KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x48444301ull, index, 0, 0);
            }

            SvmFreeProcessorContext(g_Contexts[index]);
            g_Contexts[index] = NULL;
        }
    }
}
#endif

// 睡眠前停止虚拟化，恢复后重新启动。
static VOID
SvmPowerCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 != (PVOID)(ULONG_PTR)PO_CB_SYSTEM_STATE_LOCK)
    {
        return;
    }

    if (Argument2 != FALSE)
    {
        if (g_VirtualizationSuspended != FALSE)
        {
            status = HACDBG_RESTART_ALL();
            if (!NT_SUCCESS(status))
            {
                HACDBG_LOG("HacDbg: Err, processor virtualization after resume failed: 0x%08x.\n", status);
            }
            else
            {
                g_VirtualizationSuspended = FALSE;
            }
        }
    }
    else
    {
        HACDBG_STOP_ALL();
        HypercallInitialize();
        g_VirtualizationSuspended = TRUE;
    }
}

// 完成一个成功返回的 IRP。
static NTSTATUS
HacDbgCompleteSuccess(
    _Inout_ PIRP Irp
    )
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// 允许三环打开控制设备。
static NTSTATUS
_Dispatch_type_(IRP_MJ_CREATE)
HacDbgCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return HacDbgCompleteSuccess(Irp);
}

// 关闭控制设备句柄。
static NTSTATUS
_Dispatch_type_(IRP_MJ_CLOSE)
HacDbgClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return HacDbgCompleteSuccess(Irp);
}

// 句柄清理，当前无需额外处理。
static NTSTATUS
_Dispatch_type_(IRP_MJ_CLEANUP)
HacDbgCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return HacDbgCompleteSuccess(Irp);
}

// 控制设备不再执行调试命令。命令 IOCTL 一律拒绝，并要求管理员权限。
static NTSTATUS
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
HacDbgDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PACCESS_TOKEN token;
    BOOLEAN isAdmin;
    ULONG inputLength;
    ULONG outputLength;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (token == NULL)
    {
        isAdmin = FALSE;
    }
    else
    {
        isAdmin = SeTokenIsAdmin(token);
        PsDereferencePrimaryToken(token);
    }

    if (isAdmin == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, IOCTL 0x%08x denied for non-admin caller.\n",
                 stack->Parameters.DeviceIoControl.IoControlCode);
        status = STATUS_ACCESS_DENIED;
    }
    else if (stack->Parameters.DeviceIoControl.IoControlCode == HACDBG_IOCTL_FLUSH_SLAT ||
             stack->Parameters.DeviceIoControl.IoControlCode == HACDBG_IOCTL_HYPERCALL ||
             stack->Parameters.DeviceIoControl.IoControlCode == HACDBG_IOCTL_QUERY_VERSION)
    {
        HACDBG_LOG("HacDbg: Err, IOCTL 0x%08x is not a command path.\n",
                 stack->Parameters.DeviceIoControl.IoControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
    {
        HACDBG_LOG("HacDbg: Err, unknown IOCTL 0x%08x in=%u out=%u.\n",
                 stack->Parameters.DeviceIoControl.IoControlCode, inputLength, outputLength);
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// 创建 \Device\HacDbg 及其符号链接。
static NTSTATUS
HacDbgCreateDevice(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    NTSTATUS status;

    RtlInitUnicodeString(&deviceName, HACDBG_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, HACDBG_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        g_DeviceObject = NULL;
        return status;
    }

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    //
    // This is a WDM driver; installing dispatch entry points directly is the
    // required registration mechanism. The analyzer's WDF-oriented warning
    // does not apply to this block.
    //
#pragma warning(push)
#pragma warning(disable: 28175)
    DriverObject->MajorFunction[IRP_MJ_CREATE] = HacDbgCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HacDbgClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = HacDbgCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HacDbgDeviceControl;
#pragma warning(pop)

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

// 删除控制设备和符号链接。
static VOID
HacDbgDeleteDevice(
    VOID
    )
{
    UNICODE_STRING symbolicLinkName;

    if (g_DeviceObject == NULL)
    {
        return;
    }

    RtlInitUnicodeString(&symbolicLinkName, HACDBG_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
}

// 卸载：停止所有处理器，再释放全局资源。
static VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    HACDBG_LOG("HacDbg: DriverUnload start.\n");

    if (g_PowerCallbackRegistration != NULL)
    {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;
    }

    HacDbgDeleteDevice();
    HACDBG_STOP_ALL();
    HACDBG_FREE_ALL();

    LogsCleanup();
    HACDBG_SHARED_CLEANUP();
    HACDBG_PAGING_CLEANUP();
    PhysicalMemoryCleanup();

    HACDBG_LOG("HacDbg: DriverUnload complete.\n");
}

// 驱动入口：按固定顺序初始化各模块，最后虚拟化所有处理器。
EXTERN_C NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING callbackName;
    OBJECT_ATTRIBUTES callbackAttributes;
    PCALLBACK_OBJECT callbackObject;

    HACDBG_LOG("HacDbg: DriverEntry start: driver version %s (%s).\n",
             HACDBG_VERSION_STRING, HACDBG_VENDOR_NAME);

#if !HACDBG_DIAGNOSTICS
    UNREFERENCED_PARAMETER(RegistryPath);
#endif

    DriverObject->DriverUnload = DriverUnload;
    HacDbgRecordLoadStatus(RegistryPath, HACDBG_LOAD_STAGE_START, STATUS_SUCCESS);
    HacDbgRecordLoadDetail(RegistryPath, 0);

    PhysicalMemorySetFiveLevelPaging((__readcr4() & (1ull << 12)) != 0);

    status = HACDBG_CHECK_SUPPORT();
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, virtualization support is unavailable.\n");
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_SVM_SUPPORT, status);
    }

    status = PhysicalMemoryInitialize();
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, physical memory map initialization failed: 0x%08x.\n", status);
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_PHYSICAL_MEMORY, status);
    }

    status = HACDBG_PAGING_INITIALIZE();
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, nested paging initialization failed: 0x%08x.\n", status);
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_NPT, status);
    }

    status = LogsInitialize();
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, log initialization failed: 0x%08x.\n", status);
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_LOGS, status);
    }

    status = HACDBG_SHARED_INITIALIZE();
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, shared virtualization state initialization failed: 0x%08x.\n", status);
        HacDbgRecordLoadDetail(RegistryPath, HACDBG_SHARED_DETAIL());
        LogsCleanup();
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_MSRPM, status);
    }

    status = HacDbgCreateDevice(DriverObject);
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, control device creation failed: 0x%08x.\n", status);
        HACDBG_SHARED_CLEANUP();
        LogsCleanup();
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_DEVICE, status);
    }

    HypercallInitialize();

    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&callbackAttributes, &callbackName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(&callbackObject, &callbackAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, power callback open failed: 0x%08x.\n", status);
        HacDbgDeleteDevice();
        HACDBG_SHARED_CLEANUP();
        LogsCleanup();
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_POWER, status);
    }

    g_PowerCallbackRegistration = ExRegisterCallback(callbackObject, SvmPowerCallback, NULL);
    ObDereferenceObject(callbackObject);

    if (g_PowerCallbackRegistration == NULL)
    {
        HACDBG_LOG("HacDbg: Err, power callback registration failed.\n");
        HacDbgDeleteDevice();
        HACDBG_SHARED_CLEANUP();
        LogsCleanup();
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_POWER, STATUS_UNSUCCESSFUL);
    }

    status = HACDBG_START_ALL();
    if (!NT_SUCCESS(status))
    {
        HACDBG_LOG("HacDbg: Err, processor virtualization failed: 0x%08x.\n", status);
        HacDbgRecordLoadStatus(RegistryPath, HACDBG_LOAD_STAGE_PROCESSORS, status);
        HACDBG_STOP_ALL();
        HacDbgDeleteDevice();
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;
        HACDBG_FREE_ALL();

        LogsCleanup();
        HACDBG_SHARED_CLEANUP();
        HACDBG_PAGING_CLEANUP();
        PhysicalMemoryCleanup();
        return status;
    }

    g_VirtualizationSuspended = FALSE;
    HacDbgRecordLoadStatus(RegistryPath, HACDBG_LOAD_STAGE_COMPLETE, STATUS_SUCCESS);
    HACDBG_LOG("HacDbg: DriverEntry complete.\n");
    return STATUS_SUCCESS;
}
