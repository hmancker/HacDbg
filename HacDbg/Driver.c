/**
 * @file Driver.c
 * @brief Driver entry point and processor lifecycle.
 *
 * @author HacDbg
 */

#include <ntifs.h>

#include "Svm.h"
#include "Hypercall.h"
#include "Logs.h"
#include "Npt.h"
#include "PhysicalMemory.h"
#include "../shared/hypercall/control.h"

#define HACDBG_MAX_PROCESSORS 256

C_ASSERT(sizeof(HACDBG_VERSION_INFO) == 0x30);
C_ASSERT(sizeof(HACDBG_VERSION_STRING) <= HACDBG_VERSION_STRING_SIZE);

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

EXTERN_C VOID
SvmLaunchVm(
    _In_ SVM_PROCESSOR_CONTEXT* ProcessorContext,
    _In_ PVOID HostStackTop
    );

static SVM_PROCESSOR_CONTEXT* g_Contexts[HACDBG_MAX_PROCESSORS];
static ULONG g_ProcessorCount;
static PVOID g_PowerCallbackRegistration;
static BOOLEAN g_VirtualizationSuspended;
static PDEVICE_OBJECT g_DeviceObject;

DRIVER_INITIALIZE DriverEntry;

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

static VOID
HacDbgRecordLoadDetail(
    _In_ PCUNICODE_STRING RegistryPath,
    _In_ ULONG Detail
    )
{
    HacDbgWriteRegistryDword(RegistryPath, L"LastLoadDetail", Detail);
}

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
        DbgPrint("HacDbg: Err, SVM support disappeared on processor %u.\n",
                 KeGetCurrentProcessorNumber());
        ProcessorContext->LaunchCompleted = TRUE;
        return;
    }

    ProcessorContext->StopRequested = FALSE;
    ProcessorContext->Virtualized = TRUE;
    //
    // Keep interrupts out of the window where the processor leaves its
    // original stack and enters the host VMRUN stack.
    //
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

    //
    // INVARIANT: HostStack is a nonpaged 32 KiB stack owned by this
    // processor, and both VMCBs are mapped in the host address space.
    //
    SvmLaunchVm(ProcessorContext,
                (PVOID)((ULONG_PTR)ProcessorContext->HostStack + 0x8000));
}

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

    //
    // Build every per-processor context before any VMRUN. Hiding VMCB pages
    // allocates NPT split tables, so no guest may be running while these
    // tables are being edited.
    //
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
}

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
            status = SvmRestartAllProcessors();
            if (!NT_SUCCESS(status))
            {
                DbgPrint("HacDbg: Err, processor virtualization after resume failed: 0x%08x.\n", status);
            }
            else
            {
                g_VirtualizationSuspended = FALSE;
            }
        }
    }
    else
    {
        SvmStopAllProcessors();
        HypercallInitialize();
        g_VirtualizationSuspended = TRUE;
    }
}

static ULONG_PTR
NTAPI
HacDbgFlushIpi(
    _In_ ULONG_PTR Context
    )
{
    int registers[4];

    UNREFERENCED_PARAMETER(Context);
    __cpuidex(registers, HACDBG_FLUSH_CPUID_LEAF, HACDBG_FLUSH_CPUID_SUBLEAF);
    return 0;
}

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
        DbgPrint("HacDbg: Err, IOCTL 0x%08x denied for non-admin caller.\n",
                 stack->Parameters.DeviceIoControl.IoControlCode);
        status = STATUS_ACCESS_DENIED;
    }
    else if (stack->Parameters.DeviceIoControl.IoControlCode == HACDBG_IOCTL_FLUSH_SLAT)
    {
        KeIpiGenericCall(HacDbgFlushIpi, 0);
        status = STATUS_SUCCESS;
    }
    else if (stack->Parameters.DeviceIoControl.IoControlCode == HACDBG_IOCTL_HYPERCALL)
    {
        HACDBG_HYPERCALL_REQUEST* request;

        if (inputLength < sizeof(*request) || outputLength < sizeof(*request) ||
            Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            DbgPrint("HacDbg: Err, hypercall IOCTL buffer too small: in=%u out=%u need=%u.\n",
                     inputLength, outputLength, (ULONG)sizeof(*request));
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            request = (HACDBG_HYPERCALL_REQUEST*)Irp->AssociatedIrp.SystemBuffer;

            status = HypercallHandleIoctl(request);
            if (!NT_SUCCESS(status))
            {
                request->Status = (UINT32)status;
                request->Result = 0;
                DbgPrint("HacDbg: Err, IOCTL hypercall dispatch failed: 0x%08x.\n", status);
            }

            Irp->IoStatus.Information = sizeof(*request);
            status = STATUS_SUCCESS;
        }
    }
    else if (stack->Parameters.DeviceIoControl.IoControlCode == HACDBG_IOCTL_QUERY_VERSION)
    {
        HACDBG_VERSION_INFO* version;

        if (outputLength < sizeof(*version) || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            DbgPrint("HacDbg: Err, version IOCTL buffer too small: out=%u need=%u.\n",
                     outputLength, (ULONG)sizeof(*version));
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            version = (HACDBG_VERSION_INFO*)Irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(version, sizeof(*version));
            version->Major = HACDBG_VERSION_MAJOR;
            version->Minor = HACDBG_VERSION_MINOR;
            version->Patch = HACDBG_VERSION_PATCH;
            version->HypercallAbiVersion = HACDBG_HYPERCALL_REQUEST_VERSION;
            RtlCopyMemory(version->VersionString, HACDBG_VERSION_STRING,
                          sizeof(HACDBG_VERSION_STRING));

            Irp->IoStatus.Information = sizeof(*version);
            status = STATUS_SUCCESS;
        }
    }
    else
    {
        DbgPrint("HacDbg: Err, unknown IOCTL 0x%08x in=%u out=%u.\n",
                 stack->Parameters.DeviceIoControl.IoControlCode, inputLength, outputLength);
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    if ((stack->Parameters.DeviceIoControl.IoControlCode != HACDBG_IOCTL_HYPERCALL &&
         stack->Parameters.DeviceIoControl.IoControlCode != HACDBG_IOCTL_QUERY_VERSION) ||
        !NT_SUCCESS(status))
    {
        Irp->IoStatus.Information = 0;
    }
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

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

static VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    ULONG index;

    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("HacDbg: DriverUnload start.\n");

    if (g_PowerCallbackRegistration != NULL)
    {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;
    }

    HacDbgDeleteDevice();
    SvmStopAllProcessors();

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

    LogsCleanup();
    SvmCleanupShared();
    NptCleanup();
    PhysicalMemoryCleanup();

    DbgPrint("HacDbg: DriverUnload complete.\n");
}

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

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("HacDbg: DriverEntry start: driver version %s.\n", HACDBG_VERSION_STRING);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    DriverObject->DriverUnload = DriverUnload;
    HacDbgRecordLoadStatus(RegistryPath, HACDBG_LOAD_STAGE_START, STATUS_SUCCESS);
    HacDbgRecordLoadDetail(RegistryPath, 0);

    PhysicalMemorySetFiveLevelPaging((__readcr4() & (1ull << 12)) != 0);

    status = SvmCheckSupport();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, SVM or NPT is unavailable.\n");
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_SVM_SUPPORT, status);
    }

    status = PhysicalMemoryInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, physical memory map initialization failed: 0x%08x.\n", status);
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_PHYSICAL_MEMORY, status);
    }

    status = NptInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, nested page table initialization failed: 0x%08x.\n", status);
        NptCleanup();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_NPT, status);
    }

    status = LogsInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, log initialization failed: 0x%08x.\n", status);
        NptCleanup();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_LOGS, status);
    }

    status = SvmInitializeShared();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, MSR permission map initialization failed: 0x%08x.\n", status);
        HacDbgRecordLoadDetail(RegistryPath, SvmGetSharedFailureDetail());
        LogsCleanup();
        NptCleanup();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_MSRPM, status);
    }

    status = HacDbgCreateDevice(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, control device creation failed: 0x%08x.\n", status);
        SvmCleanupShared();
        LogsCleanup();
        NptCleanup();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_DEVICE, status);
    }

    HypercallInitialize();

    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&callbackAttributes, &callbackName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(&callbackObject, &callbackAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("HacDbg: Err, power callback open failed: 0x%08x.\n", status);
        HacDbgDeleteDevice();
        SvmCleanupShared();
        LogsCleanup();
        NptCleanup();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_POWER, status);
    }

    g_PowerCallbackRegistration = ExRegisterCallback(callbackObject, SvmPowerCallback, NULL);
    ObDereferenceObject(callbackObject);

    if (g_PowerCallbackRegistration == NULL)
    {
        DbgPrint("HacDbg: Err, power callback registration failed.\n");
        HacDbgDeleteDevice();
        SvmCleanupShared();
        LogsCleanup();
        NptCleanup();
        PhysicalMemoryCleanup();
        return HacDbgRecordFailure(RegistryPath, HACDBG_LOAD_STAGE_POWER, STATUS_UNSUCCESSFUL);
    }

    status = SvmStartAllProcessors();
    if (!NT_SUCCESS(status))
    {
        ULONG index;

        DbgPrint("HacDbg: Err, processor virtualization failed: 0x%08x.\n", status);
        HacDbgRecordLoadStatus(RegistryPath, HACDBG_LOAD_STAGE_PROCESSORS, status);
        SvmStopAllProcessors();
        HacDbgDeleteDevice();
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;

        for (index = 0; index < HACDBG_MAX_PROCESSORS; index++)
        {
            if (g_Contexts[index] != NULL)
            {
                if (g_Contexts[index]->Virtualized != FALSE)
                {
                    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x48444302ull, index, 0, 0);
                }

                SvmFreeProcessorContext(g_Contexts[index]);
                g_Contexts[index] = NULL;
            }
        }

        LogsCleanup();
        SvmCleanupShared();
        NptCleanup();
        PhysicalMemoryCleanup();
        return status;
    }

    g_VirtualizationSuspended = FALSE;
    HacDbgRecordLoadStatus(RegistryPath, HACDBG_LOAD_STAGE_COMPLETE, STATUS_SUCCESS);
    DbgPrint("HacDbg: DriverEntry complete.\n");
    return STATUS_SUCCESS;
}
