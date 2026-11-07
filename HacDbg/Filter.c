/**
 * @file Filter.c
 * @brief Legacy filesystem, disk, volume, and input filter stacks.
 *
 * @author HacDbg
 */

#include <ntifs.h>

#include "Filter.h"
#include "Debug.h"
#include "Search.h"

#define FILTER_TAG 'rFlH'
#define FILTER_CHAIN_LIMIT 8u
#define FILTER_DEVICE_LIMIT 256u

extern POBJECT_TYPE* IoDriverObjectType;


NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

PVOID
RtlPcToFileHeader(
    PVOID PcValue,
    PVOID* BaseOfImage
    );

static BOOLEAN
FilterEndsWith(
    _In_ PCWSTR Path,
    _In_ PCWSTR Suffix
    );

static PRTL_PROCESS_MODULES
FilterQueryModules(
    VOID
    )
{
    ULONG Bytes;
    NTSTATUS Status;
    PRTL_PROCESS_MODULES Modules;

    Bytes = 0;
    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, NULL, 0, &Bytes);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || Bytes < sizeof(RTL_PROCESS_MODULES))
    {
        HACDBG_LOG("HacDbg: Err, filter module list size failed: 0x%08x.\n", Status);
        return NULL;
    }

    Bytes += sizeof(RTL_PROCESS_MODULE_INFORMATION);
    Modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, Bytes, FILTER_TAG);
    if (Modules == NULL)
    {
        HACDBG_LOG("HacDbg: Err, filter module list allocation failed.\n");
        return NULL;
    }

    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, Modules, Bytes, &Bytes);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, filter module list failed: 0x%08x.\n", Status);
        ExFreePoolWithTag(Modules, FILTER_TAG);
        return NULL;
    }

    return Modules;
}

static VOID
FilterCopyString(
    _Out_writes_(DestChars) WCHAR* Dest,
    _In_ ULONG DestChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    ULONG Chars;

    Dest[0] = 0;
    if (DestChars == 0 || Source == NULL || Source->Buffer == NULL || Source->Length < sizeof(WCHAR))
    {
        return;
    }

    if (MmIsAddressValid(Source->Buffer) == FALSE)
    {
        return;
    }

    Chars = Source->Length / sizeof(WCHAR);
    if (Chars >= DestChars)
    {
        Chars = DestChars - 1;
    }

    RtlCopyMemory(Dest, Source->Buffer, Chars * sizeof(WCHAR));
    Dest[Chars] = 0;
}

static VOID
FilterNarrow(
    _Out_writes_(DestChars) CHAR* Dest,
    _In_ ULONG DestChars,
    _In_ PCWSTR Source
    )
{
    ULONG Index;

    Dest[0] = 0;
    if (DestChars == 0)
    {
        return;
    }

    for (Index = 0; Index + 1 < DestChars && Source[Index] != 0; ++Index)
    {
        WCHAR Char;

        Char = Source[Index];
        Dest[Index] = (Char >= 32 && Char < 127) ? (CHAR)Char : '?';
    }

    Dest[Index] = 0;
}

static BOOLEAN
FilterDeviceOk(
    _In_opt_ PDEVICE_OBJECT Device
    )
{
    if (Device == NULL || MmIsAddressValid(Device) == FALSE || MmIsAddressValid(&Device->AttachedDevice) == FALSE)
    {
        return FALSE;
    }

    return Device->Type == IO_TYPE_DEVICE;
}

static VOID
FilterModulePath(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Image,
    _Out_writes_(HACDBG_FILTER_PATH_CHARS) WCHAR* Path
    )
{
    PVOID Base;
    ULONG Index;

    Path[0] = 0;
    if (Image == NULL || Modules == NULL || RtlPcToFileHeader(Image, &Base) == NULL)
    {
        return;
    }

    for (Index = 0; Index < Modules->NumberOfModules; ++Index)
    {
        const UCHAR* Source;
        ULONG Char;

        if (Modules->Modules[Index].ImageBase != Base)
        {
            continue;
        }

        Source = Modules->Modules[Index].FullPathName;
        for (Char = 0; Char + 1 < HACDBG_FILTER_PATH_CHARS && Source[Char] != 0; ++Char)
        {
            Path[Char] = (WCHAR)Source[Char];
        }

        Path[Char] = 0;
        if (FilterEndsWith(Path, L"\\ntoskrnl.exe") != FALSE || FilterEndsWith(Path, L"\\ntkrnlmp.exe") != FALSE ||
            FilterEndsWith(Path, L"\\ntkrnlpa.exe") != FALSE || FilterEndsWith(Path, L"\\hal.dll") != FALSE)
        {
            Path[0] = 0;
        }

        return;
    }
}

static BOOLEAN
FilterEndsWith(
    _In_ PCWSTR Path,
    _In_ PCWSTR Suffix
    )
{
    ULONG PathChars;
    ULONG SuffixChars;
    ULONG Index;

    PathChars = 0;
    SuffixChars = 0;
    while (Path[PathChars] != 0)
    {
        PathChars += 1;
    }

    while (Suffix[SuffixChars] != 0)
    {
        SuffixChars += 1;
    }

    if (PathChars < SuffixChars)
    {
        return FALSE;
    }

    for (Index = 0; Index < SuffixChars; ++Index)
    {
        WCHAR Left;
        WCHAR Right;

        Left = Path[PathChars - SuffixChars + Index];
        Right = Suffix[Index];
        if (Left >= L'A' && Left <= L'Z')
        {
            Left = (WCHAR)(Left - L'A' + L'a');
        }

        if (Right >= L'A' && Right <= L'Z')
        {
            Right = (WCHAR)(Right - L'A' + L'a');
        }

        if (Left != Right)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
FilterAddRow(
    _Inout_ HACDBG_FILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PDEVICE_OBJECT Device,
    _In_opt_ PDEVICE_OBJECT Host,
    _In_ unsigned int Type,
    _In_ unsigned int Depth,
    _In_ unsigned int Parent
    )
{
    HACDBG_FILTER_ROW* Row;
    PDRIVER_OBJECT Driver;
    WCHAR DriverName[HACDBG_FILTER_NAME_CHARS];
    CHAR NarrowName[HACDBG_FILTER_NAME_CHARS];
    CHAR NarrowDevice[HACDBG_FILTER_NAME_CHARS];
    CHAR NarrowPath[HACDBG_FILTER_PATH_CHARS];
    UCHAR NameInfo[sizeof(OBJECT_NAME_INFORMATION) + (HACDBG_FILTER_NAME_CHARS * sizeof(WCHAR))];
    ULONG NameBytes;
    POBJECT_NAME_INFORMATION Name;

    if (Request->Count >= HACDBG_FILTER_MAX_ROWS)
    {
        Request->Truncated = 1;
        return FALSE;
    }

    Driver = Device->DriverObject;
    if (Driver == NULL || MmIsAddressValid(Driver) == FALSE || MmIsAddressValid(&Driver->DriverName) == FALSE)
    {
        return FALSE;
    }

    FilterCopyString(DriverName, HACDBG_FILTER_NAME_CHARS, &Driver->DriverName);
    Row = &Request->Rows[Request->Count];
    RtlZeroMemory(Row, sizeof(*Row));
    Row->DriverObject = (unsigned long long)(ULONG_PTR)Driver;
    Row->DeviceObject = (unsigned long long)(ULONG_PTR)Device;
    Row->Depth = Depth;
    Row->Parent = Parent;
    Row->Type = Type;
    FilterCopyString(Row->DriverName, HACDBG_FILTER_NAME_CHARS, &Driver->DriverName);
    FilterModulePath(Modules, Driver->DriverStart, Row->DriverPath);

    Name = (POBJECT_NAME_INFORMATION)NameInfo;
    NameBytes = 0;
    if (NT_SUCCESS(ObQueryNameString(Device, Name, sizeof(NameInfo), &NameBytes)) && Name->Name.Buffer != NULL)
    {
        FilterCopyString(Row->DeviceName, HACDBG_FILTER_NAME_CHARS, &Name->Name);
    }

    if (Host != NULL && FilterDeviceOk(Host) != FALSE && Host->DriverObject != NULL &&
        MmIsAddressValid(Host->DriverObject) != FALSE && MmIsAddressValid(&Host->DriverObject->DriverName) != FALSE)
    {
        Row->HostDeviceObject = (unsigned long long)(ULONG_PTR)Host;
        Row->HostDriverObject = (unsigned long long)(ULONG_PTR)Host->DriverObject;
        FilterCopyString(Row->HostDriverName, HACDBG_FILTER_NAME_CHARS, &Host->DriverObject->DriverName);
    }

    Request->Count += 1;
    FilterNarrow(NarrowName, sizeof(NarrowName), DriverName);
    FilterNarrow(NarrowDevice, sizeof(NarrowDevice), Row->DeviceName);
    FilterNarrow(NarrowPath, sizeof(NarrowPath), Row->DriverPath);
    HACDBG_LOG("HacDbg: Filter %s type=%s depth=%u drv=%p dev=%p device=%s host=%p path=%s.\n",
               NarrowName[0] != 0 ? NarrowName : "-", HacDbgFilterTypeName(Type), Depth, Driver, Device,
               NarrowDevice[0] != 0 ? NarrowDevice : "-", Host, NarrowPath[0] != 0 ? NarrowPath : "-");
    return TRUE;
}

static VOID
FilterWalkChain(
    _Inout_ HACDBG_FILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PDEVICE_OBJECT Device,
    _In_opt_ PDEVICE_OBJECT Host,
    _In_ unsigned int Type,
    _In_ unsigned int Depth,
    _In_ unsigned int Parent,
    _Inout_updates_(FILTER_CHAIN_LIMIT) PDEVICE_OBJECT* Stack,
    _In_ ULONG StackCount
    )
{
    ULONG Index;
    unsigned int RowIndex;
    PDEVICE_OBJECT Upper;

    if (Depth >= FILTER_CHAIN_LIMIT || FilterDeviceOk(Device) == FALSE || Request->Truncated != 0)
    {
        return;
    }

    for (Index = 0; Index < StackCount; ++Index)
    {
        if (Stack[Index] == Device)
        {
            return;
        }
    }

    Stack[StackCount] = Device;
    RowIndex = Request->Count;
    if (FilterAddRow(Request, Modules, Device, Host, Type, Depth, Parent) == FALSE)
    {
        return;
    }

    Upper = Device->AttachedDevice;
    if (Upper != NULL)
    {
        FilterWalkChain(Request, Modules, Upper, Device, Type, Depth + 1, RowIndex, Stack, StackCount + 1);
    }
}

static VOID
FilterWalkDriver(
    _Inout_ HACDBG_FILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PDRIVER_OBJECT Driver,
    _In_ unsigned int Type
    )
{
    PDEVICE_OBJECT Device;
    ULONG Count;

    if (MmIsAddressValid(Driver) == FALSE || MmIsAddressValid(&Driver->DeviceObject) == FALSE)
    {
        return;
    }

    Device = Driver->DeviceObject;
    Count = 0;
    while (FilterDeviceOk(Device) != FALSE && Count < FILTER_DEVICE_LIMIT && Request->Truncated == 0)
    {
        PDEVICE_OBJECT Next;
        PDEVICE_OBJECT Stack[FILTER_CHAIN_LIMIT];

        Next = Device->NextDevice;
        FilterWalkChain(Request, Modules, Device, NULL, Type, 0, HACDBG_FILTER_NO_PARENT, Stack, 0);
        if (Next == Device)
        {
            break;
        }

        Device = Next;
        Count += 1;
    }
}

static PDRIVER_OBJECT
FilterDriverFromAddress(
    _In_ ULONG64 Address
    )
{
    PDRIVER_OBJECT Driver;

    Driver = (PDRIVER_OBJECT)(ULONG_PTR)Address;
    if (Address < 0xFFFF800000000000ull || MmIsAddressValid(Driver) == FALSE ||
        MmIsAddressValid(&Driver->MajorFunction[IRP_MJ_MAXIMUM_FUNCTION]) == FALSE || Driver->Type != IO_TYPE_DRIVER)
    {
        return NULL;
    }

    return Driver;
}

static NTSTATUS
FilterDetach(
    _In_ ULONG64 DeviceAddress,
    _In_ ULONG64 HostAddress
    )
{
    PDEVICE_OBJECT Device;
    PDEVICE_OBJECT Host;
    PDEVICE_OBJECT Upper;
    PVOID Previous;

    Device = (PDEVICE_OBJECT)(ULONG_PTR)DeviceAddress;
    Host = (PDEVICE_OBJECT)(ULONG_PTR)HostAddress;
    if (FilterDeviceOk(Device) == FALSE || FilterDeviceOk(Host) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, filter detach addresses are not devices.\n");
        return STATUS_INVALID_PARAMETER;
    }

    Upper = Device->AttachedDevice;

    //
    // INVARIANT: Host and Device were returned by the last scan. Host's
    // AttachedDevice still names Device. The splice skips Device and leaves
    // the original pages unchanged.
    //
    Previous = InterlockedCompareExchangePointer((PVOID*)&Host->AttachedDevice, Upper, Device);
    if (Previous != Device)
    {
        HACDBG_LOG("HacDbg: Err, filter detach host=%p dev=%p current=%p.\n", Host, Device, Previous);
        return STATUS_NOT_FOUND;
    }

    InterlockedExchangePointer((PVOID*)&Device->AttachedDevice, NULL);
    HACDBG_LOG("HacDbg: Filter detached dev=%p from host=%p upper=%p.\n", Device, Host, Upper);
    return STATUS_SUCCESS;
}

static NTSTATUS
FilterListDevices(
    _Inout_ HACDBG_FILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ ULONG64 DriverAddress
    )
{
    PDRIVER_OBJECT Driver;
    PDEVICE_OBJECT Device;
    ULONG Count;

    Driver = FilterDriverFromAddress(DriverAddress);
    if (Driver == NULL)
    {
        HACDBG_LOG("HacDbg: Err, filter device list driver is not readable.\n");
        return STATUS_INVALID_PARAMETER;
    }

    Device = Driver->DeviceObject;
    Count = 0;
    while (FilterDeviceOk(Device) != FALSE && Count < FILTER_DEVICE_LIMIT && Request->Truncated == 0)
    {
        PDEVICE_OBJECT Next;

        Next = Device->NextDevice;
        FilterAddRow(Request, Modules, Device, NULL, 0, 0, HACDBG_FILTER_NO_PARENT);
        if (Next == Device)
        {
            break;
        }

        Device = Next;
        Count += 1;
    }

    HACDBG_LOG("HacDbg: Filter device list drv=%p count=%u.\n", Driver, Request->Count);
    return STATUS_SUCCESS;
}

static NTSTATUS
FilterListDispatch(
    _Inout_ HACDBG_FILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ ULONG64 DriverAddress
    )
{
    PDRIVER_OBJECT Driver;
    ULONG Index;

    Driver = FilterDriverFromAddress(DriverAddress);
    if (Driver == NULL)
    {
        HACDBG_LOG("HacDbg: Err, filter dispatch driver is not readable.\n");
        return STATUS_INVALID_PARAMETER;
    }

    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION && Request->Count < HACDBG_FILTER_MAX_ROWS; ++Index)
    {
        HACDBG_FILTER_ROW* Row;

        Row = &Request->Rows[Request->Count];
        RtlZeroMemory(Row, sizeof(*Row));
        Row->DriverObject = DriverAddress;
        Row->DeviceObject = (unsigned long long)(ULONG_PTR)Driver->MajorFunction[Index];
        Row->Depth = Index;
        Row->Parent = HACDBG_FILTER_NO_PARENT;
        FilterCopyString(Row->DriverName, HACDBG_FILTER_NAME_CHARS, &Driver->DriverName);
        FilterModulePath(Modules, (PVOID)(ULONG_PTR)Row->DeviceObject, Row->DriverPath);
        Request->Count += 1;
    }

    HACDBG_LOG("HacDbg: Filter dispatch drv=%p count=%u.\n", Driver, Request->Count);
    return STATUS_SUCCESS;
}

static VOID
FilterScanKnown(
    _Inout_ HACDBG_FILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules
    )
{
    const struct
    {
        PCWSTR Path;
        unsigned int Type;
    } Drivers[] = {
        {L"\\FileSystem\\Ntfs", HACDBG_FILTER_FILE},   {L"\\Driver\\disk", HACDBG_FILTER_DISK},
        {L"\\FileSystem\\RAW", HACDBG_FILTER_RAW},     {L"\\Driver\\volmgr", HACDBG_FILTER_VOLUME},
        {L"\\FileSystem\\Npfs", 0},                    {L"\\FileSystem\\Msfs", 0},
        {L"\\FileSystem\\Mup", 0},                     {L"\\Driver\\kbdclass", HACDBG_FILTER_KEYBOARD},
        {L"\\Driver\\mouclass", HACDBG_FILTER_MOUSE},  {L"\\Driver\\i8042prt", HACDBG_FILTER_I8042},
        {L"\\Driver\\Tcpip", HACDBG_FILTER_TCPIP},     {L"\\Driver\\tdx", HACDBG_FILTER_TDI},
        {L"\\Driver\\NDIS", HACDBG_FILTER_NDIS},       {L"\\Driver\\PnpManager", HACDBG_FILTER_PNP},
    };
    ULONG Index;

    for (Index = 0; Index < sizeof(Drivers) / sizeof(Drivers[0]) && Request->Truncated == 0; ++Index)
    {
        UNICODE_STRING Name;
        PVOID Object;
        NTSTATUS Status;

        RtlInitUnicodeString(&Name, Drivers[Index].Path);
        Object = NULL;

        //
        // INVARIANT: Name is one of the fixed kernel driver paths above.
        // IoDriverObjectType selects a driver object. The reference is dropped
        // before the next path.
        //
        Status = ObReferenceObjectByName(&Name, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL,
                                         &Object);
        if (!NT_SUCCESS(Status) || Object == NULL)
        {
            HACDBG_LOG("HacDbg: Err, filter driver reference failed: 0x%08x.\n", Status);
            continue;
        }

        FilterWalkDriver(Request, Modules, (PDRIVER_OBJECT)Object, Drivers[Index].Type);
        ObDereferenceObject(Object);
    }
}

C_ASSERT(sizeof(HACDBG_FILTER_REQUEST) <= 1024u * 1024u);

NTSTATUS
FilterExecute(
    _Inout_ HACDBG_FILTER_REQUEST* Request
    )
{
    unsigned int Operation;
    ULONG64 DriverAddress;
    ULONG64 DeviceAddress;
    ULONG64 HostAddress;
    PRTL_PROCESS_MODULES Modules;
    NTSTATUS Status;

    Operation = Request->Reserved;
    DriverAddress = Request->Rows[0].DriverObject;
    DeviceAddress = Request->Rows[0].DeviceObject;
    HostAddress = Request->Rows[0].HostDeviceObject;
    Request->Status = 0;
    Request->Count = 0;
    Request->Truncated = 0;
    Request->Reserved = 0;
    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL)
    {
        HACDBG_LOG("HacDbg: Err, filter driver type is missing.\n");
        Request->Status = STATUS_NOT_FOUND;
        return Request->Status;
    }

    if (Operation == HACDBG_FILTER_OP_DETACH)
    {
        Request->Status = FilterDetach(DeviceAddress, HostAddress);
        return Request->Status;
    }

    Modules = FilterQueryModules();
    Status = STATUS_SUCCESS;
    if (Operation == HACDBG_FILTER_OP_DEVICES)
    {
        Status = FilterListDevices(Request, Modules, DriverAddress);
    }
    else if (Operation == HACDBG_FILTER_OP_DISPATCH)
    {
        Status = FilterListDispatch(Request, Modules, DriverAddress);
    }
    else
    {
        FilterScanKnown(Request, Modules);
        HACDBG_LOG("HacDbg: Filter scan count=%u truncated=%u.\n", Request->Count, Request->Truncated);
    }

    if (Modules != NULL)
    {
        ExFreePoolWithTag(Modules, FILTER_TAG);
    }

    Request->Status = Status;
    return Request->Status;
}

