/**
 * @file Callback.c
 * @brief Enumerate kernel notify routines and object callbacks.
 *
 * @author HacDbg
 */

#include <ntifs.h>

#include "Callback.h"
#include "Config.h"
#include "Debug.h"
#include "Search.h"
#include "Types.h"

#include <intrin.h>

#if defined(_AMD64_)
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#define CALLBACK_ADD_HOOK EptAddHook
#define CALLBACK_REMOVE_HOOK EptRemoveHook
#define CALLBACK_REFRESH_HOOKS EptRefreshHookCopies
#else
#include "Npt.h"
#include "Svm.h"
#define CALLBACK_ADD_HOOK NptAddHook
#define CALLBACK_REMOVE_HOOK NptRemoveHook
#define CALLBACK_REFRESH_HOOKS NptRefreshHookCopies
#endif
#endif

#ifndef HACDBG_FLUSH_CPUID_LEAF
#define HACDBG_FLUSH_CPUID_LEAF 0x48444301u
#define HACDBG_FLUSH_CPUID_SUBLEAF 0x464C5348u
#endif

#define CALLBACK_TAG 'bCaH'
#define CALLBACK_NOTIFY_SLOTS 64u
#define CALLBACK_OB_LIMIT 128u
#define CALLBACK_VERIFY_LIMIT 32u
#define CALLBACK_LONG_LIMIT 1024u
#define CALLBACK_ROUTINE_OFFSET 0x10u
#define CALLBACK_BUGCHECK_STATE 0x38u
#define CALLBACK_REASON_STATE 0x2Cu
#define CALLBACK_REGISTRY_ROUTINE 0x28u
#define CALLBACK_FS_ROUTINE 0x18u
#define CALLBACK_SHUTDOWN_DEVICE 0x10u
#define CALLBACK_LOGON_ROUTINE 0x8u
#define CALLBACK_TYPE_NAME_OFFSET 0x10u
#define CALLBACK_POWER_TAG 0x74655350u
#define CALLBACK_POWER_ROUTINE 0x50u
#define CALLBACK_POWER_LIST 0x10u
#define CALLBACK_LIST_OFFSET 0xC8u
#define CALLBACK_HOOK_PAGES 32u
#define CALLBACK_HOOK_ENTRIES 64u

typedef struct _CALLBACK_BLOCK
{
    ULONG64 Rundown;
    PVOID Function;
    ULONG64 Context;
} CALLBACK_BLOCK;

typedef struct _CALLBACK_OB_ITEM
{
    LIST_ENTRY List;
    ULONG Operations;
    ULONG Active;
    PVOID CallbackEntry;
    PVOID ObjectType;
    PVOID PreOperation;
    PVOID PostOperation;
    ULONG64 Reserved;
} CALLBACK_OB_ITEM;

typedef struct _CALLBACK_EX_REGISTRATION
{
    LIST_ENTRY List;
    PVOID Object;
    PVOID Function;
    PVOID Context;
} CALLBACK_EX_REGISTRATION;

C_ASSERT(sizeof(CALLBACK_OB_ITEM) == 0x40);
C_ASSERT(FIELD_OFFSET(CALLBACK_OB_ITEM, PreOperation) == 0x28);
C_ASSERT(FIELD_OFFSET(CALLBACK_BLOCK, Function) == 8);
C_ASSERT(FIELD_OFFSET(CALLBACK_BLOCK, Context) == 0x10);

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;

PVOID
RtlPcToFileHeader(
    PVOID PcValue,
    PVOID* BaseOfImage
    );

PVOID
RtlFindExportedRoutineByName(
    PVOID ImageBase,
    PCCH RoutineName
    );

static PRTL_PROCESS_MODULES
CallbackQueryModules(
    VOID
    );

static PVOID
CallbackNotifyArray(
    _In_ PVOID Export
    );

static VOID
CallbackModulePath(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Function,
    _Out_writes_(HACDBG_CALLBACK_PATH_CHARS) WCHAR* Path,
    _Out_writes_(256) CHAR* Narrow
    );

static VOID
CallbackAdd(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ unsigned int Type,
    _In_opt_ PVOID Function,
    _In_ ULONG64 Extra,
    _In_ ULONG Operations
    );

static VOID
CallbackWalkNotify(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Array,
    _In_ unsigned int LegacyType,
    _In_ unsigned int ExType,
    _In_ unsigned int Ex2Type
    );

static VOID
CallbackWalkObject(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID ObjectType,
    _In_ unsigned int PreType,
    _In_ unsigned int PostType,
    _In_z_ const CHAR* Name
    );

static VOID
CallbackWalkSiblingTypes(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules
    );

static VOID
CallbackWalkVerification(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PVOID Export
    );

static PVOID
CallbackDesktopType(
    _In_opt_ PRTL_PROCESS_MODULES Modules
    );

static VOID
CallbackWalkPowerSettings(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Export
    );

static ULONG
CallbackCollectHeads(
    _In_opt_ PVOID Export,
    _Out_writes_(MaxHeads) PVOID* Heads,
    _In_ ULONG MaxHeads,
    _In_ ULONG ProbeOffset
    );

static VOID
CallbackWalkRoutineList(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Head,
    _In_ unsigned int Type,
    _In_ ULONG RoutineOffset,
    _In_ ULONG StateOffset
    );

static VOID
CallbackWalkShutdown(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Head,
    _In_ unsigned int Type
    );

static VOID
CallbackWalkPointerList(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Export,
    _In_ unsigned int Type
    );

static NTSTATUS
CallbackApply(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_ unsigned int Operation,
    _In_ unsigned int Type,
    _In_ ULONG64 Entry,
    _In_ ULONG64 Extra
    );

static VOID
CallbackMarkHookState(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request
    );

NTSTATUS
CallbackExecute(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request
    )
{
    PVOID ProcessArray;
    PVOID ThreadArray;
    PVOID ImageArray;
    PVOID ProcessExport;
    PVOID ThreadExport;
    PVOID ImageExport;
    PVOID VerifyExport;
    PVOID BugCheckExport;
    PVOID BugCheckReasonExport;
    PVOID ShutdownExport;
    PVOID LastChanceExport;
    PVOID RegistryExport;
    PVOID FsExport;
    PVOID LogonExport;
    PVOID LogonExExport;
    PVOID Heads[4];
    ULONG HeadCount;
    ULONG Index;
    UNICODE_STRING Name;
    PRTL_PROCESS_MODULES Modules;

    unsigned int Operation;
    unsigned int TargetType;
    ULONG64 TargetEntry;
    ULONG64 TargetExtra;

    if (Request == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Operation = Request->Reserved;
    TargetType = Request->Rows[0].Type;
    TargetEntry = Request->Rows[0].Entry;
    TargetExtra = Request->Rows[0].Extra;
    if (Operation != HACDBG_CALLBACK_OP_SCAN)
    {
        return CallbackApply(Request, Operation, TargetType, TargetEntry, TargetExtra);
    }

    RtlZeroMemory(Request, sizeof(*Request));
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        HACDBG_LOG("HacDbg: Err, callback scan is not at PASSIVE_LEVEL.\n");
        Request->Status = (int)STATUS_INVALID_LEVEL;
        return STATUS_INVALID_LEVEL;
    }

    Modules = CallbackQueryModules();
    RtlInitUnicodeString(&Name, L"PsSetCreateProcessNotifyRoutine");
    ProcessExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"PsSetCreateThreadNotifyRoutine");
    ThreadExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"PsSetLoadImageNotifyRoutineEx");
    ImageExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"SeRegisterImageVerificationCallback");
    VerifyExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"KeRegisterBugCheckCallback");
    BugCheckExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"KeRegisterBugCheckReasonCallback");
    BugCheckReasonExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"IoRegisterShutdownNotification");
    ShutdownExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"IoRegisterLastChanceShutdownNotification");
    LastChanceExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"CmUnRegisterCallback");
    RegistryExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"IoRegisterFsRegistrationChange");
    FsExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"SeRegisterLogonSessionTerminatedRoutine");
    LogonExport = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"SeRegisterLogonSessionTerminatedRoutineEx");
    LogonExExport = MmGetSystemRoutineAddress(&Name);

    ProcessArray = CallbackNotifyArray(ProcessExport);
    ThreadArray = CallbackNotifyArray(ThreadExport);
    ImageArray = CallbackNotifyArray(ImageExport);
    HACDBG_LOG("HacDbg: Callback arrays process=%p thread=%p image=%p verify=%p.\n", ProcessArray, ThreadArray,
               ImageArray, VerifyExport);
    if (ProcessArray == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback process notify array was not found.\n");
    }

    if (ThreadArray == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback thread notify array was not found.\n");
    }

    if (ImageArray == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback image notify array was not found.\n");
    }

    HeadCount = CallbackCollectHeads(BugCheckExport, Heads, 4, CALLBACK_ROUTINE_OFFSET);
    for (Index = 0; Index < HeadCount; ++Index)
    {
        CallbackWalkRoutineList(Request, Modules, Heads[Index], HACDBG_CALLBACK_BUGCHECK, CALLBACK_ROUTINE_OFFSET,
                                CALLBACK_BUGCHECK_STATE);
    }

    HeadCount = CallbackCollectHeads(BugCheckReasonExport, Heads, 4, CALLBACK_ROUTINE_OFFSET);
    for (Index = 0; Index < HeadCount; ++Index)
    {
        CallbackWalkRoutineList(Request, Modules, Heads[Index], HACDBG_CALLBACK_BUGCHECK_REASON, CALLBACK_ROUTINE_OFFSET,
                                CALLBACK_REASON_STATE);
    }

    HeadCount = CallbackCollectHeads(ShutdownExport, Heads, 4, CALLBACK_SHUTDOWN_DEVICE);
    for (Index = 0; Index < HeadCount; ++Index)
    {
        CallbackWalkShutdown(Request, Modules, Heads[Index], HACDBG_CALLBACK_SHUTDOWN);
    }

    {
        PVOID LastHeads[4];
        ULONG LastCount;
        ULONG LastIndex;
        ULONG ShutdownIndex;

        LastCount = CallbackCollectHeads(LastChanceExport, LastHeads, 4, CALLBACK_SHUTDOWN_DEVICE);
        for (LastIndex = 0; LastIndex < LastCount; ++LastIndex)
        {
            BOOLEAN Same;

            Same = FALSE;
            for (ShutdownIndex = 0; ShutdownIndex < HeadCount; ++ShutdownIndex)
            {
                if (LastHeads[LastIndex] == Heads[ShutdownIndex])
                {
                    Same = TRUE;
                    break;
                }
            }

            if (Same == FALSE)
            {
                CallbackWalkShutdown(Request, Modules, LastHeads[LastIndex], HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN);
            }
        }
    }

    HeadCount = CallbackCollectHeads(RegistryExport, Heads, 4, CALLBACK_REGISTRY_ROUTINE);
    for (Index = 0; Index < HeadCount; ++Index)
    {
        CallbackWalkRoutineList(Request, Modules, Heads[Index], HACDBG_CALLBACK_REGISTRY, CALLBACK_REGISTRY_ROUTINE, 0);
    }

    HeadCount = CallbackCollectHeads(FsExport, Heads, 4, CALLBACK_FS_ROUTINE);
    for (Index = 0; Index < HeadCount; ++Index)
    {
        CallbackWalkRoutineList(Request, Modules, Heads[Index], HACDBG_CALLBACK_FS_NOTIFY, CALLBACK_FS_ROUTINE, 0);
    }

    CallbackWalkPointerList(Request, Modules, LogonExport, HACDBG_CALLBACK_LOGON_TERMINATED);
    CallbackWalkPointerList(Request, Modules, LogonExExport, HACDBG_CALLBACK_LOGON_TERMINATED_EX);
    RtlInitUnicodeString(&Name, L"PoRegisterPowerSettingCallback");
    CallbackWalkPowerSettings(Request, Modules, MmGetSystemRoutineAddress(&Name));
    CallbackWalkObject(Request, Modules, PsProcessType != NULL ? *PsProcessType : NULL, HACDBG_CALLBACK_PROCESS_OB_PRE,
                       HACDBG_CALLBACK_PROCESS_OB_POST, "process");
    CallbackWalkObject(Request, Modules, PsThreadType != NULL ? *PsThreadType : NULL, HACDBG_CALLBACK_THREAD_OB_PRE,
                       HACDBG_CALLBACK_THREAD_OB_POST, "thread");
    CallbackWalkObject(Request, Modules, CallbackDesktopType(Modules), HACDBG_CALLBACK_DESKTOP_OB_PRE,
                       HACDBG_CALLBACK_DESKTOP_OB_POST, "desktop");
    CallbackWalkSiblingTypes(Request, Modules);
    CallbackWalkVerification(Request, Modules, VerifyExport);
    CallbackWalkNotify(Request, Modules, ProcessArray, HACDBG_CALLBACK_CREATE_PROCESS, HACDBG_CALLBACK_CREATE_PROCESS_EX,
                       HACDBG_CALLBACK_CREATE_PROCESS_EX2);
    CallbackWalkNotify(Request, Modules, ThreadArray, HACDBG_CALLBACK_CREATE_THREAD, HACDBG_CALLBACK_CREATE_THREAD_EX, 0);
    CallbackWalkNotify(Request, Modules, ImageArray, HACDBG_CALLBACK_LOAD_IMAGE, HACDBG_CALLBACK_LOAD_IMAGE_EX, 0);

    CallbackMarkHookState(Request);
    HACDBG_LOG("HacDbg: Callback scan count=%u truncated=%u.\n", Request->Count, Request->Truncated);
    if (Modules != NULL)
    {
        ExFreePoolWithTag(Modules, CALLBACK_TAG);
    }

    Request->Status = 0;
    return STATUS_SUCCESS;
}

static PRTL_PROCESS_MODULES
CallbackQueryModules(
    VOID
    )
{
    ULONG Bytes;
    NTSTATUS Status;
    PRTL_PROCESS_MODULES Modules;

    Bytes = 0;
    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, NULL, 0, &Bytes);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || Bytes == 0)
    {
        HACDBG_LOG("HacDbg: Err, callback module size failed: 0x%08x bytes=%lu.\n", Status, Bytes);
        return NULL;
    }

    Bytes += sizeof(RTL_PROCESS_MODULE_INFORMATION);
    Modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, Bytes, CALLBACK_TAG);
    if (Modules == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback module list allocation failed.\n");
        return NULL;
    }

    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, Modules, Bytes, &Bytes);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, callback module list failed: 0x%08x.\n", Status);
        ExFreePoolWithTag(Modules, CALLBACK_TAG);
        return NULL;
    }

    HACDBG_LOG("HacDbg: Callback module list count=%lu.\n", Modules->NumberOfModules);
    return Modules;
}

static BOOLEAN
CallbackRipLea(
    _In_ const UCHAR* Code
    )
{
    if ((Code[0] == 0x48 || Code[0] == 0x4C) && Code[1] == 0x8D && (Code[2] & 0xC7) == 0x05)
    {
        return TRUE;
    }

    return FALSE;
}

static PVOID
CallbackResolveRip(
    _In_ const UCHAR* Code
    )
{
    LONG Displacement;

    Displacement = *(LONG*)(Code + 3);
    return (PVOID)(Code + 7 + Displacement);
}

static BOOLEAN
CallbackArrayLooksValid(
    _In_ PVOID Address
    )
{
    ULONG_PTR* Slots;
    ULONG Index;

    if (((ULONG_PTR)Address & 7) != 0 || MmIsAddressValid(Address) == FALSE)
    {
        return FALSE;
    }

    Slots = (ULONG_PTR*)Address;
    for (Index = 0; Index < 4; ++Index)
    {
        ULONG_PTR Value;

        if (MmIsAddressValid(&Slots[Index]) == FALSE)
        {
            return FALSE;
        }

        Value = Slots[Index];
        if (Value == 0)
        {
            continue;
        }

        if ((Value & ~0xFull) < 0xFFFF800000000000ull)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static PVOID
CallbackFirstArray(
    _In_ UCHAR* Code,
    _In_ ULONG Limit
    )
{
    ULONG Index;

    if (Code == NULL || MmIsAddressValid(Code) == FALSE)
    {
        return NULL;
    }

    for (Index = 0; Index + 7 < Limit; ++Index)
    {
        PVOID Target;

        if (MmIsAddressValid(Code + Index) == FALSE || MmIsAddressValid(Code + Index + 6) == FALSE)
        {
            break;
        }

        if (CallbackRipLea(Code + Index) == FALSE)
        {
            continue;
        }

        Target = CallbackResolveRip(Code + Index);
        if (CallbackArrayLooksValid(Target) != FALSE)
        {
            return Target;
        }
    }

    return NULL;
}

static PVOID
CallbackNotifyArray(
    _In_ PVOID Export
    )
{
    UCHAR* Code;
    ULONG Index;
    PVOID Direct;

    Code = (UCHAR*)Export;
    Direct = CallbackFirstArray(Code, 0x40);
    if (Direct != NULL)
    {
        return Direct;
    }

    if (Code == NULL)
    {
        return NULL;
    }

    for (Index = 0; Index + 5 < 0x20; ++Index)
    {
        UCHAR* Target;
        LONG Relative;

        if (MmIsAddressValid(Code + Index + 4) == FALSE)
        {
            break;
        }

        if (Code[Index] != 0xE8)
        {
            continue;
        }

        Relative = *(LONG*)(Code + Index + 1);
        Target = Code + Index + 5 + Relative;
        return CallbackFirstArray(Target, 0x180);
    }

    return NULL;
}

static VOID
CallbackModulePath(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Function,
    _Out_writes_(HACDBG_CALLBACK_PATH_CHARS) WCHAR* Path,
    _Out_writes_(256) CHAR* Narrow
    )
{
    PVOID Base;
    ULONG Index;

    Path[0] = 0;
    Narrow[0] = 0;
    if (Function == NULL || Modules == NULL || RtlPcToFileHeader(Function, &Base) == NULL)
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
        for (Char = 0; Char < 255 && Source[Char] != 0; ++Char)
        {
            Narrow[Char] = (CHAR)Source[Char];
            if (Char + 1 < HACDBG_CALLBACK_PATH_CHARS)
            {
                Path[Char] = (WCHAR)Source[Char];
            }
        }

        Narrow[Char] = 0;
        if (Char >= HACDBG_CALLBACK_PATH_CHARS)
        {
            Char = HACDBG_CALLBACK_PATH_CHARS - 1;
        }

        Path[Char] = 0;
        return;
    }
}

static VOID
CallbackAdd(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ unsigned int Type,
    _In_opt_ PVOID Function,
    _In_ ULONG64 Extra,
    _In_ ULONG Operations
    )
{
    HACDBG_CALLBACK_ROW* Row;
    WCHAR Path[HACDBG_CALLBACK_PATH_CHARS];
    CHAR Narrow[256];

    if (Request->Count >= HACDBG_CALLBACK_MAX_ROWS)
    {
        Request->Truncated = 1;
        return;
    }

    CallbackModulePath(Modules, Function, Path, Narrow);
    Row = &Request->Rows[Request->Count];
    Row->Entry = (unsigned long long)(ULONG_PTR)Function;
    Row->Extra = Extra;
    Row->Type = Type;
    RtlCopyMemory(Row->Path, Path, sizeof(Path));
    Request->Count += 1;
    HACDBG_LOG("HacDbg: Callback %s entry=%p extra=%p ops=0x%x path=%s.\n", HacDbgCallbackTypeName(Type), Function,
               (PVOID)Extra, Operations, Narrow[0] != 0 ? Narrow : "-");
}

static unsigned int
CallbackNotifyType(
    _In_ ULONG64 Context,
    _In_ unsigned int LegacyType,
    _In_ unsigned int ExType,
    _In_ unsigned int Ex2Type
    )
{
    ULONG Flags;

    Flags = (ULONG)Context;
    if (Flags == 0)
    {
        return LegacyType;
    }

    if (Ex2Type != 0 && (Flags & 4) != 0)
    {
        return Ex2Type;
    }

    if ((Flags & 2) != 0 || Flags == 1)
    {
        return ExType;
    }

    return ExType;
}

static VOID
CallbackWalkNotify(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Array,
    _In_ unsigned int LegacyType,
    _In_ unsigned int ExType,
    _In_ unsigned int Ex2Type
    )
{
    ULONG_PTR* Slots;
    ULONG Index;

    if (Array == NULL)
    {
        return;
    }

    Slots = (ULONG_PTR*)Array;
    for (Index = 0; Index < CALLBACK_NOTIFY_SLOTS; ++Index)
    {
        ULONG_PTR Value;
        CALLBACK_BLOCK* Block;
        unsigned int Type;

        if (MmIsAddressValid(&Slots[Index]) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback notify slot %lu is not readable.\n", Index);
            break;
        }

        Value = Slots[Index];
        if (Value == 0)
        {
            continue;
        }

        Block = (CALLBACK_BLOCK*)(Value & ~0xFull);
        if (MmIsAddressValid(Block) == FALSE || MmIsAddressValid((UCHAR*)Block + sizeof(CALLBACK_BLOCK) - 1) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback notify block %p is not readable.\n", Block);
            continue;
        }

        if (Block->Function == NULL)
        {
            continue;
        }

        Type = CallbackNotifyType(Block->Context, LegacyType, ExType, Ex2Type);
        CallbackAdd(Request, Modules, Type, Block->Function, (ULONG64)(ULONG_PTR)&Slots[Index], 0);
    }
}

static VOID
CallbackWalkObject(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID ObjectType,
    _In_ unsigned int PreType,
    _In_ unsigned int PostType,
    _In_z_ const CHAR* Name
    )
{
    LIST_ENTRY* Head;
    LIST_ENTRY* Link;
    ULONG Steps;

    if (ObjectType == NULL)
    {
        HACDBG_LOG("HacDbg: Callback %s object type was not found.\n", Name);
        return;
    }

    Head = (LIST_ENTRY*)((UCHAR*)ObjectType + CALLBACK_LIST_OFFSET);
    if (MmIsAddressValid(Head) == FALSE || Head->Flink == NULL || Head->Blink == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback %s list %p is not readable.\n", Name, Head);
        return;
    }

    Steps = 0;
    for (Link = Head->Flink; Link != Head && Steps < CALLBACK_OB_LIMIT; Link = Link->Flink)
    {
        CALLBACK_OB_ITEM* Item;

        Steps += 1;
        if (MmIsAddressValid(Link) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback %s link %p is not readable.\n", Name, Link);
            break;
        }

        Item = CONTAINING_RECORD(Link, CALLBACK_OB_ITEM, List);
        if (MmIsAddressValid(Item) == FALSE || MmIsAddressValid((UCHAR*)Item + sizeof(*Item) - 1) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback %s item %p is not readable.\n", Name, Item);
            break;
        }

        if ((Item->Active & 1) == 0)
        {
            continue;
        }

        if (Item->PreOperation != NULL)
        {
            CallbackAdd(Request, Modules, PreType, Item->PreOperation, (ULONG64)(ULONG_PTR)Item, Item->Operations);
        }

        if (Item->PostOperation != NULL)
        {
            CallbackAdd(Request, Modules, PostType, Item->PostOperation, (ULONG64)(ULONG_PTR)Item, Item->Operations);
        }
    }

    if (Steps >= CALLBACK_OB_LIMIT)
    {
        HACDBG_LOG("HacDbg: Err, callback %s list stopped at %lu.\n", Name, Steps);
    }
}

static BOOLEAN
CallbackMovRcx(
    _In_ const UCHAR* Code
    )
{
    return Code[0] == 0x48 && Code[1] == 0x8B && Code[2] == 0x0D;
}

static VOID
CallbackWalkOneVerification(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PVOID Global
    )
{
    PVOID Object;
    LIST_ENTRY* Head;
    LIST_ENTRY* Link;
    ULONG Steps;

    if (MmIsAddressValid(Global) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, callback verification global %p is not readable.\n", Global);
        return;
    }

    Object = *(PVOID*)Global;
    if (Object == NULL)
    {
        HACDBG_LOG("HacDbg: Callback verification object at %p is empty.\n", Global);
        return;
    }

    Head = (LIST_ENTRY*)((UCHAR*)Object + 0x10);
    if (MmIsAddressValid(Head) == FALSE || Head->Flink == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback verification list %p is not readable.\n", Head);
        return;
    }

    Steps = 0;
    for (Link = Head->Flink; Link != Head && Steps < CALLBACK_VERIFY_LIMIT; Link = Link->Flink)
    {
        CALLBACK_EX_REGISTRATION* Registration;

        Steps += 1;
        if (MmIsAddressValid(Link) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback verification link %p is not readable.\n", Link);
            break;
        }

        Registration = CONTAINING_RECORD(Link, CALLBACK_EX_REGISTRATION, List);
        if (Registration->Function == NULL)
        {
            continue;
        }

        CallbackAdd(Request, Modules, HACDBG_CALLBACK_IMAGE_VERIFICATION, Registration->Function,
                    (ULONG64)(ULONG_PTR)Registration, 0);
    }
}

static VOID
CallbackWalkVerification(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PVOID Export
    )
{
    UCHAR* Code;
    ULONG Index;
    ULONG Found;

    Code = (UCHAR*)Export;
    Found = 0;
    if (Code == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback SeRegisterImageVerificationCallback was not found.\n");
        return;
    }

    for (Index = 0; Index + 7 < 0x90 && Found < 2; ++Index)
    {
        PVOID Global;

        if (MmIsAddressValid(Code + Index + 6) == FALSE)
        {
            break;
        }

        if (CallbackMovRcx(Code + Index) == FALSE)
        {
            continue;
        }

        Global = CallbackResolveRip(Code + Index);
        CallbackWalkOneVerification(Request, Modules, Global);
        Found += 1;
    }

    if (Found == 0)
    {
        HACDBG_LOG("HacDbg: Err, callback verification objects were not found.\n");
    }
}

static BOOLEAN
CallbackModuleNameHas(
    _In_ const UCHAR* Path,
    _In_z_ const CHAR* Needle
    )
{
    ULONG Index;
    ULONG NeedleLength;

    NeedleLength = 0;
    while (Needle[NeedleLength] != 0)
    {
        NeedleLength += 1;
    }

    for (Index = 0; Path[Index] != 0 && Index + NeedleLength < 256; ++Index)
    {
        ULONG Offset;
        BOOLEAN Match;

        Match = TRUE;
        for (Offset = 0; Offset < NeedleLength; ++Offset)
        {
            CHAR Left;
            CHAR Right;

            if (Path[Index + Offset] == 0)
            {
                Match = FALSE;
                break;
            }

            Left = (CHAR)Path[Index + Offset];
            Right = Needle[Offset];
            if (Left >= 'A' && Left <= 'Z')
            {
                Left = (CHAR)(Left - 'A' + 'a');
            }

            if (Right >= 'A' && Right <= 'Z')
            {
                Right = (CHAR)(Right - 'A' + 'a');
            }

            if (Left != Right)
            {
                Match = FALSE;
                break;
            }
        }

        if (Match != FALSE)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
CallbackTypeNameIs(
    _In_ PVOID ObjectType,
    _In_z_ const WCHAR* Name
    )
{
    UNICODE_STRING* TypeName;
    SIZE_T Index;
    SIZE_T Count;

    if (ObjectType == NULL || MmIsAddressValid((UCHAR*)ObjectType + CALLBACK_TYPE_NAME_OFFSET) == FALSE)
    {
        return FALSE;
    }

    TypeName = (UNICODE_STRING*)((UCHAR*)ObjectType + CALLBACK_TYPE_NAME_OFFSET);
    if (TypeName->Buffer == NULL || TypeName->Length == 0 || (TypeName->Length & 1) != 0 ||
        MmIsAddressValid(TypeName->Buffer) == FALSE)
    {
        return FALSE;
    }

    Count = TypeName->Length / sizeof(WCHAR);
    for (Index = 0; Name[Index] != 0; ++Index)
    {
    }

    if (Index != Count || MmIsAddressValid((UCHAR*)TypeName->Buffer + TypeName->Length - 1) == FALSE)
    {
        return FALSE;
    }

    for (Index = 0; Index < Count; ++Index)
    {
        WCHAR Left;
        WCHAR Right;

        Left = TypeName->Buffer[Index];
        Right = Name[Index];
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
CallbackKernelPointer(
    _In_opt_ PVOID Value
    );

static BOOLEAN
CallbackRangeValid(
    _In_opt_ PVOID Address,
    _In_ ULONG Bytes
    );

static PVOID
CallbackTypeFromObjectArray(
    _In_z_ const WCHAR* Name
    );

static PVOID
CallbackTypeByDelta(
    _In_ LIST_ENTRY* Entry,
    _In_ LONG Delta,
    _In_z_ const WCHAR* Name
    );

static PVOID
CallbackFindObjectType(
    _In_z_ const WCHAR* Name
    )
{
    PVOID Start;

    Start = CallbackTypeFromObjectArray(Name);
    if (Start != NULL)
    {
        return Start;
    }

    if (PsProcessType == NULL || *PsProcessType == NULL)
    {
        return NULL;
    }

    Start = *PsProcessType;
    if (CallbackTypeNameIs(Start, L"Process") == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, callback object type name is not at +0x%x.\n", CALLBACK_TYPE_NAME_OFFSET);
        return NULL;
    }

    if (CallbackTypeNameIs(Start, Name) != FALSE)
    {
        return Start;
    }

    //
    // Later object types are linked through a LIST_ENTRY in front of the
    // body. The list at offset 0 of Process is empty. The delta that can
    // see Thread is the one that can see Desktop.
    //
    {
        static const LONG Deltas[] = {0, -0x20, -0x30, -0x38, -0x50};
        ULONG DeltaIndex;

        for (DeltaIndex = 0; DeltaIndex < sizeof(Deltas) / sizeof(Deltas[0]); ++DeltaIndex)
        {
            LIST_ENTRY* Entry;
            PVOID ThreadType;

            Entry = (LIST_ENTRY*)((UCHAR*)Start + Deltas[DeltaIndex]);
            ThreadType = CallbackTypeByDelta(Entry, Deltas[DeltaIndex], L"Thread");
            if (ThreadType == NULL)
            {
                continue;
            }

            HACDBG_LOG("HacDbg: Callback object types use delta %ld.\n", Deltas[DeltaIndex]);
            return CallbackTypeByDelta(Entry, Deltas[DeltaIndex], Name);
        }
    }

    return NULL;
}

static PVOID
CallbackTypeFromObjectArray(
    _In_z_ const WCHAR* Name
    )
{
    UNICODE_STRING RoutineName;
    PVOID Export;
    PVOID Image;
    UCHAR* Code;
    ULONG Index;

    RtlInitUnicodeString(&RoutineName, L"NtQueryObject");
    Export = MmGetSystemRoutineAddress(&RoutineName);
    if (Export == NULL || RtlPcToFileHeader(Export, &Image) == NULL)
    {
        return NULL;
    }

    Code = (UCHAR*)Export;
    for (Index = 0; Index + 8 < 0x900; ++Index)
    {
        LONG Displacement;
        PVOID* Array;
        ULONG Slot;
        BOOLEAN SawProcess;
        PVOID Found;

        if (MmIsAddressValid(Code + Index + 7) == FALSE)
        {
            break;
        }

        if (Code[Index] != 0x48 || Code[Index + 1] != 0x8B || (Code[Index + 2] & 0xC7) != 0x84 ||
            (Code[Index + 3] & 0xC0) != 0xC0)
        {
            continue;
        }

        Displacement = *(LONG*)(Code + Index + 4);
        if (Displacement <= 0 || Displacement > 0x2000000)
        {
            continue;
        }

        Array = (PVOID*)((UCHAR*)Image + Displacement);
        if (((ULONG_PTR)Array & 7) != 0 || CallbackRangeValid(Array, sizeof(PVOID)) == FALSE)
        {
            continue;
        }

        SawProcess = FALSE;
        Found = NULL;
        for (Slot = 0; Slot < 256; ++Slot)
        {
            PVOID Type;

            if (CallbackRangeValid(Array + Slot, sizeof(PVOID)) == FALSE)
            {
                break;
            }

            Type = Array[Slot];
            if (Type == NULL)
            {
                continue;
            }

            if (CallbackKernelPointer(Type) == FALSE)
            {
                SawProcess = FALSE;
                Found = NULL;
                break;
            }

            if (CallbackTypeNameIs(Type, L"Process") != FALSE)
            {
                SawProcess = TRUE;
            }

            if (CallbackTypeNameIs(Type, Name) != FALSE)
            {
                Found = Type;
            }
        }

        if (SawProcess != FALSE && Found != NULL)
        {
            HACDBG_LOG("HacDbg: Callback object array %p type %p.\n", Array, Found);
            return Found;
        }
    }

    return NULL;
}

static PVOID
CallbackTypeByDelta(
    _In_ LIST_ENTRY* Entry,
    _In_ LONG Delta,
    _In_z_ const WCHAR* Name
    )
{
    LIST_ENTRY* Link;
    ULONG Steps;

    if (CallbackRangeValid(Entry, sizeof(LIST_ENTRY)) == FALSE || CallbackKernelPointer(Entry->Flink) == FALSE)
    {
        return NULL;
    }

    Link = Entry;
    Steps = 0;
    do
    {
        PVOID Shifted;

        Steps += 1;
        if (CallbackRangeValid(Link, sizeof(LIST_ENTRY)) == FALSE)
        {
            return NULL;
        }

        if (CallbackTypeNameIs(Link, Name) != FALSE)
        {
            return Link;
        }

        Shifted = (UCHAR*)Link - Delta;
        if (Shifted != Link && CallbackTypeNameIs(Shifted, Name) != FALSE)
        {
            return Shifted;
        }

        Link = Link->Flink;
    } while (Link != Entry && Steps < 80 && CallbackKernelPointer(Link) != FALSE);

    return NULL;
}

static PVOID
CallbackDesktopType(
    _In_opt_ PRTL_PROCESS_MODULES Modules
    )
{
    PVOID Found;
    ULONG Index;

    Found = CallbackFindObjectType(L"Desktop");
    if (Found != NULL)
    {
        return Found;
    }

    if (Modules == NULL)
    {
        return NULL;
    }

    for (Index = 0; Index < Modules->NumberOfModules; ++Index)
    {
        PVOID Export;
        PVOID Type;

        if (CallbackModuleNameHas(Modules->Modules[Index].FullPathName, "win32k") == FALSE)
        {
            continue;
        }

        Export = RtlFindExportedRoutineByName(Modules->Modules[Index].ImageBase, "ExDesktopObjectType");
        if (Export == NULL || MmIsAddressValid(Export) == FALSE)
        {
            continue;
        }

        Type = *(PVOID*)Export;
        if (Type != NULL)
        {
            HACDBG_LOG("HacDbg: Callback desktop type %p from %s.\n", Type,
                       Modules->Modules[Index].FullPathName +
                           (Modules->Modules[Index].OffsetToFileName < 256 ? Modules->Modules[Index].OffsetToFileName
                                                                            : 0));
            return Type;
        }
    }

    return NULL;
}

static VOID
CallbackWalkSiblingTypes(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules
    )
{
    ULONG SeenRows;
    ULONG Index;
    PVOID ProcessType;
    PVOID ThreadType;
    PVOID SeenTypes[8];
    ULONG SeenCount;

    SeenRows = Request->Count;
    SeenCount = 0;
    ProcessType = PsProcessType != NULL ? *PsProcessType : NULL;
    ThreadType = PsThreadType != NULL ? *PsThreadType : NULL;
    for (Index = 0; Index < SeenRows; ++Index)
    {
        unsigned int RowType;
        CALLBACK_OB_ITEM* Item;
        UCHAR* Header;
        USHORT Count;
        ULONG ItemIndex;

        RowType = Request->Rows[Index].Type;
        if (RowType < HACDBG_CALLBACK_PROCESS_OB_PRE || RowType > HACDBG_CALLBACK_THREAD_OB_POST)
        {
            continue;
        }

        Item = (CALLBACK_OB_ITEM*)(ULONG_PTR)Request->Rows[Index].Extra;
        if (CallbackRangeValid(Item, sizeof(*Item)) == FALSE || Item->CallbackEntry == NULL)
        {
            continue;
        }

        Header = (UCHAR*)Item->CallbackEntry;
        if (CallbackRangeValid(Header, 0x22) == FALSE || *(USHORT*)Header != 0x100)
        {
            if (CallbackRangeValid(Header, 4) != FALSE)
            {
                HACDBG_LOG("HacDbg: Callback registration %p version 0x%x.\n", Header, *(USHORT*)Header);
            }

            continue;
        }

        Count = *(USHORT*)(Header + 2);
        if (Count == 0 || Count > 8)
        {
            continue;
        }

        for (ItemIndex = 0; ItemIndex < Count; ++ItemIndex)
        {
            CALLBACK_OB_ITEM* Sibling;
            PVOID ObjectType;
            ULONG SeenIndex;
            BOOLEAN Known;

            Sibling = (CALLBACK_OB_ITEM*)(Header + 0x20 + (ItemIndex * 0x40));
            if (CallbackRangeValid(Sibling, sizeof(*Sibling)) == FALSE || Sibling->CallbackEntry != Header ||
                (Sibling->Active & 1) == 0)
            {
                continue;
            }

            ObjectType = Sibling->ObjectType;
            if (ObjectType == NULL || ObjectType == ProcessType || ObjectType == ThreadType)
            {
                continue;
            }

            if (CallbackTypeNameIs(ObjectType, L"Desktop") == FALSE)
            {
                HACDBG_LOG("HacDbg: Callback sibling type %p is not Desktop.\n", ObjectType);
                continue;
            }

            Known = FALSE;
            for (SeenIndex = 0; SeenIndex < SeenCount; ++SeenIndex)
            {
                if (SeenTypes[SeenIndex] == ObjectType)
                {
                    Known = TRUE;
                    break;
                }
            }

            if (Known != FALSE)
            {
                continue;
            }

            if (SeenCount < 8)
            {
                SeenTypes[SeenCount] = ObjectType;
                SeenCount += 1;
            }

            HACDBG_LOG("HacDbg: Callback desktop type %p from registration %p.\n", ObjectType, Header);
            CallbackWalkObject(Request, Modules, ObjectType, HACDBG_CALLBACK_DESKTOP_OB_PRE,
                               HACDBG_CALLBACK_DESKTOP_OB_POST, "desktop");
        }
    }
}

static BOOLEAN
CallbackKernelPointer(
    _In_opt_ PVOID Value
    )
{
    return (ULONG_PTR)Value >= 0xFFFF800000000000ull;
}

static BOOLEAN
CallbackListHeadValid(
    _In_ PVOID Head,
    _In_ ULONG ProbeOffset
    )
{
    LIST_ENTRY* List;
    LIST_ENTRY* First;
    PVOID Probed;

    if (((ULONG_PTR)Head & 7) != 0 || MmIsAddressValid(Head) == FALSE ||
        MmIsAddressValid((UCHAR*)Head + sizeof(LIST_ENTRY) - 1) == FALSE)
    {
        return FALSE;
    }

    List = (LIST_ENTRY*)Head;
    if (List->Flink == List && List->Blink == List)
    {
        return TRUE;
    }

    if (CallbackKernelPointer(List->Flink) == FALSE || MmIsAddressValid(List->Flink) == FALSE ||
        MmIsAddressValid((UCHAR*)List->Flink + sizeof(LIST_ENTRY) - 1) == FALSE)
    {
        return FALSE;
    }

    First = (LIST_ENTRY*)List->Flink;
    if (First->Blink != List)
    {
        return FALSE;
    }

    if (ProbeOffset == 0)
    {
        return TRUE;
    }

    if (MmIsAddressValid((UCHAR*)First + ProbeOffset) == FALSE)
    {
        return FALSE;
    }

    Probed = *(PVOID*)((UCHAR*)First + ProbeOffset);
    return CallbackKernelPointer(Probed);
}

static ULONG
CallbackScanHeads(
    _In_ UCHAR* Code,
    _In_ ULONG Limit,
    _Out_writes_(MaxHeads) PVOID* Heads,
    _In_ ULONG MaxHeads,
    _In_ ULONG Found,
    _In_ ULONG ProbeOffset
    )
{
    ULONG Index;

    if (Code == NULL || MmIsAddressValid(Code) == FALSE)
    {
        return Found;
    }

    for (Index = 0; Index + 7 < Limit && Found < MaxHeads; ++Index)
    {
        PVOID Target;
        ULONG Slot;

        if (MmIsAddressValid(Code + Index + 6) == FALSE)
        {
            break;
        }

        if (CallbackRipLea(Code + Index) == FALSE)
        {
            continue;
        }

        Target = CallbackResolveRip(Code + Index);
        if (CallbackListHeadValid(Target, ProbeOffset) == FALSE)
        {
            continue;
        }

        for (Slot = 0; Slot < Found; ++Slot)
        {
            if (Heads[Slot] == Target)
            {
                Target = NULL;
                break;
            }
        }

        if (Target == NULL)
        {
            continue;
        }

        Heads[Found] = Target;
        Found += 1;
        HACDBG_LOG("HacDbg: Callback list head %p probe=+0x%x.\n", Target, ProbeOffset);
    }

    return Found;
}

static BOOLEAN
CallbackInImage(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Routine
    )
{
    ULONG Index;

    if (CallbackKernelPointer(Routine) == FALSE || Modules == NULL)
    {
        return FALSE;
    }

    for (Index = 0; Index < Modules->NumberOfModules; ++Index)
    {
        UCHAR* Base;
        ULONG Size;

        Base = (UCHAR*)Modules->Modules[Index].ImageBase;
        Size = Modules->Modules[Index].ImageSize;
        if ((UCHAR*)Routine >= Base && (UCHAR*)Routine < Base + Size)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static ULONG
CallbackCollectHeads(
    _In_opt_ PVOID Export,
    _Out_writes_(MaxHeads) PVOID* Heads,
    _In_ ULONG MaxHeads,
    _In_ ULONG ProbeOffset
    )
{
    UCHAR* Code;
    ULONG Found;
    ULONG Index;

    Code = (UCHAR*)Export;
    Found = 0;
    if (Code == NULL)
    {
        return 0;
    }

    Found = CallbackScanHeads(Code, 0x180, Heads, MaxHeads, 0, ProbeOffset);
    if (Found != 0)
    {
        return Found;
    }

    for (Index = 0; Index + 5 < 0x20; ++Index)
    {
        LONG Relative;
        UCHAR* Target;

        if (MmIsAddressValid(Code + Index + 4) == FALSE)
        {
            break;
        }

        if (Code[Index] != 0xE8)
        {
            continue;
        }

        Relative = *(LONG*)(Code + Index + 1);
        Target = Code + Index + 5 + Relative;
        Found = CallbackScanHeads(Target, 0x180, Heads, MaxHeads, 0, ProbeOffset);
        break;
    }

    if (Found == 0)
    {
        HACDBG_LOG("HacDbg: Err, callback list head was not found in %p.\n", Export);
    }

    return Found;
}

static VOID
CallbackWalkRoutineList(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Head,
    _In_ unsigned int Type,
    _In_ ULONG RoutineOffset,
    _In_ ULONG StateOffset
    )
{
    LIST_ENTRY* List;
    LIST_ENTRY* Link;
    PVOID Previous;
    ULONG Steps;
    ULONG Added;

    if (Head == NULL)
    {
        return;
    }

    List = (LIST_ENTRY*)Head;
    Previous = Head;
    Steps = 0;
    Added = 0;
    for (Link = List->Flink; Link != List && Steps < CALLBACK_LONG_LIMIT; Link = Link->Flink)
    {
        PVOID Routine;

        Steps += 1;
        if (MmIsAddressValid(Link) == FALSE || MmIsAddressValid((UCHAR*)Link + sizeof(LIST_ENTRY) - 1) == FALSE ||
            Link->Blink != Previous)
        {
            HACDBG_LOG("HacDbg: Err, callback %s link %p broke the list.\n", HacDbgCallbackTypeName(Type), Link);
            break;
        }

        if (StateOffset != 0)
        {
            if (MmIsAddressValid((UCHAR*)Link + StateOffset) == FALSE)
            {
                break;
            }

            if (*((UCHAR*)Link + StateOffset) == 0)
            {
                Previous = Link;
                continue;
            }
        }

        if (MmIsAddressValid((UCHAR*)Link + RoutineOffset) == FALSE)
        {
            break;
        }

        Routine = *(PVOID*)((UCHAR*)Link + RoutineOffset);
        if (CallbackInImage(Modules, Routine) != FALSE)
        {
            CallbackAdd(Request, Modules, Type, Routine, (ULONG64)(ULONG_PTR)Link, 0);
            Added += 1;
        }

        Previous = Link;
    }

    HACDBG_LOG("HacDbg: Callback %s head=%p added=%lu.\n", HacDbgCallbackTypeName(Type), Head, Added);
}

static VOID
CallbackWalkShutdown(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Head,
    _In_ unsigned int Type
    )
{
    LIST_ENTRY* List;
    LIST_ENTRY* Link;
    PVOID Previous;
    ULONG Steps;
    ULONG Added;

    if (Head == NULL)
    {
        return;
    }

    List = (LIST_ENTRY*)Head;
    Previous = Head;
    Steps = 0;
    Added = 0;
    for (Link = List->Flink; Link != List && Steps < CALLBACK_LONG_LIMIT; Link = Link->Flink)
    {
        PDEVICE_OBJECT Device;
        PDRIVER_OBJECT Driver;
        PVOID Routine;

        Steps += 1;
        if (MmIsAddressValid(Link) == FALSE || Link->Blink != Previous ||
            MmIsAddressValid((UCHAR*)Link + CALLBACK_SHUTDOWN_DEVICE) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback %s link %p broke the list.\n", HacDbgCallbackTypeName(Type), Link);
            break;
        }

        Device = *(PDEVICE_OBJECT*)((UCHAR*)Link + CALLBACK_SHUTDOWN_DEVICE);
        if (CallbackKernelPointer(Device) == FALSE || MmIsAddressValid(Device) == FALSE ||
            MmIsAddressValid((UCHAR*)Device + FIELD_OFFSET(DEVICE_OBJECT, DriverObject)) == FALSE)
        {
            Previous = Link;
            continue;
        }

        Driver = Device->DriverObject;
        if (CallbackKernelPointer(Driver) == FALSE || MmIsAddressValid(Driver) == FALSE)
        {
            Previous = Link;
            continue;
        }

        Routine = (PVOID)(ULONG_PTR)Driver->MajorFunction[IRP_MJ_SHUTDOWN];
        if (CallbackInImage(Modules, Routine) != FALSE)
        {
            CallbackAdd(Request, Modules, Type, Routine, (ULONG64)(ULONG_PTR)Link, 0);
            Added += 1;
        }

        Previous = Link;
    }

    HACDBG_LOG("HacDbg: Callback %s head=%p added=%lu.\n", HacDbgCallbackTypeName(Type), Head, Added);
}

static PVOID
CallbackPointerSlot(
    _In_opt_ PVOID Export
    )
{
    UCHAR* Code;
    ULONG Index;

    Code = (UCHAR*)Export;
    if (Code == NULL || MmIsAddressValid(Code) == FALSE)
    {
        return NULL;
    }

    for (Index = 0; Index + 7 < 0x100; ++Index)
    {
        PVOID Slot;
        PVOID Value;

        if (MmIsAddressValid(Code + Index + 6) == FALSE)
        {
            break;
        }

        if (Code[Index] != 0x48 || Code[Index + 1] != 0x8B || Code[Index + 2] != 0x05)
        {
            continue;
        }

        Slot = CallbackResolveRip(Code + Index);
        if (MmIsAddressValid(Slot) == FALSE)
        {
            continue;
        }

        Value = *(PVOID*)Slot;
        if (Value == NULL || CallbackKernelPointer(Value) != FALSE)
        {
            HACDBG_LOG("HacDbg: Callback pointer list %p value=%p.\n", Slot, Value);
            return Slot;
        }
    }

    HACDBG_LOG("HacDbg: Err, callback pointer list was not found in %p.\n", Export);
    return NULL;
}

static VOID
CallbackWalkPointerList(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Export,
    _In_ unsigned int Type
    )
{
    PVOID Slot;
    PVOID Node;
    ULONG Steps;

    Slot = CallbackPointerSlot(Export);
    if (Slot == NULL)
    {
        return;
    }

    Node = *(PVOID*)Slot;
    Steps = 0;
    while (Node != NULL && Steps < 64)
    {
        PVOID Routine;
        PVOID Next;

        Steps += 1;
        if (CallbackKernelPointer(Node) == FALSE || MmIsAddressValid(Node) == FALSE ||
            MmIsAddressValid((UCHAR*)Node + CALLBACK_LOGON_ROUTINE) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback %s node %p is not readable.\n", HacDbgCallbackTypeName(Type), Node);
            break;
        }

        Next = *(PVOID*)Node;
        Routine = *(PVOID*)((UCHAR*)Node + CALLBACK_LOGON_ROUTINE);
        if (CallbackInImage(Modules, Routine) != FALSE)
        {
            CallbackAdd(Request, Modules, Type, Routine, (ULONG64)(ULONG_PTR)Node, 0);
        }

        if (Next == Node)
        {
            break;
        }

        Node = Next;
    }
}

typedef struct _CALLBACK_PAGE_HOOK
{
    BOOLEAN Used;
    UINT64 TargetPa;
    PVOID ShadowRaw;
    UCHAR* Shadow;
    ULONG Patches;
} CALLBACK_PAGE_HOOK;

typedef struct _CALLBACK_ENTRY_HOOK
{
    BOOLEAN Used;
    PVOID Entry;
    ULONG PageIndex;
    ULONG Offset;
    UCHAR Original;
} CALLBACK_ENTRY_HOOK;

static CALLBACK_PAGE_HOOK g_CallbackPages[CALLBACK_HOOK_PAGES];
static CALLBACK_ENTRY_HOOK g_CallbackEntries[CALLBACK_HOOK_ENTRIES];

static BOOLEAN
CallbackFlushTranslations(
    VOID
    )
{
#if !defined(_AMD64_)
    return FALSE;
#else
    ULONG Count;
    ULONG Index;
    BOOLEAN Flushed;

    Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    Flushed = TRUE;
    for (Index = 0; Index < Count; ++Index)
    {
        PROCESSOR_NUMBER Number;
        GROUP_AFFINITY Affinity;
        GROUP_AFFINITY Previous;
        int Registers[4];

        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(Index, &Number)))
        {
            Flushed = FALSE;
            break;
        }

        Affinity.Group = Number.Group;
        Affinity.Mask = 1ull << Number.Number;
        Affinity.Reserved[0] = 0;
        Affinity.Reserved[1] = 0;
        Affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&Affinity, &Previous);

        //
        // INVARIANT: This processor is already a guest. The leaf drops cached
        // translations so the shadow page or the restored page is fetched.
        //
        __cpuidex(Registers, HACDBG_FLUSH_CPUID_LEAF, HACDBG_FLUSH_CPUID_SUBLEAF);
        KeRevertToUserGroupAffinityThread(&Previous);
        if ((UINT32)Registers[0] != 1)
        {
            Flushed = FALSE;
            break;
        }
    }

    return Flushed;
#endif
}

static VOID
CallbackMarkHookState(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request
    )
{
    ULONG Index;
    ULONG Hook;

    for (Index = 0; Index < Request->Count && Index < HACDBG_CALLBACK_MAX_ROWS; ++Index)
    {
        Request->Rows[Index].Reserved = HACDBG_CALLBACK_STATE_NORMAL;
        for (Hook = 0; Hook < CALLBACK_HOOK_ENTRIES; ++Hook)
        {
            if (g_CallbackEntries[Hook].Used != FALSE &&
                g_CallbackEntries[Hook].Entry == (PVOID)(ULONG_PTR)Request->Rows[Index].Entry)
            {
                Request->Rows[Index].Reserved = HACDBG_CALLBACK_STATE_DISABLED;
                break;
            }
        }
    }
}

static CALLBACK_ENTRY_HOOK*
CallbackFindEntryHook(
    _In_ PVOID Entry
    )
{
    ULONG Index;

    for (Index = 0; Index < CALLBACK_HOOK_ENTRIES; ++Index)
    {
        if (g_CallbackEntries[Index].Used != FALSE && g_CallbackEntries[Index].Entry == Entry)
        {
            return &g_CallbackEntries[Index];
        }
    }

    return NULL;
}

static VOID
CallbackFreePageHook(
    _Inout_ CALLBACK_PAGE_HOOK* Page
    )
{
    if (Page->ShadowRaw != NULL)
    {
        ExFreePoolWithTag(Page->ShadowRaw, CALLBACK_TAG);
    }

    Page->ShadowRaw = NULL;
    Page->Shadow = NULL;
    Page->TargetPa = 0;
    Page->Patches = 0;
    Page->Used = FALSE;
}

static NTSTATUS
CallbackRefreshOrFlush(
    _In_ BOOLEAN Refresh
    )
{
#if !defined(_AMD64_)
    UNREFERENCED_PARAMETER(Refresh);
    return STATUS_NOT_SUPPORTED;
#else
    if (Refresh != FALSE)
    {
        CALLBACK_REFRESH_HOOKS();
    }

    if (CallbackFlushTranslations() == FALSE && CallbackFlushTranslations() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, callback shadow flush failed.\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
#endif
}

static BOOLEAN
CallbackRangeValid(
    _In_opt_ PVOID Address,
    _In_ ULONG Bytes
    )
{
    if (Address == NULL || Bytes == 0)
    {
        return FALSE;
    }

    return MmIsAddressValid(Address) != FALSE && MmIsAddressValid((UCHAR*)Address + Bytes - 1) != FALSE;
}

static BOOLEAN
CallbackUnlinkNode(
    _In_ PVOID Node
    )
{
    LIST_ENTRY* Entry;
    LIST_ENTRY* Previous;
    LIST_ENTRY* Next;

    Entry = (LIST_ENTRY*)Node;
    if (CallbackRangeValid(Entry, sizeof(*Entry)) == FALSE || Entry->Flink == NULL || Entry->Blink == NULL ||
        CallbackRangeValid(Entry->Flink, sizeof(LIST_ENTRY)) == FALSE ||
        CallbackRangeValid(Entry->Blink, sizeof(LIST_ENTRY)) == FALSE)
    {
        return FALSE;
    }

    if (Entry->Flink == Entry && Entry->Blink == Entry)
    {
        return TRUE;
    }

    Previous = Entry->Blink;
    Next = Entry->Flink;
    if (Previous->Flink != Entry || Next->Blink != Entry)
    {
        return FALSE;
    }

    Previous->Flink = Next;
    Next->Blink = Previous;
    Entry->Flink = Entry;
    Entry->Blink = Entry;
    return TRUE;
}

static NTSTATUS
CallbackLocateSlot(
    _In_ unsigned int Type,
    _In_ ULONG64 Entry,
    _In_ ULONG64 Extra,
    _Out_ PVOID** Slot
    );

static NTSTATUS
CallbackZeroTable(
    _In_ unsigned int Type,
    _In_ ULONG64 Entry,
    _In_ ULONG64 Extra
    )
{
    PVOID* Slot;
    NTSTATUS Status;

    if (Type >= HACDBG_CALLBACK_CREATE_PROCESS && Type <= HACDBG_CALLBACK_LOAD_IMAGE_EX)
    {
        ULONG_PTR Value;
        CALLBACK_BLOCK* Block;

        if (CallbackRangeValid((PVOID)Extra, sizeof(ULONG_PTR)) == FALSE)
        {
            return STATUS_INVALID_ADDRESS;
        }

        Value = *(ULONG_PTR*)Extra;
        if (Value == 0)
        {
            return STATUS_SUCCESS;
        }

        Block = (CALLBACK_BLOCK*)(Value & ~0xFull);
        if (CallbackRangeValid(Block, sizeof(*Block)) == FALSE || Block->Function != (PVOID)Entry)
        {
            return STATUS_NOT_FOUND;
        }

        InterlockedExchange64((LONG64 volatile*)Extra, 0);
        HACDBG_LOG("HacDbg: Callback table slot %p cleared.\n", (PVOID)Extra);
        return STATUS_SUCCESS;
    }

    if (Type == HACDBG_CALLBACK_SHUTDOWN || Type == HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN)
    {
        if (CallbackUnlinkNode((PVOID)Extra) == FALSE)
        {
            return STATUS_NOT_FOUND;
        }

        HACDBG_LOG("HacDbg: Callback shutdown node %p cleared.\n", (PVOID)Extra);
        return STATUS_SUCCESS;
    }

    Status = CallbackLocateSlot(Type, Entry, Extra, &Slot);
    if (NT_SUCCESS(Status) == FALSE || Slot == NULL)
    {
        return Status;
    }

    if (*Slot != (PVOID)Entry && *Slot != NULL)
    {
        return STATUS_NOT_FOUND;
    }

    InterlockedExchangePointer((PVOID volatile*)Slot, NULL);
    if (Type == HACDBG_CALLBACK_BUGCHECK && CallbackRangeValid((UCHAR*)Extra + CALLBACK_BUGCHECK_STATE, 1) != FALSE)
    {
        *((UCHAR*)Extra + CALLBACK_BUGCHECK_STATE) = 0;
        CallbackUnlinkNode((PVOID)Extra);
    }
    else if (Type == HACDBG_CALLBACK_BUGCHECK_REASON &&
             CallbackRangeValid((UCHAR*)Extra + CALLBACK_REASON_STATE, 1) != FALSE)
    {
        *((UCHAR*)Extra + CALLBACK_REASON_STATE) = 0;
        CallbackUnlinkNode((PVOID)Extra);
    }
    else if (Type == HACDBG_CALLBACK_REGISTRY || Type == HACDBG_CALLBACK_FS_NOTIFY ||
             Type == HACDBG_CALLBACK_IMAGE_VERIFICATION || Type == HACDBG_CALLBACK_POWER_SETTING)
    {
        CallbackUnlinkNode((PVOID)Extra);
    }
    else if (Type == HACDBG_CALLBACK_LOGON_TERMINATED || Type == HACDBG_CALLBACK_LOGON_TERMINATED_EX)
    {
        UNICODE_STRING RoutineName;
        PVOID Export;
        PVOID* Link;

        RtlInitUnicodeString(&RoutineName, Type == HACDBG_CALLBACK_LOGON_TERMINATED_EX
                                               ? L"SeRegisterLogonSessionTerminatedRoutineEx"
                                               : L"SeRegisterLogonSessionTerminatedRoutine");
        Export = MmGetSystemRoutineAddress(&RoutineName);
        Link = (PVOID*)CallbackPointerSlot(Export);
        while (Link != NULL && CallbackRangeValid(Link, sizeof(PVOID)) != FALSE && *Link != NULL &&
               *Link != (PVOID)Extra)
        {
            Link = (PVOID*)(*Link);
        }

        if (Link != NULL && *Link == (PVOID)Extra)
        {
            *Link = *(PVOID*)Extra;
        }
    }

    HACDBG_LOG("HacDbg: Callback pointer %p cleared.\n", Slot);
    return STATUS_SUCCESS;
}

static NTSTATUS
CallbackObjectSlot(
    _In_ unsigned int Type,
    _In_ ULONG64 Entry,
    _In_ ULONG64 Extra,
    _Out_ PVOID** Slot
    )
{
    PVOID ObjectType;
    BOOLEAN Pre;
    LIST_ENTRY* Head;
    LIST_ENTRY* Link;
    ULONG Steps;
    PRTL_PROCESS_MODULES Modules;

    *Slot = NULL;
    ObjectType = NULL;
    Pre = FALSE;
    Modules = NULL;
    if (Type == HACDBG_CALLBACK_PROCESS_OB_PRE || Type == HACDBG_CALLBACK_PROCESS_OB_POST)
    {
        ObjectType = PsProcessType != NULL ? *PsProcessType : NULL;
        Pre = Type == HACDBG_CALLBACK_PROCESS_OB_PRE;
    }
    else if (Type == HACDBG_CALLBACK_THREAD_OB_PRE || Type == HACDBG_CALLBACK_THREAD_OB_POST)
    {
        ObjectType = PsThreadType != NULL ? *PsThreadType : NULL;
        Pre = Type == HACDBG_CALLBACK_THREAD_OB_PRE;
    }
    else if (Type == HACDBG_CALLBACK_DESKTOP_OB_PRE || Type == HACDBG_CALLBACK_DESKTOP_OB_POST)
    {
        Modules = CallbackQueryModules();
        ObjectType = CallbackDesktopType(Modules);
        Pre = Type == HACDBG_CALLBACK_DESKTOP_OB_PRE;
    }
    else
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (ObjectType == NULL)
    {
        if (Modules != NULL)
        {
            ExFreePoolWithTag(Modules, CALLBACK_TAG);
        }

        return STATUS_NOT_FOUND;
    }

    Head = (LIST_ENTRY*)((UCHAR*)ObjectType + CALLBACK_LIST_OFFSET);
    if (CallbackRangeValid(Head, sizeof(LIST_ENTRY)) == FALSE || Head->Flink == NULL)
    {
        if (Modules != NULL)
        {
            ExFreePoolWithTag(Modules, CALLBACK_TAG);
        }

        return STATUS_INVALID_ADDRESS;
    }

    Steps = 0;
    for (Link = Head->Flink; Link != Head && Steps < CALLBACK_OB_LIMIT; Link = Link->Flink)
    {
        CALLBACK_OB_ITEM* Item;
        PVOID Current;

        Steps += 1;
        if (MmIsAddressValid(Link) == FALSE)
        {
            break;
        }

        Item = CONTAINING_RECORD(Link, CALLBACK_OB_ITEM, List);
        if (CallbackRangeValid(Item, sizeof(*Item)) == FALSE)
        {
            break;
        }

        if ((ULONG64)(ULONG_PTR)Item != Extra && (ULONG64)(ULONG_PTR)Item->CallbackEntry != Extra)
        {
            continue;
        }

        Current = Pre != FALSE ? Item->PreOperation : Item->PostOperation;
        if (Current == (PVOID)Entry || Current == NULL)
        {
            *Slot = Pre != FALSE ? &Item->PreOperation : &Item->PostOperation;
            break;
        }
    }

    if (Modules != NULL)
    {
        ExFreePoolWithTag(Modules, CALLBACK_TAG);
    }

    return *Slot != NULL ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS
CallbackLocateSlot(
    _In_ unsigned int Type,
    _In_ ULONG64 Entry,
    _In_ ULONG64 Extra,
    _Out_ PVOID** Slot
    )
{
    ULONG Offset;
    PVOID Current;

    *Slot = NULL;
    if (Type == HACDBG_CALLBACK_SHUTDOWN || Type == HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN)
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (Type >= HACDBG_CALLBACK_PROCESS_OB_PRE && Type <= HACDBG_CALLBACK_DESKTOP_OB_POST)
    {
        return CallbackObjectSlot(Type, Entry, Extra, Slot);
    }

    if (Type >= HACDBG_CALLBACK_CREATE_PROCESS && Type <= HACDBG_CALLBACK_LOAD_IMAGE_EX)
    {
        ULONG_PTR Value;
        CALLBACK_BLOCK* Block;

        if (CallbackRangeValid((PVOID)Extra, sizeof(ULONG_PTR)) == FALSE)
        {
            return STATUS_INVALID_ADDRESS;
        }

        Value = *(ULONG_PTR*)Extra;
        Block = (CALLBACK_BLOCK*)(Value & ~0xFull);
        if (CallbackRangeValid(Block, sizeof(*Block)) == FALSE)
        {
            return STATUS_INVALID_ADDRESS;
        }

        *Slot = &Block->Function;
        return STATUS_SUCCESS;
    }

    Offset = 0;
    if (Type == HACDBG_CALLBACK_BUGCHECK || Type == HACDBG_CALLBACK_BUGCHECK_REASON)
    {
        Offset = CALLBACK_ROUTINE_OFFSET;
    }
    else if (Type == HACDBG_CALLBACK_REGISTRY)
    {
        Offset = CALLBACK_REGISTRY_ROUTINE;
    }
    else if (Type == HACDBG_CALLBACK_FS_NOTIFY)
    {
        Offset = CALLBACK_FS_ROUTINE;
    }
    else if (Type == HACDBG_CALLBACK_LOGON_TERMINATED || Type == HACDBG_CALLBACK_LOGON_TERMINATED_EX)
    {
        Offset = CALLBACK_LOGON_ROUTINE;
    }
    else if (Type == HACDBG_CALLBACK_IMAGE_VERIFICATION)
    {
        Offset = FIELD_OFFSET(CALLBACK_EX_REGISTRATION, Function);
    }
    else if (Type == HACDBG_CALLBACK_POWER_SETTING)
    {
        Offset = CALLBACK_POWER_ROUTINE;
    }
    else
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (CallbackRangeValid((UCHAR*)Extra + Offset, sizeof(PVOID)) == FALSE)
    {
        return STATUS_INVALID_ADDRESS;
    }

    *Slot = (PVOID*)((UCHAR*)Extra + Offset);
    Current = **Slot;
    if (Current != (PVOID)Entry && Current != NULL)
    {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

static CALLBACK_PAGE_HOOK*
CallbackFindPageHook(
    _In_ UINT64 TargetPa
    )
{
    ULONG Index;

    for (Index = 0; Index < CALLBACK_HOOK_PAGES; ++Index)
    {
        if (g_CallbackPages[Index].Used != FALSE && g_CallbackPages[Index].TargetPa == TargetPa)
        {
            return &g_CallbackPages[Index];
        }
    }

    return NULL;
}

static NTSTATUS
CallbackInstallRet(
    _In_ PVOID Entry
    )
{
#if !defined(_AMD64_)
    UNREFERENCED_PARAMETER(Entry);
    return STATUS_NOT_SUPPORTED;
#else
    UCHAR* PageBase;
    ULONG Offset;
    ULONG PageIndex;
    ULONG EntryIndex;
    CALLBACK_PAGE_HOOK* Page;
    CALLBACK_ENTRY_HOOK* Hook;
    PHYSICAL_ADDRESS TargetPhysical;
    PHYSICAL_ADDRESS ShadowPhysical;
    PVOID ShadowRaw;
    UCHAR* Shadow;
    BOOLEAN Added;

    if (CallbackKernelPointer(Entry) == FALSE || CallbackFindEntryHook(Entry) != NULL)
    {
        return CallbackFindEntryHook(Entry) != NULL ? STATUS_SUCCESS : STATUS_INVALID_ADDRESS;
    }

    PageBase = (UCHAR*)((ULONG_PTR)Entry & ~(ULONG_PTR)(PAGE_SIZE - 1));
    Offset = (ULONG)((ULONG_PTR)Entry & (PAGE_SIZE - 1));
    TargetPhysical = MmGetPhysicalAddress(PageBase);
    if (TargetPhysical.QuadPart == 0)
    {
        HACDBG_LOG("HacDbg: Err, callback %p has no physical page.\n", Entry);
        return STATUS_NOT_FOUND;
    }

    Page = CallbackFindPageHook((UINT64)TargetPhysical.QuadPart & ~(UINT64)(PAGE_SIZE - 1));
    if (Page == NULL)
    {
        for (PageIndex = 0; PageIndex < CALLBACK_HOOK_PAGES; ++PageIndex)
        {
            if (g_CallbackPages[PageIndex].Used == FALSE)
            {
                Page = &g_CallbackPages[PageIndex];
                break;
            }
        }

        if (Page == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ShadowRaw = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE * 2, CALLBACK_TAG);
        if (ShadowRaw == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Shadow = (UCHAR*)(((ULONG_PTR)ShadowRaw + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
        RtlCopyMemory(Shadow, PageBase, PAGE_SIZE);
        Shadow[Offset] = 0xC3;
        ShadowPhysical = MmGetPhysicalAddress(Shadow);
        if (ShadowPhysical.QuadPart == 0)
        {
            ExFreePoolWithTag(ShadowRaw, CALLBACK_TAG);
            return STATUS_NOT_FOUND;
        }

        //
        // INVARIANT: TargetPa is the guest physical page of the callback.
        // Shadow is a nonpaged copy of that page with ret at the entry.
        // The guest executes the copy. The original page stays unchanged.
        //
        Added = CALLBACK_ADD_HOOK(HacDbgGuestPhysicalAddress((UINT64)TargetPhysical.QuadPart),
                                  HacDbgGuestPhysicalAddress((UINT64)ShadowPhysical.QuadPart));
        if (Added == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback shadow hook failed for %p.\n", Entry);
            ExFreePoolWithTag(ShadowRaw, CALLBACK_TAG);
            return STATUS_UNSUCCESSFUL;
        }

        Page->Used = TRUE;
        Page->TargetPa = (UINT64)TargetPhysical.QuadPart & ~(UINT64)(PAGE_SIZE - 1);
        Page->ShadowRaw = ShadowRaw;
        Page->Shadow = Shadow;
        Page->Patches = 0;
    }
    else
    {
        Page->Shadow[Offset] = 0xC3;
    }

    for (EntryIndex = 0; EntryIndex < CALLBACK_HOOK_ENTRIES; ++EntryIndex)
    {
        if (g_CallbackEntries[EntryIndex].Used == FALSE)
        {
            break;
        }
    }

    if (EntryIndex == CALLBACK_HOOK_ENTRIES)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Hook = &g_CallbackEntries[EntryIndex];
    Hook->Used = TRUE;
    Hook->Entry = Entry;
    Hook->PageIndex = (ULONG)(Page - g_CallbackPages);
    Hook->Offset = Offset;
    Hook->Original = PageBase[Offset];
    Page->Patches += 1;
    if (!NT_SUCCESS(CallbackRefreshOrFlush(Page->Patches > 1)))
    {
        return STATUS_UNSUCCESSFUL;
    }

    HACDBG_LOG("HacDbg: Callback %p disabled by shadow ret at +0x%x.\n", Entry, Offset);
    return STATUS_SUCCESS;
#endif
}

static NTSTATUS
CallbackRemoveRet(
    _In_ PVOID Entry
    )
{
#if !defined(_AMD64_)
    UNREFERENCED_PARAMETER(Entry);
    return STATUS_NOT_SUPPORTED;
#else
    CALLBACK_ENTRY_HOOK* Hook;
    CALLBACK_PAGE_HOOK* Page;
    BOOLEAN Removed;

    Hook = CallbackFindEntryHook(Entry);
    if (Hook == NULL)
    {
        return STATUS_NOT_FOUND;
    }

    Page = &g_CallbackPages[Hook->PageIndex];
    if (Page->Used == FALSE || Page->Shadow == NULL || Hook->Offset >= PAGE_SIZE)
    {
        Hook->Used = FALSE;
        return STATUS_NOT_FOUND;
    }

    Page->Shadow[Hook->Offset] = Hook->Original;
    if (Page->Patches > 0)
    {
        Page->Patches -= 1;
    }

    Hook->Used = FALSE;
    if (Page->Patches == 0)
    {
        //
        // INVARIANT: TargetPa is the same guest physical page passed to the
        // shadow hook. Removing it makes the guest execute the original page.
        //
        Removed = CALLBACK_REMOVE_HOOK(HacDbgGuestPhysicalAddress(Page->TargetPa));
        if (Removed == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, callback shadow remove failed pa=0x%I64x.\n", Page->TargetPa);
            return STATUS_UNSUCCESSFUL;
        }

        CallbackFreePageHook(Page);
    }

    if (!NT_SUCCESS(CallbackRefreshOrFlush(Page->Used)))
    {
        return STATUS_UNSUCCESSFUL;
    }

    HACDBG_LOG("HacDbg: Callback %p enabled, shadow ret removed.\n", Entry);
    return STATUS_SUCCESS;
#endif
}

static NTSTATUS
CallbackApply(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_ unsigned int Operation,
    _In_ unsigned int Type,
    _In_ ULONG64 Entry,
    _In_ ULONG64 Extra
    )
{
    NTSTATUS Status;

    Request->Count = 0;
    Request->Truncated = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        Status = STATUS_INVALID_LEVEL;
        goto Done;
    }

    if (Operation == HACDBG_CALLBACK_OP_REMOVE)
    {
        Status = CallbackRemoveRet((PVOID)Entry);
        if (Status == STATUS_NOT_FOUND)
        {
            Status = STATUS_SUCCESS;
        }

        if (NT_SUCCESS(Status) != FALSE)
        {
            Status = CallbackZeroTable(Type, Entry, Extra);
        }
    }
    else if (Operation == HACDBG_CALLBACK_OP_DISABLE)
    {
        Status = CallbackInstallRet((PVOID)Entry);
    }
    else if (Operation == HACDBG_CALLBACK_OP_ENABLE)
    {
        Status = CallbackRemoveRet((PVOID)Entry);
    }
    else
    {
        Status = STATUS_INVALID_PARAMETER;
    }

Done:
    Request->Status = (int)Status;
    Request->Reserved = 0;
    HACDBG_LOG("HacDbg: Callback edit op=%u type=%s entry=%p extra=%p status=0x%08x.\n", Operation,
               HacDbgCallbackTypeName(Type), (PVOID)Entry, (PVOID)Extra, Status);
    return Status;
}

static BOOLEAN
CallbackPowerNode(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Node
    )
{
    ULONG Tag;
    PVOID Routine;

    if (CallbackRangeValid(Node, CALLBACK_POWER_ROUTINE + sizeof(PVOID)) == FALSE)
    {
        return FALSE;
    }

    Tag = *(ULONG*)((UCHAR*)Node + CALLBACK_POWER_LIST);
    Routine = *(PVOID*)((UCHAR*)Node + CALLBACK_POWER_ROUTINE);
    return Tag == CALLBACK_POWER_TAG && CallbackInImage(Modules, Routine) != FALSE;
}

static ULONG
CallbackAddPowerList(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PLIST_ENTRY Head
    )
{
    LIST_ENTRY* Link;
    PVOID Previous;
    ULONG Steps;
    ULONG Added;

    Previous = Head;
    Steps = 0;
    Added = 0;
    for (Link = Head->Flink; Link != Head && Steps < CALLBACK_LONG_LIMIT; Link = Link->Flink)
    {
        PVOID Routine;

        Steps += 1;
        if (CallbackRangeValid(Link, sizeof(LIST_ENTRY)) == FALSE || Link->Blink != Previous)
        {
            break;
        }

        if (CallbackPowerNode(Modules, Link) != FALSE)
        {
            Routine = *(PVOID*)((UCHAR*)Link + CALLBACK_POWER_ROUTINE);
            CallbackAdd(Request, Modules, HACDBG_CALLBACK_POWER_SETTING, Routine, (ULONG64)(ULONG_PTR)Link, 0);
            Added += 1;
        }

        Previous = Link;
    }

    return Added;
}

static VOID
CallbackConsiderPowerHead(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Head,
    _Inout_updates_(32) PVOID* Seen,
    _Inout_ ULONG* SeenCount
    )
{
    LIST_ENTRY* List;
    ULONG Index;
    ULONG Added;

    if (Head == NULL || CallbackListHeadValid(Head, 0) == FALSE)
    {
        return;
    }

    for (Index = 0; Index < *SeenCount; ++Index)
    {
        if (Seen[Index] == Head)
        {
            return;
        }
    }

    if (*SeenCount < 32)
    {
        Seen[*SeenCount] = Head;
        *SeenCount += 1;
    }

    List = (LIST_ENTRY*)Head;
    if (List->Flink == List || CallbackPowerNode(Modules, List->Flink) == FALSE)
    {
        return;
    }

    Added = CallbackAddPowerList(Request, Modules, List);
    HACDBG_LOG("HacDbg: Callback PowerSetting head=%p added=%lu.\n", Head, Added);
}

static VOID
CallbackVisitPowerCode(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ UCHAR* Code,
    _In_ ULONG Depth,
    _Inout_ ULONG* Visits,
    _Inout_updates_(32) PVOID* Seen,
    _Inout_ ULONG* SeenCount
    )
{
    ULONG Index;
    ULONG Calls;

    if (Code == NULL || Depth > 2 || MmIsAddressValid(Code) == FALSE || *Visits > 64)
    {
        return;
    }

    *Visits += 1;
    Calls = 0;
    for (Index = 0; Index + 7 < (Depth == 0 ? 0x400u : 0x180u) && Calls < 24; ++Index)
    {
        if (MmIsAddressValid(Code + Index + 6) == FALSE)
        {
            break;
        }

        if (CallbackRipLea(Code + Index) != FALSE)
        {
            CallbackConsiderPowerHead(Request, Modules, CallbackResolveRip(Code + Index), Seen, SeenCount);
        }

        if (Depth < 2 && Code[Index] == 0xE8 && MmIsAddressValid(Code + Index + 4) != FALSE)
        {
            LONG Relative;
            UCHAR* Target;

            Relative = *(LONG*)(Code + Index + 1);
            Target = Code + Index + 5 + Relative;
            if (MmIsAddressValid(Target) != FALSE && MmIsAddressValid(Target - 1) != FALSE &&
                (*(Target - 1) == 0xCC || *(Target - 1) == 0xC3))
            {
                CallbackVisitPowerCode(Request, Modules, Target, Depth + 1, Visits, Seen, SeenCount);
                Calls += 1;
            }
        }
    }
}

static VOID
CallbackWalkPowerSettings(
    _Inout_ HACDBG_CALLBACK_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Export
    )
{
    PVOID Seen[32];
    ULONG SeenCount;
    ULONG Visits;

    if (Export == NULL)
    {
        HACDBG_LOG("HacDbg: Err, callback PoRegisterPowerSettingCallback was not found.\n");
        return;
    }

    SeenCount = 0;
    Visits = 0;
    CallbackVisitPowerCode(Request, Modules, (UCHAR*)Export, 0, &Visits, Seen, &SeenCount);
}
