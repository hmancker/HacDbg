/**
 * @file Minifilter.c
 * @brief Enumerate Filter Manager minifilters and their callbacks.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <fltKernel.h>

#include "Minifilter.h"
#include "Config.h"
#include "Debug.h"
#include "Search.h"
#include "Types.h"

#include <intrin.h>

#if defined(_AMD64_)
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#define MINIFILTER_ADD_HOOK EptAddHook
#define MINIFILTER_REMOVE_HOOK EptRemoveHook
#define MINIFILTER_REFRESH_HOOKS EptRefreshHookCopies
#else
#include "Npt.h"
#include "Svm.h"
#define MINIFILTER_ADD_HOOK NptAddHook
#define MINIFILTER_REMOVE_HOOK NptRemoveHook
#define MINIFILTER_REFRESH_HOOKS NptRefreshHookCopies
#endif
#endif

#ifndef HACDBG_FLUSH_CPUID_LEAF
#define HACDBG_FLUSH_CPUID_LEAF 0x48444301u
#define HACDBG_FLUSH_CPUID_SUBLEAF 0x464C5348u
#endif

#pragma comment(lib, "fltMgr.lib")

#define MINIFILTER_TAG 'fMiH'
#define MINIFILTER_LIST_LIMIT 64u
#define MINIFILTER_OP_LIMIT 48u
#define MINIFILTER_HOOK_PAGES 48u
#define MINIFILTER_HOOK_ENTRIES 256u
#define MINIFILTER_PATCH_BYTES 3u

//
// fltmgr!_FLT_FILTER for the fltmgr.sys that matches this machine.
// DriverObject is +0x068. Operations is +0x1b0.
//
#define MINIFILTER_DRIVER_OBJECT 0x068u
#define MINIFILTER_OPERATIONS 0x1b0u

typedef struct _MINIFILTER_PAGE_HOOK
{
    BOOLEAN Used;
    UINT64 TargetPa;
    PVOID ShadowRaw;
    UCHAR* Shadow;
    ULONG Patches;
} MINIFILTER_PAGE_HOOK;

typedef struct _MINIFILTER_ENTRY_HOOK
{
    BOOLEAN Used;
    PVOID Entry;
    ULONG PageIndex;
    ULONG Offset;
    UCHAR Original[MINIFILTER_PATCH_BYTES];
} MINIFILTER_ENTRY_HOOK;

typedef struct _MINIFILTER_ITEM
{
    PFLT_FILTER Filter;
    WCHAR Name[HACDBG_MINIFILTER_NAME_CHARS];
    WCHAR Altitude[HACDBG_MINIFILTER_ALTITUDE_CHARS];
    WCHAR Path[HACDBG_MINIFILTER_PATH_CHARS];
    UINT64 AltitudeKey;
} MINIFILTER_ITEM;

static MINIFILTER_PAGE_HOOK g_MinifilterPages[MINIFILTER_HOOK_PAGES];
static MINIFILTER_ENTRY_HOOK g_MinifilterEntries[MINIFILTER_HOOK_ENTRIES];

PVOID
RtlPcToFileHeader(
    PVOID PcValue,
    PVOID* BaseOfImage
    );

static VOID
MiniCopyChars(
    _Out_writes_(DestChars) WCHAR* Dest,
    _In_ ULONG DestChars,
    _In_reads_(SourceChars) PCWSTR Source,
    _In_ ULONG SourceChars
    )
{
    ULONG Count;

    Dest[0] = 0;
    if (DestChars == 0)
    {
        return;
    }

    Count = SourceChars;
    if (Count >= DestChars)
    {
        Count = DestChars - 1;
    }

    if (Count != 0 && Source != NULL)
    {
        RtlCopyMemory(Dest, Source, Count * sizeof(WCHAR));
    }

    Dest[Count] = 0;
}

static UINT64
MiniAltitudeKey(
    _In_ PCWSTR Text
    )
{
    UINT64 Whole;
    UINT64 Fraction;
    ULONG FractionDigits;
    BOOLEAN Dot;
    ULONG Index;

    Whole = 0;
    Fraction = 0;
    FractionDigits = 0;
    Dot = FALSE;
    for (Index = 0; Text[Index] != 0 && Index < HACDBG_MINIFILTER_ALTITUDE_CHARS; ++Index)
    {
        if (Text[Index] == L'.')
        {
            Dot = TRUE;
            continue;
        }

        if (Text[Index] < L'0' || Text[Index] > L'9')
        {
            break;
        }

        if (Dot == FALSE)
        {
            Whole = Whole * 10 + (UINT64)(Text[Index] - L'0');
        }
        else if (FractionDigits < 4)
        {
            Fraction = Fraction * 10 + (UINT64)(Text[Index] - L'0');
            FractionDigits += 1;
        }
    }

    while (FractionDigits < 4)
    {
        Fraction *= 10;
        FractionDigits += 1;
    }

    return Whole * 10000 + Fraction;
}

static VOID
MiniModulePath(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_opt_ PVOID Image,
    _Out_writes_(HACDBG_MINIFILTER_PATH_CHARS) WCHAR* Path
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
        for (Char = 0; Char + 1 < HACDBG_MINIFILTER_PATH_CHARS && Source[Char] != 0; ++Char)
        {
            Path[Char] = (WCHAR)Source[Char];
        }

        Path[Char] = 0;
        return;
    }
}

static PRTL_PROCESS_MODULES
MiniQueryModules(
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
        return NULL;
    }

    Bytes += sizeof(RTL_PROCESS_MODULE_INFORMATION);
    Modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, Bytes, MINIFILTER_TAG);
    if (Modules == NULL)
    {
        return NULL;
    }

    Status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, Modules, Bytes, &Bytes);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Modules, MINIFILTER_TAG);
        return NULL;
    }

    return Modules;
}

static PDRIVER_OBJECT
MiniDriver(
    _In_ PFLT_FILTER Filter
    )
{
    PDRIVER_OBJECT Driver;

    if (MmIsAddressValid((PUCHAR)Filter + MINIFILTER_DRIVER_OBJECT) == FALSE)
    {
        return NULL;
    }

    Driver = *(PDRIVER_OBJECT*)((PUCHAR)Filter + MINIFILTER_DRIVER_OBJECT);
    if (Driver == NULL || MmIsAddressValid(Driver) == FALSE || Driver->Type != IO_TYPE_DRIVER)
    {
        return NULL;
    }

    return Driver;
}

static PFLT_OPERATION_REGISTRATION
MiniOperations(
    _In_ PFLT_FILTER Filter
    )
{
    PFLT_OPERATION_REGISTRATION Operations;

    if (MmIsAddressValid((PUCHAR)Filter + MINIFILTER_OPERATIONS) == FALSE)
    {
        return NULL;
    }

    Operations = *(PFLT_OPERATION_REGISTRATION*)((PUCHAR)Filter + MINIFILTER_OPERATIONS);
    if (Operations == NULL || MmIsAddressValid(Operations) == FALSE)
    {
        return NULL;
    }

    return Operations;
}

static ULONG_PTR
MiniRoutine(
    _In_ const VOID* Slot
    )
{
    ULONG_PTR Value;

    Value = 0;
    if (MmIsAddressValid((PVOID)Slot) == FALSE)
    {
        return 0;
    }

    RtlCopyMemory(&Value, Slot, sizeof(Value));
    if (Value < 0xFFFF800000000000ull)
    {
        return 0;
    }

    return Value;
}

static PCWSTR
MiniOperationText(
    _In_ UCHAR Major
    )
{
    switch (Major)
    {
    case IRP_MJ_CREATE:
        return L"IRP_MJ_CREATE";
    case IRP_MJ_CREATE_NAMED_PIPE:
        return L"IRP_MJ_CREATE_NAMED_PIPE";
    case IRP_MJ_CLOSE:
        return L"IRP_MJ_CLOSE";
    case IRP_MJ_READ:
        return L"IRP_MJ_READ";
    case IRP_MJ_WRITE:
        return L"IRP_MJ_WRITE";
    case IRP_MJ_QUERY_INFORMATION:
        return L"IRP_MJ_QUERY_INFORMATION";
    case IRP_MJ_SET_INFORMATION:
        return L"IRP_MJ_SET_INFORMATION";
    case IRP_MJ_QUERY_EA:
        return L"IRP_MJ_QUERY_EA";
    case IRP_MJ_SET_EA:
        return L"IRP_MJ_SET_EA";
    case IRP_MJ_FLUSH_BUFFERS:
        return L"IRP_MJ_FLUSH_BUFFERS";
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        return L"IRP_MJ_QUERY_VOLUME_INFORMATION";
    case IRP_MJ_SET_VOLUME_INFORMATION:
        return L"IRP_MJ_SET_VOLUME_INFORMATION";
    case IRP_MJ_DIRECTORY_CONTROL:
        return L"IRP_MJ_DIRECTORY_CONTROL";
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return L"IRP_MJ_FILE_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CONTROL:
        return L"IRP_MJ_DEVICE_CONTROL";
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        return L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
    case IRP_MJ_SHUTDOWN:
        return L"IRP_MJ_SHUTDOWN";
    case IRP_MJ_LOCK_CONTROL:
        return L"IRP_MJ_LOCK_CONTROL";
    case IRP_MJ_CLEANUP:
        return L"IRP_MJ_CLEANUP";
    case IRP_MJ_CREATE_MAILSLOT:
        return L"IRP_MJ_CREATE_MAILSLOT";
    case IRP_MJ_QUERY_SECURITY:
        return L"IRP_MJ_QUERY_SECURITY";
    case IRP_MJ_SET_SECURITY:
        return L"IRP_MJ_SET_SECURITY";
    case IRP_MJ_POWER:
        return L"IRP_MJ_POWER";
    case IRP_MJ_SYSTEM_CONTROL:
        return L"IRP_MJ_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CHANGE:
        return L"IRP_MJ_DEVICE_CHANGE";
    case IRP_MJ_QUERY_QUOTA:
        return L"IRP_MJ_QUERY_QUOTA";
    case IRP_MJ_SET_QUOTA:
        return L"IRP_MJ_SET_QUOTA";
    case IRP_MJ_PNP:
        return L"IRP_MJ_PNP";
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        return L"IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION";
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
        return L"IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION";
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
        return L"IRP_MJ_ACQUIRE_FOR_MOD_WRITE";
    case IRP_MJ_RELEASE_FOR_MOD_WRITE:
        return L"IRP_MJ_RELEASE_FOR_MOD_WRITE";
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
        return L"IRP_MJ_ACQUIRE_FOR_CC_FLUSH";
    case IRP_MJ_RELEASE_FOR_CC_FLUSH:
        return L"IRP_MJ_RELEASE_FOR_CC_FLUSH";
    case IRP_MJ_QUERY_OPEN:
        return L"IRP_MJ_QUERY_OPEN";
    case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
        return L"IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE";
    case IRP_MJ_NETWORK_QUERY_OPEN:
        return L"IRP_MJ_NETWORK_QUERY_OPEN";
    case IRP_MJ_MDL_READ:
        return L"IRP_MJ_MDL_READ";
    case IRP_MJ_MDL_READ_COMPLETE:
        return L"IRP_MJ_MDL_READ_COMPLETE";
    case IRP_MJ_PREPARE_MDL_WRITE:
        return L"IRP_MJ_PREPARE_MDL_WRITE";
    case IRP_MJ_MDL_WRITE_COMPLETE:
        return L"IRP_MJ_MDL_WRITE_COMPLETE";
    case IRP_MJ_VOLUME_MOUNT:
        return L"IRP_MJ_VOLUME_MOUNT";
    case IRP_MJ_VOLUME_DISMOUNT:
        return L"IRP_MJ_VOLUME_DISMOUNT";
    default:
        return L"IRP_MJ";
    }
}

static VOID
MiniCallbackName(
    _Out_writes_(HACDBG_MINIFILTER_NAME_CHARS) WCHAR* Dest,
    _In_ UCHAR Major,
    _In_ BOOLEAN Post
    )
{
    PCWSTR Text;
    ULONG Index;

    Text = MiniOperationText(Major);
    Dest[0] = 0;
    for (Index = 0; Text[Index] != 0 && Index + 6 < HACDBG_MINIFILTER_NAME_CHARS; ++Index)
    {
        Dest[Index] = Text[Index];
    }

    Dest[Index] = L' ';
    Index += 1;
    if (Post == FALSE)
    {
        Dest[Index] = L'P';
        Dest[Index + 1] = L'r';
        Dest[Index + 2] = L'e';
        Dest[Index + 3] = 0;
    }
    else
    {
        Dest[Index] = L'P';
        Dest[Index + 1] = L'o';
        Dest[Index + 2] = L's';
        Dest[Index + 3] = L't';
        Dest[Index + 4] = 0;
    }
}

static BOOLEAN
MiniAddRow(
    _Inout_ HACDBG_MINIFILTER_REQUEST* Request,
    _In_ unsigned long long Filter,
    _In_ unsigned long long Callback,
    _In_ unsigned int Parent,
    _In_ unsigned int Depth,
    _In_ unsigned int Major,
    _In_ unsigned int Post,
    _In_ PCWSTR Name,
    _In_ PCWSTR Altitude,
    _In_ PCWSTR Path
    )
{
    HACDBG_MINIFILTER_ROW* Row;
    ULONG Index;

    if (Request->Count >= HACDBG_MINIFILTER_MAX_ROWS)
    {
        Request->Truncated = 1;
        return FALSE;
    }

    Row = &Request->Rows[Request->Count];
    RtlZeroMemory(Row, sizeof(*Row));
    Row->Filter = Filter;
    Row->Callback = Callback;
    Row->Parent = Parent;
    Row->Depth = Depth;
    Row->Major = Major;
    Row->Post = Post;
    for (Index = 0; Name[Index] != 0 && Index + 1 < HACDBG_MINIFILTER_NAME_CHARS; ++Index)
    {
        Row->Name[Index] = Name[Index];
    }

    Row->Name[Index] = 0;
    for (Index = 0; Altitude[Index] != 0 && Index + 1 < HACDBG_MINIFILTER_ALTITUDE_CHARS; ++Index)
    {
        Row->Altitude[Index] = Altitude[Index];
    }

    Row->Altitude[Index] = 0;
    for (Index = 0; Path[Index] != 0 && Index + 1 < HACDBG_MINIFILTER_PATH_CHARS; ++Index)
    {
        Row->Path[Index] = Path[Index];
    }

    Row->Path[Index] = 0;
    Request->Count += 1;
    return TRUE;
}

static VOID
MiniReadInfo(
    _In_ PFLT_FILTER Filter,
    _Out_writes_(HACDBG_MINIFILTER_NAME_CHARS) WCHAR* Name,
    _Out_writes_(HACDBG_MINIFILTER_ALTITUDE_CHARS) WCHAR* Altitude
    )
{
    UCHAR Buffer[1024];
    ULONG Returned;
    PFILTER_AGGREGATE_STANDARD_INFORMATION Info;
    NTSTATUS Status;

    Name[0] = 0;
    Altitude[0] = 0;
    Returned = 0;
    Status = FltGetFilterInformation(Filter, FilterAggregateStandardInformation, Buffer, sizeof(Buffer), &Returned);
    if (!NT_SUCCESS(Status) || Returned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION))
    {
        return;
    }

    Info = (PFILTER_AGGREGATE_STANDARD_INFORMATION)Buffer;
    if ((Info->Flags & FLTFL_ASI_IS_MINIFILTER) == 0)
    {
        return;
    }

    if (Info->Type.MiniFilter.FilterNameBufferOffset != 0 && Info->Type.MiniFilter.FilterNameLength != 0 &&
        (ULONG)Info->Type.MiniFilter.FilterNameBufferOffset + Info->Type.MiniFilter.FilterNameLength <= Returned)
    {
        MiniCopyChars(Name, HACDBG_MINIFILTER_NAME_CHARS,
                      (PCWSTR)(Buffer + Info->Type.MiniFilter.FilterNameBufferOffset),
                      Info->Type.MiniFilter.FilterNameLength / sizeof(WCHAR));
    }

    if (Info->Type.MiniFilter.FilterAltitudeBufferOffset != 0 && Info->Type.MiniFilter.FilterAltitudeLength != 0 &&
        (ULONG)Info->Type.MiniFilter.FilterAltitudeBufferOffset + Info->Type.MiniFilter.FilterAltitudeLength <= Returned)
    {
        MiniCopyChars(Altitude, HACDBG_MINIFILTER_ALTITUDE_CHARS,
                      (PCWSTR)(Buffer + Info->Type.MiniFilter.FilterAltitudeBufferOffset),
                      Info->Type.MiniFilter.FilterAltitudeLength / sizeof(WCHAR));
    }
}

static VOID
MiniForEachCallback(
    _In_ PFLT_FILTER Filter,
    _In_ BOOLEAN Patch,
    _Inout_opt_ HACDBG_MINIFILTER_REQUEST* Request,
    _In_ unsigned int Parent,
    _In_ PCWSTR Path
    );

static BOOLEAN
MiniFlushTranslations(
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

static MINIFILTER_ENTRY_HOOK*
MiniFindEntry(
    _In_ PVOID Entry
    )
{
    ULONG Index;

    for (Index = 0; Index < MINIFILTER_HOOK_ENTRIES; ++Index)
    {
        if (g_MinifilterEntries[Index].Used != FALSE && g_MinifilterEntries[Index].Entry == Entry)
        {
            return &g_MinifilterEntries[Index];
        }
    }

    return NULL;
}

static NTSTATUS
MiniInstallReturn(
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
    MINIFILTER_PAGE_HOOK* Page;
    MINIFILTER_ENTRY_HOOK* Hook;
    PHYSICAL_ADDRESS TargetPhysical;
    PHYSICAL_ADDRESS ShadowPhysical;
    PVOID ShadowRaw;
    UCHAR* Shadow;
    BOOLEAN Added;
    static const UCHAR Patch[MINIFILTER_PATCH_BYTES] = {0x33, 0xC0, 0xC3};

    if (Entry == NULL || (ULONG_PTR)Entry < 0xFFFF800000000000ull)
    {
        return STATUS_INVALID_ADDRESS;
    }

    if (MiniFindEntry(Entry) != NULL)
    {
        return STATUS_SUCCESS;
    }

    PageBase = (UCHAR*)((ULONG_PTR)Entry & ~(ULONG_PTR)(PAGE_SIZE - 1));
    Offset = (ULONG)((ULONG_PTR)Entry & (PAGE_SIZE - 1));
    if (Offset > PAGE_SIZE - MINIFILTER_PATCH_BYTES || MmIsAddressValid(PageBase) == FALSE)
    {
        return STATUS_INVALID_ADDRESS;
    }

    TargetPhysical = MmGetPhysicalAddress(PageBase);
    if (TargetPhysical.QuadPart == 0)
    {
        return STATUS_NOT_FOUND;
    }

    Page = NULL;
    for (PageIndex = 0; PageIndex < MINIFILTER_HOOK_PAGES; ++PageIndex)
    {
        if (g_MinifilterPages[PageIndex].Used != FALSE &&
            g_MinifilterPages[PageIndex].TargetPa == ((UINT64)TargetPhysical.QuadPart & ~(UINT64)(PAGE_SIZE - 1)))
        {
            Page = &g_MinifilterPages[PageIndex];
            break;
        }
    }

    if (Page == NULL)
    {
        for (PageIndex = 0; PageIndex < MINIFILTER_HOOK_PAGES; ++PageIndex)
        {
            if (g_MinifilterPages[PageIndex].Used == FALSE)
            {
                Page = &g_MinifilterPages[PageIndex];
                break;
            }
        }

        if (Page == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ShadowRaw = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE * 2, MINIFILTER_TAG);
        if (ShadowRaw == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Shadow = (UCHAR*)(((ULONG_PTR)ShadowRaw + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
        RtlCopyMemory(Shadow, PageBase, PAGE_SIZE);
        RtlCopyMemory(Shadow + Offset, Patch, sizeof(Patch));
        ShadowPhysical = MmGetPhysicalAddress(Shadow);
        if (ShadowPhysical.QuadPart == 0)
        {
            ExFreePoolWithTag(ShadowRaw, MINIFILTER_TAG);
            return STATUS_NOT_FOUND;
        }

        //
        // INVARIANT: TargetPa is the guest physical page of the callback.
        // Shadow is a nonpaged copy with xor eax, eax; ret at the entry.
        // The guest executes the copy. The original page stays unchanged.
        //
        Added = MINIFILTER_ADD_HOOK(HacDbgGuestPhysicalAddress((UINT64)TargetPhysical.QuadPart),
                                    HacDbgGuestPhysicalAddress((UINT64)ShadowPhysical.QuadPart));
        if (Added == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, minifilter shadow hook failed for %p.\n", Entry);
            ExFreePoolWithTag(ShadowRaw, MINIFILTER_TAG);
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
        RtlCopyMemory(Page->Shadow + Offset, Patch, sizeof(Patch));
    }

    for (EntryIndex = 0; EntryIndex < MINIFILTER_HOOK_ENTRIES; ++EntryIndex)
    {
        if (g_MinifilterEntries[EntryIndex].Used == FALSE)
        {
            break;
        }
    }

    if (EntryIndex == MINIFILTER_HOOK_ENTRIES)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Hook = &g_MinifilterEntries[EntryIndex];
    Hook->Used = TRUE;
    Hook->Entry = Entry;
    Hook->PageIndex = (ULONG)(Page - g_MinifilterPages);
    Hook->Offset = Offset;
    RtlCopyMemory(Hook->Original, PageBase + Offset, MINIFILTER_PATCH_BYTES);
    Page->Patches += 1;
    if (Page->Patches > 1)
    {
        MINIFILTER_REFRESH_HOOKS();
    }

    if (MiniFlushTranslations() == FALSE && MiniFlushTranslations() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, minifilter shadow flush failed.\n");
        return STATUS_UNSUCCESSFUL;
    }

    HACDBG_LOG("HacDbg: Minifilter callback %p disabled.\n", Entry);
    return STATUS_SUCCESS;
#endif
}

static NTSTATUS
MiniRemoveReturn(
    _In_ PVOID Entry
    )
{
#if !defined(_AMD64_)
    UNREFERENCED_PARAMETER(Entry);
    return STATUS_NOT_SUPPORTED;
#else
    MINIFILTER_ENTRY_HOOK* Hook;
    MINIFILTER_PAGE_HOOK* Page;
    BOOLEAN Removed;

    Hook = MiniFindEntry(Entry);
    if (Hook == NULL)
    {
        return STATUS_NOT_FOUND;
    }

    Page = &g_MinifilterPages[Hook->PageIndex];
    if (Page->Used == FALSE || Page->Shadow == NULL || Hook->Offset > PAGE_SIZE - MINIFILTER_PATCH_BYTES)
    {
        Hook->Used = FALSE;
        return STATUS_NOT_FOUND;
    }

    RtlCopyMemory(Page->Shadow + Hook->Offset, Hook->Original, MINIFILTER_PATCH_BYTES);
    if (Page->Patches > 0)
    {
        Page->Patches -= 1;
    }

    Hook->Used = FALSE;
    if (Page->Patches == 0)
    {
        //
        // INVARIANT: TargetPa is the guest physical page passed to the shadow
        // hook. Removing it makes the guest execute the original page.
        //
        Removed = MINIFILTER_REMOVE_HOOK(HacDbgGuestPhysicalAddress(Page->TargetPa));
        if (Removed == FALSE)
        {
            return STATUS_UNSUCCESSFUL;
        }

        if (Page->ShadowRaw != NULL)
        {
            ExFreePoolWithTag(Page->ShadowRaw, MINIFILTER_TAG);
        }

        Page->ShadowRaw = NULL;
        Page->Shadow = NULL;
        Page->TargetPa = 0;
        Page->Used = FALSE;
    }
    else
    {
        MINIFILTER_REFRESH_HOOKS();
    }

    if (MiniFlushTranslations() == FALSE && MiniFlushTranslations() == FALSE)
    {
        return STATUS_UNSUCCESSFUL;
    }

    HACDBG_LOG("HacDbg: Minifilter callback %p enabled.\n", Entry);
    return STATUS_SUCCESS;
#endif
}

static VOID
MiniVisitRoutine(
    _Inout_opt_ HACDBG_MINIFILTER_REQUEST* Request,
    _In_ unsigned long long Filter,
    _In_ unsigned int Parent,
    _In_ PCWSTR Path,
    _In_ ULONG_PTR Routine,
    _In_ UCHAR Major,
    _In_ BOOLEAN Post,
    _In_ BOOLEAN Patch
    )
{
    WCHAR Name[HACDBG_MINIFILTER_NAME_CHARS];

    if (Routine == 0)
    {
        return;
    }

    if (Request != NULL)
    {
        MiniCallbackName(Name, Major, Post);
        MiniAddRow(Request, Filter, (unsigned long long)Routine, Parent, 1, Major, Post != FALSE ? 1u : 0u, Name, L"",
                   Path);
    }

    if (Patch != FALSE)
    {
        MiniInstallReturn((PVOID)Routine);
    }
    else if (Request == NULL)
    {
        MiniRemoveReturn((PVOID)Routine);
    }
}

static VOID
MiniForEachCallback(
    _In_ PFLT_FILTER Filter,
    _In_ BOOLEAN Patch,
    _Inout_opt_ HACDBG_MINIFILTER_REQUEST* Request,
    _In_ unsigned int Parent,
    _In_ PCWSTR Path
    )
{
    PFLT_OPERATION_REGISTRATION Operations;
    ULONG Index;

    Operations = MiniOperations(Filter);
    if (Operations == NULL)
    {
        return;
    }

    for (Index = 0; Index < MINIFILTER_OP_LIMIT; ++Index)
    {
        if (MmIsAddressValid(&Operations[Index]) == FALSE || MmIsAddressValid(&Operations[Index].Reserved1) == FALSE)
        {
            break;
        }

        if (Operations[Index].MajorFunction == IRP_MJ_OPERATION_END)
        {
            break;
        }

        MiniVisitRoutine(Request, (unsigned long long)(ULONG_PTR)Filter, Parent, Path,
                         MiniRoutine(&Operations[Index].PreOperation), Operations[Index].MajorFunction, FALSE, Patch);
        MiniVisitRoutine(Request, (unsigned long long)(ULONG_PTR)Filter, Parent, Path,
                         MiniRoutine(&Operations[Index].PostOperation), Operations[Index].MajorFunction, TRUE, Patch);
        if (Request != NULL && Request->Truncated != 0)
        {
            break;
        }
    }
}

static VOID
MiniSort(
    _Inout_updates_(Count) MINIFILTER_ITEM* Items,
    _In_ ULONG Count
    )
{
    ULONG Index;
    ULONG Cursor;

    for (Index = 1; Index < Count; ++Index)
    {
        MINIFILTER_ITEM Key;

        Key = Items[Index];
        Cursor = Index;
        while (Cursor > 0 && Items[Cursor - 1].AltitudeKey < Key.AltitudeKey)
        {
            Items[Cursor] = Items[Cursor - 1];
            Cursor -= 1;
        }

        Items[Cursor] = Key;
    }
}

static NTSTATUS
MiniScan(
    _Inout_ HACDBG_MINIFILTER_REQUEST* Request,
    _In_opt_ PRTL_PROCESS_MODULES Modules
    )
{
    ULONG Need;
    ULONG Listed;
    PFLT_FILTER* Filters;
    NTSTATUS Status;
    MINIFILTER_ITEM* Items;
    ULONG Count;
    ULONG Index;

    Need = 0;
    Status = FltEnumerateFilters(NULL, 0, &Need);
    if (Status != STATUS_BUFFER_TOO_SMALL || Need == 0)
    {
        HACDBG_LOG("HacDbg: Err, minifilter count failed: 0x%08x.\n", Status);
        return Status == STATUS_BUFFER_TOO_SMALL ? STATUS_NOT_FOUND : Status;
    }

    if (Need > MINIFILTER_LIST_LIMIT)
    {
        Need = MINIFILTER_LIST_LIMIT;
        Request->Truncated = 1;
    }

    Filters = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, Need * sizeof(PFLT_FILTER), MINIFILTER_TAG);
    if (Filters == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Listed = 0;
    Status = FltEnumerateFilters(Filters, Need, &Listed);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Filters, MINIFILTER_TAG);
        HACDBG_LOG("HacDbg: Err, minifilter enumerate failed: 0x%08x.\n", Status);
        return Status;
    }

    //
    // The kernel stack is 24 KiB. Sixty-four filter records are about 46 KiB,
    // and probing that frame walks off the stack into the guard page.
    //
    Items = (MINIFILTER_ITEM*)ExAllocatePool2(POOL_FLAG_NON_PAGED, MINIFILTER_LIST_LIMIT * sizeof(MINIFILTER_ITEM),
                                              MINIFILTER_TAG);
    if (Items == NULL)
    {
        for (Index = 0; Index < Listed; ++Index)
        {
            FltObjectDereference(Filters[Index]);
        }

        ExFreePoolWithTag(Filters, MINIFILTER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Count = 0;
    for (Index = 0; Index < Listed && Count < MINIFILTER_LIST_LIMIT; ++Index)
    {
        PDRIVER_OBJECT Driver;

        Items[Count].Filter = Filters[Index];
        MiniReadInfo(Filters[Index], Items[Count].Name, Items[Count].Altitude);
        Items[Count].Path[0] = 0;
        Driver = MiniDriver(Filters[Index]);
        if (Driver != NULL)
        {
            MiniModulePath(Modules, Driver->DriverStart, Items[Count].Path);
        }

        Items[Count].AltitudeKey = MiniAltitudeKey(Items[Count].Altitude);
        Count += 1;
    }

    for (Index = Count; Index < Listed; ++Index)
    {
        FltObjectDereference(Filters[Index]);
    }

    ExFreePoolWithTag(Filters, MINIFILTER_TAG);
    MiniSort(Items, Count);
    for (Index = 0; Index < Count; ++Index)
    {
        unsigned int Parent;
        CHAR Narrow[HACDBG_MINIFILTER_NAME_CHARS];
        ULONG Char;

        Parent = Request->Count;
        if (MiniAddRow(Request, (unsigned long long)(ULONG_PTR)Items[Index].Filter, 0, HACDBG_MINIFILTER_NO_PARENT, 0,
                       0, 0, Items[Index].Name, Items[Index].Altitude, Items[Index].Path) == FALSE)
        {
            FltObjectDereference(Items[Index].Filter);
            continue;
        }

        MiniForEachCallback(Items[Index].Filter, FALSE, Request, Parent, Items[Index].Path);
        for (Char = 0; Char + 1 < sizeof(Narrow) && Items[Index].Name[Char] != 0; ++Char)
        {
            Narrow[Char] = (Items[Index].Name[Char] < 127) ? (CHAR)Items[Index].Name[Char] : '?';
        }

        Narrow[Char] = 0;
        HACDBG_LOG("HacDbg: Minifilter %s filter=%p callbacks follow.\n", Narrow[0] != 0 ? Narrow : "-",
                   Items[Index].Filter);
        FltObjectDereference(Items[Index].Filter);
    }

    ExFreePoolWithTag(Items, MINIFILTER_TAG);
    HACDBG_LOG("HacDbg: Minifilter scan count=%u truncated=%u.\n", Request->Count, Request->Truncated);
    return STATUS_SUCCESS;
}

static PFLT_FILTER
MiniFindListed(
    _In_ ULONG64 Address
    )
{
    ULONG Need;
    ULONG Listed;
    PFLT_FILTER* Filters;
    NTSTATUS Status;
    ULONG Index;
    PFLT_FILTER Found;

    Need = 0;
    Status = FltEnumerateFilters(NULL, 0, &Need);
    if (Status != STATUS_BUFFER_TOO_SMALL || Need == 0)
    {
        return NULL;
    }

    Filters = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, Need * sizeof(PFLT_FILTER), MINIFILTER_TAG);
    if (Filters == NULL)
    {
        return NULL;
    }

    Listed = 0;
    Status = FltEnumerateFilters(Filters, Need, &Listed);
    Found = NULL;
    if (NT_SUCCESS(Status))
    {
        for (Index = 0; Index < Listed; ++Index)
        {
            if ((ULONG64)(ULONG_PTR)Filters[Index] == Address)
            {
                Found = Filters[Index];
            }
            else
            {
                FltObjectDereference(Filters[Index]);
            }
        }
    }

    ExFreePoolWithTag(Filters, MINIFILTER_TAG);
    return Found;
}

static NTSTATUS
MiniChange(
    _In_ ULONG64 Address,
    _In_ BOOLEAN Disable
    )
{
    PFLT_FILTER Filter;
    NTSTATUS Status;

    Filter = MiniFindListed(Address);
    if (Filter == NULL)
    {
        HACDBG_LOG("HacDbg: Err, minifilter %p is not registered.\n", (PVOID)Address);
        return STATUS_NOT_FOUND;
    }

    MiniForEachCallback(Filter, Disable, NULL, 0, L"");
    FltObjectDereference(Filter);
    Status = STATUS_SUCCESS;
    HACDBG_LOG("HacDbg: Minifilter %p %s.\n", Filter, Disable != FALSE ? "disabled" : "enabled");
    return Status;
}

C_ASSERT(sizeof(HACDBG_MINIFILTER_REQUEST) <= 1024u * 1024u);

NTSTATUS
MinifilterExecute(
    _Inout_ HACDBG_MINIFILTER_REQUEST* Request
    )
{
    unsigned int Operation;
    ULONG64 Filter;
    PRTL_PROCESS_MODULES Modules;

    Operation = Request->Reserved;
    Filter = Request->Rows[0].Filter;
    Request->Status = 0;
    Request->Count = 0;
    Request->Truncated = 0;
    Request->Reserved = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        Request->Status = STATUS_INVALID_LEVEL;
        return Request->Status;
    }

    if (Operation == HACDBG_MINIFILTER_OP_DISABLE || Operation == HACDBG_MINIFILTER_OP_ENABLE)
    {
        Request->Status = MiniChange(Filter, Operation == HACDBG_MINIFILTER_OP_DISABLE);
        return Request->Status;
    }

    Modules = MiniQueryModules();
    Request->Status = MiniScan(Request, Modules);
    if (Modules != NULL)
    {
        ExFreePoolWithTag(Modules, MINIFILTER_TAG);
    }

    return Request->Status;
}
