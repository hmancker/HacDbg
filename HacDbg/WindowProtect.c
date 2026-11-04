/**
 * @file WindowProtect.c
 * @brief Display-affinity self-defense and DWM protected-window scan.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>

#include "Config.h"
#include "Debug.h"
#include "Types.h"
#include "WindowProtect.h"

#if defined(_AMD64_)
#include "Svm.h"
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#define WINDOW_PROTECT_ADD_HOOK    EptAddHook
#define WINDOW_PROTECT_REMOVE_HOOK EptRemoveHook
#else
#include "Npt.h"
#define WINDOW_PROTECT_ADD_HOOK    NptAddHook
#define WINDOW_PROTECT_REMOVE_HOOK NptRemoveHook
#endif
#endif

#define WINDOW_PROTECT_TAG 'wPaH'
#define WINDOW_PROTECT_MODULE_INFORMATION 11u
#define WINDOW_PROTECT_JUMP_SIZE 14u
#define WINDOW_PROTECT_STEAL_MAX 32u
#define WINDOW_PROTECT_OBJECT_SPAN 0x300u
#define WINDOW_PROTECT_KIND_END 0x200u
#define WINDOW_PROTECT_FIELD_SPAN 0x100u
#define WINDOW_PROTECT_SCAN_BUDGET (256u * 1024u * 1024u)
#define WINDOW_PROTECT_CHUNK (64u * 1024u)
#define WINDOW_PROTECT_LAYOUT_SLOTS 8u
#define WINDOW_PROTECT_VTABLE_SLOTS 32u
#define WINDOW_PROTECT_DRAIN_SPINS 1000u
#define WINDOW_PROTECT_PROTECTION_BIT 0x40u
//
// MEMORY_BASIC_INFORMATION.Type value for an image mapping. The kernel
// headers used by this driver do not publish it.
//
#define WINDOW_PROTECT_MEM_IMAGE 0x1000000u
//
// Highest canonical user address. A kernel-mode read above this bugchecks
// with PAGE_FAULT_IN_NONPAGED_AREA before __except can run.
//
#define WINDOW_PROTECT_USER_MAX 0x00007FFFFFFFFFFFull

C_ASSERT(sizeof(HACDBG_WINDOW_REQUEST) == 1096);

typedef UINT32 (NTAPI *WINDOW_PROTECT_ROUTINE)(PVOID Window, ULONG Affinity);

typedef struct _WINDOW_PROTECT_MODULE
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} WINDOW_PROTECT_MODULE;

C_ASSERT(sizeof(WINDOW_PROTECT_MODULE) == 296);

typedef struct _WINDOW_PROTECT_LAYOUT
{
    UINT64 Vtable;
    ULONG FlagsOffset;
    ULONG KindOffset;
    ULONG HwndOffset;
    ULONG PidOffset;
    ULONG Hits;
} WINDOW_PROTECT_LAYOUT;

NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(
    _In_ PEPROCESS Process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

static volatile LONG g_Armed;
static volatile LONG g_InFilter;
static volatile LONG g_OwnerPid;
static volatile LONG g_BypassPid;
static volatile LONG g_HookInstalled;
static PVOID g_Trampoline;
static PVOID g_TrampolineRaw;
static PVOID g_Shadow;
static PVOID g_ShadowRaw;
static PMDL g_LockedMdl;
static UINT64 g_TargetPage;
static UINT64 g_TargetVa;
static WINDOW_PROTECT_LAYOUT g_Layout;
static BOOLEAN g_LayoutReady;

static UINT32 NTAPI WindowProtectFilter(PVOID Window, ULONG Affinity);
static NTSTATUS WindowProtectArm(VOID);
static NTSTATUS WindowProtectDisarm(VOID);
static NTSTATUS WindowProtectScan(HACDBG_WINDOW_REQUEST* Request);
static VOID WindowProtectFillHook(HACDBG_WINDOW_REQUEST* Request);

__declspec(noinline)
static UINT32 NTAPI
WindowProtectFilter(
    PVOID Window,
    ULONG Affinity
    )
{
    WINDOW_PROTECT_ROUTINE Routine;
    UINT32 Result;

    ULONG CallerPid;
    ULONG OwnerPid;
    ULONG BypassPid;

    InterlockedIncrement(&g_InFilter);
    Routine = (WINDOW_PROTECT_ROUTINE)g_Trampoline;
    CallerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    OwnerPid = (ULONG)g_OwnerPid;
    BypassPid = (ULONG)g_BypassPid;
    if (g_Armed != 0 && CallerPid != OwnerPid && (BypassPid == 0 || CallerPid != BypassPid))
    {
        Result = 0;
    }
    else if (Routine == NULL)
    {
        Result = 0;
    }
    else
    {
        Result = Routine(Window, Affinity);
    }

    InterlockedDecrement(&g_InFilter);
    return Result;
}

static BOOLEAN
WindowProtectFlushTranslations(
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
    for (Index = 0; Index < Count; Index++)
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
        // INVARIANT: This processor is already a guest. The leaf is the
        // VM-exit flush, so cached translations drop before the patched
        // execute page is fetched.
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
WindowProtectWriteJump(
    _Out_writes_(WINDOW_PROTECT_JUMP_SIZE) UCHAR* Destination,
    _In_ UINT64 Target
    )
{
    UINT32 Low;
    UINT32 High;

    Low = (UINT32)Target;
    High = (UINT32)(Target >> 32);
    Destination[0] = 0x68;
    RtlCopyMemory(Destination + 1, &Low, sizeof(Low));
    Destination[5] = 0xC7;
    Destination[6] = 0x44;
    Destination[7] = 0x24;
    Destination[8] = 0x04;
    RtlCopyMemory(Destination + 9, &High, sizeof(High));
    Destination[13] = 0xC3;
}

static ULONG
WindowProtectInstructionLength(
    _In_reads_(Available) const UCHAR* Code,
    _In_ ULONG Available
    )
{
    if (Available == 0)
    {
        return 0;
    }

    if (Code[0] >= 0x50 && Code[0] <= 0x57)
    {
        return 1;
    }

    if (Available >= 2 && Code[0] == 0x41 && Code[1] >= 0x50 && Code[1] <= 0x57)
    {
        return 2;
    }

    if (Available >= 2 && Code[0] == 0x33 && (Code[1] & 0xC0) == 0xC0)
    {
        return 2;
    }

    if (Available >= 2 && Code[0] == 0x8B && (Code[1] & 0xC0) == 0xC0)
    {
        return 2;
    }

    if (Available >= 3 &&
        (Code[0] == 0x48 || Code[0] == 0x49 || Code[0] == 0x4C || Code[0] == 0x4D) &&
        (Code[1] == 0x89 || Code[1] == 0x8B) &&
        (Code[2] & 0xC0) == 0xC0)
    {
        return 3;
    }

    if (Available >= 4 && Code[0] == 0x48 && Code[1] == 0x83 && Code[2] == 0xEC)
    {
        return 4;
    }

    if (Available >= 4 && Code[0] == 0x49 && Code[1] == 0x89 && (Code[2] & 0xC7) == 0x43)
    {
        return 4;
    }

    if (Available >= 5 &&
        (Code[0] == 0x48 || Code[0] == 0x4C) &&
        Code[1] == 0x89 &&
        (Code[2] & 0xC7) == 0x44 &&
        Code[3] == 0x24)
    {
        return 5;
    }

    if (Available >= 7 && Code[0] == 0x48 && Code[1] == 0x81 && Code[2] == 0xEC)
    {
        return 7;
    }

    return 0;
}

static ULONG
WindowProtectStealLength(
    _In_reads_(Available) const UCHAR* Code,
    _In_ ULONG Available
    )
{
    ULONG Stolen;

    Stolen = 0;
    while (Stolen < WINDOW_PROTECT_JUMP_SIZE && Stolen < WINDOW_PROTECT_STEAL_MAX)
    {
        ULONG Length;

        Length = WindowProtectInstructionLength(Code + Stolen, Available - Stolen);
        if (Length == 0 || Stolen + Length > Available)
        {
            return 0;
        }

        Stolen += Length;
    }

    if (Stolen < WINDOW_PROTECT_JUMP_SIZE || Stolen > WINDOW_PROTECT_STEAL_MAX)
    {
        return 0;
    }

    return Stolen;
}

static BOOLEAN
WindowProtectNameMatches(
    _In_reads_(256) const UCHAR* Path,
    _In_ const CHAR* Expected
    )
{
    CHAR Name[256];
    const CHAR* Leaf;
    ULONG Index;

    RtlCopyMemory(Name, Path, sizeof(Name) - 1);
    Name[sizeof(Name) - 1] = '\0';
    Leaf = Name;
    for (Index = 0; Name[Index] != '\0'; Index++)
    {
        if (Name[Index] == '\\' || Name[Index] == '/')
        {
            Leaf = Name + Index + 1;
        }
    }

    return _stricmp(Leaf, Expected) == 0;
}

static NTSTATUS
WindowProtectFindModule(
    _In_ const CHAR* Name,
    _Out_ PVOID* ImageBase,
    _Out_ ULONG* ImageSize
    )
{
    ULONG Capacity;
    ULONG Needed;
    NTSTATUS Status;
    UCHAR* Buffer;
    ULONG Count;
    ULONG Index;

    *ImageBase = NULL;
    *ImageSize = 0;
    Capacity = 256u * 1024u;
    Buffer = NULL;
    Status = STATUS_UNSUCCESSFUL;
    for (Index = 0; Index < 4; Index++)
    {
        if (Buffer != NULL)
        {
            ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);
            Buffer = NULL;
        }

        Buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, Capacity, WINDOW_PROTECT_TAG);
        if (Buffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Needed = 0;
        Status = ZwQuerySystemInformation(WINDOW_PROTECT_MODULE_INFORMATION, Buffer, Capacity, &Needed);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
        {
            break;
        }

        Capacity = Needed + 4096u;
        if (Capacity < Needed)
        {
            ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);
            return STATUS_INTEGER_OVERFLOW;
        }
    }

    if (!NT_SUCCESS(Status) || Buffer == NULL || Capacity < 8)
    {
        if (Buffer != NULL)
        {
            ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);
        }
        return NT_SUCCESS(Status) ? STATUS_NOT_FOUND : Status;
    }

    Count = *(ULONG*)Buffer;
    if (Count > 4096u || 8u + (Count * sizeof(WINDOW_PROTECT_MODULE)) > Capacity)
    {
        ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    for (Index = 0; Index < Count; Index++)
    {
        WINDOW_PROTECT_MODULE* Module;

        Module = (WINDOW_PROTECT_MODULE*)(Buffer + 8) + Index;
        if (WindowProtectNameMatches(Module->FullPathName, Name) == FALSE || Module->ImageBase == NULL)
        {
            continue;
        }

        *ImageBase = Module->ImageBase;
        *ImageSize = Module->ImageSize;
        ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);
        return STATUS_SUCCESS;
    }

    ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);
    return STATUS_NOT_FOUND;
}

static PVOID
WindowProtectFindExport(
    _In_ PVOID Image,
    _In_ ULONG ImageSize,
    _In_ const CHAR* Name
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_DATA_DIRECTORY* Directory;
    IMAGE_EXPORT_DIRECTORY* Export;
    ULONG* Names;
    USHORT* Ordinals;
    ULONG* Functions;
    ULONG Index;

    if (ImageSize < sizeof(IMAGE_DOS_HEADER) || MmIsAddressValid(Image) == FALSE)
    {
        return NULL;
    }

    __try
    {
        Dos = (IMAGE_DOS_HEADER*)Image;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew < 0x40 ||
            (ULONG)Dos->e_lfanew > ImageSize - sizeof(IMAGE_NT_HEADERS64))
        {
            return NULL;
        }

        Nt = (IMAGE_NT_HEADERS64*)((UCHAR*)Image + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE)
        {
            return NULL;
        }

        Directory = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (Directory->VirtualAddress == 0 || Directory->Size == 0 ||
            Directory->VirtualAddress > ImageSize ||
            Directory->Size > ImageSize - Directory->VirtualAddress)
        {
            return NULL;
        }

        Export = (IMAGE_EXPORT_DIRECTORY*)((UCHAR*)Image + Directory->VirtualAddress);
        if (Export->NumberOfNames > 0x10000 || Export->AddressOfNames > ImageSize ||
            Export->AddressOfNameOrdinals > ImageSize || Export->AddressOfFunctions > ImageSize)
        {
            return NULL;
        }

        Names = (ULONG*)((UCHAR*)Image + Export->AddressOfNames);
        Ordinals = (USHORT*)((UCHAR*)Image + Export->AddressOfNameOrdinals);
        Functions = (ULONG*)((UCHAR*)Image + Export->AddressOfFunctions);
        for (Index = 0; Index < Export->NumberOfNames; Index++)
        {
            const CHAR* ExportName;
            ULONG Rva;

            if (Names[Index] >= ImageSize)
            {
                continue;
            }

            ExportName = (const CHAR*)((UCHAR*)Image + Names[Index]);
            if (_stricmp(ExportName, Name) != 0)
            {
                continue;
            }

            if (Ordinals[Index] >= Export->NumberOfFunctions)
            {
                return NULL;
            }

            Rva = Functions[Ordinals[Index]];
            if (Rva == 0 || Rva >= ImageSize)
            {
                return NULL;
            }

            if (Rva >= Directory->VirtualAddress && Rva < Directory->VirtualAddress + Directory->Size)
            {
                return NULL;
            }

            return (UCHAR*)Image + Rva;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

static VOID
WindowProtectFreeHookResources(
    VOID
    )
{
    if (g_LockedMdl != NULL)
    {
        MmUnlockPages(g_LockedMdl);
        IoFreeMdl(g_LockedMdl);
        g_LockedMdl = NULL;
    }

    if (g_ShadowRaw != NULL)
    {
        ExFreePoolWithTag(g_ShadowRaw, WINDOW_PROTECT_TAG);
        g_ShadowRaw = NULL;
        g_Shadow = NULL;
    }

    if (g_TrampolineRaw != NULL)
    {
        ExFreePoolWithTag(g_TrampolineRaw, WINDOW_PROTECT_TAG);
        g_TrampolineRaw = NULL;
        g_Trampoline = NULL;
    }

    g_TargetPage = 0;
    g_TargetVa = 0;
}

static NTSTATUS
WindowProtectArm(
    VOID
    )
{
#if !defined(_AMD64_)
    return STATUS_NOT_SUPPORTED;
#else
    PVOID Image;
    ULONG ImageSize;
    UCHAR* Target;
    ULONG PageOffset;
    ULONG Stolen;
    UCHAR* PageBase;
    UCHAR* ShadowRaw;
    UCHAR* Shadow;
    UCHAR* TrampolineRaw;
    UCHAR* Trampoline;
    PMDL Mdl;
    PHYSICAL_ADDRESS Physical;
    NTSTATUS Status;
    BOOLEAN Added;

    if (g_HookInstalled != 0)
    {
        InterlockedExchange(&g_OwnerPid, (LONG)(ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        InterlockedExchange(&g_Armed, 1);
        return STATUS_SUCCESS;
    }

    Status = WindowProtectFindModule("win32kfull.sys", &Image, &ImageSize);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, window protect did not find win32kfull.sys: 0x%08x.\n", Status);
        return Status;
    }

    Target = (UCHAR*)WindowProtectFindExport(Image, ImageSize, "NtUserSetWindowDisplayAffinity");
    if (Target == NULL)
    {
        HACDBG_LOG("HacDbg: Err, window protect export was not found in %p.\n", Image);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    PageOffset = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
    if (PageOffset + WINDOW_PROTECT_STEAL_MAX > PAGE_SIZE)
    {
        HACDBG_LOG("HacDbg: Err, window protect entry %p is too close to a page boundary.\n", Target);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PageBase = (UCHAR*)((ULONG_PTR)Target & ~(ULONG_PTR)(PAGE_SIZE - 1));
    Mdl = IoAllocateMdl(PageBase, PAGE_SIZE, FALSE, FALSE, NULL);
    if (Mdl == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(Mdl);
        HACDBG_LOG("HacDbg: Err, window protect page %p could not be locked.\n", PageBase);
        return GetExceptionCode();
    }

    Stolen = WindowProtectStealLength(Target, WINDOW_PROTECT_STEAL_MAX);
    if (Stolen == 0)
    {
        HACDBG_LOG("HacDbg: Err, window protect prologue is not relocatable at %p: "
                   "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x.\n",
                   Target,
                   Target[0], Target[1], Target[2], Target[3], Target[4], Target[5], Target[6], Target[7],
                   Target[8], Target[9], Target[10], Target[11], Target[12], Target[13], Target[14], Target[15]);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_NOT_SUPPORTED;
    }

    Physical = MmGetPhysicalAddress(PageBase);
    if (Physical.QuadPart == 0)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_NOT_FOUND;
    }

    ShadowRaw = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE * 2, WINDOW_PROTECT_TAG);
    TrampolineRaw = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE, WINDOW_PROTECT_TAG);
    if (ShadowRaw == NULL || TrampolineRaw == NULL)
    {
        if (ShadowRaw != NULL)
        {
            ExFreePoolWithTag(ShadowRaw, WINDOW_PROTECT_TAG);
        }
        if (TrampolineRaw != NULL)
        {
            ExFreePoolWithTag(TrampolineRaw, WINDOW_PROTECT_TAG);
        }
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Shadow = (UCHAR*)(((ULONG_PTR)ShadowRaw + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    Trampoline = TrampolineRaw;
    RtlCopyMemory(Shadow, PageBase, PAGE_SIZE);
    RtlCopyMemory(Trampoline, Target, Stolen);
    WindowProtectWriteJump(Trampoline + Stolen, (UINT64)(ULONG_PTR)(Target + Stolen));
    WindowProtectWriteJump(Shadow + PageOffset, (UINT64)(ULONG_PTR)WindowProtectFilter);
    if (Stolen > WINDOW_PROTECT_JUMP_SIZE)
    {
        RtlFillMemory(Shadow + PageOffset + WINDOW_PROTECT_JUMP_SIZE, Stolen - WINDOW_PROTECT_JUMP_SIZE, 0x90);
    }

    g_LockedMdl = Mdl;
    g_ShadowRaw = ShadowRaw;
    g_Shadow = Shadow;
    g_TrampolineRaw = TrampolineRaw;
    g_Trampoline = Trampoline;
    g_TargetPage = (UINT64)Physical.QuadPart & ~(UINT64)(PAGE_SIZE - 1);
    g_TargetVa = (UINT64)(ULONG_PTR)Target;
    InterlockedExchange(&g_OwnerPid, (LONG)(ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    InterlockedExchange(&g_Armed, 1);
    KeMemoryBarrier();

    //
    // INVARIANT: g_TargetPage is the locked physical page of
    // win32kfull!NtUserSetWindowDisplayAffinity. Shadow is a nonpaged copy
    // of that page. The guest executes the copy. The original page stays
    // readable. The jump lands on WindowProtectFilter in this image.
    //
    Added = WINDOW_PROTECT_ADD_HOOK(HacDbgGuestPhysicalAddress(g_TargetPage),
                                    HacDbgGuestPhysicalAddress((UINT64)MmGetPhysicalAddress(Shadow).QuadPart));
    if (Added == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, window protect SLAT hook failed for %p pa 0x%I64x.\n", Target, g_TargetPage);
        InterlockedExchange(&g_Armed, 0);
        WindowProtectFreeHookResources();
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedExchange(&g_HookInstalled, 1);
    if (WindowProtectFlushTranslations() == FALSE && WindowProtectFlushTranslations() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, window protect flush failed after arming %p.\n", Target);
        return STATUS_UNSUCCESSFUL;
    }

    HACDBG_LOG("HacDbg: Window protect hooked %p stolen %lu owner %lu.\n",
               Target,
               Stolen,
               (ULONG)g_OwnerPid);
    return STATUS_SUCCESS;
#endif
}

static VOID
WindowProtectDrainFilter(
    VOID
    )
{
    ULONG Index;
    LARGE_INTEGER Interval;

    Interval.QuadPart = -10 * 1000 * 10;
    for (Index = 0; Index < WINDOW_PROTECT_DRAIN_SPINS && g_InFilter != 0; Index++)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }
}

static NTSTATUS
WindowProtectDisarm(
    VOID
    )
{
    BOOLEAN Removed;

    InterlockedExchange(&g_BypassPid, 0);
    InterlockedExchange(&g_Armed, 0);
    KeMemoryBarrier();
    if (g_HookInstalled == 0)
    {
        InterlockedExchange(&g_OwnerPid, 0);
        return STATUS_SUCCESS;
    }

#if !defined(_AMD64_)
    Removed = FALSE;
#else
    //
    // INVARIANT: g_TargetPage is the same locked page passed to the SLAT
    // hook. Removing it restores execute permission on the original page.
    //
    Removed = WINDOW_PROTECT_REMOVE_HOOK(HacDbgGuestPhysicalAddress(g_TargetPage));
#endif
    if (Removed == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, window protect SLAT unhook failed for pa 0x%I64x.\n", g_TargetPage);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedExchange(&g_HookInstalled, 0);
    if (WindowProtectFlushTranslations() == FALSE && WindowProtectFlushTranslations() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, window protect flush failed after disarm. Hook memory is kept.\n");
        return STATUS_UNSUCCESSFUL;
    }

    WindowProtectDrainFilter();
    if (g_InFilter != 0)
    {
        HACDBG_LOG("HacDbg: Err, window protect filter is still active. Hook memory is kept.\n");
        return STATUS_UNSUCCESSFUL;
    }

    WindowProtectFreeHookResources();
    InterlockedExchange(&g_OwnerPid, 0);
    HACDBG_LOG("HacDbg: Window protect hook removed.\n");
    return STATUS_SUCCESS;
}

//
// A kernel-mode fault on a non-canonical or kernel address bugchecks
// before __except runs. Only a canonical user span may be touched, and
// only while this thread is attached to the process that owns it.
// Adding a length to an address such as 0xFFFFFFFFFFFFFFF8 wraps to 0
// and must not be treated as in range.
//
static BOOLEAN
WindowProtectUserSpan(
    _In_ UINT64 Address,
    _In_ SIZE_T Length
    )
{
    if (Length == 0 || Address > WINDOW_PROTECT_USER_MAX)
    {
        return FALSE;
    }

    if (Length - 1 > WINDOW_PROTECT_USER_MAX - Address)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
WindowProtectReadUser(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ UINT64 Address,
    _In_ SIZE_T Length
    )
{
    if (WindowProtectUserSpan(Address, Length) == FALSE)
    {
        return FALSE;
    }

    __try
    {
        RtlCopyMemory(Destination, (PVOID)Address, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
WindowProtectKind(
    _In_ ULONG Kind
    )
{
    return Kind == 2 || Kind == 4;
}

static BOOLEAN
WindowProtectPid(
    _In_ ULONG Pid
    )
{
    return Pid != 0 && Pid < 0x400000u && (Pid % 4u) == 0;
}

static BOOLEAN
WindowProtectVtable(
    _In_ UINT64 Value,
    _In_ UINT64 ModuleBase,
    _In_ UINT64 ModuleEnd
    )
{
    UINT64 First;

    if ((Value & 7u) != 0 || ModuleEnd <= ModuleBase)
    {
        return FALSE;
    }

    if (WindowProtectUserSpan(ModuleBase, (SIZE_T)(ModuleEnd - ModuleBase)) == FALSE ||
        ModuleEnd - ModuleBase < sizeof(UINT64))
    {
        return FALSE;
    }

    if (Value < ModuleBase || Value > ModuleEnd - sizeof(UINT64))
    {
        return FALSE;
    }

    if (WindowProtectReadUser(&First, Value, sizeof(First)) == FALSE)
    {
        return FALSE;
    }

    return First >= 0x10000ull && First <= WINDOW_PROTECT_USER_MAX;
}

static BOOLEAN
WindowProtectReadRegion(
    _In_ PVOID Source,
    _Out_writes_bytes_(Length) UCHAR* Destination,
    _In_ SIZE_T Length
    )
{
    return WindowProtectReadUser(Destination, (UINT64)Source, Length);
}

static VOID
WindowProtectNoteLayout(
    _Inout_ WINDOW_PROTECT_LAYOUT* Slots,
    _Inout_ ULONG* SlotCount,
    _In_ UINT64 Vtable,
    _In_ ULONG FlagsOffset,
    _In_ ULONG KindOffset,
    _In_ ULONG HwndOffset,
    _In_ ULONG PidOffset
    )
{
    ULONG Index;

    for (Index = 0; Index < *SlotCount; Index++)
    {
        if (Slots[Index].Vtable == Vtable &&
            Slots[Index].FlagsOffset == FlagsOffset &&
            Slots[Index].KindOffset == KindOffset &&
            Slots[Index].HwndOffset == HwndOffset &&
            Slots[Index].PidOffset == PidOffset)
        {
            Slots[Index].Hits += 1;
            return;
        }
    }

    if (*SlotCount >= WINDOW_PROTECT_LAYOUT_SLOTS)
    {
        return;
    }

    Slots[*SlotCount].Vtable = Vtable;
    Slots[*SlotCount].FlagsOffset = FlagsOffset;
    Slots[*SlotCount].KindOffset = KindOffset;
    Slots[*SlotCount].HwndOffset = HwndOffset;
    Slots[*SlotCount].PidOffset = PidOffset;
    Slots[*SlotCount].Hits = 1;
    *SlotCount += 1;
}

static BOOLEAN
WindowProtectCalibrateObject(
    _In_ const UCHAR* Object,
    _In_ ULONG ObjectBytes,
    _In_ UINT64 Vtable,
    _In_ ULONG CalibrateHwnd,
    _In_ ULONG CalibratePid,
    _Inout_ WINDOW_PROTECT_LAYOUT* Slots,
    _Inout_ ULONG* SlotCount
    )
{
    ULONG KindOffset;

    if (ObjectBytes < WINDOW_PROTECT_OBJECT_SPAN)
    {
        return FALSE;
    }

    for (KindOffset = 0xC; KindOffset < WINDOW_PROTECT_KIND_END; KindOffset += 4)
    {
        ULONG FlagsOffset;
        ULONG Flags;
        ULONG Kind;
        ULONG HwndOffset;
        ULONG PidOffset;
        ULONG Field;

        Kind = *(ULONG*)(Object + KindOffset);
        if (WindowProtectKind(Kind) == FALSE)
        {
            continue;
        }

        FlagsOffset = KindOffset - 4;
        Flags = *(ULONG*)(Object + FlagsOffset);
        if ((Flags & WINDOW_PROTECT_PROTECTION_BIT) == 0)
        {
            continue;
        }

        HwndOffset = 0;
        PidOffset = 0;
        for (Field = KindOffset + 4; Field <= KindOffset + WINDOW_PROTECT_FIELD_SPAN && Field + 4 <= ObjectBytes; Field += 4)
        {
            ULONG Value;

            Value = *(ULONG*)(Object + Field);
            if (HwndOffset == 0)
            {
                if (Value == CalibrateHwnd)
                {
                    HwndOffset = Field;
                }
                continue;
            }

            if (Field > HwndOffset && Value == CalibratePid)
            {
                PidOffset = Field;
                break;
            }
        }

        if (HwndOffset == 0 || PidOffset == 0)
        {
            continue;
        }

        WindowProtectNoteLayout(Slots, SlotCount, Vtable, FlagsOffset, KindOffset, HwndOffset, PidOffset);
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
WindowProtectCollectObject(
    _In_ const UCHAR* Object,
    _In_ ULONG ObjectBytes,
    _In_ const WINDOW_PROTECT_LAYOUT* Layout,
    _Inout_ HACDBG_WINDOW_REQUEST* Request
    )
{
    ULONG Hwnd;
    ULONG Pid;
    ULONG Index;

    if (Layout->PidOffset + sizeof(ULONG) > ObjectBytes || Layout->HwndOffset + sizeof(ULONG) > ObjectBytes ||
        Layout->KindOffset + sizeof(ULONG) > ObjectBytes || Layout->FlagsOffset + sizeof(ULONG) > ObjectBytes)
    {
        return FALSE;
    }

    if (WindowProtectKind(*(ULONG*)(Object + Layout->KindOffset)) == FALSE ||
        (*(ULONG*)(Object + Layout->FlagsOffset) & WINDOW_PROTECT_PROTECTION_BIT) == 0)
    {
        return FALSE;
    }

    Hwnd = *(ULONG*)(Object + Layout->HwndOffset);
    Pid = *(ULONG*)(Object + Layout->PidOffset);
    if (Hwnd == 0 || WindowProtectPid(Pid) == FALSE)
    {
        return FALSE;
    }

    for (Index = 0; Index < Request->RowCount; Index++)
    {
        if (Request->Rows[Index].Hwnd == Hwnd && Request->Rows[Index].Pid == Pid)
        {
            return TRUE;
        }
    }

    if (Request->RowCount >= HACDBG_WINDOW_MAX_ROWS)
    {
        Request->Truncated = 1;
        return FALSE;
    }

    Request->Rows[Request->RowCount].Hwnd = Hwnd;
    Request->Rows[Request->RowCount].Pid = Pid;
    Request->RowCount += 1;
    return TRUE;
}

static BOOLEAN
WindowProtectRegionReadable(
    _In_ const MEMORY_BASIC_INFORMATION* Info
    )
{
    ULONG Protect;

    if (Info->State != MEM_COMMIT || Info->Type == WINDOW_PROTECT_MEM_IMAGE || Info->RegionSize == 0)
    {
        return FALSE;
    }

    if (WindowProtectUserSpan((UINT64)Info->BaseAddress, Info->RegionSize) == FALSE)
    {
        return FALSE;
    }

    Protect = Info->Protect & 0xFFu;
    if ((Info->Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
    {
        return FALSE;
    }

    return Protect == PAGE_READWRITE || Protect == PAGE_WRITECOPY || Protect == PAGE_EXECUTE_READWRITE;
}

static NTSTATUS
WindowProtectWalkDwm(
    _In_ PEPROCESS Process,
    _In_ UINT64 ModuleBase,
    _In_ UINT64 ModuleEnd,
    _In_ BOOLEAN Calibrating,
    _Inout_ HACDBG_WINDOW_REQUEST* Request,
    _Out_ WINDOW_PROTECT_LAYOUT* Chosen
    )
{
    KAPC_STATE State;
    UCHAR* Buffer;
    PVOID Address;
    ULONG Scanned;
    WINDOW_PROTECT_LAYOUT Slots[WINDOW_PROTECT_LAYOUT_SLOTS];
    UINT64 Vtables[WINDOW_PROTECT_VTABLE_SLOTS];
    ULONG VtableHits[WINDOW_PROTECT_VTABLE_SLOTS];
    ULONG VtableCount;
    ULONG SlotCount;
    ULONG Best;
    ULONG Index;

    RtlZeroMemory(Slots, sizeof(Slots));
    RtlZeroMemory(Vtables, sizeof(Vtables));
    RtlZeroMemory(VtableHits, sizeof(VtableHits));
    SlotCount = 0;
    VtableCount = 0;
    Best = 0;
    Scanned = 0;
    RtlZeroMemory(Chosen, sizeof(*Chosen));
    Buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, WINDOW_PROTECT_CHUNK, WINDOW_PROTECT_TAG);
    if (Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeStackAttachProcess(Process, &State);
    Address = NULL;
    for (;;)
    {
        MEMORY_BASIC_INFORMATION Info;
        SIZE_T Returned;
        NTSTATUS Status;
        ULONG Offset;

        Returned = 0;
        Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &Info, sizeof(Info), &Returned);
        if (!NT_SUCCESS(Status) || Info.RegionSize == 0)
        {
            break;
        }

        if (WindowProtectRegionReadable(&Info) != FALSE && Scanned < WINDOW_PROTECT_SCAN_BUDGET)
        {
            SIZE_T RegionOffset;

            RegionOffset = 0;
            while (RegionOffset < Info.RegionSize && Scanned < WINDOW_PROTECT_SCAN_BUDGET)
            {
                SIZE_T Remain;
                ULONG Chunk;
                ULONG Usable;

                Remain = Info.RegionSize - RegionOffset;
                Chunk = Remain > WINDOW_PROTECT_CHUNK ? WINDOW_PROTECT_CHUNK : (ULONG)Remain;

                if (WindowProtectReadRegion((UCHAR*)Info.BaseAddress + RegionOffset, Buffer, Chunk) == FALSE)
                {
                    break;
                }

                Scanned += Chunk;
                Usable = Chunk > WINDOW_PROTECT_OBJECT_SPAN ? Chunk - WINDOW_PROTECT_OBJECT_SPAN : 0;
                for (Offset = 0; Offset < Usable; Offset += 8)
                {
                    UINT64 Vtable;

                    Vtable = *(UINT64*)(Buffer + Offset);
                    if (Calibrating == FALSE)
                    {
                        if (Vtable != g_Layout.Vtable)
                        {
                            continue;
                        }

                        WindowProtectCollectObject(Buffer + Offset, WINDOW_PROTECT_OBJECT_SPAN, &g_Layout, Request);
                        continue;
                    }

                    if (WindowProtectVtable(Vtable, ModuleBase, ModuleEnd) == FALSE)
                    {
                        continue;
                    }

                    for (Index = 0; Index < VtableCount; Index++)
                    {
                        if (Vtables[Index] == Vtable)
                        {
                            VtableHits[Index] += 1;
                            break;
                        }
                    }

                    if (Index == VtableCount && VtableCount < WINDOW_PROTECT_VTABLE_SLOTS)
                    {
                        Vtables[VtableCount] = Vtable;
                        VtableHits[VtableCount] = 1;
                        VtableCount += 1;
                    }

                    WindowProtectCalibrateObject(Buffer + Offset,
                                                 WINDOW_PROTECT_OBJECT_SPAN,
                                                 Vtable,
                                                 Request->CalibrateHwnd,
                                                 Request->CalibratePid,
                                                 Slots,
                                                 &SlotCount);
                }

                if (RegionOffset + Chunk >= Info.RegionSize)
                {
                    break;
                }

                RegionOffset += Chunk > WINDOW_PROTECT_OBJECT_SPAN ? Chunk - WINDOW_PROTECT_OBJECT_SPAN : Chunk;
            }
        }
        else if (Scanned >= WINDOW_PROTECT_SCAN_BUDGET)
        {
            Request->Truncated = 1;
        }

        if ((ULONG_PTR)Info.BaseAddress + Info.RegionSize <= (ULONG_PTR)Info.BaseAddress)
        {
            break;
        }

        Address = (PVOID)((ULONG_PTR)Info.BaseAddress + Info.RegionSize);
    }

    KeUnstackDetachProcess(&State);
    ExFreePoolWithTag(Buffer, WINDOW_PROTECT_TAG);

    if (Calibrating == FALSE)
    {
        *Chosen = g_Layout;
        return g_LayoutReady != FALSE ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    for (Index = 0; Index < SlotCount; Index++)
    {
        ULONG Score;
        ULONG BestScore;
        ULONG Frequency;
        ULONG BestFrequency;
        ULONG Slot;

        Frequency = 0;
        BestFrequency = 0;
        for (Slot = 0; Slot < VtableCount; Slot++)
        {
            if (Vtables[Slot] == Slots[Index].Vtable)
            {
                Frequency = VtableHits[Slot];
            }
            if (Vtables[Slot] == Slots[Best].Vtable)
            {
                BestFrequency = VtableHits[Slot];
            }
        }

        Score = (Slots[Index].Hits * 100000u) + Frequency;
        BestScore = (Slots[Best].Hits * 100000u) + BestFrequency;
        if (Score > BestScore)
        {
            Best = Index;
        }
    }

    if (SlotCount == 0)
    {
        return STATUS_NOT_FOUND;
    }

    *Chosen = Slots[Best];
    return STATUS_SUCCESS;
}

static UINT64
WindowProtectDwmredir(
    _In_ PEPROCESS Process,
    _Out_ ULONG* ImageSize
    )
{
    KAPC_STATE State;
    UINT64 PebAddress;
    UINT64 LdrAddress;
    UINT64 HeadAddress;
    UINT64 LinkAddress;
    UINT64 Base;
    ULONG Guard;

    *ImageSize = 0;
    Base = 0;
    KeStackAttachProcess(Process, &State);
    PebAddress = (UINT64)PsGetProcessPeb(Process);
    if (PebAddress == 0 || WindowProtectUserSpan(PebAddress, 0x20) == FALSE ||
        WindowProtectReadUser(&LdrAddress, PebAddress + 0x18, sizeof(LdrAddress)) == FALSE ||
        LdrAddress == 0 || WindowProtectUserSpan(LdrAddress, 0x28) == FALSE)
    {
        KeUnstackDetachProcess(&State);
        return 0;
    }

    HeadAddress = LdrAddress + 0x20;
    if (WindowProtectReadUser(&LinkAddress, HeadAddress, sizeof(LinkAddress)) == FALSE)
    {
        KeUnstackDetachProcess(&State);
        return 0;
    }

    for (Guard = 0; Guard < 512 && LinkAddress != 0 && LinkAddress != HeadAddress; Guard++)
    {
        UINT64 Entry;
        UNICODE_STRING ModuleName;
        WCHAR Wide[32];
        CHAR Narrow[64];
        ULONG Index;
        ULONG NameChars;
        UINT64 Next;

        if (LinkAddress < 0x10)
        {
            break;
        }

        Entry = LinkAddress - 0x10;
        if (WindowProtectReadUser(&ModuleName, Entry + 0x58, sizeof(ModuleName)) == FALSE)
        {
            break;
        }

        NameChars = ModuleName.Length / sizeof(WCHAR);
        if (ModuleName.Buffer != NULL && ModuleName.Length != 0 && ModuleName.Length < sizeof(Wide) &&
            NameChars != 0 &&
            WindowProtectReadUser(Wide, (UINT64)ModuleName.Buffer, (SIZE_T)NameChars * sizeof(WCHAR)) != FALSE)
        {
            for (Index = 0; Index < NameChars && Index < 63; Index++)
            {
                WCHAR Character;

                Character = Wide[Index];
                if (Character >= L'A' && Character <= L'Z')
                {
                    Character = (WCHAR)(Character - L'A' + L'a');
                }
                Narrow[Index] = (CHAR)Character;
            }
            Narrow[Index] = '\0';
            if (_stricmp(Narrow, "dwmredir.dll") == 0)
            {
                ULONG SizeOfImage;

                SizeOfImage = 0;
                if (WindowProtectReadUser(&Base, Entry + 0x30, sizeof(Base)) == FALSE ||
                    WindowProtectReadUser(&SizeOfImage, Entry + 0x40, sizeof(SizeOfImage)) == FALSE ||
                    WindowProtectUserSpan(Base, SizeOfImage) == FALSE || SizeOfImage < PAGE_SIZE)
                {
                    Base = 0;
                    SizeOfImage = 0;
                }

                *ImageSize = SizeOfImage;
                break;
            }
        }

        Next = 0;
        if (WindowProtectReadUser(&Next, LinkAddress, sizeof(Next)) == FALSE)
        {
            break;
        }

        LinkAddress = Next;
    }

    KeUnstackDetachProcess(&State);
    return Base;
}

static NTSTATUS
WindowProtectScan(
    _Inout_ HACDBG_WINDOW_REQUEST* Request
    )
{
    PEPROCESS Process;
    NTSTATUS Status;
    UINT64 ModuleBase;
    ULONG ModuleSize;
    BOOLEAN Calibrating;
    WINDOW_PROTECT_LAYOUT Chosen;

    Request->RowCount = 0;
    Request->Truncated = 0;
    if (Request->DwmPid == 0 || Request->DwmPid == 4)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Calibrating = g_LayoutReady == FALSE || (Request->Flags & HACDBG_WINDOW_FLAG_RECALIBRATE) != 0;
    if (Calibrating != FALSE && (Request->CalibrateHwnd == 0 || Request->CalibratePid == 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Request->DwmPid, &Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ModuleBase = WindowProtectDwmredir(Process, &ModuleSize);
    if (ModuleBase == 0 || ModuleSize < PAGE_SIZE || WindowProtectUserSpan(ModuleBase, ModuleSize) == FALSE)
    {
        ObDereferenceObject(Process);
        HACDBG_LOG("HacDbg: Err, window protect did not find dwmredir.dll in pid %lu.\n", Request->DwmPid);
        return STATUS_NOT_FOUND;
    }

    if (Calibrating != FALSE)
    {
        g_LayoutReady = FALSE;
    }

    Status = WindowProtectWalkDwm(Process,
                                  ModuleBase,
                                  ModuleBase + ModuleSize,
                                  Calibrating,
                                  Request,
                                  &Chosen);
    ObDereferenceObject(Process);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, window protect DWM scan failed: 0x%08x.\n", Status);
        return Status;
    }

    if (Calibrating != FALSE)
    {
        g_Layout = Chosen;
        g_LayoutReady = TRUE;
        HACDBG_LOG("HacDbg: Window protect DWM layout vtable 0x%I64x flags +0x%x kind +0x%x hwnd +0x%x pid +0x%x hits %lu.\n",
                   Chosen.Vtable,
                   Chosen.FlagsOffset,
                   Chosen.KindOffset,
                   Chosen.HwndOffset,
                   Chosen.PidOffset,
                   Chosen.Hits);
        Request->RowCount = 0;
        Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Request->DwmPid, &Process);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

        Status = WindowProtectWalkDwm(Process, ModuleBase, ModuleBase + ModuleSize, FALSE, Request, &Chosen);
        ObDereferenceObject(Process);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    Request->FlagsOffset = g_Layout.FlagsOffset;
    Request->KindOffset = g_Layout.KindOffset;
    Request->HwndOffset = g_Layout.HwndOffset;
    Request->PidOffset = g_Layout.PidOffset;
    Request->Vtable = g_Layout.Vtable;
    return STATUS_SUCCESS;
}

static NTSTATUS
WindowProtectAllow(
    _In_ const HACDBG_WINDOW_REQUEST* Request
    )
{
    InterlockedExchange(&g_BypassPid, (LONG)Request->CalibratePid);
    HACDBG_LOG("HacDbg: Window protect allow pid %lu.\n", Request->CalibratePid);
    return STATUS_SUCCESS;
}

static VOID
WindowProtectFillHook(
    _Inout_ HACDBG_WINDOW_REQUEST* Request
    )
{
    Request->HookArmed = g_HookInstalled != 0 && g_Armed != 0 ? 1u : 0u;
    Request->OwnerPid = (ULONG)g_OwnerPid;
    Request->Target = g_TargetVa;
    if (g_LayoutReady != FALSE)
    {
        Request->FlagsOffset = g_Layout.FlagsOffset;
        Request->KindOffset = g_Layout.KindOffset;
        Request->HwndOffset = g_Layout.HwndOffset;
        Request->PidOffset = g_Layout.PidOffset;
        Request->Vtable = g_Layout.Vtable;
    }
}

NTSTATUS
WindowProtectExecute(
    _Inout_ HACDBG_WINDOW_REQUEST* Request
    )
{
    NTSTATUS Status;

    if (Request == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Request->Operation)
    {
    case HACDBG_WINDOW_QUERY:
        Status = STATUS_SUCCESS;
        break;

    case HACDBG_WINDOW_ARM:
        Status = WindowProtectArm();
        break;

    case HACDBG_WINDOW_DISARM:
        Status = WindowProtectDisarm();
        break;

    case HACDBG_WINDOW_SCAN:
        Status = WindowProtectScan(Request);
        break;

    case HACDBG_WINDOW_ALLOW:
        Status = WindowProtectAllow(Request);
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    Request->Status = Status;
    WindowProtectFillHook(Request);
    return Status;
}

VOID
WindowProtectCleanup(
    VOID
    )
{
    if (g_HookInstalled != 0 || g_ShadowRaw != NULL || g_TrampolineRaw != NULL)
    {
        WindowProtectDisarm();
    }
}
