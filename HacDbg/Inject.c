/**
 * @file Inject.c
 * @brief APC and page-table DLL injection.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <ntimage.h>

#include "Debug.h"
#include "Inject.h"

#if defined(_AMD64_)
#include <intrin.h>

#include "Config.h"
#include "PhysicalMemory.h"
#include "Svm.h"
#include "Types.h"

#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#define INJECT_ADD_HOOK    EptAddHook
#define INJECT_REMOVE_HOOK EptRemoveHook
#else
#include "Npt.h"
#define INJECT_ADD_HOOK    NptAddHook
#define INJECT_REMOVE_HOOK NptRemoveHook
#endif

#define INJECT_TAG 'jIaH'
#define INJECT_MAX_IMAGE (16u * 1024u * 1024u)
#define INJECT_MAX_PAGES 4096u
#define INJECT_EXTRA_PAGES 3u
#define INJECT_FRAME 0x000FFFFFFFFFF000ull
#define INJECT_PRESENT 0x1ull
#define INJECT_WRITE 0x2ull
#define INJECT_USER 0x4ull
#define INJECT_ACCESSED 0x20ull
#define INJECT_DIRTY 0x40ull
#define INJECT_LARGE 0x80ull
#define INJECT_NX (1ull << 63)
#define INJECT_PROTOTYPE (1ull << 10)
#define INJECT_TRANSITION (1ull << 11)
#define INJECT_DIR_TABLE 0x28u
#define INJECT_MAX_EDITS (INJECT_MAX_PAGES * 8u)
#define INJECT_PLACE_MAIN 1u
#define INJECT_PLACE_GAP 2u
#define INJECT_PLACE_PML4 3u
#define INJECT_SMAP (1ull << 21)
#define INJECT_AC_FLAG 0x40000ull
#define INJECT_SHARED_DATA 0xFFFFF78000000000ull
#define INJECT_BUILD_OFFSET 0x260u
#define INJECT_NAME_CHARS 64u
#define INJECT_PATH_CHARS 260u
#define INJECT_NT_CHARS 520u
#define INJECT_TEB_LAST_ERROR 0x68u
#define INJECT_LINK_QUERY 0x0001u
#define INJECT_DUPLICATE_SAME 0x0002u
#define INJECT_ERROR_FILE_NOT_FOUND 2u
#define INJECT_ERROR_PATH_NOT_FOUND 3u
#define INJECT_ERROR_ACCESS_DENIED 5u
#define INJECT_ERROR_INVALID_PARAMETER 87u
#define INJECT_ERROR_MOD_NOT_FOUND 126u
#define INJECT_ERROR_PROC_NOT_FOUND 127u
#define INJECT_ERROR_BAD_EXE_FORMAT 193u
#define INJECT_ERROR_DLL_INIT_FAILED 1114u
#define INJECT_STACK_BYTES 0x100000u
#define INJECT_VM_CFG_CALL_TARGET 2u
#define INJECT_CFG_CALL_TARGET_VALID 1ull

typedef NTSTATUS(NTAPI* INJECT_GET_NEXT_THREAD)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                                ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
typedef NTSTATUS(NTAPI* INJECT_CREATE_THREAD)(HANDLE ProcessHandle, PVOID SecurityDescriptor, BOOLEAN CreateSuspended,
                                              ULONG StackZeroBits, SIZE_T StackReserved, SIZE_T StackCommit,
                                              PVOID StartAddress, PVOID Parameter, PHANDLE ThreadHandle,
                                              PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* INJECT_CONTEXT_THREAD)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);
typedef NTSTATUS(NTAPI* INJECT_QUERY_THREAD)(HANDLE ThreadHandle, ULONG InformationClass, PVOID Information,
                                             ULONG InformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* INJECT_DUPLICATE)(HANDLE SourceProcess, HANDLE SourceHandle, HANDLE TargetProcess,
                                          PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
                                          ULONG Options);
typedef PVOID(NTAPI* INJECT_WIN32_THREAD)(PETHREAD Thread);
typedef PVOID(NTAPI* INJECT_WOW64_PROCESS)(PEPROCESS Process);

typedef struct _INJECT_THREAD_BASIC
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} INJECT_THREAD_BASIC;

typedef struct _INJECT_MEMORY_RANGE
{
    PVOID Address;
    SIZE_T Bytes;
} INJECT_MEMORY_RANGE;

typedef struct _INJECT_CFG_TARGET
{
    ULONG_PTR Offset;
    ULONG_PTR Flags;
} INJECT_CFG_TARGET;

//
// VmCfgCallTargetInformation. The caller passes class 2 and 0x28 bytes.
// The first ULONG is the target count and must be non-zero. The next ULONG
// must be zero. The pointer at +8 receives a ULONG. The pointer at +0x10 is
// an array of offset/flag pairs. CFG_CALL_TARGET_VALID is 1.
//
typedef struct _INJECT_CFG_INFORMATION
{
    ULONG NumberOfEntries;
    ULONG Reserved;
    ULONG* Output;
    INJECT_CFG_TARGET* Targets;
    ULONG_PTR Unused0;
    ULONG_PTR Unused1;
} INJECT_CFG_INFORMATION;

C_ASSERT(sizeof(INJECT_CFG_INFORMATION) == 0x28);

typedef NTSTATUS(NTAPI* INJECT_SET_VM)(HANDLE ProcessHandle, ULONG InformationClass, ULONG_PTR NumberOfEntries,
                                       PVOID VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength);

typedef struct _INJECT_LOAD_RESULT
{
    ULONG Ran;
    ULONG LastError;
    UINT64 Module;
} INJECT_LOAD_RESULT;

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

NTSYSAPI
NTSTATUS
NTAPI
ZwSuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef struct _INJECT_OWNED
{
    PVOID Virtual;
    UINT64 Physical;
    BOOLEAN Hooked;
} INJECT_OWNED;

typedef struct _INJECT_EDIT
{
    UINT64 Table;
    ULONG Index;
    UINT64 Previous;
} INJECT_EDIT;

typedef struct _INJECT_SPAN
{
    UINT64 Base;
    UINT64 End;
} INJECT_SPAN;

static PVOID
InjectRoutine(
    _In_ PCWSTR Name
    )
{
    UNICODE_STRING Unicode;

    RtlInitUnicodeString(&Unicode, Name);
    return MmGetSystemRoutineAddress(&Unicode);
}

static BOOLEAN
InjectWow64(
    _In_ PEPROCESS Process
    )
{
    INJECT_WOW64_PROCESS Routine;

    Routine = (INJECT_WOW64_PROCESS)InjectRoutine(L"PsGetProcessWow64Process");
    return Routine != NULL && Routine(Process) != NULL;
}

static ULONG
InjectBuild(
    VOID
    )
{
    ULONG Build;

    Build = *(ULONG*)(INJECT_SHARED_DATA + INJECT_BUILD_OFFSET);
    return Build & 0xFFFFu;
}

static ULONG
InjectUserDirectoryOffset(
    VOID
    )
{
    ULONG Build;

    Build = InjectBuild();
    if (Build >= 26100)
    {
        return 0x158u;
    }

    if (Build >= 19041)
    {
        return 0x388u;
    }

    if (Build >= 18362)
    {
        return 0x280u;
    }

    if (Build >= 17134)
    {
        return 0x278u;
    }

    return 0;
}

static UINT64
InjectDirectory(
    _In_ PEPROCESS Process,
    _In_ ULONG Offset
    )
{
    UINT64 Value;

    if (Offset == 0 || Offset >= 0x1000)
    {
        return 0;
    }

    Value = *(UINT64*)((UCHAR*)Process + Offset);
    if (Value <= 1)
    {
        return 0;
    }

    return Value & INJECT_FRAME;
}

static BOOLEAN
InjectMapRam(
    _In_ UINT64 Physical,
    _Out_ PVOID* Mapped,
    _Out_ SIZE_T* MappedSize
    )
{
    *MappedSize = 0;
    if ((Physical & ~INJECT_FRAME) != 0 || Physical == 0)
    {
        *Mapped = NULL;
        return FALSE;
    }

    //
    // INVARIANT: Physical is a 4 KiB RAM frame. The temporary window is the
    // host alias used by the rest of the driver. MmMapIoSpace is not used:
    // mapping a PFN-database page that way bugchecks 0x1A when a debugger
    // is connected.
    //
    *Mapped = PhysicalMemoryMapTemporary(HacDbgGuestPhysicalAddress(Physical), PAGE_SIZE, MappedSize);
    return *Mapped != NULL && *MappedSize >= PAGE_SIZE;
}

static BOOLEAN
InjectReadEntry(
    _In_ UINT64 Table,
    _In_ ULONG Index,
    _Out_ UINT64* Value
    )
{
    PVOID Mapped;
    SIZE_T MappedSize;

    if (Index >= 512 || InjectMapRam(Table, &Mapped, &MappedSize) == FALSE)
    {
        return FALSE;
    }

    *Value = ((volatile UINT64*)Mapped)[Index];
    PhysicalMemoryUnmapTemporary(Mapped, MappedSize);
    return TRUE;
}

static UINT64
InjectUsableUserDirectory(
    _In_ PEPROCESS Process,
    _In_ UINT64 KernelDirectory
    )
{
    UINT64 User;
    UINT64 Entry;

    User = InjectDirectory(Process, InjectUserDirectoryOffset());
    if (User == 0 || User == KernelDirectory)
    {
        return 0;
    }

    if (InjectReadEntry(User, 0, &Entry) == FALSE)
    {
        return 0;
    }

    return User;
}

static BOOLEAN
InjectWriteEntry(
    _In_ UINT64 Table,
    _In_ ULONG Index,
    _In_ UINT64 Value
    )
{
    PVOID Mapped;
    SIZE_T MappedSize;

    if (Index >= 512 || InjectMapRam(Table, &Mapped, &MappedSize) == FALSE)
    {
        return FALSE;
    }

    ((volatile UINT64*)Mapped)[Index] = Value;
    KeMemoryBarrier();
    PhysicalMemoryUnmapTemporary(Mapped, MappedSize);
    return TRUE;
}

static BOOLEAN
InjectWriteTracked(
    _In_ UINT64 Table,
    _In_ ULONG Index,
    _In_ UINT64 Value,
    _Inout_ INJECT_EDIT* Edits,
    _Inout_ ULONG* EditCount
    )
{
    UINT64 Previous;

    if (InjectReadEntry(Table, Index, &Previous) == FALSE)
    {
        return FALSE;
    }

    if (Previous == Value)
    {
        return TRUE;
    }

    if (*EditCount >= INJECT_MAX_EDITS || InjectWriteEntry(Table, Index, Value) == FALSE)
    {
        return FALSE;
    }

    Edits[*EditCount].Table = Table;
    Edits[*EditCount].Index = Index;
    Edits[*EditCount].Previous = Previous;
    *EditCount += 1;
    return TRUE;
}

static VOID
InjectRestoreEdits(
    _In_ INJECT_EDIT* Edits,
    _In_ ULONG Count
    )
{
    while (Count > 0)
    {
        Count -= 1;
        InjectWriteEntry(Edits[Count].Table, Edits[Count].Index, Edits[Count].Previous);
    }
}

static BOOLEAN
InjectTrack(
    _Inout_ INJECT_OWNED* Owned,
    _Inout_ ULONG* Count,
    _In_ PVOID Virtual,
    _In_ UINT64 Physical
    )
{
    if (*Count >= INJECT_MAX_PAGES || Virtual == NULL || Physical == 0)
    {
        return FALSE;
    }

    Owned[*Count].Virtual = Virtual;
    Owned[*Count].Physical = Physical;
    Owned[*Count].Hooked = FALSE;
    *Count += 1;
    return TRUE;
}

static UINT64
InjectAllocFrame(
    _Out_ PVOID* Virtual
    )
{
    PHYSICAL_ADDRESS High;
    PVOID Page;

    High.QuadPart = -1;
    Page = MmAllocateContiguousMemory(PAGE_SIZE, High);
    if (Page == NULL)
    {
        *Virtual = NULL;
        return 0;
    }

    RtlZeroMemory(Page, PAGE_SIZE);
    *Virtual = Page;
    return (UINT64)MmGetPhysicalAddress(Page).QuadPart & INJECT_FRAME;
}

static VOID
InjectFreeOwned(
    _Inout_ INJECT_OWNED* Owned,
    _In_ ULONG Count
    )
{
    ULONG Index;

    for (Index = 0; Index < Count; Index++)
    {
        if (Owned[Index].Hooked != FALSE)
        {
            INJECT_REMOVE_HOOK(HacDbgGuestPhysicalAddress(Owned[Index].Physical));
            Owned[Index].Hooked = FALSE;
        }
    }

    for (Index = 0; Index < Count; Index++)
    {
        if (Owned[Index].Virtual != NULL)
        {
            MmFreeContiguousMemory(Owned[Index].Virtual);
            Owned[Index].Virtual = NULL;
        }
    }
}

static BOOLEAN
InjectFlush(
    VOID
    )
{
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
        // INVARIANT: This processor is already a guest. The leaf drops
        // cached nested translations before the disguised page is fetched.
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
}

static BOOLEAN
InjectEnsureChild(
    _In_ UINT64 Table,
    _In_ ULONG Index,
    _Out_ UINT64* Child,
    _Inout_ INJECT_OWNED* Owned,
    _Inout_ ULONG* Count,
    _Inout_ INJECT_EDIT* Edits,
    _Inout_ ULONG* EditCount
    )
{
    UINT64 Entry;
    PVOID Page;
    UINT64 Frame;

    if (InjectReadEntry(Table, Index, &Entry) == FALSE)
    {
        return FALSE;
    }

    if ((Entry & INJECT_PRESENT) != 0)
    {
        if ((Entry & INJECT_LARGE) != 0)
        {
            return FALSE;
        }

        *Child = Entry & INJECT_FRAME;
        return *Child != 0;
    }

    Frame = InjectAllocFrame(&Page);
    if (Frame == 0 || InjectTrack(Owned, Count, Page, Frame) == FALSE)
    {
        if (Page != NULL)
        {
            MmFreeContiguousMemory(Page);
        }

        return FALSE;
    }

    Entry = Frame | INJECT_PRESENT | INJECT_WRITE | INJECT_USER;
    if (InjectWriteTracked(Table, Index, Entry, Edits, EditCount) == FALSE)
    {
        return FALSE;
    }

    *Child = Frame;
    return TRUE;
}

static BOOLEAN
InjectMapLeaf(
    _In_ UINT64 Directory,
    _In_ UINT64 Virtual,
    _In_ UINT64 DataPhysical,
    _In_ BOOLEAN Execute,
    _Inout_ INJECT_OWNED* Owned,
    _Inout_ ULONG* Count,
    _Inout_ INJECT_EDIT* Edits,
    _Inout_ ULONG* EditCount
    )
{
    ULONG Shift;
    ULONG Depth;
    ULONG Index;
    UINT64 Table;
    UINT64 Child;
    UINT64 Value;

    if (Virtual < 0x10000ull || Virtual > 0x00007FFFFFFFFFFFull || (Virtual & (PAGE_SIZE - 1)) != 0)
    {
        return FALSE;
    }

    Table = Directory;
    for (Depth = 0; Depth < 3; Depth++)
    {
        Shift = 39 - (Depth * 9);
        Index = (ULONG)((Virtual >> Shift) & 0x1FFu);
        if (InjectEnsureChild(Table, Index, &Child, Owned, Count, Edits, EditCount) == FALSE)
        {
            return FALSE;
        }

        Table = Child;
    }

    Index = (ULONG)((Virtual >> 12) & 0x1FFu);
    Value = (DataPhysical & INJECT_FRAME) | INJECT_PRESENT | INJECT_WRITE | INJECT_USER | INJECT_ACCESSED |
            INJECT_DIRTY;
    if (Execute == FALSE)
    {
        Value |= INJECT_NX;
    }

    return InjectWriteTracked(Table, Index, Value, Edits, EditCount);
}

static VOID
InjectFileName(
    _In_ const WCHAR* Path,
    _Out_writes_(INJECT_NAME_CHARS) CHAR* Narrow
    )
{
    const WCHAR* Base;
    const WCHAR* Cursor;
    ULONG Index;

    Base = Path;
    for (Cursor = Path; *Cursor != L'\0'; Cursor++)
    {
        if (*Cursor == L'\\' || *Cursor == L'/')
        {
            Base = Cursor + 1;
        }
    }

    for (Index = 0; Index < INJECT_NAME_CHARS - 1 && Base[Index] != L'\0'; Index++)
    {
        WCHAR Character = Base[Index];
        if (Character >= L'A' && Character <= L'Z')
        {
            Character = (WCHAR)(Character - L'A' + L'a');
        }

        Narrow[Index] = (CHAR)Character;
    }

    Narrow[Index] = 0;
}

//
// CR4.SMAP turns a supervisor data access to a present user page into a
// protection fault when EFLAGS.AC is clear. The fault is bugcheck 0x50, and
// __try does not catch it. A caller that already set AC keeps the flag.
//
static BOOLEAN
InjectAllowUser(
    VOID
    )
{
    if ((__readcr4() & INJECT_SMAP) == 0 || (__readeflags() & INJECT_AC_FLAG) != 0)
    {
        return FALSE;
    }

    _stac();
    return TRUE;
}

static VOID
InjectEndUser(
    _In_ BOOLEAN Opened
    )
{
    if (Opened != FALSE)
    {
        _clac();
    }
}

static UINT64
InjectModuleBase(
    _In_ PEPROCESS Process,
    _In_ const CHAR* Name
    )
{
    KAPC_STATE State;
    UINT64 Base;
    ULONG Guard;
    BOOLEAN Opened;

    Base = 0;
    KeStackAttachProcess(Process, &State);
    Opened = InjectAllowUser();
    __try
    {
        UCHAR* Peb;
        UCHAR* Ldr;
        LIST_ENTRY* Head;
        LIST_ENTRY* Link;

        Peb = (UCHAR*)PsGetProcessPeb(Process);
        if (Peb == NULL)
        {
            __leave;
        }

        Ldr = *(UCHAR**)(Peb + 0x18);
        if (Ldr == NULL)
        {
            __leave;
        }

        Head = (LIST_ENTRY*)(Ldr + 0x20);
        Link = Head->Flink;
        for (Guard = 0; Guard < 512 && Link != NULL && Link != Head; Guard++)
        {
            UCHAR* Entry = (UCHAR*)Link - 0x10;
            UNICODE_STRING* ModuleName;
            CHAR Narrow[INJECT_NAME_CHARS];
            ULONG Index;

            ModuleName = (UNICODE_STRING*)(Entry + 0x58);
            if (ModuleName->Buffer != NULL && ModuleName->Length > 0 &&
                ModuleName->Length < sizeof(Narrow) * sizeof(WCHAR))
            {
                for (Index = 0; Index < ModuleName->Length / sizeof(WCHAR) && Index < INJECT_NAME_CHARS - 1; Index++)
                {
                    WCHAR Character = ModuleName->Buffer[Index];
                    if (Character >= L'A' && Character <= L'Z')
                    {
                        Character = (WCHAR)(Character - L'A' + L'a');
                    }

                    Narrow[Index] = (CHAR)Character;
                }

                Narrow[Index] = 0;
                if (_stricmp(Narrow, Name) == 0)
                {
                    Base = *(UINT64*)(Entry + 0x30);
                    break;
                }
            }

            Link = Link->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Base = 0;
    }

    InjectEndUser(Opened);
    KeUnstackDetachProcess(&State);
    return Base;
}

static BOOLEAN
InjectWaitModule(
    _In_ PEPROCESS Process,
    _In_ const CHAR* Name,
    _In_ ULONG Attempts
    )
{
    ULONG Index;
    LARGE_INTEGER Delay;

    Delay.QuadPart = -1000000;
    for (Index = 0; Index < Attempts; Index++)
    {
        if (InjectModuleBase(Process, Name) != 0)
        {
            return TRUE;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    return InjectModuleBase(Process, Name) != 0;
}

static UINT64
InjectResolve(
    _In_ PEPROCESS Process,
    _In_ UINT64 ModuleBase,
    _In_ const CHAR* ExportName,
    _In_ ULONG Depth
    );

static UINT64
InjectResolveForward(
    _In_ PEPROCESS Process,
    _In_ const CHAR* Text,
    _In_ ULONG Depth
    )
{
    CHAR Module[80];
    const CHAR* Dot;
    const CHAR* Name;
    ULONG Index;
    UINT64 ModuleBase;

    if (Depth >= 8 || Text == NULL)
    {
        return 0;
    }

    Dot = NULL;
    for (Index = 0; Text[Index] != 0; Index++)
    {
        if (Text[Index] == '.')
        {
            Dot = Text + Index;
        }
    }

    if (Dot == NULL || Dot == Text || Dot[1] == 0 || (ULONG)(Dot - Text) >= 64)
    {
        return 0;
    }

    for (Index = 0; Text + Index < Dot && Index < 63; Index++)
    {
        Module[Index] = Text[Index];
    }

    Module[Index] = '.';
    Module[Index + 1] = 'd';
    Module[Index + 2] = 'l';
    Module[Index + 3] = 'l';
    Module[Index + 4] = 0;
    Name = Dot + 1;
    ModuleBase = InjectModuleBase(Process, Module);
    if (ModuleBase == 0)
    {
        Module[Index] = 0;
        ModuleBase = InjectModuleBase(Process, Module);
    }

    if (ModuleBase == 0)
    {
        return 0;
    }

    return InjectResolve(Process, ModuleBase, Name, Depth + 1);
}

static UINT64
InjectResolve(
    _In_ PEPROCESS Process,
    _In_ UINT64 ModuleBase,
    _In_ const CHAR* ExportName,
    _In_ ULONG Depth
    )
{
    KAPC_STATE State;
    UINT64 Address;
    CHAR Forward[96];
    BOOLEAN Forwarded;
    BOOLEAN Opened;

    if (ModuleBase == 0 || ExportName == NULL || ExportName[0] == 0 || Depth >= 8)
    {
        return 0;
    }

    Address = 0;
    Forwarded = FALSE;
    Forward[0] = 0;
    KeStackAttachProcess(Process, &State);
    Opened = InjectAllowUser();
    __try
    {
        PUCHAR Base = (PUCHAR)ModuleBase;
        IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)Base;
        IMAGE_NT_HEADERS64* Nt;
        IMAGE_EXPORT_DIRECTORY* Export;
        ULONG* Names;
        USHORT* Ordinals;
        ULONG* Functions;
        ULONG Index;
        ULONG Directory;
        ULONG DirectorySize;
        ULONG FunctionRva;

        if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            __leave;
        }

        Nt = (IMAGE_NT_HEADERS64*)(Base + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE)
        {
            __leave;
        }

        Directory = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DirectorySize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (Directory == 0)
        {
            __leave;
        }

        Export = (IMAGE_EXPORT_DIRECTORY*)(Base + Directory);
        Names = (ULONG*)(Base + Export->AddressOfNames);
        Ordinals = (USHORT*)(Base + Export->AddressOfNameOrdinals);
        Functions = (ULONG*)(Base + Export->AddressOfFunctions);
        for (Index = 0; Index < Export->NumberOfNames && Index < 8192; Index++)
        {
            if (strcmp((CHAR*)(Base + Names[Index]), ExportName) != 0)
            {
                continue;
            }

            FunctionRva = Functions[Ordinals[Index]];
            if (FunctionRva >= Directory && FunctionRva < Directory + DirectorySize)
            {
                ULONG Copy;

                for (Copy = 0; Copy < sizeof(Forward) - 1; Copy++)
                {
                    Forward[Copy] = (CHAR)Base[FunctionRva + Copy];
                    if (Forward[Copy] == 0)
                    {
                        break;
                    }
                }

                Forward[Copy] = 0;
                Forwarded = TRUE;
            }
            else
            {
                Address = ModuleBase + FunctionRva;
            }

            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Address = 0;
        Forwarded = FALSE;
    }

    InjectEndUser(Opened);
    KeUnstackDetachProcess(&State);
    if (Forwarded == FALSE)
    {
        return Address;
    }

    return InjectResolveForward(Process, Forward, Depth);
}

static NTSTATUS
InjectCopyUser(
    _In_ PEPROCESS Process,
    _In_ PVOID Remote,
    _In_reads_bytes_(Bytes) const VOID* Buffer,
    _In_ SIZE_T Bytes
    )
{
    KAPC_STATE State;
    NTSTATUS Status;

    KeStackAttachProcess(Process, &State);
    if ((__readcr4() & (1ull << 21)) != 0)
    {
        _stac();
    }

    __try
    {
        RtlCopyMemory(Remote, Buffer, Bytes);
        Status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
    }

    if ((__readcr4() & (1ull << 21)) != 0)
    {
        _clac();
    }

    KeUnstackDetachProcess(&State);
    return Status;
}

static NTSTATUS
InjectAllocUser(
    _In_ PEPROCESS Process,
    _In_ SIZE_T Bytes,
    _In_ ULONG Protect,
    _Out_ PVOID* Remote
    )
{
    KAPC_STATE State;
    NTSTATUS Status;
    SIZE_T Size;
    PVOID Address;

    *Remote = NULL;
    Size = Bytes;
    Address = NULL;
    KeStackAttachProcess(Process, &State);
    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &Address, 0, &Size, MEM_COMMIT | MEM_RESERVE, Protect);
    KeUnstackDetachProcess(&State);
    if (NT_SUCCESS(Status))
    {
        *Remote = Address;
    }

    return Status;
}

static VOID
InjectLogWide(
    _In_ const CHAR* Label,
    _In_ const WCHAR* Text
    )
{
    WCHAR Copy[100];
    SIZE_T Length;
    SIZE_T Start;

    Length = 0;
    if (Text != NULL)
    {
        Length = wcslen(Text);
    }

    Start = 0;
    if (Length > 96)
    {
        Start = Length - 96;
        Length = 96;
    }

    if (Length != 0)
    {
        RtlCopyMemory(Copy, Text + Start, Length * sizeof(WCHAR));
    }

    Copy[Length] = 0;
    HACDBG_LOG("HacDbg: DLL inject %s \"%ws\"\n", Label, Copy);
}

static NTSTATUS
InjectReadUser(
    _In_ PEPROCESS Process,
    _In_ PVOID Remote,
    _Out_writes_bytes_(Bytes) VOID* Buffer,
    _In_ SIZE_T Bytes
    )
{
    KAPC_STATE State;
    NTSTATUS Status;
    BOOLEAN Opened;

    KeStackAttachProcess(Process, &State);
    Opened = InjectAllowUser();
    __try
    {
        RtlCopyMemory(Buffer, Remote, Bytes);
        Status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
    }

    InjectEndUser(Opened);
    KeUnstackDetachProcess(&State);
    return Status;
}

static ULONG
InjectTebError(
    _In_ PEPROCESS Process,
    _In_ PVOID Teb
    )
{
    KAPC_STATE State;
    ULONG Error;
    BOOLEAN Opened;

    Error = 0xFFFFFFFFu;
    if (Teb == NULL)
    {
        return Error;
    }

    KeStackAttachProcess(Process, &State);
    Opened = InjectAllowUser();
    __try
    {
        Error = *(ULONG*)((UCHAR*)Teb + INJECT_TEB_LAST_ERROR);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Error = 0xFFFFFFFFu;
    }

    InjectEndUser(Opened);
    KeUnstackDetachProcess(&State);
    return Error;
}

static ULONG
InjectSyscallNumber(
    _In_ PEPROCESS Process,
    _In_ UINT64 Routine
    )
{
    KAPC_STATE State;
    ULONG Number;
    BOOLEAN Opened;

    Number = 0;
    if (Routine == 0)
    {
        return 0;
    }

    KeStackAttachProcess(Process, &State);
    Opened = InjectAllowUser();
    __try
    {
        UCHAR* Code = (UCHAR*)Routine;

        if (Code[0] == 0x4C && Code[1] == 0x8B && Code[2] == 0xD1 && Code[3] == 0xB8)
        {
            Number = *(ULONG*)(Code + 4);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Number = 0;
    }

    InjectEndUser(Opened);
    KeUnstackDetachProcess(&State);
    if (Number == 0 || Number > 0x1000)
    {
        return 0;
    }

    return Number;
}

static VOID
InjectWriteLoadStub(
    _Out_writes_(96) UCHAR* Stub,
    _In_ UINT64 ResultBase,
    _In_ UINT64 Context,
    _In_ UINT64 NtContinue,
    _In_ ULONG SyscallNumber
    )
{
    UCHAR* Cursor;
    UINT64 ModuleAddress;
    UINT64 ErrorAddress;
    UINT64 RanAddress;
    ULONG Selector;

    ModuleAddress = ResultBase + 8;
    ErrorAddress = ResultBase + 4;
    RanAddress = ResultBase;
    Selector = 0x7FFE0308u;
    RtlZeroMemory(Stub, 96);
    Cursor = Stub;
    *Cursor++ = 0x48;
    *Cursor++ = 0xA3;
    RtlCopyMemory(Cursor, &ModuleAddress, sizeof(ModuleAddress));
    Cursor += sizeof(ModuleAddress);
    *Cursor++ = 0x65;
    *Cursor++ = 0x8B;
    *Cursor++ = 0x04;
    *Cursor++ = 0x25;
    *Cursor++ = (UCHAR)INJECT_TEB_LAST_ERROR;
    *Cursor++ = 0;
    *Cursor++ = 0;
    *Cursor++ = 0;
    *Cursor++ = 0x48;
    *Cursor++ = 0xB9;
    RtlCopyMemory(Cursor, &ErrorAddress, sizeof(ErrorAddress));
    Cursor += sizeof(ErrorAddress);
    *Cursor++ = 0x89;
    *Cursor++ = 0x01;
    *Cursor++ = 0x48;
    *Cursor++ = 0xB8;
    RtlCopyMemory(Cursor, &RanAddress, sizeof(RanAddress));
    Cursor += sizeof(RanAddress);
    *Cursor++ = 0xC7;
    *Cursor++ = 0x00;
    *Cursor++ = 0x01;
    *Cursor++ = 0x00;
    *Cursor++ = 0x00;
    *Cursor++ = 0x00;
    *Cursor++ = 0x48;
    *Cursor++ = 0xB9;
    RtlCopyMemory(Cursor, &Context, sizeof(Context));
    Cursor += sizeof(Context);
    *Cursor++ = 0x33;
    *Cursor++ = 0xD2;
    if (SyscallNumber != 0)
    {
        *Cursor++ = 0x4C;
        *Cursor++ = 0x8B;
        *Cursor++ = 0xD1;
        *Cursor++ = 0xB8;
        RtlCopyMemory(Cursor, &SyscallNumber, sizeof(SyscallNumber));
        Cursor += sizeof(SyscallNumber);
        *Cursor++ = 0xF6;
        *Cursor++ = 0x04;
        *Cursor++ = 0x25;
        RtlCopyMemory(Cursor, &Selector, sizeof(Selector));
        Cursor += sizeof(Selector);
        *Cursor++ = 0x01;
        *Cursor++ = 0x75;
        *Cursor++ = 0x03;
        *Cursor++ = 0x0F;
        *Cursor++ = 0x05;
        *Cursor++ = 0xCC;
        *Cursor++ = 0xCD;
        *Cursor++ = 0x2E;
        *Cursor++ = 0xCC;
    }
    else
    {
        *Cursor++ = 0x48;
        *Cursor++ = 0xB8;
        RtlCopyMemory(Cursor, &NtContinue, sizeof(NtContinue));
        Cursor += sizeof(NtContinue);
        *Cursor++ = 0xFF;
        *Cursor++ = 0xE0;
        *Cursor++ = 0xCC;
    }
}

static NTSTATUS
InjectSuspendOne(
    _In_ PEPROCESS Process,
    _Out_ HANDLE* ThreadHandle,
    _Out_ PETHREAD* ThreadObject
    )
{
    INJECT_GET_NEXT_THREAD NextThread;
    INJECT_WIN32_THREAD Win32;
    HANDLE ProcessHandle;
    HANDLE Previous;
    HANDLE Chosen;
    PETHREAD Thread;
    NTSTATUS Status;
    ULONG PreviousSuspend;
    BOOLEAN WantWin32;
    ULONG Seen;

    *ThreadHandle = NULL;
    *ThreadObject = NULL;
    NextThread = (INJECT_GET_NEXT_THREAD)InjectRoutine(L"ZwGetNextThread");
    Win32 = (INJECT_WIN32_THREAD)InjectRoutine(L"PsGetThreadWin32Thread");
    if (NextThread == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }

    Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode,
                                   &ProcessHandle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Chosen = NULL;
    for (WantWin32 = TRUE;; WantWin32 = FALSE)
    {
        Seen = 0;
        Previous = NULL;
        while (Seen < 256 &&
               NT_SUCCESS(NextThread(ProcessHandle, Previous, THREAD_ALL_ACCESS, OBJ_KERNEL_HANDLE, 0, &Chosen)))
        {
            if (Previous != NULL)
            {
                ZwClose(Previous);
            }

            Previous = Chosen;
            Seen++;
            if (!NT_SUCCESS(ObReferenceObjectByHandle(Chosen, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
                                                      (PVOID*)&Thread, NULL)))
            {
                Chosen = NULL;
                continue;
            }

            if (WantWin32 != FALSE && (Win32 == NULL || Win32(Thread) == NULL))
            {
                ObDereferenceObject(Thread);
                Chosen = NULL;
                continue;
            }

            PreviousSuspend = 0;
            Status = ZwSuspendThread(Chosen, &PreviousSuspend);
            if (!NT_SUCCESS(Status) || PreviousSuspend != 0)
            {
                if (NT_SUCCESS(Status))
                {
                    ZwResumeThread(Chosen, &PreviousSuspend);
                }

                ObDereferenceObject(Thread);
                Chosen = NULL;
                continue;
            }

            *ThreadHandle = Chosen;
            *ThreadObject = Thread;
            ZwClose(ProcessHandle);
            return STATUS_SUCCESS;
        }

        if (Previous != NULL)
        {
            ZwClose(Previous);
        }

        if (WantWin32 == FALSE)
        {
            break;
        }
    }

    ZwClose(ProcessHandle);
    return STATUS_NOT_FOUND;
}

C_ASSERT(sizeof(CONTEXT) <= 0x800);
C_ASSERT(FIELD_OFFSET(INJECT_LOAD_RESULT, LastError) == 4);
C_ASSERT(FIELD_OFFSET(INJECT_LOAD_RESULT, Module) == 8);

static NTSTATUS
InjectCreateLoadThread(
    _In_ PEPROCESS Process,
    _In_ PVOID LoadLibrary,
    _In_ PVOID RemotePath,
    _Out_ HANDLE* ThreadHandle,
    _Out_ CLIENT_ID* ClientId
    )
{
    INJECT_CREATE_THREAD Create;
    INJECT_DUPLICATE Duplicate;
    HANDLE ProcessHandle;
    HANDLE LocalThread;
    KAPC_STATE State;
    NTSTATUS Status;
    NTSTATUS DupStatus;

    *ThreadHandle = NULL;
    RtlZeroMemory(ClientId, sizeof(*ClientId));
    Create = (INJECT_CREATE_THREAD)InjectRoutine(L"RtlCreateUserThread");
    Duplicate = (INJECT_DUPLICATE)InjectRoutine(L"ZwDuplicateObject");
    if (Create == NULL || LoadLibrary == NULL || RemotePath == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }

    Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode,
                                   &ProcessHandle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // The IOCTL arrives from user mode. RtlCreateUserThread probes the start
    // address and the path in the current process, so this call is attached.
    //
    LocalThread = NULL;
    KeStackAttachProcess(Process, &State);
    //
    // The service reads the user PEB with the caller's AC flag. SMAP turns a
    // clear AC flag into a protection fault and bugcheck 0x50.
    //
    if ((__readcr4() & (1ull << 21)) != 0)
    {
        _stac();
    }

    __try
    {
        Status = Create(ZwCurrentProcess(), NULL, FALSE, 0, INJECT_STACK_BYTES, PAGE_SIZE, LoadLibrary, RemotePath,
                        &LocalThread, ClientId);
    }
    __finally
    {
        if ((__readcr4() & (1ull << 21)) != 0)
        {
            _clac();
        }
    }

    if (NT_SUCCESS(Status) && LocalThread != NULL && Duplicate != NULL)
    {
        DupStatus = Duplicate(ZwCurrentProcess(), LocalThread, ZwCurrentProcess(), ThreadHandle, 0, OBJ_KERNEL_HANDLE,
                              INJECT_DUPLICATE_SAME);
        if (!NT_SUCCESS(DupStatus) || *ThreadHandle == NULL || (LONG_PTR)*ThreadHandle >= 0)
        {
            if (*ThreadHandle != NULL && (LONG_PTR)*ThreadHandle >= 0)
            {
                ZwClose(*ThreadHandle);
            }

            *ThreadHandle = NULL;
            HACDBG_LOG("HacDbg: Err, DLL inject thread handle status=0x%08x.\n", DupStatus);
        }
    }

    if (LocalThread != NULL)
    {
        ZwClose(LocalThread);
    }

    KeUnstackDetachProcess(&State);
    ZwClose(ProcessHandle);
    HACDBG_LOG("HacDbg: DLL inject thread status=0x%08x tid=%llu start=0x%p.\n", Status,
               (UINT64)(ULONG_PTR)ClientId->UniqueThread, LoadLibrary);
    return Status;
}

static VOID
InjectThreadRip(
    _In_ HANDLE ThreadHandle,
    _Out_ UINT64* Rip
    )
{
    INJECT_CONTEXT_THREAD GetContext;
    PETHREAD Thread;
    CONTEXT* Captured;
    ULONG Previous;
    NTSTATUS Status;

    *Rip = 0;
    GetContext = (INJECT_CONTEXT_THREAD)InjectRoutine(L"PsGetContextThread");
    if (GetContext == NULL || ThreadHandle == NULL)
    {
        return;
    }

    Previous = 0;
    Status = ZwSuspendThread(ThreadHandle, &Previous);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject suspend load thread status=0x%08x.\n", Status);
        return;
    }

    Captured = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), INJECT_TAG);
    if (Captured == NULL)
    {
        ZwResumeThread(ThreadHandle, &Previous);
        return;
    }

    RtlZeroMemory(Captured, sizeof(CONTEXT));
    Captured->ContextFlags = CONTEXT_CONTROL;
    Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL);
    if (NT_SUCCESS(Status))
    {
        //
        // KernelMode skips the user probe. UserMode treats this pool buffer as a
        // user address and returns STATUS_ACCESS_VIOLATION.
        //
        Status = GetContext(Thread, Captured, KernelMode);
        if (NT_SUCCESS(Status))
        {
            *Rip = Captured->Rip;
        }

        ObDereferenceObject(Thread);
    }

    ZwResumeThread(ThreadHandle, &Previous);
    ExFreePool(Captured);
}

static VOID
InjectLogThread(
    _In_ PEPROCESS Process,
    _In_ HANDLE ThreadHandle
    )
{
    INJECT_QUERY_THREAD Query;
    INJECT_THREAD_BASIC Info;
    NTSTATUS Status;
    ULONG Error;
    UINT64 Rip;

    Query = (INJECT_QUERY_THREAD)InjectRoutine(L"ZwQueryInformationThread");
    if (Query == NULL || ThreadHandle == NULL)
    {
        return;
    }

    RtlZeroMemory(&Info, sizeof(Info));
    Status = Query(ThreadHandle, 0, &Info, sizeof(Info), NULL);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject thread query status=0x%08x.\n", Status);
        return;
    }

    Error = 0xFFFFFFFFu;
    if (Info.ExitStatus == STATUS_PENDING)
    {
        Error = InjectTebError(Process, Info.TebBaseAddress);
    }

    Rip = 0;
    InjectThreadRip(ThreadHandle, &Rip);
    HACDBG_LOG("HacDbg: DLL inject thread exit=0x%08x teb=0x%p last=%lu rip=0x%I64x.\n", Info.ExitStatus,
               Info.TebBaseAddress, Error, Rip);
}

static BOOLEAN
InjectStartsWith(
    _In_ const WCHAR* Text,
    _In_ const WCHAR* Prefix
    )
{
    WCHAR Left;
    WCHAR Right;

    while (*Prefix != 0)
    {
        Left = *Text;
        Right = *Prefix;
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

        Text++;
        Prefix++;
    }

    return TRUE;
}

static VOID
InjectNormalizePath(
    _In_ const WCHAR* Path,
    _Out_writes_(INJECT_PATH_CHARS) WCHAR* Dos
    )
{
    const WCHAR* Cursor;
    SIZE_T Out;
    WCHAR Character;

    Dos[0] = 0;
    if (Path == NULL)
    {
        return;
    }

    Cursor = Path;
    while (*Cursor == L' ' || *Cursor == L'"')
    {
        Cursor++;
    }

    if (InjectStartsWith(Cursor, L"\\\\?\\unc\\") != FALSE)
    {
        Cursor += 8;
        Dos[0] = L'\\';
        Dos[1] = L'\\';
        Out = 2;
    }
    else
    {
        if (InjectStartsWith(Cursor, L"\\\\?\\") != FALSE || InjectStartsWith(Cursor, L"\\\\.\\") != FALSE)
        {
            Cursor += 4;
        }
        else if (InjectStartsWith(Cursor, L"\\??\\") != FALSE)
        {
            Cursor += 4;
        }
        else if (InjectStartsWith(Cursor, L"\\global??\\") != FALSE)
        {
            Cursor += 10;
        }

        Out = 0;
    }

    for (; *Cursor != 0 && Out + 1 < INJECT_PATH_CHARS; Cursor++)
    {
        Character = *Cursor;
        if (Character == L'"')
        {
            continue;
        }

        if (Character == L'/')
        {
            Character = L'\\';
        }

        Dos[Out] = Character;
        Out++;
    }

    while (Out > 0 && Dos[Out - 1] == L' ')
    {
        Out--;
    }

    Dos[Out] = 0;
}

static NTSTATUS
InjectHijackLoad(
    _In_ PEPROCESS Process,
    _In_ PVOID LoadLibrary,
    _In_ PVOID RemotePath,
    _In_ const CHAR* Narrow,
    _Out_ ULONG* Win32Error,
    _Out_ UINT64* Loaded
    )
{
    INJECT_CONTEXT_THREAD GetContext;
    INJECT_CONTEXT_THREAD SetContext;
    HANDLE ThreadHandle;
    PETHREAD Thread;
    CONTEXT* Captured;
    UCHAR Stub[96];
    PVOID StubPage;
    PVOID DataPage;
    PVOID StackPage;
    UINT64 StubVa;
    UINT64 DataVa;
    UINT64 StackVa;
    UINT64 NtContinue;
    UINT64 Ntdll;
    ULONG SyscallNumber;
    ULONG PreviousSuspend;
    ULONG Index;
    NTSTATUS Status;
    CONTEXT Run;
    UINT64 Rsp;
    UINT64 ReturnAddress;
    INJECT_LOAD_RESULT Result;
    LARGE_INTEGER Delay;

    *Win32Error = 0;
    *Loaded = 0;
    PreviousSuspend = 0;
    Rsp = 0;
    ReturnAddress = 0;
    GetContext = (INJECT_CONTEXT_THREAD)InjectRoutine(L"PsGetContextThread");
    SetContext = (INJECT_CONTEXT_THREAD)InjectRoutine(L"PsSetContextThread");
    if (GetContext == NULL || SetContext == NULL || LoadLibrary == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }

    Ntdll = InjectModuleBase(Process, "ntdll.dll");
    NtContinue = InjectResolve(Process, Ntdll, "NtContinue", 0);
    SyscallNumber = InjectSyscallNumber(Process, NtContinue);
    if (NtContinue == 0)
    {
        HACDBG_LOG("HacDbg: Err, DLL inject found no NtContinue.\n");
        return STATUS_NOT_FOUND;
    }

    Status = InjectAllocUser(Process, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &StubPage);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject stub alloc status=0x%08x.\n", Status);
        return Status;
    }

    Status = InjectAllocUser(Process, PAGE_SIZE, PAGE_READWRITE, &DataPage);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject context alloc status=0x%08x.\n", Status);
        return Status;
    }

    Status = InjectAllocUser(Process, 0x100000, PAGE_READWRITE, &StackPage);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject stack alloc status=0x%08x.\n", Status);
        return Status;
    }

    StubVa = (UINT64)(ULONG_PTR)StubPage;
    DataVa = (UINT64)(ULONG_PTR)DataPage;
    StackVa = (UINT64)(ULONG_PTR)StackPage;
    InjectWriteLoadStub(Stub, DataVa + 0x800, DataVa, NtContinue, SyscallNumber);
    Status = InjectCopyUser(Process, StubPage, Stub, sizeof(Stub));
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = InjectSuspendOne(Process, &ThreadHandle, &Thread);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject found no thread to start LoadLibrary: 0x%08x.\n", Status);
        return Status;
    }

    Captured = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), INJECT_TAG);
    if (Captured == NULL)
    {
        ZwResumeThread(ThreadHandle, &PreviousSuspend);
        ObDereferenceObject(Thread);
        ZwClose(ThreadHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Captured, sizeof(CONTEXT));
    Captured->ContextFlags = CONTEXT_FULL;
    Status = GetContext(Thread, Captured, KernelMode);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject get context status=0x%08x tid=%llu.\n", Status,
                   (UINT64)(ULONG_PTR)PsGetThreadId(Thread));
        ZwResumeThread(ThreadHandle, &PreviousSuspend);
        ObDereferenceObject(Thread);
        ZwClose(ThreadHandle);
        ExFreePool(Captured);
        return Status;
    }

    Status = InjectCopyUser(Process, (PVOID)DataVa, Captured, sizeof(CONTEXT));
    if (NT_SUCCESS(Status))
    {
        Rsp = (StackVa + 0x100000 - 0x1000) & ~0xFull;
        Rsp -= 8;
        ReturnAddress = StubVa;
        Status = InjectCopyUser(Process, (PVOID)Rsp, &ReturnAddress, sizeof(ReturnAddress));
    }

    if (NT_SUCCESS(Status))
    {
        Run = *Captured;
        Run.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        Run.Rip = (DWORD64)(ULONG_PTR)LoadLibrary;
        Run.Rcx = (DWORD64)(ULONG_PTR)RemotePath;
        Run.Rsp = Rsp;
        Status = SetContext(Thread, &Run, KernelMode);
        if (!NT_SUCCESS(Status))
        {
            Run.ContextFlags = CONTEXT_FULL;
            Status = SetContext(Thread, &Run, KernelMode);
        }
    }

    HACDBG_LOG("HacDbg: DLL inject hijack tid=%llu status=0x%08x oldrip=0x%I64x library=0x%p syscall=0x%x.\n",
               (UINT64)(ULONG_PTR)PsGetThreadId(Thread), Status, Captured->Rip, LoadLibrary, SyscallNumber);
    ZwResumeThread(ThreadHandle, &PreviousSuspend);
    ObDereferenceObject(Thread);
    ZwClose(ThreadHandle);
    ExFreePool(Captured);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Delay.QuadPart = -1000000;
    for (Index = 0; Index < 30; Index++)
    {
        if (InjectModuleBase(Process, Narrow) != 0)
        {
            *Loaded = 1;
            return STATUS_SUCCESS;
        }

        RtlZeroMemory(&Result, sizeof(Result));
        if (NT_SUCCESS(InjectReadUser(Process, (PVOID)(DataVa + 0x800), &Result, sizeof(Result))) && Result.Ran != 0)
        {
            *Win32Error = Result.LastError;
            *Loaded = Result.Module;
            HACDBG_LOG("HacDbg: DLL inject LoadLibrary module=0x%I64x win32=%lu.\n", Result.Module, Result.LastError);
            return Result.Module != 0 ? STATUS_SUCCESS : STATUS_DLL_NOT_FOUND;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    HACDBG_LOG("HacDbg: Err, DLL inject hijack timed out.\n");
    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
InjectWin32Status(
    _In_ ULONG Error
    )
{
    if (Error == INJECT_ERROR_FILE_NOT_FOUND || Error == INJECT_ERROR_PATH_NOT_FOUND)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (Error == INJECT_ERROR_MOD_NOT_FOUND || Error == INJECT_ERROR_PROC_NOT_FOUND)
    {
        return STATUS_DLL_NOT_FOUND;
    }

    if (Error == INJECT_ERROR_BAD_EXE_FORMAT)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (Error == INJECT_ERROR_ACCESS_DENIED)
    {
        return STATUS_ACCESS_DENIED;
    }

    if (Error == INJECT_ERROR_DLL_INIT_FAILED)
    {
        return STATUS_DLL_INIT_FAILED;
    }

    if (Error == INJECT_ERROR_INVALID_PARAMETER)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
InjectCallLoadLibrary(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* PathOrName,
    _In_ BOOLEAN WaitForLoad
    )
{
    UINT64 Kernel32;
    UINT64 LoadLibrary;
    PVOID Remote;
    SIZE_T Bytes;
    CHAR Narrow[INJECT_NAME_CHARS];
    WCHAR Dos[INJECT_PATH_CHARS];
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    INJECT_QUERY_THREAD Query;
    INJECT_THREAD_BASIC Info;
    NTSTATUS Status;
    NTSTATUS CreateStatus;
    ULONG Win32Error;
    UINT64 Loaded;
    const WCHAR* Used;

    InjectLogWide("path", PathOrName);
    InjectNormalizePath(PathOrName, Dos);
    Used = Dos[0] != 0 ? Dos : PathOrName;
    if (Used != PathOrName)
    {
        InjectLogWide("normalized", Used);
    }

    Kernel32 = InjectModuleBase(Process, "kernel32.dll");
    LoadLibrary = InjectResolve(Process, Kernel32, "LoadLibraryW", 0);
    if (LoadLibrary == 0)
    {
        HACDBG_LOG("HacDbg: Err, DLL inject found no LoadLibraryW.\n");
        return STATUS_NOT_FOUND;
    }

    HACDBG_LOG("HacDbg: DLL inject LoadLibraryW=0x%I64x pid=%llu.\n", LoadLibrary,
               (UINT64)(ULONG_PTR)PsGetProcessId(Process));
    Bytes = (wcslen(Used) + 1) * sizeof(WCHAR);
    Status = InjectAllocUser(Process, Bytes, PAGE_READWRITE, &Remote);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject path alloc status=0x%08x.\n", Status);
        return Status;
    }

    Status = InjectCopyUser(Process, Remote, Used, Bytes);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject path copy status=0x%08x.\n", Status);
        return Status;
    }

    InjectFileName(Used, Narrow);
    ThreadHandle = NULL;
    RtlZeroMemory(&ClientId, sizeof(ClientId));
    CreateStatus = InjectCreateLoadThread(Process, (PVOID)LoadLibrary, Remote, &ThreadHandle, &ClientId);
    if (WaitForLoad == FALSE)
    {
        if (ThreadHandle != NULL)
        {
            ZwClose(ThreadHandle);
        }

        return CreateStatus;
    }

    if (NT_SUCCESS(CreateStatus) && InjectWaitModule(Process, Narrow, 8) != FALSE)
    {
        if (ThreadHandle != NULL)
        {
            ZwClose(ThreadHandle);
        }

        return STATUS_SUCCESS;
    }

    if (ThreadHandle != NULL)
    {
        InjectLogThread(Process, ThreadHandle);
        Query = (INJECT_QUERY_THREAD)InjectRoutine(L"ZwQueryInformationThread");
        RtlZeroMemory(&Info, sizeof(Info));
        if (Query != NULL && NT_SUCCESS(Query(ThreadHandle, 0, &Info, sizeof(Info), NULL)))
        {
            if (Info.ExitStatus == STATUS_PENDING)
            {
                ULONG Previous;

                Previous = 0;
                ZwResumeThread(ThreadHandle, &Previous);
                HACDBG_LOG("HacDbg: DLL inject resume previous=%lu.\n", Previous);
                if (InjectWaitModule(Process, Narrow, 15) != FALSE)
                {
                    ZwClose(ThreadHandle);
                    return STATUS_SUCCESS;
                }

                HACDBG_LOG("HacDbg: Err, DLL inject load thread still running tid=%llu.\n",
                           (UINT64)(ULONG_PTR)ClientId.UniqueThread);
                ZwClose(ThreadHandle);
                return STATUS_UNSUCCESSFUL;
            }

            if ((ULONG)Info.ExitStatus >= 0xC0000000)
            {
                HACDBG_LOG("HacDbg: Err, DLL inject load thread failed: 0x%08x.\n", Info.ExitStatus);
                ZwClose(ThreadHandle);
                return Info.ExitStatus;
            }
        }

        ZwClose(ThreadHandle);
    }

    Win32Error = 0;
    Loaded = 0;
    Status = InjectHijackLoad(Process, (PVOID)LoadLibrary, Remote, Narrow, &Win32Error, &Loaded);
    if (Loaded != 0 || InjectModuleBase(Process, Narrow) != 0)
    {
        return STATUS_SUCCESS;
    }

    HACDBG_LOG("HacDbg: Err, DLL inject did not load %s win32=%lu status=0x%08x.\n", Narrow, Win32Error, Status);
    if (Win32Error != 0)
    {
        return InjectWin32Status(Win32Error);
    }

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return NT_SUCCESS(CreateStatus) ? STATUS_DLL_NOT_FOUND : CreateStatus;
}

static NTSTATUS
InjectCreateDataFile(
    _In_ const WCHAR* NtPath,
    _Out_ HANDLE* File
    )
{
    UNICODE_STRING Unicode;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;

    *File = NULL;
    RtlInitUnicodeString(&Unicode, NtPath);
    InitializeObjectAttributes(&Attributes, &Unicode, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(File, FILE_GENERIC_READ, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        InjectLogWide("open failed", NtPath);
        HACDBG_LOG("HacDbg: Err, DLL inject open status=0x%08x.\n", Status);
        *File = NULL;
    }

    return Status;
}

static BOOLEAN
InjectBuildNt(
    _Out_writes_(INJECT_NT_CHARS) WCHAR* Out,
    _In_ const WCHAR* Prefix,
    _In_ const WCHAR* Rest
    )
{
    SIZE_T PrefixChars;
    SIZE_T RestChars;

    PrefixChars = wcslen(Prefix);
    RestChars = wcslen(Rest);
    if (PrefixChars + RestChars + 1 > INJECT_NT_CHARS)
    {
        return FALSE;
    }

    RtlCopyMemory(Out, Prefix, PrefixChars * sizeof(WCHAR));
    RtlCopyMemory(Out + PrefixChars, Rest, (RestChars + 1) * sizeof(WCHAR));
    return TRUE;
}

static NTSTATUS
InjectOpenVolume(
    _In_ const WCHAR* Dos,
    _Out_ HANDLE* File
    )
{
    WCHAR LinkName[16];
    WCHAR TargetBuffer[160];
    WCHAR Combined[INJECT_NT_CHARS];
    UNICODE_STRING Link;
    UNICODE_STRING Target;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE LinkHandle;
    NTSTATUS Status;
    SIZE_T TargetChars;
    SIZE_T RestChars;

    *File = NULL;
    if (Dos[0] == 0 || Dos[1] != L':' || Dos[2] != L'\\')
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    RtlCopyMemory(LinkName, L"\\GLOBAL??\\", 10 * sizeof(WCHAR));
    LinkName[10] = Dos[0];
    LinkName[11] = L':';
    LinkName[12] = 0;
    RtlInitUnicodeString(&Link, LinkName);
    InitializeObjectAttributes(&Attributes, &Link, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenSymbolicLinkObject(&LinkHandle, INJECT_LINK_QUERY, &Attributes);
    if (!NT_SUCCESS(Status))
    {
        InjectLogWide("volume link", LinkName);
        HACDBG_LOG("HacDbg: Err, DLL inject volume link status=0x%08x.\n", Status);
        return Status;
    }

    Target.Buffer = TargetBuffer;
    Target.Length = 0;
    Target.MaximumLength = sizeof(TargetBuffer);
    Status = ZwQuerySymbolicLinkObject(LinkHandle, &Target, NULL);
    ZwClose(LinkHandle);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject volume target status=0x%08x.\n", Status);
        return Status;
    }

    TargetChars = Target.Length / sizeof(WCHAR);
    if (TargetChars >= sizeof(TargetBuffer) / sizeof(TargetBuffer[0]))
    {
        TargetChars = sizeof(TargetBuffer) / sizeof(TargetBuffer[0]) - 1;
    }

    TargetBuffer[TargetChars] = 0;
    RestChars = wcslen(Dos + 2);
    if (TargetChars + RestChars + 1 > INJECT_NT_CHARS)
    {
        return STATUS_NAME_TOO_LONG;
    }

    RtlCopyMemory(Combined, TargetBuffer, TargetChars * sizeof(WCHAR));
    RtlCopyMemory(Combined + TargetChars, Dos + 2, (RestChars + 1) * sizeof(WCHAR));
    return InjectCreateDataFile(Combined, File);
}

static NTSTATUS
InjectOpenDos(
    _In_ const WCHAR* Dos,
    _Out_ HANDLE* File
    )
{
    WCHAR Nt[INJECT_NT_CHARS];
    NTSTATUS Status;
    ULONG Index;
    const WCHAR* Prefixes[3];

    *File = NULL;
    if (Dos[0] == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    if (Dos[1] == L':')
    {
        Prefixes[0] = L"\\GLOBAL??\\";
        Prefixes[1] = L"\\??\\";
        Prefixes[2] = L"\\DosDevices\\";
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        for (Index = 0; Index < 3; Index++)
        {
            if (InjectBuildNt(Nt, Prefixes[Index], Dos) == FALSE)
            {
                return STATUS_NAME_TOO_LONG;
            }

            Status = InjectCreateDataFile(Nt, File);
            if (NT_SUCCESS(Status))
            {
                InjectLogWide("opened", Nt);
                return Status;
            }
        }

        return InjectOpenVolume(Dos, File);
    }

    if (Dos[0] == L'\\' && Dos[1] == L'\\')
    {
        if (InjectBuildNt(Nt, L"\\GLOBAL??\\UNC\\", Dos + 2) == FALSE)
        {
            return STATUS_NAME_TOO_LONG;
        }

        return InjectCreateDataFile(Nt, File);
    }

    return InjectCreateDataFile(Dos, File);
}

static NTSTATUS
InjectReadFile(
    _In_ const WCHAR* Path,
    _Out_ UCHAR** Buffer,
    _Out_ ULONG* Length
    )
{
    IO_STATUS_BLOCK Io;
    HANDLE File;
    FILE_STANDARD_INFORMATION Info;
    NTSTATUS Status;
    LARGE_INTEGER Offset;
    WCHAR Dos[INJECT_PATH_CHARS];

    InjectLogWide("file", Path);
    InjectNormalizePath(Path, Dos);
    if (Dos[0] == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    if (wcscmp(Dos, Path) != 0)
    {
        InjectLogWide("file normalized", Dos);
    }

    Status = InjectOpenDos(Dos, &File);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ZwQueryInformationFile(File, &Io, &Info, sizeof(Info), FileStandardInformation);
    if (!NT_SUCCESS(Status) || Info.EndOfFile.QuadPart <= 0 || Info.EndOfFile.QuadPart > INJECT_MAX_IMAGE)
    {
        ZwClose(File);
        return NT_SUCCESS(Status) ? STATUS_FILE_TOO_LARGE : Status;
    }

    *Length = (ULONG)Info.EndOfFile.QuadPart;
    *Buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, *Length, INJECT_TAG);
    if (*Buffer == NULL)
    {
        ZwClose(File);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Offset.QuadPart = 0;
    Status = ZwReadFile(File, NULL, NULL, NULL, &Io, *Buffer, *Length, &Offset, NULL);
    ZwClose(File);
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(*Buffer);
        *Buffer = NULL;
    }

    return Status;
}

static BOOLEAN
InjectJoinPath(
    _In_ const WCHAR* FilePath,
    _In_ const CHAR* DllName,
    _Out_writes_(520) WCHAR* Combined
    )
{
    SIZE_T Index;
    SIZE_T Slash;
    ULONG Name;

    Slash = 0;
    for (Index = 0; FilePath[Index] != L'\0' && Index < 480; Index++)
    {
        if (FilePath[Index] == L'\\' || FilePath[Index] == L'/')
        {
            Slash = Index;
        }
    }

    if (Slash == 0 || Slash >= 480)
    {
        return FALSE;
    }

    RtlCopyMemory(Combined, FilePath, Slash * sizeof(WCHAR));
    Combined[Slash] = L'\\';
    for (Name = 0; DllName[Name] != 0 && Slash + 1 + Name < 518; Name++)
    {
        Combined[Slash + 1 + Name] = (WCHAR)DllName[Name];
    }

    Combined[Slash + 1 + Name] = L'\0';
    return Name > 0 && DllName[Name] == 0;
}

static NTSTATUS
InjectEnsureModule(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* PayloadPath,
    _In_ const CHAR* DllName,
    _Out_ UINT64* ModuleBase
    )
{
    WCHAR Wide[96];
    WCHAR Combined[520];
    ULONG Index;
    NTSTATUS Status;

    *ModuleBase = InjectModuleBase(Process, DllName);
    if (*ModuleBase != 0)
    {
        return STATUS_SUCCESS;
    }

    for (Index = 0; DllName[Index] != 0 && Index < 90; Index++)
    {
        Wide[Index] = (WCHAR)DllName[Index];
    }

    Wide[Index] = L'\0';
    Status = InjectCallLoadLibrary(Process, Wide, TRUE);
    *ModuleBase = InjectModuleBase(Process, DllName);
    if (*ModuleBase != 0)
    {
        return STATUS_SUCCESS;
    }

    if (InjectJoinPath(PayloadPath, DllName, Combined) == FALSE)
    {
        return NT_SUCCESS(Status) ? STATUS_DLL_NOT_FOUND : Status;
    }

    Status = InjectCallLoadLibrary(Process, Combined, TRUE);
    *ModuleBase = InjectModuleBase(Process, DllName);
    return *ModuleBase != 0 ? STATUS_SUCCESS : (NT_SUCCESS(Status) ? STATUS_DLL_NOT_FOUND : Status);
}

static UINT64
InjectResolveOrdinal(
    _In_ PEPROCESS Process,
    _In_ UINT64 ModuleBase,
    _In_ USHORT Ordinal
    )
{
    KAPC_STATE State;
    UINT64 Address;
    BOOLEAN Opened;

    Address = 0;
    KeStackAttachProcess(Process, &State);
    Opened = InjectAllowUser();
    __try
    {
        PUCHAR Base = (PUCHAR)ModuleBase;
        IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)Base;
        IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)(Base + Dos->e_lfanew);
        IMAGE_EXPORT_DIRECTORY* Export;
        ULONG* Functions;
        ULONG Directory;
        ULONG FunctionRva;

        Directory = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        Export = (IMAGE_EXPORT_DIRECTORY*)(Base + Directory);
        if (Ordinal >= Export->Base && Ordinal - Export->Base < Export->NumberOfFunctions)
        {
            Functions = (ULONG*)(Base + Export->AddressOfFunctions);
            FunctionRva = Functions[Ordinal - Export->Base];
            if (FunctionRva != 0)
            {
                Address = ModuleBase + FunctionRva;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Address = 0;
    }

    InjectEndUser(Opened);
    KeUnstackDetachProcess(&State);
    return Address;
}

static NTSTATUS
InjectResolveImports(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* PayloadPath,
    _Inout_ UCHAR* Image,
    _In_ ULONG ImageSize
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_IMPORT_DESCRIPTOR* Descriptor;
    ULONG ImportRva;

    Dos = (IMAGE_DOS_HEADER*)Image;
    Nt = (IMAGE_NT_HEADERS64*)(Image + Dos->e_lfanew);
    ImportRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ImportRva == 0)
    {
        return STATUS_SUCCESS;
    }

    if (ImportRva >= ImageSize)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(Image + ImportRva);
    while (Descriptor->Name != 0)
    {
        IMAGE_THUNK_DATA64* Lookup;
        IMAGE_THUNK_DATA64* Iat;
        CHAR DllName[96];
        UINT64 ModuleBase;
        NTSTATUS Status;
        ULONG NameIndex;

        if (Descriptor->Name >= ImageSize)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        for (NameIndex = 0; NameIndex < sizeof(DllName) - 1; NameIndex++)
        {
            DllName[NameIndex] = (CHAR)Image[Descriptor->Name + NameIndex];
            if (DllName[NameIndex] == 0)
            {
                break;
            }
        }

        DllName[NameIndex] = 0;
        if (NameIndex == 0 || Image[Descriptor->Name + NameIndex] != 0)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        for (NameIndex = 0; DllName[NameIndex] != 0; NameIndex++)
        {
            if (DllName[NameIndex] >= 'A' && DllName[NameIndex] <= 'Z')
            {
                DllName[NameIndex] = (CHAR)(DllName[NameIndex] - 'A' + 'a');
            }
        }

        Status = InjectEnsureModule(Process, PayloadPath, DllName, &ModuleBase);
        if (!NT_SUCCESS(Status))
        {
            HACDBG_LOG("HacDbg: Err, DLL inject missing import %s: 0x%08x.\n", DllName, Status);
            return Status;
        }

        Lookup = (IMAGE_THUNK_DATA64*)(Image + (Descriptor->OriginalFirstThunk != 0 ? Descriptor->OriginalFirstThunk
                                                                                    : Descriptor->FirstThunk));
        Iat = (IMAGE_THUNK_DATA64*)(Image + Descriptor->FirstThunk);
        if (Descriptor->FirstThunk >= ImageSize)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        while (Lookup->u1.AddressOfData != 0)
        {
            UINT64 Function;

            if (IMAGE_SNAP_BY_ORDINAL64(Lookup->u1.Ordinal) != FALSE)
            {
                Function = InjectResolveOrdinal(Process, ModuleBase, (USHORT)IMAGE_ORDINAL64(Lookup->u1.Ordinal));
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* ImportName;
                ULONG HintRva;

                HintRva = (ULONG)Lookup->u1.AddressOfData;
                if (HintRva >= ImageSize || HintRva + sizeof(IMAGE_IMPORT_BY_NAME) >= ImageSize)
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }

                ImportName = (IMAGE_IMPORT_BY_NAME*)(Image + HintRva);
                Function = InjectResolve(Process, ModuleBase, (CHAR*)ImportName->Name, 0);
            }

            if (Function == 0)
            {
                HACDBG_LOG("HacDbg: Err, DLL inject unresolved import from %s.\n", DllName);
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            Iat->u1.Function = Function;
            Lookup++;
            Iat++;
        }

        Descriptor++;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
InjectApplyRelocs(
    _Inout_ UCHAR* Image,
    _In_ ULONG ImageSize,
    _In_ LONGLONG Delta
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_BASE_RELOCATION* Block;
    ULONG RelocRva;
    ULONG RelocSize;
    ULONG Offset;

    if (Delta == 0)
    {
        return STATUS_SUCCESS;
    }

    Dos = (IMAGE_DOS_HEADER*)Image;
    Nt = (IMAGE_NT_HEADERS64*)(Image + Dos->e_lfanew);
    RelocRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    RelocSize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (RelocRva == 0 || RelocSize < sizeof(IMAGE_BASE_RELOCATION))
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    Offset = 0;
    while (Offset + sizeof(IMAGE_BASE_RELOCATION) <= RelocSize)
    {
        ULONG Count;
        ULONG Index;
        USHORT* Entry;

        if (RelocRva + Offset >= ImageSize)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Block = (IMAGE_BASE_RELOCATION*)(Image + RelocRva + Offset);
        if (Block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || Offset + Block->SizeOfBlock > RelocSize)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Count = (Block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        Entry = (USHORT*)(Block + 1);
        for (Index = 0; Index < Count; Index++)
        {
            ULONG Type = Entry[Index] >> 12;
            ULONG Target = Block->VirtualAddress + (Entry[Index] & 0xFFFu);

            if (Type == IMAGE_REL_BASED_ABSOLUTE)
            {
                continue;
            }

            if (Type == IMAGE_REL_BASED_DIR64)
            {
                if (Target + sizeof(UINT64) > ImageSize)
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }

                *(UINT64*)(Image + Target) += (UINT64)Delta;
                continue;
            }

            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Offset += Block->SizeOfBlock;
    }

    return STATUS_SUCCESS;
}

static VOID
InjectMarkExecute(
    _In_ const UCHAR* Image,
    _In_ ULONG ImagePages,
    _Out_writes_((INJECT_MAX_PAGES + 7) / 8) UCHAR* Bits
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_SECTION_HEADER* Section;
    USHORT Index;

    RtlZeroMemory(Bits, (INJECT_MAX_PAGES + 7) / 8);
    Dos = (IMAGE_DOS_HEADER*)Image;
    Nt = (IMAGE_NT_HEADERS64*)(Image + Dos->e_lfanew);
    Section = IMAGE_FIRST_SECTION(Nt);
    for (Index = 0; Index < Nt->FileHeader.NumberOfSections; Index++)
    {
        ULONG Start;
        ULONG End;
        ULONG Page;

        if ((Section[Index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
        {
            continue;
        }

        Start = Section[Index].VirtualAddress / PAGE_SIZE;
        End = (Section[Index].VirtualAddress + Section[Index].Misc.VirtualSize + PAGE_SIZE - 1) / PAGE_SIZE;
        if (End > ImagePages)
        {
            End = ImagePages;
        }

        for (Page = Start; Page < End; Page++)
        {
            Bits[Page / 8] |= (UCHAR)(1u << (Page % 8));
        }
    }

    if (Nt->OptionalHeader.AddressOfEntryPoint != 0)
    {
        ULONG Page = Nt->OptionalHeader.AddressOfEntryPoint / PAGE_SIZE;
        if (Page < ImagePages)
        {
            Bits[Page / 8] |= (UCHAR)(1u << (Page % 8));
        }
    }
}

static BOOLEAN
InjectBit(
    _In_ const UCHAR* Bits,
    _In_ ULONG Page
    )
{
    return (Bits[Page / 8] & (UCHAR)(1u << (Page % 8))) != 0;
}

static BOOLEAN
InjectPageNonZero(
    _In_ const UCHAR* Page
    )
{
    ULONG Index;

    for (Index = 0; Index < PAGE_SIZE; Index++)
    {
        if (Page[Index] != 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
InjectWriteStub(
    _Out_writes_(64) UCHAR* Stub,
    _In_ UINT64 ImageBase,
    _In_ UINT64 Entry,
    _In_ UINT64 ExitThread
    )
{
    RtlZeroMemory(Stub, 64);
    Stub[0] = 0x48;
    Stub[1] = 0x83;
    Stub[2] = 0xEC;
    Stub[3] = 0x28;
    Stub[4] = 0x48;
    Stub[5] = 0xB9;
    RtlCopyMemory(Stub + 6, &ImageBase, sizeof(ImageBase));
    Stub[14] = 0xBA;
    Stub[15] = 0x01;
    Stub[19] = 0x45;
    Stub[20] = 0x33;
    Stub[21] = 0xC0;
    Stub[22] = 0x48;
    Stub[23] = 0xB8;
    RtlCopyMemory(Stub + 24, &Entry, sizeof(Entry));
    Stub[32] = 0xFF;
    Stub[33] = 0xD0;
    Stub[34] = 0x33;
    Stub[35] = 0xC9;
    Stub[36] = 0x48;
    Stub[37] = 0xB8;
    RtlCopyMemory(Stub + 38, &ExitThread, sizeof(ExitThread));
    Stub[46] = 0xFF;
    Stub[47] = 0xD0;
    Stub[48] = 0xCC;
}

static NTSTATUS
InjectMarkCallTarget(
    _In_ PVOID Address
    )
{
    INJECT_SET_VM SetVm;
    INJECT_MEMORY_RANGE Range;
    INJECT_CFG_TARGET Target;
    INJECT_CFG_INFORMATION Information;
    ULONG Output;

    SetVm = (INJECT_SET_VM)InjectRoutine(L"ZwSetInformationVirtualMemory");
    if (SetVm == NULL || Address == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }

    Range.Address = Address;
    Range.Bytes = PAGE_SIZE;
    Target.Offset = 0;
    Target.Flags = INJECT_CFG_CALL_TARGET_VALID;
    Output = 0;
    RtlZeroMemory(&Information, sizeof(Information));
    Information.NumberOfEntries = 1;
    Information.Output = &Output;
    Information.Targets = &Target;
    return SetVm(ZwCurrentProcess(), INJECT_VM_CFG_CALL_TARGET, 1, &Range, &Information, sizeof(Information));
}

static NTSTATUS
InjectStartEntry(
    _In_ PEPROCESS Process,
    _In_ UINT64 StubVa
    )
{
    INJECT_CREATE_THREAD Create;
    INJECT_QUERY_THREAD Query;
    INJECT_THREAD_BASIC Info;
    KAPC_STATE State;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    PVOID CodePage;
    UINT64 Rip;
    NTSTATUS Status;
    NTSTATUS ExitStatus;
    LARGE_INTEGER Delay;

    Create = (INJECT_CREATE_THREAD)InjectRoutine(L"RtlCreateUserThread");
    Query = (INJECT_QUERY_THREAD)InjectRoutine(L"ZwQueryInformationThread");
    if (Create == NULL || StubVa < 0x10000ull || StubVa > 0x00007FFFFFFFFFFFull)
    {
        return STATUS_NOT_SUPPORTED;
    }

    CodePage = (PVOID)(ULONG_PTR)StubVa;
    ThreadHandle = NULL;
    RtlZeroMemory(&ClientId, sizeof(ClientId));
    Rip = StubVa;
    KeStackAttachProcess(Process, &State);
    //
    // BaseThreadInitThunk checks the start address in the CFG bitmap and
    // fastfails the process with 0xc0000409 when the bit is clear. The stub
    // is the page already written into the target page tables. This call uses
    // the current process and must run while attached. A zero reserve or
    // commit makes RtlCreateUserStack read the process image header. Commit
    // is one page and stays below the reserve.
    //
    Status = InjectMarkCallTarget(CodePage);
    if (!NT_SUCCESS(Status))
    {
        KeUnstackDetachProcess(&State);
        HACDBG_LOG("HacDbg: Err, DLL inject cfg mark status=0x%08x va=0x%I64x.\n", Status, Rip);
        return Status;
    }

    //
    // RtlCreateUserStack reads PEB.MinimumStackCommit with the caller's AC
    // flag. SMAP is enabled, so a clear AC flag bugchecks 0x50 before the
    // new thread exists.
    //
    if ((__readcr4() & (1ull << 21)) != 0)
    {
        _stac();
    }

    __try
    {
        Status = Create(ZwCurrentProcess(), NULL, FALSE, 0, INJECT_STACK_BYTES, PAGE_SIZE, CodePage, NULL,
                        &ThreadHandle, &ClientId);
    }
    __finally
    {
        if ((__readcr4() & (1ull << 21)) != 0)
        {
            _clac();
        }
    }

    if (!NT_SUCCESS(Status))
    {
        KeUnstackDetachProcess(&State);
        HACDBG_LOG("HacDbg: Err, DLL inject start thread status=0x%08x stub=0x%I64x.\n", Status, Rip);
        return Status;
    }

    Delay.QuadPart = -3000000;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    ExitStatus = STATUS_PENDING;
    if (Query != NULL && ThreadHandle != NULL)
    {
        RtlZeroMemory(&Info, sizeof(Info));
        if (NT_SUCCESS(Query(ThreadHandle, 0, &Info, sizeof(Info), NULL)))
        {
            ExitStatus = Info.ExitStatus;
        }
    }

    if (ThreadHandle != NULL)
    {
        ZwClose(ThreadHandle);
    }

    KeUnstackDetachProcess(&State);
    HACDBG_LOG("HacDbg: DLL inject start tid=%llu exit=0x%08x stub=0x%I64x.\n",
               (UINT64)(ULONG_PTR)ClientId.UniqueThread, ExitStatus, Rip);
    if (ExitStatus == STATUS_PENDING || ExitStatus == STATUS_SUCCESS)
    {
        return STATUS_SUCCESS;
    }

    return ExitStatus;
}

static NTSTATUS
InjectMapImage(
    _In_ PEPROCESS Process,
    _In_ const UCHAR* Image,
    _In_ ULONG ImageBytes,
    _In_ UINT64 Base,
    _In_ const UCHAR* ExecuteBits,
    _In_reads_bytes_(64) const UCHAR* Stub,
    _Out_ ULONG* HookCount
    )
{
    INJECT_OWNED* Owned;
    INJECT_EDIT* Edits;
    ULONG Count;
    ULONG EditCount;
    ULONG Pages;
    ULONG Index;
    UINT64 Directory;
    UINT64 UserDirectory;
    NTSTATUS Status;
    BOOLEAN Failed;

    *HookCount = 0;
    Directory = InjectDirectory(Process, INJECT_DIR_TABLE);
    UserDirectory = InjectUsableUserDirectory(Process, Directory);
    if (Directory == 0)
    {
        return STATUS_NOT_FOUND;
    }

    Pages = ImageBytes / PAGE_SIZE;
    Owned = (INJECT_OWNED*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_OWNED) * INJECT_MAX_PAGES, INJECT_TAG);
    Edits = (INJECT_EDIT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_EDIT) * INJECT_MAX_EDITS, INJECT_TAG);
    if (Owned == NULL || Edits == NULL)
    {
        if (Owned != NULL)
        {
            ExFreePool(Owned);
        }

        if (Edits != NULL)
        {
            ExFreePool(Edits);
        }

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Owned, sizeof(INJECT_OWNED) * INJECT_MAX_PAGES);
    Count = 0;
    EditCount = 0;
    Failed = FALSE;
    Status = STATUS_SUCCESS;
    for (Index = 0; Index < Pages + INJECT_EXTRA_PAGES && Failed == FALSE; Index++)
    {
        PVOID RealVirtual;
        PVOID DecoyVirtual;
        UINT64 Real;
        UINT64 Decoy;
        UINT64 Virtual;
        BOOLEAN Execute;
        const UCHAR* Source;

        Virtual = Base + ((UINT64)Index * PAGE_SIZE);
        Real = InjectAllocFrame(&RealVirtual);
        if (Real == 0 || InjectTrack(Owned, &Count, RealVirtual, Real) == FALSE)
        {
            Failed = TRUE;
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Source = NULL;
        Execute = FALSE;
        if (Index < Pages)
        {
            Source = Image + ((SIZE_T)Index * PAGE_SIZE);
            Execute = InjectBit(ExecuteBits, Index) && InjectPageNonZero(Source);
        }
        else if (Index == Pages)
        {
            Source = Stub;
            Execute = TRUE;
        }

        if (Source != NULL)
        {
            RtlCopyMemory(RealVirtual, Source, Index == Pages ? 64 : PAGE_SIZE);
        }

        if (Execute != FALSE)
        {
            Decoy = InjectAllocFrame(&DecoyVirtual);
            if (Decoy == 0 || InjectTrack(Owned, &Count, DecoyVirtual, Decoy) == FALSE)
            {
                if (DecoyVirtual != NULL)
                {
                    MmFreeContiguousMemory(DecoyVirtual);
                }

                Failed = TRUE;
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            {
                ULONG DecoyIndex;

                DecoyIndex = Count - 1;
                if (InjectMapLeaf(Directory, Virtual, Decoy, TRUE, Owned, &Count, Edits, &EditCount) == FALSE ||
                    (UserDirectory != 0 &&
                     InjectMapLeaf(UserDirectory, Virtual, Decoy, TRUE, Owned, &Count, Edits, &EditCount) == FALSE) ||
                    INJECT_ADD_HOOK(HacDbgGuestPhysicalAddress(Decoy), HacDbgGuestPhysicalAddress(Real)) == FALSE)
                {
                    HACDBG_LOG("HacDbg: Err, DLL inject disguise failed va=0x%I64x.\n", Virtual);
                    Failed = TRUE;
                    Status = STATUS_UNSUCCESSFUL;
                    break;
                }

                Owned[DecoyIndex].Hooked = TRUE;
                *HookCount += 1;
            }
        }
        else if (InjectMapLeaf(Directory, Virtual, Real, FALSE, Owned, &Count, Edits, &EditCount) == FALSE ||
                 (UserDirectory != 0 &&
                  InjectMapLeaf(UserDirectory, Virtual, Real, FALSE, Owned, &Count, Edits, &EditCount) == FALSE))
        {
            Failed = TRUE;
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
    }

    if (Failed == FALSE && InjectFlush() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, DLL inject SLAT flush failed.\n");
        Failed = TRUE;
        Status = STATUS_UNSUCCESSFUL;
    }

    if (Failed != FALSE)
    {
        InjectRestoreEdits(Edits, EditCount);
        InjectFreeOwned(Owned, Count);
    }

    ExFreePool(Edits);
    ExFreePool(Owned);
    return Status;
}

NTSTATUS
InjectApc(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path
    )
{
    if (Process == NULL || Path == NULL || Path[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (InjectWow64(Process) != FALSE)
    {
        return STATUS_NOT_SUPPORTED;
    }

    if ((__readcr4() & (1ull << 12)) != 0)
    {
        HACDBG_LOG("HacDbg: Err, DLL inject refused five-level paging.\n");
        return STATUS_NOT_SUPPORTED;
    }

    return InjectCallLoadLibrary(Process, Path, TRUE);
}

static BOOLEAN
InjectLeafEmpty(
    _In_ UINT64 Entry
    )
{
    return (Entry & INJECT_PRESENT) == 0 && (Entry & INJECT_FRAME) == 0 && (Entry & INJECT_PROTOTYPE) == 0 &&
           (Entry & INJECT_TRANSITION) == 0;
}

static ULONG
InjectClassify(
    _In_ UINT64 Directory,
    _In_ UINT64 Virtual
    )
{
    ULONG Depth;
    UINT64 Table;
    UINT64 Entry;

    if (Directory == 0 || Virtual > 0x00007FFFFFFFFFFFull)
    {
        return 2;
    }

    Table = Directory;
    for (Depth = 0; Depth < 4; Depth++)
    {
        ULONG Shift = 39 - (Depth * 9);
        ULONG Index = (ULONG)((Virtual >> Shift) & 0x1FFu);

        if (InjectReadEntry(Table, Index, &Entry) == FALSE)
        {
            return 2;
        }

        if (Depth == 3)
        {
            return InjectLeafEmpty(Entry) ? 0 : 2;
        }

        if ((Entry & INJECT_PRESENT) == 0)
        {
            return 1;
        }

        if ((Entry & INJECT_LARGE) != 0)
        {
            return 2;
        }

        Table = Entry & INJECT_FRAME;
        if (Table == 0)
        {
            return 2;
        }
    }

    return 2;
}

static BOOLEAN
InjectRangeUsable(
    _In_ UINT64 Directory,
    _In_ UINT64 UserDirectory,
    _In_ UINT64 Base,
    _In_ ULONG Pages,
    _In_ BOOLEAN RequireTable
    )
{
    ULONG Index;

    for (Index = 0; Index < Pages; Index++)
    {
        UINT64 Virtual = Base + ((UINT64)Index * PAGE_SIZE);
        ULONG Kernel = InjectClassify(Directory, Virtual);
        ULONG User = UserDirectory == 0 ? 1 : InjectClassify(UserDirectory, Virtual);

        if (Kernel == 2 || User == 2)
        {
            return FALSE;
        }

        if (RequireTable != FALSE && Kernel != 0)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
InjectSectionName(
    _In_ const UCHAR* Name,
    _In_ const CHAR* Text
    )
{
    ULONG Index;

    for (Index = 0; Text[Index] != 0; Index++)
    {
        if (Index >= IMAGE_SIZEOF_SHORT_NAME || Name[Index] != (UCHAR)Text[Index])
        {
            return FALSE;
        }
    }

    return TRUE;
}

static UINT64
InjectHoleInSection(
    _In_ UINT64 Directory,
    _In_ UINT64 UserDirectory,
    _In_ UINT64 SectionBase,
    _In_ UINT64 SectionBytes,
    _In_ ULONG Pages
    )
{
    UINT64 Page;
    UINT64 Last;
    UINT64 RunBase;
    ULONG Run;

    if (SectionBytes < PAGE_SIZE || SectionBase > 0x00007FFFFFFFFFFFull)
    {
        return 0;
    }

    Page = (SectionBase + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ull);
    Last = (SectionBase + SectionBytes) & ~(PAGE_SIZE - 1ull);
    Run = 0;
    RunBase = 0;
    for (; Page + PAGE_SIZE <= Last; Page += PAGE_SIZE)
    {
        if (InjectRangeUsable(Directory, UserDirectory, Page, 1, TRUE) != FALSE)
        {
            if (Run == 0)
            {
                RunBase = Page;
            }

            Run += 1;
            if (Run >= Pages)
            {
                return RunBase;
            }
        }
        else
        {
            Run = 0;
        }
    }

    return 0;
}

static UINT64
InjectChooseBase(
    _In_ PEPROCESS Process,
    _In_ UINT64 Directory,
    _In_ UINT64 UserDirectory,
    _In_ ULONG Pages,
    _Out_ ULONG* Place
    )
{
    KAPC_STATE State;
    INJECT_SPAN* Spans;
    ULONG SpanCount;
    ULONG Index;
    UINT64 Needed;
    UINT64 Chosen;
    UCHAR* Peb;
    UCHAR* Ldr;
    LIST_ENTRY* Head;
    LIST_ENTRY* Link;

    *Place = 0;
    if (Directory == 0 || Pages == 0)
    {
        return 0;
    }

    Needed = (UINT64)Pages * PAGE_SIZE;
    Spans = (INJECT_SPAN*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_SPAN) * 512, INJECT_TAG);
    if (Spans == NULL)
    {
        return 0;
    }

    SpanCount = 0;
    Chosen = 0;
    KeStackAttachProcess(Process, &State);
    if ((__readcr4() & (1ull << 21)) != 0)
    {
        _stac();
    }

    __try
    {
        Peb = (UCHAR*)PsGetProcessPeb(Process);
        Ldr = Peb == NULL ? NULL : *(UCHAR**)(Peb + 0x18);
        Head = Ldr == NULL ? NULL : (LIST_ENTRY*)(Ldr + 0x20);
        Link = Head == NULL ? NULL : Head->Flink;
        if (Link != NULL && Link != Head)
        {
            UCHAR* Entry = (UCHAR*)Link - 0x10;
            UINT64 Module = *(UINT64*)(Entry + 0x30);
            IMAGE_DOS_HEADER Dos;
            IMAGE_NT_HEADERS64 Nt;

            if (Module != 0)
            {
                RtlZeroMemory(&Dos, sizeof(Dos));
                RtlZeroMemory(&Nt, sizeof(Nt));
                __try
                {
                    RtlCopyMemory(&Dos, (PVOID)Module, sizeof(Dos));
                    if (Dos.e_magic == IMAGE_DOS_SIGNATURE && Dos.e_lfanew > 0)
                    {
                        RtlCopyMemory(&Nt, (PVOID)(Module + (UINT64)Dos.e_lfanew), sizeof(Nt));
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    Dos.e_magic = 0;
                }

                if (Dos.e_magic == IMAGE_DOS_SIGNATURE && Nt.Signature == IMAGE_NT_SIGNATURE &&
                    Nt.FileHeader.NumberOfSections > 0 && Nt.FileHeader.NumberOfSections <= 96)
                {
                    UINT64 SectionVa = Module + (UINT64)Dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
                                       Nt.FileHeader.SizeOfOptionalHeader;
                    USHORT SectionIndex;

                    for (SectionIndex = 0; SectionIndex < Nt.FileHeader.NumberOfSections && Chosen == 0; SectionIndex++)
                    {
                        IMAGE_SECTION_HEADER Section;
                        UINT64 Bytes;

                        RtlZeroMemory(&Section, sizeof(Section));
                        __try
                        {
                            RtlCopyMemory(&Section, (PVOID)(SectionVa + (UINT64)SectionIndex * sizeof(Section)),
                                          sizeof(Section));
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                            break;
                        }

                        if (InjectSectionName(Section.Name, ".text") == FALSE &&
                            InjectSectionName(Section.Name, ".rdata") == FALSE &&
                            InjectSectionName(Section.Name, "CODE") == FALSE)
                        {
                            continue;
                        }

                        Bytes = Section.Misc.VirtualSize == 0 ? Section.SizeOfRawData : Section.Misc.VirtualSize;
                        Chosen = InjectHoleInSection(Directory, UserDirectory, Module + Section.VirtualAddress, Bytes,
                                                     Pages);
                    }

                    if (Chosen != 0)
                    {
                        *Place = INJECT_PLACE_MAIN;
                        __leave;
                    }
                }
            }
        }

        for (Index = 0; Head != NULL && Link != NULL && Link != Head && Index < 512 && SpanCount < 512; Index++)
        {
            UCHAR* Entry = (UCHAR*)Link - 0x10;
            UINT64 Module = *(UINT64*)(Entry + 0x30);
            ULONG Image = *(ULONG*)(Entry + 0x40);

            if (Module >= 0x10000ull && Module <= 0x00007FFFFFFFFFFFull && Image != 0 && Module + Image > Module &&
                Module + Image <= 0x0000800000000000ull)
            {
                Spans[SpanCount].Base = Module;
                Spans[SpanCount].End = Module + Image;
                SpanCount += 1;
            }

            Link = Link->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Chosen = 0;
        *Place = 0;
    }

    if ((__readcr4() & (1ull << 21)) != 0)
    {
        _clac();
    }

    KeUnstackDetachProcess(&State);
    if (Chosen != 0)
    {
        ExFreePool(Spans);
        return Chosen;
    }

    for (Index = 1; Index < SpanCount; Index++)
    {
        INJECT_SPAN Key = Spans[Index];
        ULONG Slot = Index;

        while (Slot > 0 && Spans[Slot - 1].Base > Key.Base)
        {
            Spans[Slot] = Spans[Slot - 1];
            Slot -= 1;
        }

        Spans[Slot] = Key;
    }

    for (Index = 1; Index < SpanCount; Index++)
    {
        UINT64 Gap = (Spans[Index - 1].End + 0xFFFFull) & ~0xFFFFull;

        if (Gap < Spans[Index].Base && Spans[Index].Base - Gap >= Needed && Gap >= 0x10000ull &&
            InjectRangeUsable(Directory, UserDirectory, Gap, Pages, FALSE) != FALSE)
        {
            ExFreePool(Spans);
            *Place = INJECT_PLACE_GAP;
            return Gap;
        }
    }

    ExFreePool(Spans);
    for (Index = 1; Index < 127; Index++)
    {
        UINT64 KernelEntry;
        UINT64 UserEntry;

        if (InjectReadEntry(Directory, Index, &KernelEntry) == FALSE || (KernelEntry & INJECT_PRESENT) != 0)
        {
            continue;
        }

        if (UserDirectory != 0)
        {
            if (InjectReadEntry(UserDirectory, Index, &UserEntry) == FALSE || (UserEntry & INJECT_PRESENT) != 0)
            {
                continue;
            }
        }

        *Place = INJECT_PLACE_PML4;
        return (UINT64)Index << 39;
    }

    return 0;
}

NTSTATUS
InjectPte(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path
    )
{
    UCHAR* File;
    UCHAR* Image;
    UCHAR ExecuteBits[(INJECT_MAX_PAGES + 7) / 8];
    UCHAR Stub[64];
    ULONG FileLength;
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_SECTION_HEADER* Section;
    ULONG ImageSize;
    ULONG Pages;
    UINT64 Base;
    UINT64 Directory;
    UINT64 UserDirectory;
    ULONG Index;
    ULONG Place;
    UINT64 Ntdll;
    UINT64 ExitThread;
    ULONG Hooks;
    NTSTATUS Status;
    LONGLONG Delta;

    if (Process == NULL || Path == NULL || Path[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (InjectWow64(Process) != FALSE || (__readcr4() & (1ull << 12)) != 0)
    {
        return STATUS_NOT_SUPPORTED;
    }

    File = NULL;
    Image = NULL;
    Status = InjectReadFile(Path, &File, &FileLength);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject read failed: 0x%08x.\n", Status);
        return Status;
    }

    if (FileLength < sizeof(IMAGE_DOS_HEADER))
    {
        ExFreePool(File);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Dos = (IMAGE_DOS_HEADER*)File;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew <= 0 || (ULONG)Dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > FileLength)
    {
        ExFreePool(File);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Nt = (IMAGE_NT_HEADERS64*)(File + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE || Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || Nt->OptionalHeader.AddressOfEntryPoint == 0)
    {
        ExFreePool(File);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ImageSize = Nt->OptionalHeader.SizeOfImage;
    if (ImageSize == 0 || ImageSize > INJECT_MAX_IMAGE || Nt->FileHeader.NumberOfSections == 0 ||
        Nt->FileHeader.NumberOfSections > 96)
    {
        ExFreePool(File);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Pages = (ImageSize + PAGE_SIZE - 1) / PAGE_SIZE;
    if (Pages + INJECT_EXTRA_PAGES > INJECT_MAX_PAGES)
    {
        ExFreePool(File);
        return STATUS_FILE_TOO_LARGE;
    }

    Directory = InjectDirectory(Process, INJECT_DIR_TABLE);
    UserDirectory = InjectUsableUserDirectory(Process, Directory);
    Place = 0;
    Base = InjectChooseBase(Process, Directory, UserDirectory, Pages + INJECT_EXTRA_PAGES, &Place);
    if (Base == 0)
    {
        ExFreePool(File);
        HACDBG_LOG("HacDbg: Err, DLL inject found no image hole, module gap, or free user page-table slot.\n");
        return STATUS_NOT_FOUND;
    }

    Image = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)Pages * PAGE_SIZE, INJECT_TAG);
    if (Image == NULL)
    {
        ExFreePool(File);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Image, (SIZE_T)Pages * PAGE_SIZE);
    if (Nt->OptionalHeader.SizeOfHeaders > FileLength || Nt->OptionalHeader.SizeOfHeaders > ImageSize)
    {
        ExFreePool(Image);
        ExFreePool(File);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RtlCopyMemory(Image, File, Nt->OptionalHeader.SizeOfHeaders);
    Section = IMAGE_FIRST_SECTION(Nt);
    for (Index = 0; Index < Nt->FileHeader.NumberOfSections; Index++)
    {
        ULONG Raw = Section[Index].SizeOfRawData;
        ULONG VirtualSize = Section[Index].Misc.VirtualSize;

        if (Section[Index].PointerToRawData >= FileLength)
        {
            continue;
        }

        if (Section[Index].PointerToRawData + Raw > FileLength)
        {
            Raw = FileLength - Section[Index].PointerToRawData;
        }

        if (Section[Index].VirtualAddress >= ImageSize)
        {
            continue;
        }

        if (VirtualSize == 0 || VirtualSize > Raw)
        {
            VirtualSize = Raw;
        }

        if (Section[Index].VirtualAddress + VirtualSize > ImageSize)
        {
            VirtualSize = ImageSize - Section[Index].VirtualAddress;
        }

        RtlCopyMemory(Image + Section[Index].VirtualAddress, File + Section[Index].PointerToRawData, VirtualSize);
    }

    ExFreePool(File);
    File = NULL;
    Delta = (LONGLONG)Base - (LONGLONG)Nt->OptionalHeader.ImageBase;
    Status = InjectApplyRelocs(Image, Pages * PAGE_SIZE, Delta);
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(Image);
        return Status;
    }

    ((IMAGE_NT_HEADERS64*)(Image + ((IMAGE_DOS_HEADER*)Image)->e_lfanew))->OptionalHeader.ImageBase = Base;
    Status = InjectResolveImports(Process, Path, Image, Pages * PAGE_SIZE);
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(Image);
        return Status;
    }

    Ntdll = InjectModuleBase(Process, "ntdll.dll");
    ExitThread = InjectResolve(Process, Ntdll, "RtlExitUserThread", 0);
    if (ExitThread == 0)
    {
        HACDBG_LOG("HacDbg: Err, DLL inject found no RtlExitUserThread.\n");
        ExFreePool(Image);
        return STATUS_NOT_FOUND;
    }

    InjectMarkExecute(Image, Pages, ExecuteBits);
    InjectWriteStub(Stub, Base, Base + ((IMAGE_NT_HEADERS64*)(Image + ((IMAGE_DOS_HEADER*)Image)->e_lfanew))->OptionalHeader.AddressOfEntryPoint,
                    ExitThread);
    Hooks = 0;
    Status = InjectMapImage(Process, Image, Pages * PAGE_SIZE, Base, ExecuteBits, Stub, &Hooks);
    ExFreePool(Image);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = InjectStartEntry(Process, Base + ((UINT64)Pages * PAGE_SIZE));
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, DLL inject start failed: 0x%08x.\n", Status);
        return Status;
    }

    HACDBG_LOG("HacDbg: DLL inject PTE pid=%llu va=0x%I64x place=%lu hooks=%lu.\n",
               (UINT64)(ULONG_PTR)PsGetProcessId(Process), Base, Place, Hooks);
    return STATUS_SUCCESS;
}

#else

NTSTATUS
InjectApc(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path
    )
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Path);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
InjectPte(
    _In_ PEPROCESS Process,
    _In_ const WCHAR* Path
    )
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Path);
    return STATUS_NOT_SUPPORTED;
}

#endif
