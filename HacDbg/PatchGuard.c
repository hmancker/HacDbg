/**
 * @file PatchGuard.c
 * @brief Runtime Kernel Patch Protection disable for Windows 11 26100.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>

#include "PatchGuard.h"
#include "Config.h"
#include "Debug.h"
#include "PhysicalMemory.h"
#include "Types.h"
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#include "Svm.h"
#include "Vmx.h"
#define PATCH_GUARD_SLAT_ADD_HOOK EptAddHook
#define PATCH_GUARD_SLAT_REMOVE_HOOK EptRemoveHook
#define PATCH_GUARD_SLAT_FLUSH VmxFlushAllProcessors
#else
#include "Npt.h"
#include "Svm.h"
#define PATCH_GUARD_SLAT_ADD_HOOK NptAddHook
#define PATCH_GUARD_SLAT_REMOVE_HOOK NptRemoveHook
#define PATCH_GUARD_SLAT_FLUSH SvmFlushAllProcessors
#endif

#if defined(_M_AMD64)

#define PATCH_GUARD_RET_PATCH0              0xC3
#define PATCH_GUARD_RET_PATCH1              0xCC
#define PATCH_GUARD_KPCR_CURRENT_PRCB       0x20ull
#define PATCH_GUARD_PRCB_TIMER_TABLE        0x4100ull
#define PATCH_GUARD_PRCB_DPC_DATA           0x3840ull
#define PATCH_GUARD_DPC_DATA_SIZE           0x30ull
#define PATCH_GUARD_DPC_DATA_COUNT          2ul
#define PATCH_GUARD_DPC_LIST_ENTRY          0x08ull
#define PATCH_GUARD_DPC_WALK_LIMIT          256ul
#define PATCH_GUARD_TIMER_TABLE_ENTRIES     0x200ull
#define PATCH_GUARD_TIMER_TABLE_ENTRY_COUNT 512ull
#define PATCH_GUARD_TIMER_WALK_LIMIT        4096ul
#define PATCH_GUARD_NTOS_PAGE_WALK          0x4000ul
#define PATCH_GUARD_SYSTEM_MODULE_INFORMATION 11ul
#define PATCH_GUARD_KERNEL_VA_START         0xFFFF800000000000ull
#define PATCH_GUARD_TIMER2_COLLECTION_COUNT 8ul
#define PATCH_GUARD_TIMER2_COLLECTION_SIZE  0x18ul
#define PATCH_GUARD_TIMER2_ROOT             0ul
#define PATCH_GUARD_TIMER2_ENCODED          8ul
#define PATCH_GUARD_TIMER2_NODE_LOW         0x18ul
#define PATCH_GUARD_PROFILER_QUEUE_FLAG     0xACull
#define PATCH_GUARD_PROFILER_WORK_ITEM      0xB8ull
#define PATCH_GUARD_WORK_ROUTINE            0x10ull
#define PATCH_GUARD_EPROCESS_THREAD_LIST    0x370ull
#define PATCH_GUARD_ETHREAD_LIST_ENTRY      0x578ull
#define PATCH_GUARD_KTHREAD_START           0x4e0ull
#define PATCH_GUARD_ETHREAD_WIN32_START     0x560ull
#define PATCH_GUARD_THREAD_OBJECT           0x06ul
#define PATCH_GUARD_BUGCHECK_CORRUPTION     0x109ul
#define PATCH_GUARD_THREAD_WALK_LIMIT       4096ul
#define PATCH_GUARD_BUGCHECK_PROLOGUE       15ul
#define PATCH_GUARD_ABSOLUTE_JUMP           14ul
#define PATCH_GUARD_HOOK_PAGE_COUNT         4ul
#define PATCH_GUARD_ALLOCATION_COUNT        6ul
#define PATCH_GUARD_RETIRE_LOG_LIMIT        8ul
#define PATCH_GUARD_STACK_PAGES             4ul
#define PATCH_GUARD_TIMER2_COLLECTION_SPLIT 3ul
#define PATCH_GUARD_TIMER2_CALLBACK         0x60ul
#define PATCH_GUARD_TIMER2_CONTEXT          0x68ul
#define PATCH_GUARD_TIMER2_DISABLE_CALLBACK 0x70ul
#define PATCH_GUARD_TIMER2_OBJECT_TYPE      0x19ul
#define PATCH_GUARD_TIMER2_WALK_LIMIT       4096ul
#define PATCH_GUARD_TIMER2_STACK            128ul
#define PATCH_GUARD_MODULE_WALK_LIMIT       512ul
#define PATCH_GUARD_TIMER2_SAMPLE_LIMIT     12ul
#define PATCH_GUARD_TIMER2_KEEP_LOG_LIMIT   8ul
#define PATCH_GUARD_REASON_STUB             1ul
#define PATCH_GUARD_REASON_POOL             2ul
#define PATCH_GUARD_REASON_CONTEXT          3ul
#define PATCH_GUARD_KLDR_DLL_BASE           0x30ul
#define PATCH_GUARD_KLDR_SIZE_OF_IMAGE      0x40ul

typedef struct _PATCH_GUARD_KTIMER
{
    UCHAR Unused[0x20];
    LIST_ENTRY TimerListEntry;
    UINT64 EncryptedDpc;
} PATCH_GUARD_KTIMER;

C_ASSERT(FIELD_OFFSET(PATCH_GUARD_KTIMER, TimerListEntry) == 0x20);
C_ASSERT(FIELD_OFFSET(PATCH_GUARD_KTIMER, EncryptedDpc) == 0x30);

typedef struct _PATCH_GUARD_TIMER_TABLE_ENTRY
{
    UINT64 Lock;
    LIST_ENTRY Entry;
    UINT64 Time;
} PATCH_GUARD_TIMER_TABLE_ENTRY;

C_ASSERT(sizeof(PATCH_GUARD_TIMER_TABLE_ENTRY) == 32);
C_ASSERT(FIELD_OFFSET(PATCH_GUARD_TIMER_TABLE_ENTRY, Entry) == 8);

typedef struct _PATCH_GUARD_KDPC
{
    UCHAR Unused[0x18];
    PVOID DeferredRoutine;
    PVOID DeferredContext;
} PATCH_GUARD_KDPC;

C_ASSERT(FIELD_OFFSET(PATCH_GUARD_KDPC, DeferredRoutine) == 0x18);
C_ASSERT(FIELD_OFFSET(PATCH_GUARD_KDPC, DeferredContext) == 0x20);

static UCHAR* g_NtosBase;
static ULONG g_NtosSize;
static PVOID g_KiSwInterruptDispatch;
static PVOID g_MaxDataSize;
static PVOID g_NtosReturn;
static UINT64* g_KiWaitNever;
static UINT64* g_KiWaitAlways;
static PVOID g_CcBcbProfiler;
static PVOID g_CcBcbProfiler2;
static PATCH_GUARD_KDPC* g_KiBalanceSetManagerPeriodicDpc;
static PVOID g_KiBalanceSetManagerDeferredRoutine;
static PVOID g_KiTimerDispatch;
static PVOID g_KiTimer2Collections;
static PKSPIN_LOCK g_KiTimer2CollectionLock;
static volatile LONG g_CancelledTimerCount;
static volatile LONG g_CancelledTimer2Count;
static volatile LONG g_GlobalDisableOnce;

typedef struct _PATCH_GUARD_TIMER2_COLLECTION_LOG
{
    UINT64 StoredRoot;
    PVOID Root;
    ULONG Nodes;
    ULONG Objects;
    ULONG Replaced;
    BOOLEAN Encoded;
    BOOLEAN Truncated;
} PATCH_GUARD_TIMER2_COLLECTION_LOG;

typedef struct _PATCH_GUARD_LDR_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT Reserved;
    PVOID SectionPointer;
} PATCH_GUARD_LDR_ENTRY;

typedef struct _PATCH_GUARD_TIMER2_SAMPLE
{
    PVOID Timer;
    PVOID Callback;
    PVOID Context;
    ULONG Reason;
    ULONG Field;
} PATCH_GUARD_TIMER2_SAMPLE;

static PATCH_GUARD_TIMER2_COLLECTION_LOG g_Timer2CollectionLogs[PATCH_GUARD_TIMER2_COLLECTION_COUNT];
static PATCH_GUARD_TIMER2_SAMPLE g_Timer2Samples[PATCH_GUARD_TIMER2_SAMPLE_LIMIT];
static ULONG g_Timer2SampleCount;
static ULONG g_Timer2KeptLogged;
static ULONG g_Timer2Kept;
static ULONG g_Timer2BadNodes;
static VOID
PatchGuardReturn(
    VOID
    )
{
    return;
}

static volatile LONG g_DpcRedirected;
static volatile LONG g_TimerExamined;
static volatile LONG g_TimerKeptLogged;
static volatile LONG g_TimerSampleCount;
static PATCH_GUARD_TIMER2_SAMPLE g_TimerSamples[PATCH_GUARD_TIMER2_SAMPLE_LIMIT];
static PATCH_GUARD_TIMER2_COLLECTION_LOG* g_Timer2Current;

static LIST_ENTRY* g_LoadedModuleList;
static PVOID g_HookAllocations[PATCH_GUARD_ALLOCATION_COUNT];
static ULONG g_HookAllocationCount;
static PVOID g_SwallowStack;
static volatile LONG g_SwallowedBugcheck;

typedef struct _PATCH_GUARD_SYSTEM_MODULE
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
} PATCH_GUARD_SYSTEM_MODULE;

typedef struct _PATCH_GUARD_SYSTEM_MODULES
{
    ULONG NumberOfModules;
    PATCH_GUARD_SYSTEM_MODULE Modules[1];
} PATCH_GUARD_SYSTEM_MODULES;

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID PcValue,
    _Out_ PVOID *BaseOfImage
    );

NTKERNELAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
    );

NTKERNELAPI
VOID
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
    );

NTKERNELAPI
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
    );

static BOOLEAN
PatchGuardPointerInImage(
    _In_ PVOID Pointer
    )
{
    UINT64 Address;
    UINT64 Base;
    UINT64 End;

    Address = (UINT64)Pointer;
    Base = (UINT64)g_NtosBase;
    End = Base + g_NtosSize;
    return Address >= Base && Address < End;
}

static BOOLEAN
PatchGuardIsCanonical(
    _In_ UINT64 Address
    )
{
    UINT64 High;

    High = Address >> 47;
    return High == 0 || High == 0x1FFFFull;
}

static PVOID
PatchGuardFindPattern(
    _In_ PVOID Base,
    _In_ SIZE_T Size,
    _In_reads_(PatternLength) const UCHAR* Pattern,
    _In_reads_(PatternLength) const CHAR* Mask,
    _In_ SIZE_T PatternLength
    )
{
    SIZE_T Index;
    SIZE_T ByteIndex;
    const UCHAR* Bytes;

    if (Base == NULL || Size < PatternLength)
    {
        return NULL;
    }

    Bytes = (const UCHAR*)Base;
    for (Index = 0; Index <= Size - PatternLength; Index++)
    {
        for (ByteIndex = 0; ByteIndex < PatternLength; ByteIndex++)
        {
            if (Mask[ByteIndex] == 'x' && Bytes[Index + ByteIndex] != Pattern[ByteIndex])
            {
                break;
            }
        }

        if (ByteIndex == PatternLength)
        {
            return (PVOID)(Bytes + Index);
        }
    }

    return NULL;
}

static PVOID
PatchGuardRipTarget(
    _In_ PVOID Instruction,
    _In_ ULONG DisplacementOffset,
    _In_ ULONG InstructionLength
    )
{
    INT32 Displacement;

    RtlCopyMemory(&Displacement,
                  (UCHAR*)Instruction + DisplacementOffset,
                  sizeof(Displacement));
    return (UCHAR*)Instruction + InstructionLength + Displacement;
}

static BOOLEAN
PatchGuardGetSection(
    _In_ PVOID Base,
    _In_reads_(IMAGE_SIZEOF_SHORT_NAME) const CHAR* Name,
    _Out_ PVOID* SectionBase,
    _Out_ PULONG SectionSize
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_SECTION_HEADER* Section;
    USHORT Index;
    ULONG Size;

    Dos = (IMAGE_DOS_HEADER*)Base;
    Nt = (IMAGE_NT_HEADERS64*)((UCHAR*)Base + Dos->e_lfanew);
    Section = IMAGE_FIRST_SECTION(Nt);

    for (Index = 0; Index < Nt->FileHeader.NumberOfSections; Index++)
    {
        if (RtlCompareMemory(Section[Index].Name, Name, IMAGE_SIZEOF_SHORT_NAME) !=
            IMAGE_SIZEOF_SHORT_NAME)
        {
            continue;
        }

        Size = Section[Index].Misc.VirtualSize;
        if (Section[Index].SizeOfRawData > Size)
        {
            Size = Section[Index].SizeOfRawData;
        }

        *SectionBase = (UCHAR*)Base + Section[Index].VirtualAddress;
        *SectionSize = Size;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
PatchGuardReadImageSize(
    _In_ PVOID Base,
    _Out_ PULONG SizeOfImage
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;

    Dos = (IMAGE_DOS_HEADER*)Base;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE ||
        Dos->e_lfanew < 0x40 ||
        (ULONG)Dos->e_lfanew > 0x1000)
    {
        return FALSE;
    }

    Nt = (IMAGE_NT_HEADERS64*)((UCHAR*)Base + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE ||
        Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        Nt->OptionalHeader.SizeOfImage == 0)
    {
        return FALSE;
    }

    *SizeOfImage = Nt->OptionalHeader.SizeOfImage;
    return TRUE;
}

static PVOID
PatchGuardNtosBaseFromModules(
    _Out_ PULONG SizeOfImage
    )
{
    NTSTATUS Status;
    ULONG Length;
    PVOID Buffer;
    PATCH_GUARD_SYSTEM_MODULES* Modules;
    PVOID Base;

    Length = 0;
    Status = ZwQuerySystemInformation(PATCH_GUARD_SYSTEM_MODULE_INFORMATION,
                                      NULL,
                                      0,
                                      &Length);
    if (Length == 0)
    {
        UNREFERENCED_PARAMETER(Status);
        return NULL;
    }

    Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Length, 'PgaH');
    if (Buffer == NULL)
    {
        return NULL;
    }

    Status = ZwQuerySystemInformation(PATCH_GUARD_SYSTEM_MODULE_INFORMATION,
                                      Buffer,
                                      Length,
                                      &Length);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Buffer, 'PgaH');
        return NULL;
    }

    Modules = (PATCH_GUARD_SYSTEM_MODULES*)Buffer;
    Base = NULL;
    if (Modules->NumberOfModules != 0 &&
        PatchGuardReadImageSize(Modules->Modules[0].ImageBase, SizeOfImage))
    {
        Base = Modules->Modules[0].ImageBase;
    }

    ExFreePoolWithTag(Buffer, 'PgaH');
    return Base;
}

static PVOID
PatchGuardNtosBase(
    _Out_ PULONG SizeOfImage
    )
{
    UNICODE_STRING Name;
    PVOID Routine;
    PVOID Base;
    UCHAR* Address;
    ULONG Index;

    RtlInitUnicodeString(&Name, L"IoCreateDevice");
    Routine = MmGetSystemRoutineAddress(&Name);
    if (Routine != NULL)
    {
        Base = NULL;
        if (RtlPcToFileHeader(Routine, &Base) != NULL &&
            Base != NULL &&
            PatchGuardReadImageSize(Base, SizeOfImage))
        {
            HACDBG_LOG("HacDbg: PatchGuard ntoskrnl base %p size 0x%x from RtlPcToFileHeader.\n",
                       Base,
                       *SizeOfImage);
            return Base;
        }
    }

    Base = PatchGuardNtosBaseFromModules(SizeOfImage);
    if (Base != NULL)
    {
        HACDBG_LOG("HacDbg: PatchGuard ntoskrnl base %p size 0x%x from loaded module list.\n",
                   Base,
                   *SizeOfImage);
        return Base;
    }

    if (Routine == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard IoCreateDevice export was not found.\n");
        return NULL;
    }

    Address = (UCHAR*)((ULONG_PTR)Routine & ~0xFFFull);
    for (Index = 0; Index < PATCH_GUARD_NTOS_PAGE_WALK; Index++)
    {
        if (PatchGuardReadImageSize(Address, SizeOfImage))
        {
            HACDBG_LOG("HacDbg: PatchGuard ntoskrnl base %p size 0x%x from page walk.\n",
                       Address,
                       *SizeOfImage);
            return Address;
        }

        Address -= 0x1000;
    }

    return NULL;
}

static BOOLEAN
PatchGuardNameEquals(
    _In_ const CHAR* Left,
    _In_ const CHAR* Right
    )
{
    while (*Left != '\0' && *Left == *Right)
    {
        Left++;
        Right++;
    }

    return *Left == *Right;
}

static PVOID
PatchGuardFindExport(
    _In_ PVOID Image,
    _In_ const CHAR* Name
    )
{
    IMAGE_DOS_HEADER* Dos;
    IMAGE_NT_HEADERS64* Nt;
    IMAGE_EXPORT_DIRECTORY* Export;
    ULONG* Names;
    USHORT* Ordinals;
    ULONG* Functions;
    ULONG Index;

    Dos = (IMAGE_DOS_HEADER*)Image;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew < 0x40)
    {
        return NULL;
    }

    Nt = (IMAGE_NT_HEADERS64*)((UCHAR*)Image + Dos->e_lfanew);
    if (Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return NULL;
    }

    Export = (IMAGE_EXPORT_DIRECTORY*)((UCHAR*)Image +
             Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    Names = (ULONG*)((UCHAR*)Image + Export->AddressOfNames);
    Ordinals = (USHORT*)((UCHAR*)Image + Export->AddressOfNameOrdinals);
    Functions = (ULONG*)((UCHAR*)Image + Export->AddressOfFunctions);

    for (Index = 0; Index < Export->NumberOfNames; Index++)
    {
        const CHAR* ExportName;

        ExportName = (const CHAR*)((UCHAR*)Image + Names[Index]);
        if (PatchGuardNameEquals(ExportName, Name))
        {
            return (UCHAR*)Image + Functions[Ordinals[Index]];
        }
    }

    return NULL;
}

static NTSTATUS
PatchGuardResolve(
    VOID
    )
{
    PVOID TextBase;
    ULONG TextSize;
    PVOID PageBase;
    UCHAR* Window;
    ULONG PageSize;
    PVOID Match;
    PVOID AlwaysInstruction;
    static const UCHAR KiSwInterruptDispatchPat[] =
    {
        0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54,
        0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x00,
        0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x3D
    };
    static const CHAR KiSwInterruptDispatchMask[] =
        "xxxx?xxxxxxxxxxxxxxxx?xxx????xxx";
    static const UCHAR MaxDataSizePat[] =
    {
        0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xE9
    };
    static const CHAR MaxDataSizeMask[] = "xxx????xxx";
    static const UCHAR NtosReturnPat[] =
    {
        0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3
    };
    static const CHAR NtosReturnMask[] = "xxxxxxxxx";
    static const UCHAR KiWaitNeverPat[] =
    {
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0xEE, 0x48, 0x33, 0x2D
    };
    static const CHAR KiWaitNeverMask[] = "xxx????xxxxxx";
    static const UCHAR KiBalanceSetManagerPeriodicDpcPat[] =
    {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0x89, 0x05
    };
    static const CHAR KiBalanceSetManagerPeriodicDpcMask[] = "xxx????xxxxx";
    static const UCHAR KiBalanceSetManagerDeferredRoutinePat[] =
    {
        0x33, 0xD2, 0x44, 0x8D, 0x42, 0x5F, 0x48, 0x8D, 0x88, 0x38, 0xFF, 0xFF, 0xFF
    };
    static const CHAR KiBalanceSetManagerDeferredRoutineMask[] = "xxxxxxxxxxxxx";
    static const UCHAR CcBcbProfilerPat[] =
    {
        0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x48,
        0x89, 0x74, 0x24, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
        0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x8B, 0xF2, 0xE8
    };
    static const CHAR CcBcbProfilerMask[] = "xxxx?xxxx?xxxx?xxxxxxxxxxxx?xxxx";
    static const UCHAR CcBcbProfiler2Pat[] =
    {
        0x48, 0x89, 0x5C, 0x24, 0x00, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41,
        0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x8B,
        0xF1, 0xE8
    };
    static const CHAR CcBcbProfiler2Mask[] = "xxxx?xxxxxxxxxxxxxx?xxxx";
    static const UCHAR KiTimer2CollectionsPat[] =
    {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x04, 0x5B,
        0x48, 0x8D, 0x3C, 0xC1, 0xB9, 0x18, 0x00, 0x00, 0x00
    };
    static const CHAR KiTimer2CollectionsMask[] = "xxx????xxxxxxxxxxxxx";
    static const UCHAR KiTimer2CollectionLockPat[] =
    {
        0xF0, 0x48, 0x0F, 0xBA, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x83
    };
    static const CHAR KiTimer2CollectionLockMask[] = "xxxxx????xxx";
    static const UCHAR KiTimerDispatchPat[] =
    {
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x9C, 0x56, 0x57, 0x48, 0x83,
        0xEC, 0x20, 0x4C, 0x8B, 0xD2, 0x0F, 0xAE, 0xE8
    };
    static const CHAR KiTimerDispatchMask[] = "xxxxxxxxxxxxxxxxxxx";

    g_NtosBase = (UCHAR*)PatchGuardNtosBase(&g_NtosSize);
    if (g_NtosBase == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard ntoskrnl base was not found.\n");
        return STATUS_NOT_FOUND;
    }

    if (!PatchGuardGetSection(g_NtosBase, ".text\0\0\0", &TextBase, &TextSize))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard .text section was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_KiSwInterruptDispatch = PatchGuardFindPattern(TextBase,
                                                    TextSize,
                                                    KiSwInterruptDispatchPat,
                                                    KiSwInterruptDispatchMask,
                                                    sizeof(KiSwInterruptDispatchPat));
    if (g_KiSwInterruptDispatch == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern KiSwInterruptDispatch was not found.\n");
        return STATUS_NOT_FOUND;
    }

    Match = PatchGuardFindPattern(g_KiSwInterruptDispatch,
                                  0x100,
                                  MaxDataSizePat,
                                  MaxDataSizeMask,
                                  sizeof(MaxDataSizePat));
    if (Match == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern MaxDataSize was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_MaxDataSize = PatchGuardRipTarget(Match, 3, 7);
    if (!PatchGuardPointerInImage(g_MaxDataSize))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard MaxDataSize is outside ntoskrnl.\n");
        return STATUS_NOT_FOUND;
    }

    Match = PatchGuardFindPattern(TextBase,
                                  TextSize,
                                  NtosReturnPat,
                                  NtosReturnMask,
                                  sizeof(NtosReturnPat));
    if (Match == NULL || ((UCHAR*)Match)[8] != 0xC3)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern KiServiceLinkage was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_NtosReturn = (UCHAR*)Match + 8;
    if (!PatchGuardPointerInImage(g_NtosReturn))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard KiServiceLinkage is outside ntoskrnl.\n");
        return STATUS_NOT_FOUND;
    }

    Match = PatchGuardFindPattern(TextBase,
                                  TextSize,
                                  KiWaitNeverPat,
                                  KiWaitNeverMask,
                                  sizeof(KiWaitNeverPat));
    if (Match == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern KiWaitNever was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_KiWaitNever = (UINT64*)PatchGuardRipTarget(Match, 3, 7);
    AlwaysInstruction = (UCHAR*)Match + 10;
    if (((UCHAR*)AlwaysInstruction)[0] != 0x48 ||
        ((UCHAR*)AlwaysInstruction)[1] != 0x33 ||
        ((UCHAR*)AlwaysInstruction)[2] != 0x2D)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern KiWaitAlways was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_KiWaitAlways = (UINT64*)PatchGuardRipTarget(AlwaysInstruction, 3, 7);
    if (!PatchGuardPointerInImage(g_KiWaitNever) ||
        !PatchGuardPointerInImage(g_KiWaitAlways))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard KiWaitNever is outside ntoskrnl.\n");
        return STATUS_NOT_FOUND;
    }

    g_CcBcbProfiler = PatchGuardFindPattern(TextBase,
                                            TextSize,
                                            CcBcbProfilerPat,
                                            CcBcbProfilerMask,
                                            sizeof(CcBcbProfilerPat));

    Match = PatchGuardFindPattern(TextBase,
                                  TextSize,
                                  KiBalanceSetManagerPeriodicDpcPat,
                                  KiBalanceSetManagerPeriodicDpcMask,
                                  sizeof(KiBalanceSetManagerPeriodicDpcPat));
    if (Match != NULL)
    {
        g_KiBalanceSetManagerPeriodicDpc =
            (PATCH_GUARD_KDPC*)PatchGuardRipTarget(Match, 3, 7);
        if (!PatchGuardPointerInImage(g_KiBalanceSetManagerPeriodicDpc))
        {
            g_KiBalanceSetManagerPeriodicDpc = NULL;
        }
    }

    //
    // ExpCenturyDpcRoutine, CmpLazyFlushDpcRoutine and several other DPCs
    // share the balance-manager prologue. The memset size 0x5F and the
    // [rax-0C8h] operand identify KiBalanceSetManagerDeferredRoutine.
    //
    Match = PatchGuardFindPattern(TextBase,
                                  TextSize,
                                  KiBalanceSetManagerDeferredRoutinePat,
                                  KiBalanceSetManagerDeferredRoutineMask,
                                  sizeof(KiBalanceSetManagerDeferredRoutinePat));
    if (Match != NULL)
    {
        g_KiBalanceSetManagerDeferredRoutine = (UCHAR*)Match - 0x30;
        if (!PatchGuardPointerInImage(g_KiBalanceSetManagerDeferredRoutine) ||
            ((UCHAR*)g_KiBalanceSetManagerDeferredRoutine)[0] != 0x48 ||
            ((UCHAR*)g_KiBalanceSetManagerDeferredRoutine)[1] != 0x8B ||
            ((UCHAR*)g_KiBalanceSetManagerDeferredRoutine)[2] != 0xC4)
        {
            g_KiBalanceSetManagerDeferredRoutine = NULL;
        }
    }

    if (PatchGuardGetSection(g_NtosBase, "PAGE\0\0\0\0", &PageBase, &PageSize))
    {
        g_CcBcbProfiler2 = PatchGuardFindPattern(PageBase,
                                                 PageSize,
                                                 CcBcbProfiler2Pat,
                                                 CcBcbProfiler2Mask,
                                                 sizeof(CcBcbProfiler2Pat));
    }

    g_KiTimerDispatch = PatchGuardFindPattern(g_NtosBase,
                                              g_NtosSize,
                                              KiTimerDispatchPat,
                                              KiTimerDispatchMask,
                                              sizeof(KiTimerDispatchPat));
    if (g_CcBcbProfiler == NULL || g_KiTimerDispatch == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard check routine was not found. profiler %p dispatch %p.\n",
                   g_CcBcbProfiler,
                   g_KiTimerDispatch);
        return STATUS_NOT_FOUND;
    }

    Match = PatchGuardFindPattern(TextBase,
                                  TextSize,
                                  KiTimer2CollectionsPat,
                                  KiTimer2CollectionsMask,
                                  sizeof(KiTimer2CollectionsPat));
    if (Match == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern KiTimer2Collections was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_KiTimer2Collections = PatchGuardRipTarget(Match, 3, 7);
    if (!PatchGuardPointerInImage(g_KiTimer2Collections))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard KiTimer2Collections is outside ntoskrnl.\n");
        return STATUS_NOT_FOUND;
    }

    Window = (UCHAR*)Match - 0x200;
    if (Window < (UCHAR*)TextBase)
    {
        Window = (UCHAR*)TextBase;
    }

    Match = PatchGuardFindPattern(Window,
                                  (SIZE_T)((UCHAR*)Match - Window),
                                  KiTimer2CollectionLockPat,
                                  KiTimer2CollectionLockMask,
                                  sizeof(KiTimer2CollectionLockPat));
    if (Match == NULL)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard pattern KiTimer2CollectionLock was not found.\n");
        return STATUS_NOT_FOUND;
    }

    g_LoadedModuleList = (LIST_ENTRY*)PatchGuardFindExport(g_NtosBase, "PsLoadedModuleList");
    if (g_LoadedModuleList == NULL || !PatchGuardPointerInImage(g_LoadedModuleList))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard PsLoadedModuleList export was not found.\n");
        return STATUS_NOT_FOUND;
    }

    HACDBG_LOG("HacDbg: PatchGuard PsLoadedModuleList %p.\n", g_LoadedModuleList);

    g_KiTimer2CollectionLock = (PKSPIN_LOCK)PatchGuardRipTarget(Match, 5, 10);
    if (!PatchGuardPointerInImage(g_KiTimer2CollectionLock))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard KiTimer2CollectionLock is outside ntoskrnl.\n");
        return STATUS_NOT_FOUND;
    }

    HACDBG_LOG("HacDbg: PatchGuard .text %p size 0x%x.\n", TextBase, TextSize);
    HACDBG_LOG("HacDbg: PatchGuard KiSwInterruptDispatch %p.\n", g_KiSwInterruptDispatch);
    HACDBG_LOG("HacDbg: PatchGuard MaxDataSize %p value %p.\n",
               g_MaxDataSize,
               *(PVOID*)g_MaxDataSize);
    HACDBG_LOG("HacDbg: PatchGuard KiServiceLinkage %p.\n", g_NtosReturn);
    HACDBG_LOG("HacDbg: PatchGuard KiWaitNever %p value 0x%I64x.\n",
               g_KiWaitNever,
               *g_KiWaitNever);
    HACDBG_LOG("HacDbg: PatchGuard KiWaitAlways %p value 0x%I64x.\n",
               g_KiWaitAlways,
               *g_KiWaitAlways);
    HACDBG_LOG("HacDbg: PatchGuard CcBcbProfiler %p.\n",
               g_CcBcbProfiler == NULL ? NULL : g_CcBcbProfiler);
    HACDBG_LOG("HacDbg: PatchGuard CcBcbProfiler2 %p.\n",
               g_CcBcbProfiler2 == NULL ? NULL : g_CcBcbProfiler2);
    HACDBG_LOG("HacDbg: PatchGuard KiTimerDispatch %p.\n",
               g_KiTimerDispatch == NULL ? NULL : g_KiTimerDispatch);
    HACDBG_LOG("HacDbg: PatchGuard KiBalanceSetManagerPeriodicDpc %p routine %p.\n",
               g_KiBalanceSetManagerPeriodicDpc,
               g_KiBalanceSetManagerPeriodicDpc == NULL ?
                   NULL :
                   g_KiBalanceSetManagerPeriodicDpc->DeferredRoutine);
    HACDBG_LOG("HacDbg: PatchGuard KiBalanceSetManagerDeferredRoutine %p.\n",
               g_KiBalanceSetManagerDeferredRoutine);
    HACDBG_LOG("HacDbg: PatchGuard KiTimer2Collections %p.\n", g_KiTimer2Collections);
    HACDBG_LOG("HacDbg: PatchGuard KiTimer2CollectionLock %p.\n", g_KiTimer2CollectionLock);
    return STATUS_SUCCESS;
}

static PATCH_GUARD_KDPC*
PatchGuardDecryptDpc(
    _In_ PATCH_GUARD_KTIMER* Timer
    )
{
    UINT64 Never;
    UINT64 Always;
    UINT64 Value;

    Never = *g_KiWaitNever;
    Always = *g_KiWaitAlways;
    Value = Timer->EncryptedDpc ^ Never;
    Value = _rotl64(Value, (UCHAR)Never);
    Value ^= (UINT64)Timer;
    Value = _byteswap_uint64(Value) ^ Always;
    return (PATCH_GUARD_KDPC*)Value;
}

static UINT64
PatchGuardEncryptPointer(
    _In_ UINT64 Plain,
    _In_ PVOID Key
    )
{
    UINT64 Never;
    UINT64 Always;
    UINT64 Value;

    Never = *g_KiWaitNever;
    Always = *g_KiWaitAlways;
    Value = Plain ^ Always;
    Value = _byteswap_uint64(Value);
    Value ^= (UINT64)Key;
    Value = _rotr64(Value, (UCHAR)Never);
    Value ^= Never;
    return Value;
}

static ULONG
PatchGuardClassifyRoutine(
    _In_opt_ PVOID Routine,
    _In_opt_ PVOID Context
    );

static VOID
PatchGuardRetargetProfiler(
    _In_opt_ PATCH_GUARD_KDPC* Dpc
    );

static VOID
PatchGuardRecordTimerSample(
    _In_ PVOID Timer,
    _In_opt_ PVOID Routine,
    _In_opt_ PVOID Context,
    _In_ ULONG Reason
    )
{
    LONG Index;
    PATCH_GUARD_TIMER2_SAMPLE* Sample;

    Index = InterlockedIncrement(&g_TimerSampleCount) - 1;
    if (Index < 0 || Index >= PATCH_GUARD_TIMER2_SAMPLE_LIMIT)
    {
        return;
    }

    Sample = &g_TimerSamples[Index];
    Sample->Timer = Timer;
    Sample->Callback = Routine;
    Sample->Context = Context;
    Sample->Reason = Reason;
    Sample->Field = 0x30;
}

static BOOLEAN
PatchGuardIsPatchGuardTimer(
    _In_ PATCH_GUARD_KTIMER* Timer
    )
{
    PATCH_GUARD_KDPC* Dpc;
    PHYSICAL_ADDRESS Physical;
    ULONG Reason;

    InterlockedIncrement(&g_TimerExamined);

    Dpc = PatchGuardDecryptDpc(Timer);
    if (!PatchGuardIsCanonical((UINT64)Dpc) ||
        (UINT64)Dpc < PATCH_GUARD_KERNEL_VA_START ||
        ((UINT64)Dpc & 7ull) != 0)
    {
        return FALSE;
    }

    Physical = MmGetPhysicalAddress(Dpc);
    if (Physical.QuadPart == 0)
    {
        return FALSE;
    }

    Reason = PatchGuardClassifyRoutine(Dpc->DeferredRoutine, Dpc->DeferredContext);
    if (Reason == 0)
    {
        if (g_TimerKeptLogged < PATCH_GUARD_TIMER2_KEEP_LOG_LIMIT &&
            InterlockedIncrement(&g_TimerKeptLogged) <= PATCH_GUARD_TIMER2_KEEP_LOG_LIMIT)
        {
            PatchGuardRecordTimerSample(Timer, Dpc->DeferredRoutine, Dpc->DeferredContext, 0);
        }

        return FALSE;
    }

    PatchGuardRecordTimerSample(Timer, Dpc->DeferredRoutine, Dpc->DeferredContext, Reason);
    Timer->EncryptedDpc = PatchGuardEncryptPointer(0, Timer);
    PatchGuardRetargetProfiler(Dpc);
    return TRUE;
}

static VOID
PatchGuardDisableTimersOnProcessor(
    VOID
    )
{
    UCHAR* Prcb;
    PATCH_GUARD_TIMER_TABLE_ENTRY* Entries;
    ULONG Index;

    Prcb = (UCHAR*)__readgsqword(PATCH_GUARD_KPCR_CURRENT_PRCB);
    Entries = (PATCH_GUARD_TIMER_TABLE_ENTRY*)(Prcb + PATCH_GUARD_PRCB_TIMER_TABLE +
                                               PATCH_GUARD_TIMER_TABLE_ENTRIES);

    for (Index = 0; Index < PATCH_GUARD_TIMER_TABLE_ENTRY_COUNT; Index++)
    {
        LIST_ENTRY* Head;
        LIST_ENTRY* Current;
        ULONG Walk;

        Head = &Entries[Index].Entry;
        if (!PatchGuardIsCanonical((UINT64)Head->Flink) || IsListEmpty(Head))
        {
            continue;
        }

        Current = Head->Flink;
        Walk = 0;
        while (Current != Head && Walk < PATCH_GUARD_TIMER_WALK_LIMIT)
        {
            PATCH_GUARD_KTIMER* Timer;

            if (!PatchGuardIsCanonical((UINT64)Current))
            {
                break;
            }

            Timer = CONTAINING_RECORD(Current, PATCH_GUARD_KTIMER, TimerListEntry);
            if (PatchGuardIsPatchGuardTimer(Timer))
            {
                InterlockedIncrement(&g_CancelledTimerCount);
            }

            Current = Current->Flink;
            Walk++;
        }
    }

    for (Index = 0; Index < PATCH_GUARD_DPC_DATA_COUNT; Index++)
    {
        UCHAR* DpcData;
        SINGLE_LIST_ENTRY* Entry;
        ULONG Walk;

        DpcData = Prcb + PATCH_GUARD_PRCB_DPC_DATA + (Index * PATCH_GUARD_DPC_DATA_SIZE);
        Entry = ((SINGLE_LIST_ENTRY*)DpcData)->Next;
        Walk = 0;
        while (Entry != NULL && Walk < PATCH_GUARD_DPC_WALK_LIMIT)
        {
            PATCH_GUARD_KDPC* Dpc;
            ULONG Reason;

            if (!PatchGuardIsCanonical((UINT64)Entry))
            {
                break;
            }

            Dpc = (PATCH_GUARD_KDPC*)((UCHAR*)Entry - PATCH_GUARD_DPC_LIST_ENTRY);
            Reason = PatchGuardClassifyRoutine(Dpc->DeferredRoutine, Dpc->DeferredContext);
            if (Reason != 0)
            {
                PatchGuardRecordTimerSample(Dpc,
                                           Dpc->DeferredRoutine,
                                           Dpc->DeferredContext,
                                           Reason);
                PatchGuardRetargetProfiler(Dpc);
                Dpc->DeferredRoutine = g_NtosReturn;
                InterlockedIncrement(&g_DpcRedirected);
            }

            Entry = Entry->Next;
            Walk++;
        }
    }
}

static PVOID
PatchGuardDecryptPointer(
    _In_ UINT64 Stored,
    _In_ PVOID Key
    )
{
    UINT64 Never;
    UINT64 Always;
    UINT64 Value;

    Never = *g_KiWaitNever;
    Always = *g_KiWaitAlways;
    Value = Stored ^ Never;
    Value = _rotl64(Value, (UCHAR)Never);
    Value ^= (UINT64)Key;
    Value = _byteswap_uint64(Value) ^ Always;
    return (PVOID)Value;
}

static BOOLEAN
PatchGuardAddressInLoadedModule(
    _In_ PVOID Address
    )
{
    UINT64 Value;
    LIST_ENTRY* Entry;
    ULONG Walk;

    Value = (UINT64)Address;
    if (Value >= (UINT64)g_NtosBase && Value < (UINT64)g_NtosBase + g_NtosSize)
    {
        return TRUE;
    }

    if (g_LoadedModuleList == NULL)
    {
        return TRUE;
    }

    Entry = g_LoadedModuleList->Flink;
    Walk = 0;
    while (Entry != g_LoadedModuleList && Walk < PATCH_GUARD_MODULE_WALK_LIMIT)
    {
        UCHAR* ImageBase;
        ULONG ImageSize;

        if (!PatchGuardIsCanonical((UINT64)Entry))
        {
            return TRUE;
        }

        ImageBase = *(UCHAR**)((UCHAR*)Entry + PATCH_GUARD_KLDR_DLL_BASE);
        ImageSize = *(ULONG*)((UCHAR*)Entry + PATCH_GUARD_KLDR_SIZE_OF_IMAGE);
        if (PatchGuardIsCanonical((UINT64)ImageBase) &&
            ImageSize != 0 &&
            Value >= (UINT64)ImageBase &&
            Value < (UINT64)ImageBase + ImageSize)
        {
            return TRUE;
        }

        Entry = Entry->Flink;
        Walk++;
    }

    return FALSE;
}

static ULONG
PatchGuardClassifyRoutine(
    _In_opt_ PVOID Routine,
    _In_opt_ PVOID Context
    )
{
    if (Routine == NULL || Routine == (PVOID)(ULONG_PTR)PatchGuardReturn)
    {
        return 0;
    }

    if (Routine == g_KiTimerDispatch ||
        Routine == g_CcBcbProfiler ||
        Routine == g_CcBcbProfiler2)
    {
        return PATCH_GUARD_REASON_STUB;
    }

    if (!PatchGuardIsCanonical((UINT64)Routine) ||
        (UINT64)Routine < PATCH_GUARD_KERNEL_VA_START ||
        MmGetPhysicalAddress(Routine).QuadPart == 0)
    {
        return 0;
    }

    if (!PatchGuardAddressInLoadedModule(Routine))
    {
        return PATCH_GUARD_REASON_POOL;
    }

    if (Context != NULL && !PatchGuardIsCanonical((UINT64)Context))
    {
        return PATCH_GUARD_REASON_CONTEXT;
    }

    return 0;
}

static VOID
PatchGuardRetargetProfiler(
    _In_opt_ PATCH_GUARD_KDPC* Dpc
    )
{
    UCHAR* Context;
    PVOID* Routine;

    if (Dpc == NULL || g_NtosReturn == NULL)
    {
        return;
    }

    if (Dpc->DeferredRoutine != g_CcBcbProfiler &&
        Dpc->DeferredRoutine != g_CcBcbProfiler2)
    {
        return;
    }

    if (!PatchGuardIsCanonical((UINT64)Dpc->DeferredContext) ||
        ((UINT64)Dpc->DeferredContext & 7ull) != 0 ||
        MmGetPhysicalAddress(Dpc->DeferredContext).QuadPart == 0)
    {
        return;
    }

    //
    // CcBcbProfiler uses DeferredContext as the check context. A non-zero
    // dword at +0xAC queues the WORK_QUEUE_ITEM at +0xB8 instead of checking
    // immediately. Encrypting the timer DPC as null stops a later entry, but
    // a work item already on the delayed queue still calls WorkerRoutine.
    //
    Context = (UCHAR*)Dpc->DeferredContext;
    if (MmGetPhysicalAddress(Context + PATCH_GUARD_PROFILER_WORK_ITEM).QuadPart == 0)
    {
        return;
    }

    *(volatile ULONG*)(Context + PATCH_GUARD_PROFILER_QUEUE_FLAG) = 0;
    Routine = (PVOID*)(Context + PATCH_GUARD_PROFILER_WORK_ITEM + PATCH_GUARD_WORK_ROUTINE);
    if (PatchGuardClassifyRoutine(*Routine, NULL) == 0)
    {
        return;
    }

    *Routine = g_NtosReturn;
}

static PCSTR
PatchGuardReasonName(
    _In_ ULONG Reason
    )
{
    if (Reason == PATCH_GUARD_REASON_STUB)
    {
        return "stub";
    }

    if (Reason == PATCH_GUARD_REASON_POOL)
    {
        return "pool";
    }

    if (Reason == PATCH_GUARD_REASON_CONTEXT)
    {
        return "context";
    }

    return "none";
}

static PVOID
PatchGuardDecodeTimer2Root(
    _In_ PVOID Collection,
    _Out_ BOOLEAN* Encoded
    )
{
    UINT64 Root;
    UINT64 Flag;

    //
    // KiInsertTimer2WithCollectionLockHeld reads the tree root at collection+0.
    // Bit 0 of the qword at +8 is the encoded flag. An encoded root is
    // stored XOR the collection address. Children are stored XOR the node.
    //
    Root = *(UINT64*)((UCHAR*)Collection + PATCH_GUARD_TIMER2_ROOT);
    Flag = *(UINT64*)((UCHAR*)Collection + PATCH_GUARD_TIMER2_ENCODED);
    *Encoded = (Flag & 1ull) != 0;
    if (Root == 0)
    {
        return NULL;
    }

    if (*Encoded != FALSE)
    {
        return (PVOID)(Root ^ (UINT64)Collection);
    }

    return (PVOID)Root;
}

static PVOID
PatchGuardDecodeTimer2Child(
    _In_ PVOID Node,
    _In_ ULONG Index,
    _In_ BOOLEAN Encoded
    )
{
    UINT64 Stored;

    Stored = ((UINT64*)Node)[Index];
    if (!Encoded)
    {
        return (PVOID)Stored;
    }

    if (Stored == 0)
    {
        return NULL;
    }

    return (PVOID)(Stored ^ (UINT64)Node);
}

static VOID
PatchGuardRecordTimer2Sample(
    _In_ PVOID Timer,
    _In_opt_ PVOID Callback,
    _In_opt_ PVOID Context,
    _In_ ULONG Reason,
    _In_ ULONG Field
    )
{
    PATCH_GUARD_TIMER2_SAMPLE* Sample;

    if (g_Timer2SampleCount >= PATCH_GUARD_TIMER2_SAMPLE_LIMIT)
    {
        return;
    }

    Sample = &g_Timer2Samples[g_Timer2SampleCount];
    Sample->Timer = Timer;
    Sample->Callback = Callback;
    Sample->Context = Context;
    Sample->Reason = Reason;
    Sample->Field = Field;
    g_Timer2SampleCount += 1;
}

static VOID
PatchGuardNeutralizeTimer2(
    _In_ UCHAR* Timer
    )
{
    PVOID Callback;
    PVOID Context;
    PVOID DisableCallback;
    ULONG Reason;

    if (MmGetPhysicalAddress(Timer).QuadPart == 0 ||
        (Timer[0] & 0x7F) != PATCH_GUARD_TIMER2_OBJECT_TYPE)
    {
        return;
    }

    if (g_Timer2Current != NULL)
    {
        g_Timer2Current->Objects += 1;
    }

    Callback = PatchGuardDecryptPointer(*(UINT64*)(Timer + PATCH_GUARD_TIMER2_CALLBACK), Timer);
    Context = PatchGuardDecryptPointer(*(UINT64*)(Timer + PATCH_GUARD_TIMER2_CONTEXT), Timer);
    Reason = PatchGuardClassifyRoutine(Callback, Context);
    if (Reason != 0)
    {
        *(volatile UINT64*)(Timer + PATCH_GUARD_TIMER2_CALLBACK) =
            PatchGuardEncryptPointer(0, Timer);
        InterlockedIncrement(&g_CancelledTimer2Count);
        if (g_Timer2Current != NULL)
        {
            g_Timer2Current->Replaced += 1;
        }

        PatchGuardRecordTimer2Sample(Timer, Callback, Context, Reason, PATCH_GUARD_TIMER2_CALLBACK);
    }
    else if (g_Timer2KeptLogged < PATCH_GUARD_TIMER2_KEEP_LOG_LIMIT)
    {
        PatchGuardRecordTimer2Sample(Timer, Callback, Context, 0, PATCH_GUARD_TIMER2_CALLBACK);
        g_Timer2KeptLogged += 1;
        g_Timer2Kept += 1;
    }
    else
    {
        g_Timer2Kept += 1;
    }

    DisableCallback = PatchGuardDecryptPointer(
        *(UINT64*)(Timer + PATCH_GUARD_TIMER2_DISABLE_CALLBACK),
        Timer);
    Reason = PatchGuardClassifyRoutine(DisableCallback, NULL);
    if (Reason != 0)
    {
        *(volatile UINT64*)(Timer + PATCH_GUARD_TIMER2_DISABLE_CALLBACK) =
            PatchGuardEncryptPointer(0, Timer);
        InterlockedIncrement(&g_CancelledTimer2Count);
        if (g_Timer2Current != NULL)
        {
            g_Timer2Current->Replaced += 1;
        }

        PatchGuardRecordTimer2Sample(Timer,
                                     DisableCallback,
                                     NULL,
                                     Reason,
                                     PATCH_GUARD_TIMER2_DISABLE_CALLBACK);
    }
}

static VOID
PatchGuardWalkTimer2Node(
    _In_ PVOID Node,
    _In_ BOOLEAN Encoded,
    _Inout_ PVOID* Stack,
    _Inout_ ULONG* Depth
    )
{
    ULONG Child;

    if (Node == NULL)
    {
        return;
    }

    if (!PatchGuardIsCanonical((UINT64)Node) ||
        ((UINT64)Node & 7ull) != 0 ||
        MmGetPhysicalAddress(Node).QuadPart == 0)
    {
        g_Timer2BadNodes += 1;
        return;
    }

    //
    // Every collection links RbNodes[0] at KTIMER2+0x18. The header type
    // rejects a node that is not a timer2 object.
    //
    PatchGuardNeutralizeTimer2((UCHAR*)Node - PATCH_GUARD_TIMER2_NODE_LOW);

    for (Child = 0; Child < 2; Child++)
    {
        PVOID Next;

        Next = PatchGuardDecodeTimer2Child(Node, Child, Encoded);
        if (Next == NULL || *Depth >= PATCH_GUARD_TIMER2_STACK)
        {
            continue;
        }

        Stack[*Depth] = Next;
        *Depth += 1;
    }
}

static VOID
PatchGuardDisableTimer2Collections(
    VOID
    )
{
    KIRQL OldIrql;
    ULONG Index;
    ULONG Sample;

    RtlZeroMemory(g_Timer2CollectionLogs, sizeof(g_Timer2CollectionLogs));
    RtlZeroMemory(g_Timer2Samples, sizeof(g_Timer2Samples));
    g_Timer2SampleCount = 0;
    g_Timer2KeptLogged = 0;
    g_Timer2Kept = 0;
    g_Timer2BadNodes = 0;
    g_CancelledTimer2Count = 0;

    KeAcquireSpinLock(g_KiTimer2CollectionLock, &OldIrql);

    for (Index = 0; Index < PATCH_GUARD_TIMER2_COLLECTION_COUNT; Index++)
    {
        UCHAR* Collection;
        BOOLEAN Encoded;
        PVOID Root;
        PVOID Stack[PATCH_GUARD_TIMER2_STACK];
        ULONG Depth;
        ULONG Seen;

        Collection = (UCHAR*)g_KiTimer2Collections +
                     (Index * PATCH_GUARD_TIMER2_COLLECTION_SIZE);
        g_Timer2Current = &g_Timer2CollectionLogs[Index];
        g_Timer2Current->StoredRoot = *(UINT64*)(Collection + PATCH_GUARD_TIMER2_ROOT);
        Root = PatchGuardDecodeTimer2Root(Collection, &Encoded);
        g_Timer2Current->Root = Root;
        g_Timer2Current->Encoded = Encoded;
        Depth = 0;
        Seen = 0;
        if (Root != NULL)
        {
            Stack[Depth] = Root;
            Depth = 1;
        }

        while (Depth != 0 && Seen < PATCH_GUARD_TIMER2_WALK_LIMIT)
        {
            PVOID Node;

            Depth -= 1;
            Node = Stack[Depth];
            Seen++;
            g_Timer2Current->Nodes = Seen;
            PatchGuardWalkTimer2Node(Node, Encoded, Stack, &Depth);
        }

        if (Depth != 0 || Seen >= PATCH_GUARD_TIMER2_WALK_LIMIT)
        {
            g_Timer2Current->Truncated = TRUE;
        }
    }

    g_Timer2Current = NULL;
    KeReleaseSpinLock(g_KiTimer2CollectionLock, OldIrql);

    for (Index = 0; Index < PATCH_GUARD_TIMER2_COLLECTION_COUNT; Index++)
    {
        HACDBG_LOG("HacDbg: PatchGuard timer2 collection %lu stored 0x%I64x root %p encoded %u nodes %lu objects %lu replaced %lu truncated %u.\n",
                   Index,
                   g_Timer2CollectionLogs[Index].StoredRoot,
                   g_Timer2CollectionLogs[Index].Root,
                   g_Timer2CollectionLogs[Index].Encoded ? 1 : 0,
                   g_Timer2CollectionLogs[Index].Nodes,
                   g_Timer2CollectionLogs[Index].Objects,
                   g_Timer2CollectionLogs[Index].Replaced,
                   g_Timer2CollectionLogs[Index].Truncated ? 1 : 0);
    }

    HACDBG_LOG("HacDbg: PatchGuard timer2 bad nodes %lu, kept callbacks %lu.\n",
               g_Timer2BadNodes,
               g_Timer2Kept);

    for (Sample = 0; Sample < g_Timer2SampleCount; Sample++)
    {
        HACDBG_LOG("HacDbg: PatchGuard timer2 sample timer %p field 0x%x callback %p context %p reason %s.\n",
                   g_Timer2Samples[Sample].Timer,
                   g_Timer2Samples[Sample].Field,
                   g_Timer2Samples[Sample].Callback,
                   g_Timer2Samples[Sample].Context,
                   PatchGuardReasonName(g_Timer2Samples[Sample].Reason));
    }
}

static VOID
PatchGuardRestoreBalanceDpc(
    VOID
    )
{
    PVOID Current;

    if (g_KiBalanceSetManagerPeriodicDpc == NULL ||
        g_KiBalanceSetManagerDeferredRoutine == NULL)
    {
        return;
    }

    Current = g_KiBalanceSetManagerPeriodicDpc->DeferredRoutine;
    if (Current == g_KiBalanceSetManagerDeferredRoutine)
    {
        HACDBG_LOG("HacDbg: PatchGuard balance DPC routine left at %p.\n", Current);
        return;
    }

    g_KiBalanceSetManagerPeriodicDpc->DeferredRoutine = g_KiBalanceSetManagerDeferredRoutine;
    HACDBG_LOG("HacDbg: PatchGuard balance DPC routine restored from %p to %p.\n",
               Current,
               g_KiBalanceSetManagerDeferredRoutine);
}

static VOID
PatchGuardDisableTimersDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //
    // The first barrier runs after every processor has entered this DPC, so
    // timer expiration is not running on any processor. The second barrier
    // holds the other processors until the global timer2 walk finishes.
    //
    KeSignalCallDpcSynchronize(SystemArgument2);
    PatchGuardDisableTimersOnProcessor();
    if (InterlockedCompareExchange(&g_GlobalDisableOnce, 1, 0) == 0)
    {
        PatchGuardDisableTimer2Collections();
        PatchGuardRestoreBalanceDpc();
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static BOOLEAN
PatchGuardWriteRet(
    _In_ PVOID Entry
    )
{
    __try
    {
        if (*(volatile UCHAR*)Entry == (UCHAR)PATCH_GUARD_RET_PATCH0)
        {
            return FALSE;
        }

        *(volatile UCHAR*)Entry = (UCHAR)PATCH_GUARD_RET_PATCH0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
PatchGuardRetirePoolEntry(
    _In_opt_ PVOID Entry
    )
{
    if (Entry == NULL ||
        !PatchGuardIsCanonical((UINT64)Entry) ||
        (UINT64)Entry < PATCH_GUARD_KERNEL_VA_START ||
        PatchGuardAddressInLoadedModule(Entry) != FALSE ||
        MmGetPhysicalAddress(Entry).QuadPart == 0)
    {
        return FALSE;
    }

    //
    // INVARIANT: Entry is a resident kernel address outside every loaded
    // image. It is the start address of a System thread whose header type
    // is a thread object. The byte is written before the first VMRUN or
    // VMLAUNCH.
    //
    if (PatchGuardWriteRet(Entry) == FALSE)
    {
        return FALSE;
    }

    {
        static ULONG Logged;

        if (Logged < PATCH_GUARD_RETIRE_LOG_LIMIT)
        {
            Logged += 1;
            HACDBG_LOG("HacDbg: PatchGuard retired pool entry %p.\n", Entry);
        }
    }

    return TRUE;
}

static VOID
PatchGuardRetireSystemThreads(
    VOID
    )
{
    PVOID* SystemPointer;
    UCHAR* Process;
    LIST_ENTRY* Head;
    LIST_ENTRY* Entry;
    ULONG Walked;
    ULONG Retired;

    SystemPointer = (PVOID*)PatchGuardFindExport(g_NtosBase, "PsInitialSystemProcess");
    if (SystemPointer == NULL || PatchGuardPointerInImage(SystemPointer) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard PsInitialSystemProcess export was not found.\n");
        return;
    }

    Process = (UCHAR*)(*SystemPointer);
    if (!PatchGuardIsCanonical((UINT64)Process) ||
        (UINT64)Process < PATCH_GUARD_KERNEL_VA_START ||
        MmGetPhysicalAddress(Process).QuadPart == 0 ||
        MmGetPhysicalAddress(Process + PATCH_GUARD_EPROCESS_THREAD_LIST).QuadPart == 0)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard system process is not resident.\n");
        return;
    }

    Head = (LIST_ENTRY*)(Process + PATCH_GUARD_EPROCESS_THREAD_LIST);
    if (!PatchGuardIsCanonical((UINT64)Head->Flink))
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard system thread list is not canonical.\n");
        return;
    }

    Entry = Head->Flink;
    Walked = 0;
    Retired = 0;
    while (Entry != Head && Walked < PATCH_GUARD_THREAD_WALK_LIMIT)
    {
        UCHAR* Thread;
        PVOID Start;
        PVOID Win32Start;

        if (!PatchGuardIsCanonical((UINT64)Entry))
        {
            break;
        }

        Thread = (UCHAR*)Entry - PATCH_GUARD_ETHREAD_LIST_ENTRY;
        if (MmGetPhysicalAddress(Thread).QuadPart == 0 ||
            MmGetPhysicalAddress(Thread + PATCH_GUARD_KTHREAD_START).QuadPart == 0 ||
            MmGetPhysicalAddress(Thread + PATCH_GUARD_ETHREAD_WIN32_START).QuadPart == 0)
        {
            break;
        }

        if (Thread[0] != (UCHAR)PATCH_GUARD_THREAD_OBJECT)
        {
            HACDBG_LOG("HacDbg: Err, PatchGuard thread list object type %u.\n", Thread[0]);
            break;
        }

        Start = *(PVOID*)(Thread + PATCH_GUARD_KTHREAD_START);
        Win32Start = *(PVOID*)(Thread + PATCH_GUARD_ETHREAD_WIN32_START);
        if (PatchGuardRetirePoolEntry(Start) != FALSE)
        {
            Retired += 1;
        }

        if (Win32Start != Start && PatchGuardRetirePoolEntry(Win32Start) != FALSE)
        {
            Retired += 1;
        }

        Entry = Entry->Flink;
        Walked += 1;
    }

    HACDBG_LOG("HacDbg: PatchGuard system threads walked %lu, retired %lu pool entries.\n",
               Walked,
               Retired);
}

static DECLSPEC_NOINLINE VOID
PatchGuardSwallowCorruption(
    VOID
    )
{
    KIRQL Irql;

    if (InterlockedCompareExchange(&g_SwallowedBugcheck, 1, 0) == 0)
    {
        HACDBG_LOG("HacDbg: PatchGuard swallowed CRITICAL_STRUCTURE_CORRUPTION cpu %u irql %u.\n",
                   KeGetCurrentProcessorNumber(),
                   KeGetCurrentIrql());
    }

    Irql = KeGetCurrentIrql();
    if (Irql <= APC_LEVEL && PsIsSystemThread((PETHREAD)KeGetCurrentThread()) != FALSE)
    {
        if (Irql != PASSIVE_LEVEL)
        {
            KeLowerIrql(PASSIVE_LEVEL);
        }

        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    _enable();
    for (;;)
    {
        _mm_pause();
    }
}

static VOID
PatchGuardWriteAbsoluteJump(
    _Out_writes_(PATCH_GUARD_ABSOLUTE_JUMP) UCHAR* Destination,
    _In_ PVOID Target
    )
{
    UINT64 Address;
    UINT32 Low;
    UINT32 High;

    Address = (UINT64)Target;
    Low = (UINT32)Address;
    High = (UINT32)(Address >> 32);
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
PatchGuardEmitBugcheckStub(
    _Out_writes_(PAGE_SIZE) UCHAR* Page,
    _In_ PVOID Continue,
    _In_ PVOID Stack
    )
{
    ULONG Cursor;
    ULONG JumpDisplacement;
    UINT64 KernelStart;
    UINT64 Swallow;
    INT32 Relative;

    Cursor = 0;
    KernelStart = PATCH_GUARD_KERNEL_VA_START;
    Swallow = (UINT64)(ULONG_PTR)PatchGuardSwallowCorruption;

    Page[Cursor++] = 0x81;
    Page[Cursor++] = 0xF9;
    Page[Cursor++] = 0x09;
    Page[Cursor++] = 0x01;
    Page[Cursor++] = 0x00;
    Page[Cursor++] = 0x00;
    Page[Cursor++] = 0x0F;
    Page[Cursor++] = 0x85;
    JumpDisplacement = Cursor;
    Cursor += sizeof(INT32);

    Page[Cursor++] = 0x48;
    Page[Cursor++] = 0x8B;
    Page[Cursor++] = 0x04;
    Page[Cursor++] = 0x24;
    Page[Cursor++] = 0x49;
    Page[Cursor++] = 0xBB;
    RtlCopyMemory(Page + Cursor, &KernelStart, sizeof(KernelStart));
    Cursor += sizeof(KernelStart);
    Page[Cursor++] = 0x4C;
    Page[Cursor++] = 0x39;
    Page[Cursor++] = 0xD8;
    Page[Cursor++] = 0x72;
    Page[Cursor++] = 0x01;
    Page[Cursor++] = 0xC3;

    Page[Cursor++] = 0x48;
    Page[Cursor++] = 0xBC;
    RtlCopyMemory(Page + Cursor, &Stack, sizeof(Stack));
    Cursor += sizeof(PVOID);
    Page[Cursor++] = 0x48;
    Page[Cursor++] = 0xB8;
    RtlCopyMemory(Page + Cursor, &Swallow, sizeof(Swallow));
    Cursor += sizeof(Swallow);
    Page[Cursor++] = 0xFF;
    Page[Cursor++] = 0xD0;
    Page[Cursor++] = 0xCC;

    Relative = (INT32)Cursor - (INT32)(JumpDisplacement + sizeof(INT32));
    RtlCopyMemory(Page + JumpDisplacement, &Relative, sizeof(Relative));

    Page[Cursor++] = 0x48;
    Page[Cursor++] = 0x89;
    Page[Cursor++] = 0x4C;
    Page[Cursor++] = 0x24;
    Page[Cursor++] = 0x08;
    Page[Cursor++] = 0x48;
    Page[Cursor++] = 0x89;
    Page[Cursor++] = 0x54;
    Page[Cursor++] = 0x24;
    Page[Cursor++] = 0x10;
    Page[Cursor++] = 0x4C;
    Page[Cursor++] = 0x89;
    Page[Cursor++] = 0x44;
    Page[Cursor++] = 0x24;
    Page[Cursor++] = 0x18;
    PatchGuardWriteAbsoluteJump(Page + Cursor, Continue);
    Cursor += PATCH_GUARD_ABSOLUTE_JUMP;
    return Cursor;
}

static PVOID
PatchGuardAllocateExecutablePage(
    VOID
    )
{
    PVOID Raw;
    PVOID Aligned;

    Raw = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE * 2, 'PgaH');
    if (Raw == NULL)
    {
        return NULL;
    }

    Aligned = (PVOID)(((ULONG_PTR)Raw + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    RtlZeroMemory(Aligned, PAGE_SIZE);
    if (g_HookAllocationCount >= PATCH_GUARD_ALLOCATION_COUNT)
    {
        ExFreePoolWithTag(Raw, 'PgaH');
        return NULL;
    }

    g_HookAllocations[g_HookAllocationCount] = Raw;
    g_HookAllocationCount += 1;
    return Aligned;
}

static PVOID
PatchGuardAllocateSwallowStack(
    VOID
    )
{
    UCHAR* Raw;
    UCHAR* Aligned;
    UCHAR* Top;

    Raw = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                  (PATCH_GUARD_STACK_PAGES + 1) * PAGE_SIZE,
                                  'PgaH');
    if (Raw == NULL)
    {
        return NULL;
    }

    Aligned = (UCHAR*)(((ULONG_PTR)Raw + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    Top = Aligned + (PATCH_GUARD_STACK_PAGES * PAGE_SIZE);
    Top = (UCHAR*)((ULONG_PTR)Top & ~(ULONG_PTR)0xF);
    Top -= 0x20;
    g_SwallowStack = Raw;
    return Top;
}

static BOOLEAN
PatchGuardPageResident(
    _In_ PVOID Address
    )
{
    __try
    {
        *(volatile UCHAR*)Address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    return MmGetPhysicalAddress((PVOID)((ULONG_PTR)Address & ~(ULONG_PTR)(PAGE_SIZE - 1))).QuadPart != 0;
}

static NTSTATUS
PatchGuardInstallExecuteHook(
    _In_ PVOID Target,
    _In_reads_(PatchSize) const UCHAR* Patch,
    _In_ ULONG PatchSize,
    _Inout_updates_(PATCH_GUARD_HOOK_PAGE_COUNT) PVOID* PageBases,
    _Inout_updates_(PATCH_GUARD_HOOK_PAGE_COUNT) PVOID* Shadows,
    _Inout_updates_(PATCH_GUARD_HOOK_PAGE_COUNT) UINT64* PhysicalPages,
    _Inout_ PULONG PageCount
    )
{
    PVOID PageBase;
    ULONG Offset;
    ULONG Index;
    PVOID Shadow;
    PHYSICAL_ADDRESS Physical;

    Offset = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
    if ((ULONG_PTR)PatchSize > PAGE_SIZE || Offset + PatchSize > PAGE_SIZE)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard hook crosses a page at %p.\n", Target);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PageBase = (PVOID)((ULONG_PTR)Target & ~(ULONG_PTR)(PAGE_SIZE - 1));
    for (Index = 0; Index < *PageCount; Index++)
    {
        if (PageBases[Index] == PageBase)
        {
            RtlCopyMemory((UCHAR*)Shadows[Index] + Offset, Patch, PatchSize);
            return STATUS_SUCCESS;
        }
    }

    if (*PageCount >= PATCH_GUARD_HOOK_PAGE_COUNT)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Physical = MmGetPhysicalAddress(PageBase);
    if (Physical.QuadPart == 0)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard hook page %p is not resident.\n", PageBase);
        return STATUS_NOT_FOUND;
    }

    Shadow = PatchGuardAllocateExecutablePage();
    if (Shadow == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Shadow, PageBase, PAGE_SIZE);
    RtlCopyMemory((UCHAR*)Shadow + Offset, Patch, PatchSize);
    PageBases[*PageCount] = PageBase;
    Shadows[*PageCount] = Shadow;
    PhysicalPages[*PageCount] = (UINT64)Physical.QuadPart & ~(UINT64)(PAGE_SIZE - 1);
    *PageCount += 1;
    return STATUS_SUCCESS;
}

static BOOLEAN
PatchGuardFlushTranslations(
    VOID
    )
{
    ULONG Count;
    ULONG Index;
    BOOLEAN Flushed;

    PATCH_GUARD_SLAT_FLUSH();
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
        // VM-exit flush, so the exit handler drops cached translations
        // before the patched execute pages are fetched.
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

NTSTATUS
PatchGuardDisable(
    VOID
    )
{
    NTSTATUS Status;
    LONG Sample;

    Status = PatchGuardResolve();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    HACDBG_LOG("HacDbg: PatchGuard leaving MaxDataSize %p value %p.\n",
               g_MaxDataSize,
               *(PVOID*)g_MaxDataSize);

    KeInvalidateAllCaches();
    g_TimerExamined = 0;
    g_TimerKeptLogged = 0;
    g_TimerSampleCount = 0;
    g_DpcRedirected = 0;
    g_CancelledTimerCount = 0;
    g_GlobalDisableOnce = 0;
    RtlZeroMemory(g_TimerSamples, sizeof(g_TimerSamples));
    KeGenericCallDpc(PatchGuardDisableTimersDpc, NULL);
    PatchGuardRetireSystemThreads();

    HACDBG_LOG("HacDbg: PatchGuard timers examined %ld, matched %ld, queued DPCs matched %ld.\n",
               g_TimerExamined,
               g_CancelledTimerCount,
               g_DpcRedirected);
    for (Sample = 0; Sample < g_TimerSampleCount && Sample < PATCH_GUARD_TIMER2_SAMPLE_LIMIT; Sample++)
    {
        HACDBG_LOG("HacDbg: PatchGuard timer sample timer %p routine %p context %p reason %s.\n",
                   g_TimerSamples[Sample].Timer,
                   g_TimerSamples[Sample].Callback,
                   g_TimerSamples[Sample].Context,
                   PatchGuardReasonName(g_TimerSamples[Sample].Reason));
    }

    HACDBG_LOG("HacDbg: PatchGuard disabled, cancelled %ld timer context(s) and %ld timer2 context(s).\n",
               g_CancelledTimerCount,
               g_CancelledTimer2Count);
    return STATUS_SUCCESS;
}

NTSTATUS
PatchGuardArmBugcheckHook(
    VOID
    )
{
    static const UCHAR Prologue[] = {
        0x48, 0x89, 0x4C, 0x24, 0x08,
        0x48, 0x89, 0x54, 0x24, 0x10,
        0x4C, 0x89, 0x44, 0x24, 0x18
    };
    UCHAR Trampoline[PATCH_GUARD_ABSOLUTE_JUMP];
    UCHAR ReturnPatch[1];
    PVOID Bugcheck;
    PVOID Stub;
    PVOID Stack;
    PVOID PageBases[PATCH_GUARD_HOOK_PAGE_COUNT];
    PVOID Shadows[PATCH_GUARD_HOOK_PAGE_COUNT];
    UINT64 PhysicalPages[PATCH_GUARD_HOOK_PAGE_COUNT];
    ULONG PageCount;
    ULONG Installed;
    ULONG Index;
    NTSTATUS Status;
    UCHAR ReturnByte;

    Bugcheck = PatchGuardFindExport(g_NtosBase, "KeBugCheckEx");
    if (Bugcheck == NULL || PatchGuardPointerInImage(Bugcheck) == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard KeBugCheckEx export was not found.\n");
        return STATUS_NOT_FOUND;
    }

    if (RtlEqualMemory(Bugcheck, Prologue, sizeof(Prologue)) == FALSE ||
        ((UCHAR*)Bugcheck)[PATCH_GUARD_BUGCHECK_PROLOGUE] != 0x4C)
    {
        HACDBG_LOG("HacDbg: Err, PatchGuard KeBugCheckEx prologue does not match.\n");
        return STATUS_REVISION_MISMATCH;
    }

    Stack = PatchGuardAllocateSwallowStack();
    Stub = PatchGuardAllocateExecutablePage();
    if (Stack == NULL || Stub == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PatchGuardEmitBugcheckStub((UCHAR*)Stub, (UCHAR*)Bugcheck + PATCH_GUARD_BUGCHECK_PROLOGUE, Stack);
    PatchGuardWriteAbsoluteJump(Trampoline, Stub);
    ReturnByte = (UCHAR)PATCH_GUARD_RET_PATCH0;
    ReturnPatch[0] = ReturnByte;
    PageCount = 0;
    RtlZeroMemory(PageBases, sizeof(PageBases));
    RtlZeroMemory(Shadows, sizeof(Shadows));
    RtlZeroMemory(PhysicalPages, sizeof(PhysicalPages));

    Status = PatchGuardInstallExecuteHook(Bugcheck,
                                          Trampoline,
                                          sizeof(Trampoline),
                                          PageBases,
                                          Shadows,
                                          PhysicalPages,
                                          &PageCount);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = PatchGuardInstallExecuteHook(g_CcBcbProfiler,
                                          ReturnPatch,
                                          sizeof(ReturnPatch),
                                          PageBases,
                                          Shadows,
                                          PhysicalPages,
                                          &PageCount);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = PatchGuardInstallExecuteHook(g_KiTimerDispatch,
                                          ReturnPatch,
                                          sizeof(ReturnPatch),
                                          PageBases,
                                          Shadows,
                                          PhysicalPages,
                                          &PageCount);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (g_CcBcbProfiler2 != NULL && PatchGuardPageResident(g_CcBcbProfiler2) != FALSE)
    {
        Status = PatchGuardInstallExecuteHook(g_CcBcbProfiler2,
                                              ReturnPatch,
                                              sizeof(ReturnPatch),
                                              PageBases,
                                              Shadows,
                                              PhysicalPages,
                                              &PageCount);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }
    else
    {
        HACDBG_LOG("HacDbg: PatchGuard CcBcbProfiler2 left unhooked.\n");
    }

    Installed = 0;
    for (Index = 0; Index < PageCount; Index++)
    {
        if (PATCH_GUARD_SLAT_ADD_HOOK(HacDbgGuestPhysicalAddress(PhysicalPages[Index]),
                                      HacDbgGuestPhysicalAddress(
                                          (UINT64)MmGetPhysicalAddress(Shadows[Index]).QuadPart)) == FALSE)
        {
            HACDBG_LOG("HacDbg: Err, PatchGuard execute hook failed for %p.\n", PageBases[Index]);
            break;
        }

        Installed += 1;
        HACDBG_LOG("HacDbg: PatchGuard execute hook %p pa 0x%I64x.\n",
                   PageBases[Index],
                   PhysicalPages[Index]);
    }

    if (Installed != PageCount || PatchGuardFlushTranslations() == FALSE)
    {
        for (Index = 0; Index < Installed; Index++)
        {
            PATCH_GUARD_SLAT_REMOVE_HOOK(HacDbgGuestPhysicalAddress(PhysicalPages[Index]));
        }

        HACDBG_LOG("HacDbg: Err, PatchGuard execute hook install failed.\n");
        return STATUS_UNSUCCESSFUL;
    }

    HACDBG_LOG("HacDbg: PatchGuard KeBugCheckEx %p stub %p.\n", Bugcheck, Stub);
    return STATUS_SUCCESS;
}

VOID
PatchGuardCleanup(
    VOID
    )
{
    ULONG Index;

    for (Index = 0; Index < g_HookAllocationCount; Index++)
    {
        if (g_HookAllocations[Index] != NULL)
        {
            ExFreePoolWithTag(g_HookAllocations[Index], 'PgaH');
            g_HookAllocations[Index] = NULL;
        }
    }

    g_HookAllocationCount = 0;
    if (g_SwallowStack != NULL)
    {
        ExFreePoolWithTag(g_SwallowStack, 'PgaH');
        g_SwallowStack = NULL;
    }
}

#else

NTSTATUS
PatchGuardDisable(
    VOID
    )
{
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
PatchGuardArmBugcheckHook(
    VOID
    )
{
    return STATUS_NOT_SUPPORTED;
}

VOID
PatchGuardCleanup(
    VOID
    )
{
}

#endif
