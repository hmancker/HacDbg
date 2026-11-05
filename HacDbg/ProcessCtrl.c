/**
 * @file ProcessCtrl.c
 * @brief Process controls that must run in the kernel at passive level.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <ntimage.h>

#include "Debug.h"
#include "Inject.h"
#include "ProcessCtrl.h"

#include "../shared/process_control.h"

#define PROCESS_CTRL_TAG 'cPaH'
#define PROCESS_CTRL_MAX_IMAGE (16u * 1024u * 1024u)
#define PROCESS_CTRL_VM_OPERATION 0x0008u
#define PROCESS_CTRL_VM_READ 0x0010u
#define PROCESS_CTRL_VM_WRITE 0x0020u
//
// PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE. Downgrade clears
// these bits and sets bit 25, NoRightsUpgrade. Elevate sets these bits and
// clears bit 25. Bits 26-31 stay as they were.
//
#define PROCESS_CTRL_STRIPPED_ACCESS (PROCESS_CTRL_VM_OPERATION | PROCESS_CTRL_VM_READ | PROCESS_CTRL_VM_WRITE)
#define PROCESS_CTRL_NO_RIGHTS_UPGRADE 0x02000000u
//
// HANDLE_TABLE.TableCode. The low 2 bits are the table level.
//
#define PROCESS_CTRL_HANDLE_TABLE_CODE 0x8u
//
// HANDLE_TABLE.UniqueProcessId.
//
#define PROCESS_CTRL_HANDLE_TABLE_PID 0x28u
//
// OBJECT_HEADER.Body.
//
#define PROCESS_CTRL_OBJECT_HEADER_BODY 0x30u
//
// Contention push lock. ntoskrnl26h2 ExEnumHandleTable reads HandleTable+0x30
// after the callback increments the entry.
//
#define PROCESS_CTRL_HANDLE_CONTENTION 0x30u
#define PROCESS_CTRL_MAX_PROCESSES 512u
#define PROCESS_CTRL_HANDLE_INTERVAL_MS 5000u
#define PROCESS_CTRL_HANDLE_IDLE_MS 200u
#define PROCESS_CTRL_IMAGE_CHARS 16u
#define PROCESS_CTRL_NT_PATH_CHARS 520u
#define PROCESS_CTRL_LINK_CHARS 128u
#define PROCESS_CTRL_PATH_PASSES 6u

typedef NTSTATUS(NTAPI* PROCESS_SUSPEND)(PEPROCESS Process);

static ULONG g_LinkOffset;
static ULONG g_PidOffset;
static ULONG g_ObjectTableOffset;
static ULONG g_ProtectionOffset;

typedef struct _PROCESS_CTRL_HANDLE_CONTROL
{
    FAST_MUTEX Lock;
    ULONG Mode;
    CHAR Actor[PROCESS_CTRL_IMAGE_CHARS];
    CHAR Victim[PROCESS_CTRL_IMAGE_CHARS];
} PROCESS_CTRL_HANDLE_CONTROL;

typedef struct _PROCESS_CTRL_HANDLE_CTX
{
    PEPROCESS Owner;
    PEPROCESS* Processes;
    ULONG ProcessCount;
    ULONG Mode;
    ULONG Changed;
    BOOLEAN FilterVictim;
    CHAR Victim[PROCESS_CTRL_IMAGE_CHARS];
    CHAR LastImage[PROCESS_CTRL_IMAGE_CHARS];
    ULONG LastPid;
    HANDLE LastHandle;
    ULONG LastAccess;
} PROCESS_CTRL_HANDLE_CTX;

typedef BOOLEAN(NTAPI* PROCESS_CTRL_ENUM_HANDLE)(PVOID HandleTable, PVOID HandleTableEntry, HANDLE Handle, PVOID Context);

static PROCESS_CTRL_HANDLE_CONTROL g_HandleCtrl;
static PEPROCESS g_HandleProcesses[PROCESS_CTRL_MAX_PROCESSES];
static PETHREAD g_HandleThread;
static PVOID g_NtBase;
static volatile LONG g_HandleRun;
static LONG g_HandleState;
static LONG g_HandlePass;

NTKERNELAPI PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

NTKERNELAPI
BOOLEAN
ExEnumHandleTable(PVOID HandleTable, PROCESS_CTRL_ENUM_HANDLE EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle);

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(PVOID PushLock, PVOID WaitBlock);

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);

C_ASSERT(HACDBG_HANDLE_NAME_CHARS * 2 <= HACDBG_PROCESS_PATH_CHARS);
C_ASSERT(PROCESS_CTRL_LINK_CHARS * sizeof(WCHAR) <= 0xFFFFu);
C_ASSERT(PROCESS_CTRL_NT_PATH_CHARS > HACDBG_PROCESS_PATH_CHARS);

static BOOLEAN
ProcessCtrlValidUser(UINT64 Value)
{
    return Value >= 0x10000ull && Value <= 0x00007FFFFFFEFFFFull;
}

static BOOLEAN
ProcessCtrlListMatches(PEPROCESS SystemProcess, ULONG Offset, ULONG PidOffset)
{
    LIST_ENTRY* Entry;
    LIST_ENTRY* Flink;
    UCHAR* Other;
    UINT64 Pid;

    if (PidOffset == 0 || Offset < 0x100 || Offset >= 0x1000)
    {
        return FALSE;
    }

    Entry = (LIST_ENTRY*)((UCHAR*)SystemProcess + Offset);
    if (MmIsAddressValid(Entry) == FALSE)
    {
        return FALSE;
    }

    Flink = Entry->Flink;
    if (MmIsAddressValid(Flink) == FALSE || MmIsAddressValid(Entry->Blink) == FALSE)
    {
        return FALSE;
    }

    if (Flink->Blink != Entry || Entry->Blink->Flink != Entry || Flink == Entry)
    {
        return FALSE;
    }

    if ((UCHAR*)Flink >= (UCHAR*)SystemProcess && (UCHAR*)Flink < (UCHAR*)SystemProcess + 0x1000)
    {
        return FALSE;
    }

    Other = (UCHAR*)Flink - Offset;
    if (MmIsAddressValid(Other + PidOffset) == FALSE)
    {
        return FALSE;
    }

    Pid = *(UINT64*)(Other + PidOffset);
    return Pid > 0 && Pid < 0x100000;
}

static ULONG
ProcessCtrlFindPidOffset(PEPROCESS SystemProcess)
{
    UNICODE_STRING Name;
    UCHAR* Code;
    ULONG Index;
    ULONG Offset;
    UINT64 SystemPid;

    //
    // PsGetProcessId is mov rax, [rcx+UniqueProcessId] ; ret.
    // 48 8B 81 imm32 is the disp32 form. 26H2 ntoskrnl 10.0.26100.9711 uses
    // displacement 0x1D0. 48 8B 41 imm8 is the disp8 form.
    //
    SystemPid = (UINT64)(ULONG_PTR)PsGetProcessId(SystemProcess);
    RtlInitUnicodeString(&Name, L"PsGetProcessId");
    Code = (UCHAR*)MmGetSystemRoutineAddress(&Name);
    if (Code != NULL)
    {
        for (Index = 0; Index < 24; Index++)
        {
            if (Code[Index] == 0x48 && Code[Index + 1] == 0x8B && Code[Index + 2] == 0x81)
            {
                Offset = *(ULONG*)(Code + Index + 3);
            }
            else if (Code[Index] == 0x48 && Code[Index + 1] == 0x8B && Code[Index + 2] == 0x41)
            {
                Offset = Code[Index + 3];
            }
            else
            {
                continue;
            }

            if (Offset >= 0x100 && Offset < 0x1000 &&
                *(UINT64*)((UCHAR*)SystemProcess + Offset) == SystemPid)
            {
                return Offset;
            }
        }
    }

    for (Offset = 0x100; Offset < 0x800; Offset += 8)
    {
        if (*(UINT64*)((UCHAR*)SystemProcess + Offset) == SystemPid &&
            ProcessCtrlListMatches(SystemProcess, Offset + (ULONG)sizeof(UINT64), Offset) != FALSE)
        {
            return Offset;
        }
    }

    return 0;
}

static ULONG
ProcessCtrlFindLinkOffset(PEPROCESS SystemProcess, ULONG PidOffset)
{
    ULONG Offset;

    if (PidOffset == 0 || PidOffset >= 0x1000u - (ULONG)sizeof(UINT64))
    {
        return 0;
    }

    //
    // ActiveProcessLinks is the LIST_ENTRY that follows UniqueProcessId.
    // On 26H2 that is 0x1D0 and 0x1D8.
    //
    Offset = PidOffset + (ULONG)sizeof(UINT64);
    if (ProcessCtrlListMatches(SystemProcess, Offset, PidOffset) != FALSE)
    {
        return Offset;
    }

    for (Offset = 0x100; Offset < 0x900; Offset += 8)
    {
        if (ProcessCtrlListMatches(SystemProcess, Offset, PidOffset) != FALSE)
        {
            return Offset;
        }
    }

    return 0;
}

static ULONG
ProcessCtrlFindProtectionOffset(VOID)
{
    UNICODE_STRING Name;
    UCHAR* Code;
    ULONG Index;

    RtlInitUnicodeString(&Name, L"PsIsProtectedProcess");
    Code = (UCHAR*)MmGetSystemRoutineAddress(&Name);
    if (Code == NULL)
    {
        return 0;
    }

    for (Index = 0; Index < 64; Index++)
    {
        if (Code[Index] == 0x0F && Code[Index + 1] == 0xB6 && Code[Index + 2] == 0x81)
        {
            return *(ULONG*)(Code + Index + 3);
        }

        if (Code[Index] == 0x8A && Code[Index + 1] == 0x81)
        {
            return *(ULONG*)(Code + Index + 2);
        }
    }

    return 0;
}

static UCHAR
ProcessCtrlPplByte(ULONG Parameter)
{
    switch (Parameter)
    {
    case HACDBG_PPL_ANTIMALWARE:
        return (UCHAR)((3u << 4) | 1u);
    case HACDBG_PPL_WINDOWS:
        return (UCHAR)((5u << 4) | 1u);
    case HACDBG_PPL_WINTCB_LIGHT:
        return (UCHAR)((6u << 4) | 1u);
    case HACDBG_PPL_WINTCB:
        return (UCHAR)((6u << 4) | 2u);
    default:
        return 0;
    }
}

static NTSTATUS
ProcessCtrlOpen(ULONG Pid, PEPROCESS* Process, HANDLE* Handle)
{
    NTSTATUS Status;

    *Process = NULL;
    *Handle = NULL;
    if (Pid == 0 || Pid == 4)
    {
        return STATUS_ACCESS_DENIED;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ObOpenObjectByPointer(*Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS,
                                   *PsProcessType, KernelMode, Handle);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(*Process);
        *Process = NULL;
    }

    return Status;
}

static VOID
ProcessCtrlClose(PEPROCESS Process, HANDLE Handle)
{
    if (Handle != NULL)
    {
        ZwClose(Handle);
    }

    if (Process != NULL)
    {
        ObDereferenceObject(Process);
    }
}

static NTSTATUS
ProcessCtrlTerminate(ULONG Pid, BOOLEAN ClearProtection)
{
    PEPROCESS Process;
    HANDLE Handle;
    NTSTATUS Status;
    ULONG ProtectionOffset;

    Status = ProcessCtrlOpen(Pid, &Process, &Handle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (ClearProtection != FALSE)
    {
        ProtectionOffset = g_ProtectionOffset != 0 ? g_ProtectionOffset : ProcessCtrlFindProtectionOffset();
        g_ProtectionOffset = ProtectionOffset;
        if (ProtectionOffset != 0 && ProtectionOffset < 0x1000)
        {
            ((UCHAR*)Process)[ProtectionOffset] = 0;
        }
    }

    Status = ZwTerminateProcess(Handle, STATUS_SUCCESS);
    ProcessCtrlClose(Process, Handle);
    return Status;
}

static NTSTATUS
ProcessCtrlSuspend(ULONG Pid, BOOLEAN Resume)
{
    UNICODE_STRING Name;
    PROCESS_SUSPEND Routine;
    PEPROCESS Process;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Resume != FALSE ? L"PsResumeProcess" : L"PsSuspendProcess");
    Routine = (PROCESS_SUSPEND)MmGetSystemRoutineAddress(&Name);
    if (Routine == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = Routine(Process);
    ObDereferenceObject(Process);
    return Status;
}

static NTSTATUS
ProcessCtrlHide(ULONG Pid)
{
    PEPROCESS Process;
    PEPROCESS System;
    NTSTATUS Status;
    LIST_ENTRY* Entry;

    if (g_LinkOffset == 0 || g_PidOffset == 0)
    {
        System = PsInitialSystemProcess;
        g_PidOffset = ProcessCtrlFindPidOffset(System);
        g_LinkOffset = ProcessCtrlFindLinkOffset(System, g_PidOffset);
    }

    if (g_LinkOffset == 0)
    {
        return STATUS_NOT_FOUND;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Entry = (LIST_ENTRY*)((UCHAR*)Process + g_LinkOffset);
    if (MmIsAddressValid(Entry) == FALSE || MmIsAddressValid(Entry->Flink) == FALSE ||
        MmIsAddressValid(Entry->Blink) == FALSE || Entry->Flink->Blink != Entry ||
        Entry->Blink->Flink != Entry)
    {
        ObDereferenceObject(Process);
        return STATUS_INVALID_ADDRESS;
    }

    Entry->Blink->Flink = Entry->Flink;
    Entry->Flink->Blink = Entry->Blink;
    Entry->Flink = Entry;
    Entry->Blink = Entry;
    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

static BOOLEAN
ProcessCtrlKernelPointer(UINT64 Value)
{
    return Value >= 0xFFFF800000000000ull && Value < 0xFFFFFFFFFFFFF000ull && (Value & 7ull) == 0;
}

static ULONG
ProcessCtrlImageNameOffset(VOID)
{
    UNICODE_STRING Name;
    UCHAR* Code;
    ULONG Index;
    ULONG Offset;

    //
    // PsGetProcessImageFileName is lea rax, [rcx+ImageFileName].
    // 48 8D 81 imm32 is the disp32 form. 26H2 ntoskrnl 10.0.26100.9711
    // uses displacement 0x338.
    //
    RtlInitUnicodeString(&Name, L"PsGetProcessImageFileName");
    Code = (UCHAR*)MmGetSystemRoutineAddress(&Name);
    if (Code == NULL)
    {
        return 0;
    }

    for (Index = 0; Index < 16; Index++)
    {
        if (Code[Index] == 0x48 && Code[Index + 1] == 0x8D && Code[Index + 2] == 0x81)
        {
            Offset = *(ULONG*)(Code + Index + 3);
        }
        else if (Code[Index] == 0x48 && Code[Index + 1] == 0x8D && Code[Index + 2] == 0x41)
        {
            Offset = Code[Index + 3];
        }
        else
        {
            continue;
        }

        if (Offset >= 0x100 && Offset < 0x1000)
        {
            return Offset;
        }
    }

    return 0;
}

static ULONG
ProcessCtrlObjectTableForImage(ULONG ImageOffset)
{
    //
    // Vergilius 24H2 and 25H2 _EPROCESS put ImageFileName at 0x338 and
    // ObjectTable at 0x300. The 26H2 ntoskrnl 10.0.26100.9711 reads that
    // field with mov rdi, [rdi+300h]. Vergilius 21H2 through 23H2 puts
    // ImageFileName at 0x5A8 and ObjectTable at 0x570.
    //
    if (ImageOffset == 0x338)
    {
        return 0x300;
    }

    if (ImageOffset == 0x5A8)
    {
        return 0x570;
    }

    return 0;
}

static ULONG
ProcessCtrlFindObjectTableOffset(PEPROCESS Process)
{
    ULONG Known;
    ULONG Pid;
    ULONG Offset;
    UCHAR* Table;
    UINT64 TableCode;

    Known = ProcessCtrlObjectTableForImage(ProcessCtrlImageNameOffset());
    if (Known != 0)
    {
        Table = *(UCHAR**)((UCHAR*)Process + Known);
        if (ProcessCtrlKernelPointer((UINT64)Table) != FALSE)
        {
            return Known;
        }
    }

    Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
    for (Offset = 0x100; Offset < 0x900; Offset += 8)
    {
        Table = *(UCHAR**)((UCHAR*)Process + Offset);
        if (ProcessCtrlKernelPointer((UINT64)Table) == FALSE)
        {
            continue;
        }

        if (*(ULONG*)(Table + PROCESS_CTRL_HANDLE_TABLE_PID) != Pid)
        {
            continue;
        }

        TableCode = *(UINT64*)(Table + PROCESS_CTRL_HANDLE_TABLE_CODE);
        if ((TableCode & 3ull) > 2 || ProcessCtrlKernelPointer(TableCode & ~3ull) == FALSE)
        {
            continue;
        }

        return Offset;
    }

    return 0;
}

static BOOLEAN
ProcessCtrlHandleElevate(ULONG Mode)
{
    return Mode == HACDBG_HANDLE_UPGRADE_ALL || Mode == HACDBG_HANDLE_UPGRADE_NAME;
}

static BOOLEAN
ProcessCtrlHandleNamed(ULONG Mode)
{
    return Mode == HACDBG_HANDLE_DOWNGRADE_NAME || Mode == HACDBG_HANDLE_UPGRADE_NAME;
}

static VOID
ProcessCtrlCopyImageName(PEPROCESS Process, CHAR Name[PROCESS_CTRL_IMAGE_CHARS])
{
    PUCHAR Image;

    RtlZeroMemory(Name, PROCESS_CTRL_IMAGE_CHARS);
    Image = PsGetProcessImageFileName(Process);
    if (Image != NULL)
    {
        RtlCopyMemory(Name, Image, 15);
    }
}

static VOID
ProcessCtrlLowerCopy15(const CHAR* Source, CHAR Dest[PROCESS_CTRL_IMAGE_CHARS])
{
    ULONG Index;

    RtlZeroMemory(Dest, PROCESS_CTRL_IMAGE_CHARS);
    if (Source == NULL)
    {
        return;
    }

    for (Index = 0; Index < 15 && Source[Index] != '\0'; Index++)
    {
        CHAR Ch;

        Ch = Source[Index];
        if (Ch >= 'A' && Ch <= 'Z')
        {
            Ch = (CHAR)(Ch - 'A' + 'a');
        }

        Dest[Index] = Ch;
    }
}

static BOOLEAN
ProcessCtrlTextStartsWith(const CHAR* Text, const CHAR* Prefix)
{
    ULONG Index;

    if (Prefix == NULL || Prefix[0] == '\0')
    {
        return FALSE;
    }

    for (Index = 0; Prefix[Index] != '\0'; Index++)
    {
        if (Text[Index] != Prefix[Index])
        {
            return FALSE;
        }
    }

    return TRUE;
}

static VOID
ProcessCtrlStripExe(const CHAR* Source, CHAR Dest[PROCESS_CTRL_IMAGE_CHARS])
{
    ULONG Index;
    ULONG Length;

    RtlZeroMemory(Dest, PROCESS_CTRL_IMAGE_CHARS);
    Length = 0;
    for (Index = 0; Index < 15 && Source[Index] != '\0'; Index++)
    {
        Dest[Index] = Source[Index];
        Length++;
    }

    if (Length >= 4 && Dest[Length - 4] == '.' && Dest[Length - 3] == 'e' && Dest[Length - 2] == 'x' &&
        Dest[Length - 1] == 'e')
    {
        Dest[Length - 4] = '\0';
    }
}

static BOOLEAN
ProcessCtrlImageMatches(const CHAR* Image, const CHAR* Target)
{
    CHAR ImageLower[PROCESS_CTRL_IMAGE_CHARS];
    CHAR TargetLower[PROCESS_CTRL_IMAGE_CHARS];
    CHAR ImageBase[PROCESS_CTRL_IMAGE_CHARS];
    CHAR TargetBase[PROCESS_CTRL_IMAGE_CHARS];

    if (Target == NULL || Target[0] == '\0')
    {
        return FALSE;
    }

    ProcessCtrlLowerCopy15(Image, ImageLower);
    ProcessCtrlLowerCopy15(Target, TargetLower);
    if (ImageLower[0] == '\0')
    {
        return FALSE;
    }

    if (ProcessCtrlTextStartsWith(ImageLower, TargetLower) != FALSE ||
        ProcessCtrlTextStartsWith(TargetLower, ImageLower) != FALSE)
    {
        return TRUE;
    }

    ProcessCtrlStripExe(ImageLower, ImageBase);
    ProcessCtrlStripExe(TargetLower, TargetBase);
    if (ImageBase[0] == '\0' || TargetBase[0] == '\0')
    {
        return FALSE;
    }

    return ProcessCtrlTextStartsWith(ImageBase, TargetBase) != FALSE ||
           ProcessCtrlTextStartsWith(TargetBase, ImageBase) != FALSE;
}

static BOOLEAN
ProcessCtrlEqualText(const CHAR* Left, const CHAR* Right)
{
    ULONG Index;

    if (Left == NULL || Right == NULL)
    {
        return FALSE;
    }

    for (Index = 0; Index < PROCESS_CTRL_IMAGE_CHARS; Index++)
    {
        if (Left[Index] != Right[Index])
        {
            return FALSE;
        }

        if (Left[Index] == '\0')
        {
            return TRUE;
        }
    }

    return TRUE;
}

static BOOLEAN
ProcessCtrlContainsAscii(const CHAR* Text, const CHAR* Needle)
{
    ULONG NeedleLength;
    ULONG TextLength;
    ULONG Index;
    ULONG Inner;

    if (Text == NULL || Needle == NULL || Needle[0] == '\0')
    {
        return FALSE;
    }

    NeedleLength = 0;
    while (Needle[NeedleLength] != '\0' && NeedleLength < 15)
    {
        NeedleLength++;
    }

    TextLength = 0;
    while (Text[TextLength] != '\0' && TextLength < 15)
    {
        TextLength++;
    }

    if (NeedleLength == 0 || NeedleLength > TextLength)
    {
        return FALSE;
    }

    for (Index = 0; Index + NeedleLength <= TextLength; Index++)
    {
        for (Inner = 0; Inner < NeedleLength; Inner++)
        {
            if (Text[Index + Inner] != Needle[Inner])
            {
                break;
            }
        }

        if (Inner == NeedleLength)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
ProcessCtrlIsActorImage(const CHAR* Image, const CHAR* Actor)
{
    CHAR Lower[PROCESS_CTRL_IMAGE_CHARS];

    if (ProcessCtrlImageMatches(Image, Actor) != FALSE)
    {
        return TRUE;
    }

    if (ProcessCtrlEqualText(Actor, "cheatengine") == FALSE)
    {
        return FALSE;
    }

    ProcessCtrlLowerCopy15(Image, Lower);
    return ProcessCtrlContainsAscii(Lower, "cheatengine") != FALSE || ProcessCtrlTextStartsWith(Lower, "cheat eng") != FALSE;
}

static BOOLEAN
ProcessCtrlBuildAnsiName(const WCHAR* Name, CHAR Ansi[PROCESS_CTRL_IMAGE_CHARS])
{
    const WCHAR* Base;
    const WCHAR* Cursor;
    ULONG Index;

    RtlZeroMemory(Ansi, PROCESS_CTRL_IMAGE_CHARS);
    if (Name == NULL)
    {
        return FALSE;
    }

    Base = Name;
    for (Cursor = Name; *Cursor != L'\0'; Cursor++)
    {
        if (*Cursor == L'\\' || *Cursor == L'/')
        {
            Base = Cursor + 1;
        }
    }

    if (Base[0] == L'\0')
    {
        return FALSE;
    }

    for (Index = 0; Base[Index] != L'\0' && Index < HACDBG_HANDLE_NAME_CHARS - 1; Index++)
    {
        if (Base[Index] > 0x7F)
        {
            RtlZeroMemory(Ansi, PROCESS_CTRL_IMAGE_CHARS);
            return FALSE;
        }
    }

    for (Index = 0; Index < 15 && Base[Index] != L'\0'; Index++)
    {
        WCHAR Ch;

        Ch = Base[Index];
        if (Ch >= L'A' && Ch <= L'Z')
        {
            Ch = (WCHAR)(Ch - L'A' + L'a');
        }

        Ansi[Index] = (CHAR)Ch;
    }

    return Ansi[0] != '\0';
}

static PVOID
ProcessCtrlDecodeHandleObject(UINT64 LowValue)
{
    UINT64 Pointer;

    //
    // ExGetHandlePointer is sar rax, 16; and rax, ~0xF. A logical shift
    // drops the kernel sign bits, and the pointer then matches nothing.
    //
    Pointer = ((UINT64)((LONG64)LowValue >> 16)) & 0xFFFFFFFFFFFFFFF0ull;
    if (Pointer < 0xFFFF800000000000ull)
    {
        return NULL;
    }

    return (PVOID)Pointer;
}

static PEPROCESS
ProcessCtrlMatchProcess(PVOID Object, PROCESS_CTRL_HANDLE_CTX* Ctx)
{
    ULONG_PTR Value;
    ULONG_PTR Sign;
    ULONG Index;

    Value = (ULONG_PTR)Object;
    Sign = Value;
    if ((Value & (1ull << 47)) != 0)
    {
        Sign |= 0xFFFF000000000000ull;
    }

    for (Index = 0; Index < Ctx->ProcessCount; Index++)
    {
        ULONG_PTR Target;

        Target = (ULONG_PTR)Ctx->Processes[Index];
        if (Value == Target || Value + PROCESS_CTRL_OBJECT_HEADER_BODY == Target)
        {
            return Ctx->Processes[Index];
        }

        if (Sign == Target || Sign + PROCESS_CTRL_OBJECT_HEADER_BODY == Target)
        {
            return Ctx->Processes[Index];
        }
    }

    return NULL;
}

static VOID
ProcessCtrlUnlockHandleEntry(PVOID HandleTable, PVOID Entry)
{
    LONG Barrier;

    if (Entry == NULL)
    {
        return;
    }

    //
    // INVARIANT: Entry is the handle-table entry ExEnumHandleTable passed in.
    // The kernel cleared bit 0 before the call. Incrementing the entry releases
    // that bit. HandleTable+0x30 is the contention push lock for this Germanium
    // HANDLE_TABLE. The page is the actor process handle table, not a guest page.
    // Skipping the increment leaves that process's handle-table lock held.
    //
    InterlockedIncrement64((LONG64 volatile*)Entry);
    Barrier = 0;
    InterlockedOr(&Barrier, 0);
    if (HandleTable != NULL && *(UINT64 volatile*)((UCHAR*)HandleTable + PROCESS_CTRL_HANDLE_CONTENTION) != 0)
    {
        ExfUnblockPushLock((UCHAR*)HandleTable + PROCESS_CTRL_HANDLE_CONTENTION, NULL);
    }
}

static BOOLEAN
ProcessCtrlApplyAccess(PVOID Entry, ULONG Access, ULONG Mode)
{
    ULONG Updated;

    if (ProcessCtrlHandleElevate(Mode) != FALSE)
    {
        if ((Access & PROCESS_CTRL_STRIPPED_ACCESS) == PROCESS_CTRL_STRIPPED_ACCESS &&
            (Access & PROCESS_CTRL_NO_RIGHTS_UPGRADE) == 0)
        {
            return FALSE;
        }

        Updated = (Access | PROCESS_CTRL_STRIPPED_ACCESS) & ~PROCESS_CTRL_NO_RIGHTS_UPGRADE;
    }
    else
    {
        if ((Access & PROCESS_CTRL_STRIPPED_ACCESS) == 0)
        {
            return FALSE;
        }

        Updated = (Access & ~PROCESS_CTRL_STRIPPED_ACCESS) | PROCESS_CTRL_NO_RIGHTS_UPGRADE;
    }

    InterlockedExchange((LONG volatile*)((UCHAR*)Entry + 8), (LONG)Updated);
    return TRUE;
}

static BOOLEAN NTAPI
ProcessCtrlEnumHandle(PVOID HandleTable, PVOID HandleTableEntry, HANDLE Handle, PVOID EnumParameter)
{
    PROCESS_CTRL_HANDLE_CTX* Ctx;
    UINT64 LowValue;
    PVOID Object;
    ULONG Access;
    PEPROCESS Victim;
    CHAR VictimName[PROCESS_CTRL_IMAGE_CHARS];

    Ctx = (PROCESS_CTRL_HANDLE_CTX*)EnumParameter;
    if (HandleTableEntry != NULL && Ctx != NULL)
    {
        LowValue = *(UINT64 volatile*)HandleTableEntry;
        Object = ProcessCtrlDecodeHandleObject(LowValue);
        Access = *(ULONG volatile*)((UCHAR*)HandleTableEntry + 8);
        if (Object != NULL)
        {
            Victim = ProcessCtrlMatchProcess(Object, Ctx);
            if (Victim != NULL && Victim != Ctx->Owner)
            {
                BOOLEAN Take;

                Take = TRUE;
                ProcessCtrlCopyImageName(Victim, VictimName);
                if (Ctx->FilterVictim != FALSE && ProcessCtrlImageMatches(VictimName, Ctx->Victim) == FALSE)
                {
                    Take = FALSE;
                }

                if (Take != FALSE)
                {
                    if (ProcessCtrlApplyAccess(HandleTableEntry, Access, Ctx->Mode) != FALSE)
                    {
                        Ctx->Changed++;
                        RtlCopyMemory(Ctx->LastImage, VictimName, PROCESS_CTRL_IMAGE_CHARS);
                        Ctx->LastPid = *(ULONG*)((UCHAR*)Victim + g_PidOffset);
                        Ctx->LastHandle = Handle;
                        Ctx->LastAccess = Access;
                    }
                }
            }
        }
    }

    ProcessCtrlUnlockHandleEntry(HandleTable, HandleTableEntry);
    return FALSE;
}

static BOOLEAN
ProcessCtrlSentinelLink(LIST_ENTRY* Link)
{
    ULONG_PTR Value;
    ULONG_PTR Base;

    Value = (ULONG_PTR)Link;
    Base = (ULONG_PTR)g_NtBase;
    if (Value < 0xFFFF800000000000ull)
    {
        return TRUE;
    }

    if (Base != 0 && Value >= Base && Value < Base + 0x2000000ull)
    {
        return TRUE;
    }

    return FALSE;
}

static ULONG
ProcessCtrlCollectProcesses(PEPROCESS* Processes)
{
    PEPROCESS Start;
    LIST_ENTRY* Head;
    LIST_ENTRY* Link;
    ULONG Count;

    Start = PsInitialSystemProcess;
    Count = 0;
    if (Start == NULL || g_LinkOffset == 0)
    {
        return 0;
    }

    Head = (LIST_ENTRY*)((UCHAR*)Start + g_LinkOffset);
    Link = Head->Flink;
    while (Link != NULL && Link != Head && Count < PROCESS_CTRL_MAX_PROCESSES && g_HandleRun != 0)
    {
        LIST_ENTRY* Next;
        PEPROCESS Process;

        Next = Link->Flink;
        if (ProcessCtrlSentinelLink(Link) != FALSE)
        {
            Link = Next;
            continue;
        }

        Process = (PEPROCESS)((UCHAR*)Link - g_LinkOffset);
        if (ObReferenceObjectSafe(Process) != FALSE)
        {
            Processes[Count] = Process;
            Count++;
        }

        Link = Next;
    }

    return Count;
}

static VOID
ProcessCtrlReleaseProcesses(PEPROCESS* Processes, ULONG Count)
{
    ULONG Index;

    for (Index = 0; Index < Count; Index++)
    {
        ObDereferenceObject(Processes[Index]);
    }
}

static ULONG
ProcessCtrlReadHandleMode(CHAR Actor[PROCESS_CTRL_IMAGE_CHARS], CHAR Victim[PROCESS_CTRL_IMAGE_CHARS])
{
    ULONG Mode;

    ExAcquireFastMutex(&g_HandleCtrl.Lock);
    Mode = g_HandleCtrl.Mode;
    RtlCopyMemory(Actor, g_HandleCtrl.Actor, PROCESS_CTRL_IMAGE_CHARS);
    RtlCopyMemory(Victim, g_HandleCtrl.Victim, PROCESS_CTRL_IMAGE_CHARS);
    ExReleaseFastMutex(&g_HandleCtrl.Lock);
    return Mode;
}

static VOID
ProcessCtrlStoreHandleMode(ULONG Mode, const CHAR* Actor, const CHAR* Victim)
{
    ExAcquireFastMutex(&g_HandleCtrl.Lock);
    g_HandleCtrl.Mode = Mode;
    if (Mode == HACDBG_HANDLE_STOP || Actor == NULL)
    {
        RtlZeroMemory(g_HandleCtrl.Actor, sizeof(g_HandleCtrl.Actor));
        RtlZeroMemory(g_HandleCtrl.Victim, sizeof(g_HandleCtrl.Victim));
    }
    else
    {
        RtlCopyMemory(g_HandleCtrl.Actor, Actor, PROCESS_CTRL_IMAGE_CHARS);
        if (ProcessCtrlHandleNamed(Mode) != FALSE && Victim != NULL)
        {
            RtlCopyMemory(g_HandleCtrl.Victim, Victim, PROCESS_CTRL_IMAGE_CHARS);
        }
        else
        {
            RtlZeroMemory(g_HandleCtrl.Victim, sizeof(g_HandleCtrl.Victim));
        }
    }

    ExReleaseFastMutex(&g_HandleCtrl.Lock);
}

static BOOLEAN
ProcessCtrlSameRequest(ULONG Mode, const CHAR* Actor, const CHAR* Victim)
{
    CHAR CurrentActor[PROCESS_CTRL_IMAGE_CHARS];
    CHAR CurrentVictim[PROCESS_CTRL_IMAGE_CHARS];
    ULONG Current;

    Current = ProcessCtrlReadHandleMode(CurrentActor, CurrentVictim);
    if (Current != Mode)
    {
        return FALSE;
    }

    return ProcessCtrlEqualText(CurrentActor, Actor) != FALSE && ProcessCtrlEqualText(CurrentVictim, Victim) != FALSE;
}

static ULONG
ProcessCtrlApplyActorHandles(PEPROCESS* Processes, ULONG ProcessCount, ULONG Mode, const CHAR* Actor, const CHAR* Victim)
{
    ULONG Index;
    ULONG Owners;
    ULONG Changed;
    LONG Pass;

    Owners = 0;
    Changed = 0;
    Pass = InterlockedIncrement(&g_HandlePass);
    for (Index = 0; Index < ProcessCount && g_HandleRun != 0; Index++)
    {
        PROCESS_CTRL_HANDLE_CTX Ctx;
        PVOID Table;
        CHAR Name[PROCESS_CTRL_IMAGE_CHARS];

        ProcessCtrlCopyImageName(Processes[Index], Name);
        if (ProcessCtrlIsActorImage(Name, Actor) == FALSE)
        {
            continue;
        }

        Owners++;
        Table = *(PVOID*)((UCHAR*)Processes[Index] + g_ObjectTableOffset);
        if ((ULONG_PTR)Table < 0xFFFF800000000000ull)
        {
            HACDBG_LOG("HacDbg: Err, handle table image %s table %p.\n", Name, Table);
            continue;
        }

        RtlZeroMemory(&Ctx, sizeof(Ctx));
        Ctx.Owner = Processes[Index];
        Ctx.Processes = Processes;
        Ctx.ProcessCount = ProcessCount;
        Ctx.Mode = Mode;
        Ctx.FilterVictim = ProcessCtrlHandleNamed(Mode);
        if (Victim != NULL)
        {
            RtlCopyMemory(Ctx.Victim, Victim, PROCESS_CTRL_IMAGE_CHARS);
        }

        //
        // INVARIANT: Table is this actor's HANDLE_TABLE. ObjectTable is 0x300
        // and the contention push lock is Table+0x30 on the checked Germanium
        // layout. ExEnumHandleTable locks one entry at a time. The callback
        // unlocks that entry before it returns, so the walk does not hold a
        // handle-table lock across processes.
        //
        ExEnumHandleTable(Table, ProcessCtrlEnumHandle, &Ctx, NULL);
        Changed += Ctx.Changed;
        if (Ctx.Changed != 0)
        {
            ULONG ActorPid;

            ActorPid = *(ULONG*)((UCHAR*)Processes[Index] + g_PidOffset);
            HACDBG_LOG("HacDbg: Handle %s actor %s pid %lu victim %s pid %lu handle %p old 0x%08x count %lu.\n",
                       ProcessCtrlHandleElevate(Mode) != FALSE ? "elevated" : "downgraded", Name, ActorPid, Ctx.LastImage,
                       Ctx.LastPid, Ctx.LastHandle, Ctx.LastAccess, Ctx.Changed);
        }
    }

    if (Owners == 0 && (Pass % 12) == 1)
    {
        HACDBG_LOG("HacDbg: Err, handle actor not found: %s.\n", Actor);
    }

    return Changed;
}

static VOID
ProcessCtrlSleepMs(ULONG Milliseconds)
{
    LARGE_INTEGER Delay;

    Delay.QuadPart = -10000LL * (LONGLONG)Milliseconds;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

static VOID
ProcessCtrlSleepActive(ULONG Mode, const CHAR* Actor, const CHAR* Victim)
{
    ULONG Left;

    Left = PROCESS_CTRL_HANDLE_INTERVAL_MS;
    while (Left > 0 && g_HandleRun != 0)
    {
        ULONG Slice;

        Slice = Left > PROCESS_CTRL_HANDLE_IDLE_MS ? PROCESS_CTRL_HANDLE_IDLE_MS : Left;
        ProcessCtrlSleepMs(Slice);
        Left -= Slice;
        if (ProcessCtrlSameRequest(Mode, Actor, Victim) == FALSE)
        {
            break;
        }
    }
}

static VOID
ProcessCtrlHandleWorker(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    while (g_HandleRun != 0)
    {
        CHAR Actor[PROCESS_CTRL_IMAGE_CHARS];
        CHAR Victim[PROCESS_CTRL_IMAGE_CHARS];
        ULONG Mode;
        ULONG Count;

        Mode = ProcessCtrlReadHandleMode(Actor, Victim);
        if (Mode == HACDBG_HANDLE_STOP || Actor[0] == '\0' ||
            (ProcessCtrlHandleNamed(Mode) != FALSE && Victim[0] == '\0'))
        {
            ProcessCtrlSleepMs(PROCESS_CTRL_HANDLE_IDLE_MS);
            continue;
        }

        Count = ProcessCtrlCollectProcesses(g_HandleProcesses);
        ProcessCtrlApplyActorHandles(g_HandleProcesses, Count, Mode, Actor, Victim);
        ProcessCtrlReleaseProcesses(g_HandleProcesses, Count);
        ProcessCtrlSleepActive(Mode, Actor, Victim);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS
ProcessCtrlEnsureHandleWorker(VOID)
{
    HANDLE Thread;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;

    if (g_HandleRun == 0 && g_HandleState != 0)
    {
        return STATUS_DELETE_PENDING;
    }

    if (InterlockedCompareExchange(&g_HandleState, 1, 0) != 0)
    {
        while (g_HandleState == 1)
        {
            YieldProcessor();
        }

        return g_HandleState == 2 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    ExInitializeFastMutex(&g_HandleCtrl.Lock);
    g_HandleCtrl.Mode = HACDBG_HANDLE_STOP;
    RtlZeroMemory(g_HandleCtrl.Actor, sizeof(g_HandleCtrl.Actor));
    RtlZeroMemory(g_HandleCtrl.Victim, sizeof(g_HandleCtrl.Victim));
    g_HandleRun = 1;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, &Attributes, NULL, NULL, ProcessCtrlHandleWorker, NULL);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, handle thread start failed: 0x%08x.\n", Status);
        g_HandleRun = 0;
        InterlockedExchange(&g_HandleState, 0);
        return Status;
    }

    Status = ObReferenceObjectByHandle(Thread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&g_HandleThread, NULL);
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, handle thread object failed: 0x%08x.\n", Status);
        g_HandleRun = 0;
        g_HandleThread = NULL;
        ZwWaitForSingleObject(Thread, FALSE, NULL);
        ZwClose(Thread);
        InterlockedExchange(&g_HandleState, 0);
        return Status;
    }

    ZwClose(Thread);
    InterlockedExchange(&g_HandleState, 2);
    return STATUS_SUCCESS;
}

static NTSTATUS
ProcessCtrlPrepareHandleLayout(VOID)
{
    PEPROCESS System;

    System = PsInitialSystemProcess;
    if (System == NULL)
    {
        return STATUS_NOT_FOUND;
    }

    if (g_LinkOffset == 0 || g_PidOffset == 0)
    {
        g_PidOffset = ProcessCtrlFindPidOffset(System);
        g_LinkOffset = ProcessCtrlFindLinkOffset(System, g_PidOffset);
    }

    if (g_ObjectTableOffset == 0)
    {
        g_ObjectTableOffset = ProcessCtrlFindObjectTableOffset(System);
    }

    if (g_LinkOffset == 0 || g_PidOffset == 0 || g_ObjectTableOffset == 0)
    {
        HACDBG_LOG("HacDbg: Err, handle offsets link 0x%lx object 0x%lx.\n", g_LinkOffset, g_ObjectTableOffset);
        return STATUS_NOT_FOUND;
    }

    if (g_PidOffset != 0x1D0 || g_LinkOffset != 0x1D8 || g_ObjectTableOffset != 0x300)
    {
        HACDBG_LOG("HacDbg: Err, handle layout pid 0x%lx link 0x%lx object 0x%lx.\n", g_PidOffset, g_LinkOffset,
                   g_ObjectTableOffset);
        return STATUS_NOT_SUPPORTED;
    }

    if (*(UINT64*)((UCHAR*)System + g_PidOffset) != 4)
    {
        HACDBG_LOG("HacDbg: Err, handle layout system pid mismatch.\n");
        return STATUS_NOT_SUPPORTED;
    }

    if (g_NtBase == NULL)
    {
        RtlPcToFileHeader((PVOID)ExEnumHandleTable, &g_NtBase);
    }

    if (g_NtBase == NULL)
    {
        HACDBG_LOG("HacDbg: Err, handle ntoskrnl base missing.\n");
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
ProcessCtrlProtectHandle(HACDBG_PROCESS_REQUEST* Request)
{
    WCHAR* ActorName;
    WCHAR* VictimName;
    CHAR Actor[PROCESS_CTRL_IMAGE_CHARS];
    CHAR Victim[PROCESS_CTRL_IMAGE_CHARS];
    ULONG Parameter;
    NTSTATUS Status;

    if (Request == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Parameter = Request->Parameter;
    if (Parameter != HACDBG_HANDLE_STOP && Parameter != HACDBG_HANDLE_DOWNGRADE_ALL &&
        Parameter != HACDBG_HANDLE_DOWNGRADE_NAME && Parameter != HACDBG_HANDLE_UPGRADE_ALL &&
        Parameter != HACDBG_HANDLE_UPGRADE_NAME)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Parameter == HACDBG_HANDLE_STOP)
    {
        while (g_HandleState == 1)
        {
            YieldProcessor();
        }

        if (g_HandleState == 2)
        {
            ProcessCtrlStoreHandleMode(HACDBG_HANDLE_STOP, NULL, NULL);
        }

        return STATUS_SUCCESS;
    }

    Request->Path[HACDBG_HANDLE_NAME_CHARS - 1] = 0;
    Request->Path[(HACDBG_HANDLE_NAME_CHARS * 2) - 1] = 0;
    ActorName = (WCHAR*)Request->Path;
    VictimName = (WCHAR*)(Request->Path + HACDBG_HANDLE_NAME_CHARS);
    if (ProcessCtrlBuildAnsiName(ActorName, Actor) == FALSE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Victim, sizeof(Victim));
    if (ProcessCtrlHandleNamed(Parameter) != FALSE && ProcessCtrlBuildAnsiName(VictimName, Victim) == FALSE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ProcessCtrlPrepareHandleLayout();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ProcessCtrlEnsureHandleWorker();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ProcessCtrlStoreHandleMode(Parameter, Actor, Victim);
    return STATUS_SUCCESS;
}

VOID
ProcessCtrlCleanup(VOID)
{
    PETHREAD Thread;

    g_HandleRun = 0;
    while (g_HandleState == 1)
    {
        YieldProcessor();
    }

    if (g_HandleState != 2)
    {
        return;
    }

    Thread = g_HandleThread;
    g_HandleThread = NULL;
    if (Thread != NULL)
    {
        KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Thread);
    }

    InterlockedExchange(&g_HandleState, 0);
}

static NTSTATUS
ProcessCtrlSetPpl(ULONG Pid, ULONG Parameter)
{
    PEPROCESS Process;
    NTSTATUS Status;
    ULONG Offset;

    Offset = g_ProtectionOffset != 0 ? g_ProtectionOffset : ProcessCtrlFindProtectionOffset();
    g_ProtectionOffset = Offset;
    if (Offset == 0 || Offset >= 0x1000)
    {
        return STATUS_NOT_SUPPORTED;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ((UCHAR*)Process)[Offset] = ProcessCtrlPplByte(Parameter);
    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

static NTSTATUS
ProcessCtrlReadFile(const WCHAR* Path, UCHAR** Buffer, ULONG* Length)
{
    UNICODE_STRING Unicode;
    WCHAR Prefixed[HACDBG_PROCESS_PATH_CHARS + 8];
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    HANDLE File;
    FILE_STANDARD_INFORMATION Info;
    NTSTATUS Status;
    LARGE_INTEGER Offset;

    if (Path[0] != L'\0' && Path[1] == L':')
    {
        Prefixed[0] = L'\\';
        Prefixed[1] = L'?';
        Prefixed[2] = L'?';
        Prefixed[3] = L'\\';
        RtlCopyMemory(Prefixed + 4, Path, HACDBG_PROCESS_PATH_CHARS * sizeof(WCHAR));
        RtlInitUnicodeString(&Unicode, Prefixed);
    }
    else
    {
        RtlInitUnicodeString(&Unicode, Path);
    }

    InitializeObjectAttributes(&Attributes, &Unicode, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&File, FILE_GENERIC_READ, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ZwQueryInformationFile(File, &Io, &Info, sizeof(Info), FileStandardInformation);
    if (!NT_SUCCESS(Status) || Info.EndOfFile.QuadPart <= 0 || Info.EndOfFile.QuadPart > PROCESS_CTRL_MAX_IMAGE)
    {
        ZwClose(File);
        return NT_SUCCESS(Status) ? STATUS_FILE_TOO_LARGE : Status;
    }

    *Length = (ULONG)Info.EndOfFile.QuadPart;
    *Buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, *Length, PROCESS_CTRL_TAG);
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
ProcessCtrlPrefixEqual(const WCHAR* Text, const WCHAR* Prefix, ULONG PrefixChars)
{
    ULONG Index;
    WCHAR Left;
    WCHAR Right;

    for (Index = 0; Index < PrefixChars; Index++)
    {
        Left = Text[Index];
        Right = Prefix[Index];
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
ProcessCtrlStartsWith(const WCHAR* Text, ULONG Chars, const WCHAR* Prefix, ULONG* PrefixChars)
{
    ULONG Count;

    Count = 0;
    while (Prefix[Count] != L'\0')
    {
        Count++;
    }

    if (Count > Chars || ProcessCtrlPrefixEqual(Text, Prefix, Count) == FALSE)
    {
        return FALSE;
    }

    if (Count < Chars && Text[Count] != L'\\')
    {
        return FALSE;
    }

    *PrefixChars = Count;
    return TRUE;
}

static BOOLEAN
ProcessCtrlStripPrefix(WCHAR* Path, ULONG* Chars, const WCHAR* Prefix)
{
    ULONG PrefixChars;
    ULONG Rest;

    PrefixChars = 0;
    while (Prefix[PrefixChars] != L'\0')
    {
        PrefixChars++;
    }

    if (*Chars < PrefixChars || ProcessCtrlPrefixEqual(Path, Prefix, PrefixChars) == FALSE)
    {
        return FALSE;
    }

    Rest = *Chars - PrefixChars;
    RtlMoveMemory(Path, Path + PrefixChars, Rest * sizeof(WCHAR));
    Path[Rest] = L'\0';
    *Chars = Rest;
    return TRUE;
}

static NTSTATUS
ProcessCtrlQueryLink(const WCHAR* LinkPath, PWCHAR Target, ULONG Capacity, PUSHORT TargetChars)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Handle;
    UNICODE_STRING Value;
    ULONG Returned;
    NTSTATUS Status;

    if (Capacity < 2)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&Name, LinkPath);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenSymbolicLinkObject(&Handle, SYMBOLIC_LINK_QUERY, &Attributes);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Value.Buffer = Target;
    Value.Length = 0;
    Value.MaximumLength = (USHORT)((Capacity - 1) * sizeof(WCHAR));
    Status = ZwQuerySymbolicLinkObject(Handle, &Value, &Returned);
    ZwClose(Handle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    *TargetChars = (USHORT)(Value.Length / sizeof(WCHAR));
    Target[*TargetChars] = L'\0';
    return STATUS_SUCCESS;
}

static NTSTATUS
ProcessCtrlCopyDos(const WCHAR* Source, ULONG Chars, PWCHAR Dest, ULONG DestChars)
{
    if (Chars == 0 || Chars >= DestChars)
    {
        return STATUS_NAME_TOO_LONG;
    }

    RtlCopyMemory(Dest, Source, Chars * sizeof(WCHAR));
    Dest[Chars] = L'\0';
    return STATUS_SUCCESS;
}

static BOOLEAN
ProcessCtrlIsDosPath(const WCHAR* Path, ULONG Chars)
{
    if (Chars < 3 || Path[1] != L':' || Path[2] != L'\\')
    {
        return FALSE;
    }

    return (Path[0] >= L'A' && Path[0] <= L'Z') || (Path[0] >= L'a' && Path[0] <= L'z');
}

static NTSTATUS
ProcessCtrlMapDrive(const WCHAR* NtPath, ULONG NtChars, PWCHAR DosPath, ULONG DosChars)
{
    WCHAR Letter;
    WCHAR Link[16];
    WCHAR Target[PROCESS_CTRL_LINK_CHARS];
    USHORT TargetChars;
    NTSTATUS Status;
    ULONG DosLength;

    for (Letter = L'A'; Letter <= L'Z'; Letter++)
    {
        Link[0] = L'\\';
        Link[1] = L'G';
        Link[2] = L'L';
        Link[3] = L'O';
        Link[4] = L'B';
        Link[5] = L'A';
        Link[6] = L'L';
        Link[7] = L'?';
        Link[8] = L'?';
        Link[9] = L'\\';
        Link[10] = Letter;
        Link[11] = L':';
        Link[12] = L'\0';
        Status = ProcessCtrlQueryLink(Link, Target, PROCESS_CTRL_LINK_CHARS, &TargetChars);
        if (!NT_SUCCESS(Status) || TargetChars == 0 || NtChars <= TargetChars || NtPath[TargetChars] != L'\\')
        {
            continue;
        }

        if (ProcessCtrlPrefixEqual(NtPath, Target, TargetChars) == FALSE)
        {
            continue;
        }

        DosLength = 2 + NtChars - TargetChars;
        if (DosLength >= DosChars)
        {
            return STATUS_NAME_TOO_LONG;
        }

        DosPath[0] = Letter;
        DosPath[1] = L':';
        RtlCopyMemory(DosPath + 2, NtPath + TargetChars, (NtChars - TargetChars) * sizeof(WCHAR));
        DosPath[DosLength] = L'\0';
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
ProcessCtrlReplacePrefix(WCHAR* Path, ULONG* Chars, ULONG Capacity, ULONG PrefixChars, const WCHAR* Target,
                         ULONG TargetChars)
{
    ULONG Rest;
    ULONG NewChars;

    if (PrefixChars > *Chars)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Rest = *Chars - PrefixChars;
    NewChars = TargetChars + Rest;
    if (NewChars >= Capacity)
    {
        return STATUS_NAME_TOO_LONG;
    }

    RtlMoveMemory(Path + TargetChars, Path + PrefixChars, Rest * sizeof(WCHAR));
    RtlCopyMemory(Path, Target, TargetChars * sizeof(WCHAR));
    Path[NewChars] = L'\0';
    *Chars = NewChars;
    return STATUS_SUCCESS;
}

static BOOLEAN
ProcessCtrlExpandOneLink(WCHAR* Path, ULONG* Chars)
{
    static const WCHAR* const Links[] = {L"\\SystemRoot", L"\\Device\\BootDevice"};
    ULONG Index;
    ULONG PrefixChars;
    WCHAR Target[PROCESS_CTRL_LINK_CHARS];
    USHORT TargetChars;
    NTSTATUS Status;

    for (Index = 0; Index < sizeof(Links) / sizeof(Links[0]); Index++)
    {
        if (ProcessCtrlStartsWith(Path, *Chars, Links[Index], &PrefixChars) == FALSE)
        {
            continue;
        }

        Status = ProcessCtrlQueryLink(Links[Index], Target, PROCESS_CTRL_LINK_CHARS, &TargetChars);
        if (!NT_SUCCESS(Status) || TargetChars == 0)
        {
            return FALSE;
        }

        Status = ProcessCtrlReplacePrefix(Path, Chars, PROCESS_CTRL_NT_PATH_CHARS, PrefixChars, Target, TargetChars);
        return NT_SUCCESS(Status);
    }

    return FALSE;
}

static NTSTATUS
ProcessCtrlNtPathToDos(WCHAR* Path, ULONG Chars, PWCHAR DosPath, ULONG DosChars)
{
    ULONG Pass;
    NTSTATUS Status;

    for (Pass = 0; Pass < PROCESS_CTRL_PATH_PASSES && Chars != 0; Pass++)
    {
        if (ProcessCtrlStripPrefix(Path, &Chars, L"\\GLOBAL??\\") != FALSE ||
            ProcessCtrlStripPrefix(Path, &Chars, L"\\??\\") != FALSE)
        {
            continue;
        }

        if (ProcessCtrlIsDosPath(Path, Chars) != FALSE)
        {
            return ProcessCtrlCopyDos(Path, Chars, DosPath, DosChars);
        }

        Status = ProcessCtrlMapDrive(Path, Chars, DosPath, DosChars);
        if (NT_SUCCESS(Status) || Status == STATUS_NAME_TOO_LONG)
        {
            return Status;
        }

        if (ProcessCtrlExpandOneLink(Path, &Chars) == FALSE)
        {
            break;
        }
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
ProcessCtrlQueryImagePath(ULONG Pid, PWCHAR DosPath, ULONG DosChars)
{
    PEPROCESS Process;
    PUNICODE_STRING ImageName;
    WCHAR Work[PROCESS_CTRL_NT_PATH_CHARS];
    ULONG Chars;
    NTSTATUS Status;

    if (DosPath == NULL || DosChars < 4)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DosPath[0] = L'\0';
    if (Pid == 0)
    {
        return STATUS_NOT_FOUND;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // SeLocateProcessImageName copies EPROCESS.SeAuditProcessCreationInfo.
    // The string is the image's NT path, not the 15-character ImageFileName.
    //
    ImageName = NULL;
    Status = SeLocateProcessImageName(Process, &ImageName);
    ObDereferenceObject(Process);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length < sizeof(WCHAR) ||
        (ImageName->Length & 1u) != 0)
    {
        if (ImageName != NULL)
        {
            ExFreePool(ImageName);
        }

        return STATUS_NOT_FOUND;
    }

    Chars = ImageName->Length / sizeof(WCHAR);
    if (Chars >= PROCESS_CTRL_NT_PATH_CHARS)
    {
        ExFreePool(ImageName);
        return STATUS_NAME_TOO_LONG;
    }

    RtlCopyMemory(Work, ImageName->Buffer, ImageName->Length);
    Work[Chars] = L'\0';
    ExFreePool(ImageName);
    return ProcessCtrlNtPathToDos(Work, Chars, DosPath, DosChars);
}

NTSTATUS
ProcessCtrlExecute(
    _Inout_ HACDBG_PROCESS_REQUEST* Request
    )
{
    NTSTATUS Status;

    if (Request == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Request->Path[HACDBG_PROCESS_PATH_CHARS - 1] = L'\0';
    switch (Request->Operation)
    {
    case HACDBG_PROCESS_TERMINATE_KERNEL:
        Status = ProcessCtrlTerminate(Request->Pid, FALSE);
        break;
    case HACDBG_PROCESS_TERMINATE_FORCE:
        Status = ProcessCtrlTerminate(Request->Pid, TRUE);
        break;
    case HACDBG_PROCESS_SUSPEND:
        Status = ProcessCtrlSuspend(Request->Pid, FALSE);
        break;
    case HACDBG_PROCESS_RESUME:
        Status = ProcessCtrlSuspend(Request->Pid, TRUE);
        break;
    case HACDBG_PROCESS_HIDE:
        Status = ProcessCtrlHide(Request->Pid);
        break;
    case HACDBG_PROCESS_HANDLE_PROTECT:
        Status = ProcessCtrlProtectHandle(Request);
        break;
    case HACDBG_PROCESS_SET_PPL:
        Status = ProcessCtrlSetPpl(Request->Pid, Request->Parameter);
        break;
    case HACDBG_PROCESS_INJECT_APC:
        {
            PEPROCESS Process;
            Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Request->Pid, &Process);
            if (NT_SUCCESS(Status))
            {
                Status = InjectApc(Process, (const WCHAR*)Request->Path);
                ObDereferenceObject(Process);
            }
        }
        break;
    case HACDBG_PROCESS_INJECT_PTE:
        {
            PEPROCESS Process;
            Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Request->Pid, &Process);
            if (NT_SUCCESS(Status))
            {
                Status = InjectPte(Process, (const WCHAR*)Request->Path);
                ObDereferenceObject(Process);
            }
        }
        break;
    case HACDBG_PROCESS_QUERY_IMAGE:
        RtlZeroMemory(Request->Path, sizeof(Request->Path));
        Status = ProcessCtrlQueryImagePath(Request->Pid, (WCHAR*)Request->Path, HACDBG_PROCESS_PATH_CHARS);
        break;
    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    Request->Status = (int)Status;
    if (!NT_SUCCESS(Status))
    {
        HACDBG_LOG("HacDbg: Err, process op %lu pid %lu failed: 0x%08x.\n", Request->Operation, Request->Pid,
                   Status);
    }

    return Status;
}
