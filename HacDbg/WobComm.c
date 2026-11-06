/**
 * @file WobComm.c
 * @brief Process and window requests through NtManageWobTicket.
 *
 * @author HacDbg
 */

#include <ntifs.h>
#include <intrin.h>

#include "Config.h"
#include "Debug.h"
#include "ProcessCtrl.h"
#include "Search.h"
#include "Types.h"
#include "WindowProtect.h"
#include "WobComm.h"

#include "../shared/wob_comm.h"

#if defined(_AMD64_)
#include "Svm.h"
#if HACDBG_BACKEND_INTEL
#include "Ept.h"
#define WOB_COMM_ADD_HOOK EptAddHook
#define WOB_COMM_REMOVE_HOOK EptRemoveHook
#else
#include "Npt.h"
#define WOB_COMM_ADD_HOOK NptAddHook
#define WOB_COMM_REMOVE_HOOK NptRemoveHook
#endif
#endif

#define WOB_COMM_TAG 'wBoH'
#define WOB_COMM_JUMP 14u
#define WOB_COMM_STEAL 19u
#define WOB_COMM_COOKIE_AT 12u

static const UCHAR g_WobMagic[16] = {
    0x48, 0x44, 0x42, 0x47, 0x57, 0x4F, 0x42, 0x31, 0, 0, 0, 0, 0, 0, 0, 0
};

static const CHAR g_WobPattern[] =
    "88542410535641564883EC50488B05****"
    "4833C44889442440448AF2488BF14C894C2428"
    "4883642420000F57C00F114424304183F81073"
    "0ABB040000C0";

typedef NTSTATUS (*WOB_COMM_ROUTINE)(PVOID Buffer, UCHAR PreviousMode, ULONG Length, ULONG* ReturnLength);

static UCHAR* g_ShadowRaw;
static UCHAR* g_Shadow;
static UCHAR* g_Trampoline;
static PMDL g_LockedMdl;
static UINT64 g_TargetPage;
static volatile LONG g_Hooked;

static VOID
WobCommWriteJump(
    _Out_writes_(WOB_COMM_JUMP) UCHAR* Destination,
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

static BOOLEAN
WobCommUserCopy(
    _Inout_updates_bytes_(Bytes) VOID* Kernel,
    _In_ PVOID User,
    _In_ SIZE_T Bytes,
    _In_ BOOLEAN ToUser
    )
{
    BOOLEAN Opened;
    BOOLEAN Ok;

    Opened = FALSE;
    Ok = FALSE;
    if ((__readcr4() & (1ull << 21)) != 0 && (__readeflags() & 0x40000ull) == 0)
    {
        _stac();
        Opened = TRUE;
    }

    __try
    {
        if (ToUser == FALSE)
        {
            ProbeForRead(User, Bytes, 1);
            RtlCopyMemory(Kernel, User, Bytes);
        }
        else
        {
            ProbeForWrite(User, Bytes, 1);
            RtlCopyMemory(User, Kernel, Bytes);
        }

        Ok = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Ok = FALSE;
    }

    if (Opened != FALSE)
    {
        _clac();
    }

    return Ok;
}

static NTSTATUS
WobCommHandle(
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _Out_ ULONG* ReturnLength
    )
{
    HACDBG_WOB_HEADER Header;
    UCHAR* Body;
    ULONG BodyBytes;

    if (WobCommUserCopy(&Header, Buffer, sizeof(Header), FALSE) == FALSE)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    if (RtlCompareMemory(Header.Magic, g_WobMagic, sizeof(g_WobMagic)) != sizeof(g_WobMagic))
    {
        return STATUS_NOT_FOUND;
    }

    if (Header.Version != HACDBG_WOB_VERSION || Header.BodyBytes == 0 ||
        Length < sizeof(Header) + Header.BodyBytes)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Header.Kind == HACDBG_WOB_KIND_PROCESS)
    {
        BodyBytes = sizeof(HACDBG_PROCESS_REQUEST);
    }
    else if (Header.Kind == HACDBG_WOB_KIND_WINDOW)
    {
        BodyBytes = sizeof(HACDBG_WINDOW_REQUEST);
    }
    else
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Header.BodyBytes != BodyBytes)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Body = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, BodyBytes, WOB_COMM_TAG);
    if (Body == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (WobCommUserCopy(Body, (UCHAR*)Buffer + sizeof(Header), BodyBytes, FALSE) == FALSE)
    {
        ExFreePoolWithTag(Body, WOB_COMM_TAG);
        return STATUS_ACCESS_VIOLATION;
    }

    if (Header.Kind == HACDBG_WOB_KIND_PROCESS)
    {
        HACDBG_PROCESS_REQUEST* ProcessRequest;

        ProcessRequest = (HACDBG_PROCESS_REQUEST*)Body;
        HACDBG_LOG("HacDbg: WOB process op=%u pid=%u flags=0x%x.\n", ProcessRequest->Operation, ProcessRequest->Pid,
                   ProcessRequest->Flags);
        ProcessCtrlExecute(ProcessRequest);
        HACDBG_LOG("HacDbg: WOB process done op=%u pid=%u status=0x%08x.\n", ProcessRequest->Operation,
                   ProcessRequest->Pid, ProcessRequest->Status);
    }
    else
    {
        HACDBG_WINDOW_REQUEST* WindowRequest;

        WindowRequest = (HACDBG_WINDOW_REQUEST*)Body;
        HACDBG_LOG("HacDbg: WOB window op=%u owner=%u.\n", WindowRequest->Operation, WindowRequest->OwnerPid);
        WindowProtectExecute(WindowRequest);
        HACDBG_LOG("HacDbg: WOB window done op=%u status=0x%08x.\n", WindowRequest->Operation, WindowRequest->Status);
    }

    if (WobCommUserCopy(Body, (UCHAR*)Buffer + sizeof(Header), BodyBytes, TRUE) == FALSE)
    {
        ExFreePoolWithTag(Body, WOB_COMM_TAG);
        return STATUS_ACCESS_VIOLATION;
    }

    ExFreePoolWithTag(Body, WOB_COMM_TAG);
    *ReturnLength = sizeof(Header) + BodyBytes;
    return STATUS_SUCCESS;
}

__declspec(noinline) static NTSTATUS
WobCommFilter(
    PVOID Buffer,
    UCHAR PreviousMode,
    ULONG Length,
    ULONG* ReturnLength
    )
{
    WOB_COMM_ROUTINE Original;
    HACDBG_WOB_HEADER Header;
    NTSTATUS Status;

    Original = (WOB_COMM_ROUTINE)g_Trampoline;
    HACDBG_LOG("HacDbg: WOB enter pid=%llu mode=%u len=%u buf=%p.\n", (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
               PreviousMode, Length, Buffer);
    if (Original == NULL)
    {
        HACDBG_LOG("HacDbg: Err, WOB trampoline is missing.\n");
        return STATUS_NOT_FOUND;
    }

    if (PreviousMode == 0 || Buffer == NULL || Length < sizeof(HACDBG_WOB_HEADER) || ReturnLength == NULL)
    {
        HACDBG_LOG("HacDbg: WOB forward native mode=%u len=%u.\n", PreviousMode, Length);
        return Original(Buffer, PreviousMode, Length, ReturnLength);
    }

    if (WobCommUserCopy(&Header, Buffer, sizeof(Header), FALSE) == FALSE)
    {
        HACDBG_LOG("HacDbg: WOB forward unreadable len=%u.\n", Length);
        return Original(Buffer, PreviousMode, Length, ReturnLength);
    }

    if (RtlCompareMemory(Header.Magic, g_WobMagic, sizeof(g_WobMagic)) != sizeof(g_WobMagic))
    {
        HACDBG_LOG("HacDbg: WOB forward ticket kind=%u version=%u bytes=%u.\n", Header.Kind, Header.Version,
                   Header.BodyBytes);
        return Original(Buffer, PreviousMode, Length, ReturnLength);
    }

    HACDBG_LOG("HacDbg: WOB packet kind=%u version=%u bytes=%u.\n", Header.Kind, Header.Version, Header.BodyBytes);
    Status = WobCommHandle(Buffer, Length, ReturnLength);
    HACDBG_LOG("HacDbg: WOB packet result 0x%08x return_len=%u.\n", Status,
               ReturnLength != NULL ? *ReturnLength : 0);
    return Status;
}

static BOOLEAN
WobCommFlush(
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
        // INVARIANT: This processor is already a guest. The leaf drops cached
        // translations before the patched execute page is fetched.
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
WobCommFree(
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
        ExFreePoolWithTag(g_ShadowRaw, WOB_COMM_TAG);
        g_ShadowRaw = NULL;
        g_Shadow = NULL;
    }

    if (g_Trampoline != NULL)
    {
        ExFreePoolWithTag(g_Trampoline, WOB_COMM_TAG);
        g_Trampoline = NULL;
    }

    g_TargetPage = 0;
}

NTSTATUS
WobCommInitialize(
    VOID
    )
{
#if !defined(_AMD64_)
    return STATUS_NOT_SUPPORTED;
#else
    UCHAR* Target;
    UCHAR* PageBase;
    UCHAR* ShadowRaw;
    UCHAR* Shadow;
    UCHAR* Trampoline;
    ULONG PageOffset;
    PMDL Mdl;
    PHYSICAL_ADDRESS Physical;
    LONG Displacement;
    ULONG_PTR Cookie;
    BOOLEAN Added;

    if (g_Hooked != 0)
    {
        return STATUS_SUCCESS;
    }

    Target = (UCHAR*)searchCode("ntoskrnl.exe", "PAGE", (char*)g_WobPattern, 0);
    if (Target == NULL)
    {
        HACDBG_LOG("HacDbg: Err, WOB signature was not found.\n");
        return STATUS_NOT_FOUND;
    }

    if (Target[WOB_COMM_COOKIE_AT] != 0x48 || Target[WOB_COMM_COOKIE_AT + 1] != 0x8B ||
        Target[WOB_COMM_COOKIE_AT + 2] != 0x05)
    {
        HACDBG_LOG("HacDbg: Err, WOB entry %p does not match the expected prologue.\n", Target);
        return STATUS_NOT_SUPPORTED;
    }

    PageOffset = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
    if (PageOffset + WOB_COMM_STEAL > PAGE_SIZE)
    {
        HACDBG_LOG("HacDbg: Err, WOB entry %p is too close to a page boundary.\n", Target);
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
        HACDBG_LOG("HacDbg: Err, WOB page %p could not be locked.\n", PageBase);
        return GetExceptionCode();
    }

    Physical = MmGetPhysicalAddress(PageBase);
    if (Physical.QuadPart == 0)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_NOT_FOUND;
    }

    ShadowRaw = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE * 2, WOB_COMM_TAG);
    Trampoline = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE, WOB_COMM_TAG);
    if (ShadowRaw == NULL || Trampoline == NULL)
    {
        if (ShadowRaw != NULL)
        {
            ExFreePoolWithTag(ShadowRaw, WOB_COMM_TAG);
        }

        if (Trampoline != NULL)
        {
            ExFreePoolWithTag(Trampoline, WOB_COMM_TAG);
        }

        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Shadow = (UCHAR*)(((ULONG_PTR)ShadowRaw + (PAGE_SIZE - 1)) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    RtlCopyMemory(Shadow, PageBase, PAGE_SIZE);
    RtlCopyMemory(Trampoline, Target, WOB_COMM_COOKIE_AT);
    Displacement = *(LONG*)(Target + WOB_COMM_COOKIE_AT + 3);
    Cookie = (ULONG_PTR)(Target + WOB_COMM_COOKIE_AT + 7) + (LONG_PTR)Displacement;
    Trampoline[WOB_COMM_COOKIE_AT] = 0x48;
    Trampoline[WOB_COMM_COOKIE_AT + 1] = 0xB8;
    RtlCopyMemory(Trampoline + WOB_COMM_COOKIE_AT + 2, &Cookie, sizeof(Cookie));
    Trampoline[WOB_COMM_COOKIE_AT + 10] = 0x48;
    Trampoline[WOB_COMM_COOKIE_AT + 11] = 0x8B;
    Trampoline[WOB_COMM_COOKIE_AT + 12] = 0x00;
    WobCommWriteJump(Trampoline + WOB_COMM_COOKIE_AT + 13, (UINT64)(ULONG_PTR)(Target + WOB_COMM_STEAL));
    WobCommWriteJump(Shadow + PageOffset, (UINT64)(ULONG_PTR)WobCommFilter);
    RtlFillMemory(Shadow + PageOffset + WOB_COMM_JUMP, WOB_COMM_STEAL - WOB_COMM_JUMP, 0x90);

    g_LockedMdl = Mdl;
    g_ShadowRaw = ShadowRaw;
    g_Shadow = Shadow;
    g_Trampoline = Trampoline;
    g_TargetPage = (UINT64)Physical.QuadPart & ~(UINT64)(PAGE_SIZE - 1);
    KeMemoryBarrier();

    //
    // INVARIANT: g_TargetPage is the locked physical page of
    // PspQueryWobTicketQos. Shadow is a nonpaged copy of that page. The
    // guest executes the copy. The original page stays readable.
    //
    Added = WOB_COMM_ADD_HOOK(HacDbgGuestPhysicalAddress(g_TargetPage),
                              HacDbgGuestPhysicalAddress((UINT64)MmGetPhysicalAddress(Shadow).QuadPart));
    if (Added == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, WOB SLAT hook failed for %p.\n", Target);
        WobCommFree();
        return STATUS_UNSUCCESSFUL;
    }

    if (WobCommFlush() == FALSE)
    {
        HACDBG_LOG("HacDbg: Err, WOB flush failed after hooking %p.\n", Target);
        WOB_COMM_REMOVE_HOOK(HacDbgGuestPhysicalAddress(g_TargetPage));
        WobCommFree();
        return STATUS_UNSUCCESSFUL;
    }

    g_Hooked = 1;
    HACDBG_LOG("HacDbg: WOB hook %p page 0x%I64x.\n", Target, g_TargetPage);
    return STATUS_SUCCESS;
#endif
}

VOID
WobCommCleanup(
    VOID
    )
{
#if defined(_AMD64_)
    if (g_Hooked == 0)
    {
        return;
    }

    WOB_COMM_REMOVE_HOOK(HacDbgGuestPhysicalAddress(g_TargetPage));
    WobCommFlush();
    g_Hooked = 0;
    WobCommFree();
#endif
}
