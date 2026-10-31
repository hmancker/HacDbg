#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_IMAGE_CERT_REVOKED
#define STATUS_IMAGE_CERT_REVOKED ((NTSTATUS)0xC0000603L)
#endif
#ifndef STATUS_REGISTRY_IO_FAILED
#define STATUS_REGISTRY_IO_FAILED ((NTSTATUS)0xC000014DL)
#endif
#ifndef STATUS_ALREADY_REGISTERED
#define STATUS_ALREADY_REGISTERED ((NTSTATUS)0xC0000718L)
#endif
#ifndef STATUS_DISK_OPERATION_FAILED
#define STATUS_DISK_OPERATION_FAILED ((NTSTATUS)0xC000016AL)
#endif
#ifndef STATUS_BAD_DLL_ENTRYPOINT
#define STATUS_BAD_DLL_ENTRYPOINT ((NTSTATUS)0xC0000251L)
#endif
#ifndef STATUS_INVALID_IMAGE_FORMAT
#define STATUS_INVALID_IMAGE_FORMAT ((NTSTATUS)0xC000007BL)
#endif
#ifndef STATUS_DELETE_PENDING
#define STATUS_DELETE_PENDING ((NTSTATUS)0xC0000056L)
#endif

namespace nt
{
	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemExtendedHandleInformation = 64;

	extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName);
	extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName);
	extern "C" NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, BOOLEAN* WasEnabled);

	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR HandleCount;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

	typedef enum class _POOL_TYPE {
		NonPagedPool,
		NonPagedPoolExecute = NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed = NonPagedPool + 2,
		DontUseThisType,
		NonPagedPoolCacheAligned = NonPagedPool + 4,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
		MaxPoolType,
		NonPagedPoolBase = 0,
		NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
		NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
		NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
		NonPagedPoolSession = 32,
		PagedPoolSession = NonPagedPoolSession + 1,
		NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
		DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
		NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
		PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
		NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
		NonPagedPoolNx = 512,
		NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
		NonPagedPoolSessionNx = NonPagedPoolNx + 32,
	} POOL_TYPE;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	typedef struct _HashBucketEntry
	{
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;
	typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

	typedef struct _PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16];
	} PiDDBCacheEntry, * NPiDDBCacheEntry;
}
