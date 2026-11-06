#pragma once
#include <ntifs.h>

#define SEARCH_CODE_MAX 0x200
#define SEARCH_SYSTEM_MODULE_INFORMATION 11u

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

NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
                                        ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct _FindCode
{
	UCHAR code[SEARCH_CODE_MAX];
	UCHAR mask[SEARCH_CODE_MAX];
	ULONG len;
	LONG offset;
	LONG lastAddressOffset;
} FindCode, *PFindCode;

BOOLEAN initFindCodeStruct(PFindCode findCode, PCHAR code, LONG offset, LONG lastAddrOffset);

ULONG_PTR findAddressByCode(ULONG_PTR beginAddr, ULONG_PTR endAddr, PFindCode findCode, ULONG numbers);

ULONG_PTR QuerySysModule(char* ModuleName, _Out_opt_ ULONG_PTR* module);

ULONG_PTR searchNtCode(char* code, int offset);

ULONG_PTR searchCode(char* moduleName, char* segmentName, char* code, int offset);
