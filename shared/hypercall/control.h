#pragma once

#include "../version.h"

#define HACDBG_DEVICE_NAME       L"\\Device\\HacDbg"
#define HACDBG_SYMLINK_NAME      L"\\DosDevices\\HacDbg"
#define HACDBG_USER_DEVICE_NAME  L"\\\\.\\HacDbg"

#define HACDBG_IOCTL_FLUSH_SLAT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Kept so a caller that still sends the old control-device request is
// rejected. Debugger commands enter through CPUID, not this IOCTL.
//
#define HACDBG_IOCTL_HYPERCALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HACDBG_HYPERCALL_REQUEST_VERSION 1

#define HACDBG_IOCTL_QUERY_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HACDBG_VERSION_STRING_SIZE 32

/**
 * @brief Driver version and hypercall ABI revision.
 */
typedef struct _HACDBG_VERSION_INFO
{
    UINT32 Major;
    UINT32 Minor;
    UINT32 Patch;
    UINT32 HypercallAbiVersion;
    char VersionString[HACDBG_VERSION_STRING_SIZE];
} HACDBG_VERSION_INFO;

/**
 * @brief Usermode-to-driver hypercall request and reply.
 */
typedef struct _HACDBG_HYPERCALL_REQUEST
{
    UINT32 Version;
    UINT32 Status;
    UINT64 CallType;
    UINT64 Reserved;
    UINT64 ProcessCr3;
    UINT64 Rdx;
    UINT64 R8;
    UINT64 R9;
    UINT64 Result;
} HACDBG_HYPERCALL_REQUEST;
