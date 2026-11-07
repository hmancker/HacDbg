#pragma once

//
// One row is one device in a legacy filter stack. Depth 0 is the bottom
// device. A later row with Parent set is the device attached above it.
// DriverName is DRIVER_OBJECT.DriverName. DeviceName is empty when the
// device object has no name. Host* names the device directly below.
//
#define HACDBG_FILTER_MAX_ROWS 512u
#define HACDBG_FILTER_NAME_CHARS 64u
#define HACDBG_FILTER_PATH_CHARS 256u
#define HACDBG_FILTER_NO_PARENT 0xffffffffu

#define HACDBG_FILTER_OP_SCAN 0u
#define HACDBG_FILTER_OP_DETACH 1u
#define HACDBG_FILTER_OP_DEVICES 2u
#define HACDBG_FILTER_OP_DISPATCH 3u

#define HACDBG_FILTER_FILE 1u
#define HACDBG_FILTER_DISK 2u
#define HACDBG_FILTER_RAW 3u
#define HACDBG_FILTER_VOLUME 4u
#define HACDBG_FILTER_KEYBOARD 5u
#define HACDBG_FILTER_MOUSE 6u
#define HACDBG_FILTER_I8042 7u
#define HACDBG_FILTER_TCPIP 8u
#define HACDBG_FILTER_TDI 9u
#define HACDBG_FILTER_NDIS 10u
#define HACDBG_FILTER_PNP 11u

typedef struct _HACDBG_FILTER_ROW
{
    unsigned long long DriverObject;
    unsigned long long DeviceObject;
    unsigned long long HostDriverObject;
    unsigned long long HostDeviceObject;
    unsigned int Depth;
    unsigned int Parent;
    unsigned int Type;
    unsigned int Reserved;
    wchar_t DriverName[HACDBG_FILTER_NAME_CHARS];
    wchar_t DeviceName[HACDBG_FILTER_NAME_CHARS];
    wchar_t HostDriverName[HACDBG_FILTER_NAME_CHARS];
    wchar_t DriverPath[HACDBG_FILTER_PATH_CHARS];
} HACDBG_FILTER_ROW;

typedef struct _HACDBG_FILTER_REQUEST
{
    int Status;
    unsigned int Count;
    unsigned int Truncated;
    unsigned int Reserved;
    HACDBG_FILTER_ROW Rows[HACDBG_FILTER_MAX_ROWS];
} HACDBG_FILTER_REQUEST;

static inline const char*
HacDbgFilterTypeName(unsigned int Type)
{
    switch (Type)
    {
    case HACDBG_FILTER_FILE:
        return "FILE";
    case HACDBG_FILTER_DISK:
        return "DISK";
    case HACDBG_FILTER_RAW:
        return "RAW";
    case HACDBG_FILTER_VOLUME:
        return "VOLUME";
    case HACDBG_FILTER_KEYBOARD:
        return "KEYBOARD";
    case HACDBG_FILTER_MOUSE:
        return "MOUSE";
    case HACDBG_FILTER_I8042:
        return "I8042PRT";
    case HACDBG_FILTER_TCPIP:
        return "TCPIP";
    case HACDBG_FILTER_TDI:
        return "TDI";
    case HACDBG_FILTER_NDIS:
        return "NDIS";
    case HACDBG_FILTER_PNP:
        return "PNP_MANAGER";
    default:
        return "";
    }
}
