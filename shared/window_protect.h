#pragma once

//
// Window protection request. The GUI sends one operation. The driver writes
// Status and the result fields. Rows holds windows whose DWM sprite has the
// protected-content bit set. Offsets are recorded by calibration; they are
// not constants.
//
#define HACDBG_WINDOW_MAX_ROWS 128u

#define HACDBG_WINDOW_QUERY  1u
#define HACDBG_WINDOW_ARM    2u
#define HACDBG_WINDOW_DISARM 3u
#define HACDBG_WINDOW_SCAN   4u
#define HACDBG_WINDOW_ALLOW  5u

//
// HACDBG_WINDOW_FLAG_RECALIBRATE discards a saved DWM layout and matches the
// calibration window again.
//
// HACDBG_WINDOW_ALLOW reads CalibratePid. That process may call the hooked
// function until the next ALLOW with CalibratePid 0. It does not change the
// hook owner. The struct layout is unchanged.
//
#define HACDBG_WINDOW_FLAG_RECALIBRATE 1u

typedef struct _HACDBG_WINDOW_ROW
{
    unsigned int Pid;
    unsigned int Hwnd;
} HACDBG_WINDOW_ROW;

typedef struct _HACDBG_WINDOW_REQUEST
{
    unsigned int Operation;
    int Status;
    unsigned int HookArmed;
    unsigned int OwnerPid;
    unsigned int DwmPid;
    unsigned int CalibrateHwnd;
    unsigned int CalibratePid;
    unsigned int FlagsOffset;
    unsigned int KindOffset;
    unsigned int HwndOffset;
    unsigned int PidOffset;
    unsigned int RowCount;
    unsigned int Truncated;
    unsigned int Flags;
    unsigned long long Target;
    unsigned long long Vtable;
    HACDBG_WINDOW_ROW Rows[HACDBG_WINDOW_MAX_ROWS];
} HACDBG_WINDOW_REQUEST;
