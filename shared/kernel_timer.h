#pragma once

//
// One row is one IO timer or one DPC timer. Period is milliseconds.
// An IO timer period is 1000. A DPC period of 0 is a one-shot timer.
// Dpc is 0 for an IO timer. Running is 1 while the timer is active.
//
#define HACDBG_TIMER_MAX_ROWS 512u
#define HACDBG_TIMER_PATH_CHARS 256u

#define HACDBG_TIMER_OP_SCAN 0u
#define HACDBG_TIMER_OP_REMOVE 1u

#define HACDBG_TIMER_IO 1u
#define HACDBG_TIMER_DPC 2u

typedef struct _HACDBG_TIMER_ROW
{
    unsigned long long Callback;
    unsigned long long Dpc;
    unsigned long long Timer;
    unsigned int Type;
    unsigned int Period;
    unsigned int Running;
    unsigned int Reserved;
    wchar_t Path[HACDBG_TIMER_PATH_CHARS];
} HACDBG_TIMER_ROW;

typedef struct _HACDBG_TIMER_REQUEST
{
    int Status;
    unsigned int Count;
    unsigned int Truncated;
    unsigned int Reserved;
    HACDBG_TIMER_ROW Rows[HACDBG_TIMER_MAX_ROWS];
} HACDBG_TIMER_REQUEST;
