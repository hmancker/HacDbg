#pragma once

//
// One parent row is one minifilter. Child rows are its pre and post
// callbacks. Callback is 0 on the parent. Altitude is the filter altitude
// string. Path is the driver image.
//
#define HACDBG_MINIFILTER_MAX_ROWS 512u
#define HACDBG_MINIFILTER_NAME_CHARS 64u
#define HACDBG_MINIFILTER_ALTITUDE_CHARS 32u
#define HACDBG_MINIFILTER_PATH_CHARS 256u
#define HACDBG_MINIFILTER_NO_PARENT 0xffffffffu

#define HACDBG_MINIFILTER_OP_SCAN 0u
#define HACDBG_MINIFILTER_OP_DISABLE 1u
#define HACDBG_MINIFILTER_OP_ENABLE 2u

typedef struct _HACDBG_MINIFILTER_ROW
{
    unsigned long long Filter;
    unsigned long long Callback;
    unsigned int Parent;
    unsigned int Depth;
    unsigned int Major;
    unsigned int Post;
    wchar_t Name[HACDBG_MINIFILTER_NAME_CHARS];
    wchar_t Altitude[HACDBG_MINIFILTER_ALTITUDE_CHARS];
    wchar_t Path[HACDBG_MINIFILTER_PATH_CHARS];
} HACDBG_MINIFILTER_ROW;

typedef struct _HACDBG_MINIFILTER_REQUEST
{
    int Status;
    unsigned int Count;
    unsigned int Truncated;
    unsigned int Reserved;
    HACDBG_MINIFILTER_ROW Rows[HACDBG_MINIFILTER_MAX_ROWS];
} HACDBG_MINIFILTER_REQUEST;
