#pragma once

#include "process_control.h"
#include "window_protect.h"

//
// First dword is 0x47424448, not 1. A real WOB QoS ticket starts with 1.
//
#define HACDBG_WOB_VERSION 1u
#define HACDBG_WOB_KIND_PROCESS 1u
#define HACDBG_WOB_KIND_WINDOW 2u

typedef struct _HACDBG_WOB_HEADER
{
    unsigned char Magic[16];
    unsigned int Version;
    unsigned int Kind;
    unsigned int BodyBytes;
    unsigned int Reserved;
} HACDBG_WOB_HEADER;
