#pragma once

#define HACDBG_PROCESS_PATH_CHARS 260

#define HACDBG_PROCESS_TERMINATE_KERNEL 1u
#define HACDBG_PROCESS_TERMINATE_FORCE  2u
#define HACDBG_PROCESS_SUSPEND          3u
#define HACDBG_PROCESS_RESUME           4u
#define HACDBG_PROCESS_HIDE             5u
#define HACDBG_PROCESS_HANDLE_PROTECT   6u

#define HACDBG_HANDLE_STOP 0u
#define HACDBG_HANDLE_DOWNGRADE_ALL 1u
#define HACDBG_HANDLE_DOWNGRADE_NAME 2u
#define HACDBG_HANDLE_UPGRADE_ALL 3u
#define HACDBG_HANDLE_UPGRADE_NAME 4u

//
// HACDBG_PROCESS_HANDLE_PROTECT stores two UTF-16 names in Path.
// Path[0] is the actor, the program holding the handles. Path[HACDBG_HANDLE_NAME_CHARS]
// is the victim for the named modes. Each slot holds HACDBG_HANDLE_NAME_CHARS
// characters including the terminator. Matching uses the image name's first 15 characters.
//
#define HACDBG_HANDLE_NAME_CHARS 64u
#define HACDBG_PROCESS_SET_PPL          7u
#define HACDBG_PROCESS_INJECT_APC       8u
#define HACDBG_PROCESS_INJECT_PTE       9u

#define HACDBG_PROCESS_FLAG_POISON 1u

#define HACDBG_PPL_NONE         0u
#define HACDBG_PPL_ANTIMALWARE  1u
#define HACDBG_PPL_WINDOWS      2u
#define HACDBG_PPL_WINTCB_LIGHT 3u
#define HACDBG_PPL_WINTCB       4u

typedef struct _HACDBG_PROCESS_REQUEST
{
    unsigned int Operation;
    unsigned int Pid;
    unsigned int Parameter;
    unsigned int Flags;
    int Status;
    unsigned int Reserved;
    unsigned short Path[HACDBG_PROCESS_PATH_CHARS];
} HACDBG_PROCESS_REQUEST;
