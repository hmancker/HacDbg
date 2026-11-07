#pragma once

//
// One row is one installed kernel callback. Entry is the routine. Extra is
// the notify-array slot, the object-callback registration, or the executive
// callback registration. Path is the kernel module path, not a DOS path.
//
#define HACDBG_CALLBACK_MAX_ROWS 1024u
#define HACDBG_CALLBACK_PATH_CHARS 96u

#define HACDBG_CALLBACK_CREATE_PROCESS 1u
#define HACDBG_CALLBACK_CREATE_PROCESS_EX 2u
#define HACDBG_CALLBACK_CREATE_PROCESS_EX2 3u
#define HACDBG_CALLBACK_CREATE_THREAD 4u
#define HACDBG_CALLBACK_CREATE_THREAD_EX 5u
#define HACDBG_CALLBACK_LOAD_IMAGE 6u
#define HACDBG_CALLBACK_LOAD_IMAGE_EX 7u
#define HACDBG_CALLBACK_PROCESS_OB_PRE 8u
#define HACDBG_CALLBACK_PROCESS_OB_POST 9u
#define HACDBG_CALLBACK_THREAD_OB_PRE 10u
#define HACDBG_CALLBACK_THREAD_OB_POST 11u
#define HACDBG_CALLBACK_DESKTOP_OB_PRE 12u
#define HACDBG_CALLBACK_DESKTOP_OB_POST 13u
#define HACDBG_CALLBACK_IMAGE_VERIFICATION 14u
#define HACDBG_CALLBACK_BUGCHECK 15u
#define HACDBG_CALLBACK_BUGCHECK_REASON 16u
#define HACDBG_CALLBACK_SHUTDOWN 17u
#define HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN 18u
#define HACDBG_CALLBACK_REGISTRY 19u
#define HACDBG_CALLBACK_FS_NOTIFY 20u
#define HACDBG_CALLBACK_LOGON_TERMINATED 21u
#define HACDBG_CALLBACK_LOGON_TERMINATED_EX 22u
#define HACDBG_CALLBACK_POWER_SETTING 23u

typedef struct _HACDBG_CALLBACK_ROW
{
    unsigned long long Entry;
    unsigned long long Extra;
    unsigned int Type;
    unsigned int Reserved;
    wchar_t Path[HACDBG_CALLBACK_PATH_CHARS];
} HACDBG_CALLBACK_ROW;

#define HACDBG_CALLBACK_OP_SCAN 0u
#define HACDBG_CALLBACK_OP_REMOVE 1u
#define HACDBG_CALLBACK_OP_DISABLE 2u
#define HACDBG_CALLBACK_OP_ENABLE 3u

#define HACDBG_CALLBACK_STATE_NORMAL 0u
#define HACDBG_CALLBACK_STATE_REMOVED 1u
#define HACDBG_CALLBACK_STATE_DISABLED 2u
#define HACDBG_CALLBACK_STATE_ENABLED 3u

typedef struct _HACDBG_CALLBACK_REQUEST
{
    int Status;
    unsigned int Count;
    unsigned int Truncated;
    unsigned int Reserved;
    HACDBG_CALLBACK_ROW Rows[HACDBG_CALLBACK_MAX_ROWS];
} HACDBG_CALLBACK_REQUEST;

static inline const char*
HacDbgCallbackTypeName(unsigned int Type)
{
    switch (Type)
    {
    case HACDBG_CALLBACK_CREATE_PROCESS:
        return "CreateProcess";
    case HACDBG_CALLBACK_CREATE_PROCESS_EX:
        return "CreateProcessEx";
    case HACDBG_CALLBACK_CREATE_PROCESS_EX2:
        return "CreateProcessEx2";
    case HACDBG_CALLBACK_CREATE_THREAD:
        return "CreateThread";
    case HACDBG_CALLBACK_CREATE_THREAD_EX:
        return "CreateThreadEx";
    case HACDBG_CALLBACK_LOAD_IMAGE:
        return "LoadImage";
    case HACDBG_CALLBACK_LOAD_IMAGE_EX:
        return "LoadImageEx";
    case HACDBG_CALLBACK_PROCESS_OB_PRE:
        return "ProcessObCallback PRE";
    case HACDBG_CALLBACK_PROCESS_OB_POST:
        return "ProcessObCallback POST";
    case HACDBG_CALLBACK_THREAD_OB_PRE:
        return "ThreadObCallback PRE";
    case HACDBG_CALLBACK_THREAD_OB_POST:
        return "ThreadObCallback POST";
    case HACDBG_CALLBACK_DESKTOP_OB_PRE:
        return "DesktopObCallback PRE";
    case HACDBG_CALLBACK_DESKTOP_OB_POST:
        return "DesktopObCallback POST";
    case HACDBG_CALLBACK_IMAGE_VERIFICATION:
        return "ImageVerification";
    case HACDBG_CALLBACK_BUGCHECK:
        return "BugCheck";
    case HACDBG_CALLBACK_BUGCHECK_REASON:
        return "BugCheckReason";
    case HACDBG_CALLBACK_SHUTDOWN:
        return "Shutdown";
    case HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN:
        return "LastChanceShutdown";
    case HACDBG_CALLBACK_REGISTRY:
        return "CmpCallback";
    case HACDBG_CALLBACK_FS_NOTIFY:
        return "FsNotifyChange";
    case HACDBG_CALLBACK_LOGON_TERMINATED:
        return "LogonSessionTerminated";
    case HACDBG_CALLBACK_LOGON_TERMINATED_EX:
        return "LogonSessionTerminatedEx";
    case HACDBG_CALLBACK_POWER_SETTING:
        return "PowerSetting";
    default:
        return "Unknown";
    }
}
