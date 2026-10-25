#pragma once

/**
 * @file hacdbg_core_api.h
 * @brief C ABI between the WPF GUI and the native debugger core.
 *
 * @author HacDbg
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define HACDBG_CORE_API_VERSION 1u
#define HACDBG_CORE_MAX_BREAKPOINTS 64u
#define HACDBG_CORE_VERSION_STRING_SIZE 32u

/**
 * @brief Status returned by the GUI core ABI.
 */
typedef enum _HACDBG_CORE_STATUS
{
    HacDbgCoreStatusOk = 0,
    HacDbgCoreStatusArgument = 1,
    HacDbgCoreStatusState = 2,
    HacDbgCoreStatusDriver = 3,
    HacDbgCoreStatusException = 4
} HACDBG_CORE_STATUS;

/**
 * @brief Output event kinds delivered on the core callback thread.
 */
typedef enum _HACDBG_OUTPUT_KIND
{
    HacDbgOutputText = 0,
    HacDbgOutputInfo = 1,
    HacDbgOutputWarning = 2,
    HacDbgOutputError = 3,
    HacDbgOutputProgress = 4,
    HacDbgOutputClear = 5,
    HacDbgOutputQuit = 6
} HACDBG_OUTPUT_KIND;

/**
 * @brief Guest register snapshot captured while a breakpoint paused a thread.
 */
typedef struct _HACDBG_CORE_REGISTERS
{
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    uint64_t Rflags;
    uint64_t Cr3;
    uint32_t RflagsKnown;
    uint32_t Reserved;
} HACDBG_CORE_REGISTERS;

/**
 * @brief One execution breakpoint.
 */
typedef struct _HACDBG_CORE_BREAKPOINT
{
    uint64_t Id;
    uint64_t Address;
    uint64_t Cr3;
    uint32_t Enabled;
    uint32_t PausesThread;
} HACDBG_CORE_BREAKPOINT;

/**
 * @brief Immutable state snapshot copied by HacDbgCoreGetState.
 */
typedef struct _HACDBG_CORE_STATE
{
    uint32_t Initialized;
    uint32_t Running;
    uint32_t Paused;
    uint32_t BreakpointCount;
    uint32_t HypercallAbiVersion;
    uint32_t Reserved;
    HACDBG_CORE_REGISTERS Registers;
    HACDBG_CORE_BREAKPOINT Breakpoints[HACDBG_CORE_MAX_BREAKPOINTS];
    char UserVersion[HACDBG_CORE_VERSION_STRING_SIZE];
    char DriverVersion[HACDBG_CORE_VERSION_STRING_SIZE];
} HACDBG_CORE_STATE;

typedef struct HACDBG_CORE HACDBG_CORE;

/**
 * @brief Receives UTF-8 output from the core thread. The text is valid only
 * during the callback and must be copied before returning.
 */
typedef void (__cdecl *HACDBG_OUTPUT_CALLBACK)(uint32_t Kind, const char* Text, uint32_t Length, void* Context);

/**
 * @brief Returns HACDBG_CORE_API_VERSION.
 */
uint32_t HacDbgCoreApiVersion(void);

/**
 * @brief Returns sizeof(HACDBG_CORE_STATE) for the loaded DLL.
 */
uint32_t HacDbgCoreStateSize(void);

/**
 * @brief Creates a core session. The callback may be null.
 */
HACDBG_CORE* HacDbgCoreCreate(HACDBG_OUTPUT_CALLBACK OutputCallback, void* Context);

/**
 * @brief Stops and frees a core session.
 */
void HacDbgCoreDestroy(HACDBG_CORE* Core);

/**
 * @brief Connects to the running driver and starts the core worker.
 * @return HacDbgCoreStatusOk on success; otherwise a HACDBG_CORE_STATUS.
 */
uint32_t HacDbgCoreStart(HACDBG_CORE* Core);

/**
 * @brief Stops the worker and releases debugger-side state.
 */
uint32_t HacDbgCoreStop(HACDBG_CORE* Core);

/**
 * @brief Queues one UTF-8 command line for the core thread.
 */
uint32_t HacDbgCoreExecute(HACDBG_CORE* Core, const char* Utf8Command);

/**
 * @brief Requests cancellation of the current long-running command.
 */
void HacDbgCoreCancel(HACDBG_CORE* Core);

/**
 * @brief Copies the latest state snapshot without entering the driver.
 */
uint32_t HacDbgCoreGetState(HACDBG_CORE* Core, HACDBG_CORE_STATE* StateOut);

#ifdef __cplusplus
}
#endif
