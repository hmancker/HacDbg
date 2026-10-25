#pragma once

/**
 * @file hacdbg_trace_api.h
 * @brief C ABI for the embedded HacDbg real-time trace renderer.
 *
 * @author HacDbg
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <stddef.h>
#include <stdint.h>

#include <structures/trace.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define HACDBG_TRACE_API_VERSION 1u
#define HACDBG_TRACE_THEME_VERSION 1u

#ifdef HACDBG_TRACE_EXPORTS
#define HACDBG_TRACE_API __declspec(dllexport)
#else
#define HACDBG_TRACE_API __declspec(dllimport)
#endif

#define HACDBG_TRACE_CALL __cdecl

/**
 * @brief Keyboard actions delivered by the native trace window.
 */
typedef enum _HACDBG_TRACE_ACTION
{
    HacDbgTraceActionContinue = 1,
    HacDbgTraceActionStepInto = 2,
    HacDbgTraceActionStepOver = 3,
    HacDbgTraceActionFocusCommand = 4,
    HacDbgTraceActionDeviceError = 5
} HACDBG_TRACE_ACTION;

/**
 * @brief Colors copied from the WPF theme. Colors are packed 0xAARRGGBB.
 */
typedef struct _HACDBG_TRACE_THEME
{
    uint32_t Size;
    uint32_t Version;
    uint32_t Background;
    uint32_t Surface;
    uint32_t SurfaceRaised;
    uint32_t Border;
    uint32_t Text;
    uint32_t Muted;
    uint32_t Accent;
    uint32_t Warning;
    uint32_t Error;
    uint32_t Reserved;
} HACDBG_TRACE_THEME;

typedef struct HACDBG_TRACE HACDBG_TRACE;

/**
 * @brief Optional notification from the render thread. The callback must not
 * call back into the trace ABI.
 */
typedef void (HACDBG_TRACE_CALL* HACDBG_TRACE_ACTION_CALLBACK)(uint32_t Action, void* Context);

/**
 * @brief Returns HACDBG_TRACE_API_VERSION.
 */
HACDBG_TRACE_API uint32_t HACDBG_TRACE_CALL HacDbgTraceApiVersion(void);

/**
 * @brief Returns sizeof(HACDBG_TRACE_THEME).
 */
HACDBG_TRACE_API uint32_t HACDBG_TRACE_CALL HacDbgTraceThemeSize(void);

/**
 * @brief Returns the last HRESULT-like failure recorded by this DLL.
 */
HACDBG_TRACE_API uint32_t HACDBG_TRACE_CALL HacDbgTraceLastError(void);

/**
 * @brief Creates a native child window and its render thread below Host.
 *
 * @details This function returns without waiting for Direct3D or window
 * initialization. Asynchronous failures are delivered through
 * HacDbgTraceActionDeviceError after HacDbgTraceSetActionCallback.
 *
 * @return A trace instance, or NULL when the render thread cannot be started.
 * HacDbgTraceLastError reports the immediate failure code.
 */
HACDBG_TRACE_API HACDBG_TRACE* HACDBG_TRACE_CALL HacDbgTraceAttach(
    HWND Host,
    HINSTANCE Instance,
    const HACDBG_TRACE_THEME* Theme);

/**
 * @brief Publishes a complete immutable snapshot to the render thread.
 *
 * @details The caller may reuse Snapshot after this function returns.
 */
HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTracePublishSnapshot(
    HACDBG_TRACE* Trace,
    const HACDBG_TRACE_SNAPSHOT* Snapshot);

HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTraceSetTheme(
    HACDBG_TRACE* Trace,
    const HACDBG_TRACE_THEME* Theme);

HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTraceSetDpi(
    HACDBG_TRACE* Trace,
    uint32_t Dpi);

HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTraceSetVisible(
    HACDBG_TRACE* Trace,
    uint32_t Visible);

HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTraceResize(
    HACDBG_TRACE* Trace,
    uint32_t Width,
    uint32_t Height);

HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTraceSetActionCallback(
    HACDBG_TRACE* Trace,
    HACDBG_TRACE_ACTION_CALLBACK Callback,
    void* Context);

/**
 * @brief Writes the latest complete snapshot as CSV.
 *
 * @return 0 on success, otherwise an HRESULT-like error code.
 */
HACDBG_TRACE_API uint32_t HACDBG_TRACE_CALL HacDbgTraceExportCsv(
    HACDBG_TRACE* Trace,
    const wchar_t* Path);

/**
 * @brief Stops the render thread, destroys the native child window and waits
 * for the thread to exit.
 */
HACDBG_TRACE_API void HACDBG_TRACE_CALL HacDbgTraceDetach(HACDBG_TRACE* Trace);

#ifdef __cplusplus
}

static_assert(sizeof(HACDBG_TRACE_THEME) == 48, "trace theme ABI changed");
#else
_Static_assert(sizeof(HACDBG_TRACE_THEME) == 48, "trace theme ABI changed");
#endif
