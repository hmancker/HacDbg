#pragma once

//
// Increment HACDBG_VERSION_PATCH for every behavior change. Increment
// HACDBG_VERSION_MINOR when the hypercall or IOCTL ABI changes. Increment
// HACDBG_VERSION_MAJOR only for an incompatible release.
//
#define HACDBG_VERSION_MAJOR 1
#define HACDBG_VERSION_MINOR 0
#define HACDBG_VERSION_PATCH 14

#define HACDBG_STRINGIFY_INNER(Value) #Value
#define HACDBG_STRINGIFY(Value)       HACDBG_STRINGIFY_INNER(Value)

#define HACDBG_VERSION_STRING          \
    HACDBG_STRINGIFY(HACDBG_VERSION_MAJOR) "." \
    HACDBG_STRINGIFY(HACDBG_VERSION_MINOR) "." \
    HACDBG_STRINGIFY(HACDBG_VERSION_PATCH)
