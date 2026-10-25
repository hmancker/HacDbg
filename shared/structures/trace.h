#pragma once

#ifdef __cplusplus
#include <cstdint>
typedef std::uint32_t hacdbg_trace_uint32_t;
typedef std::uint64_t hacdbg_trace_uint64_t;
#else
typedef unsigned int hacdbg_trace_uint32_t;
typedef unsigned long long hacdbg_trace_uint64_t;
#endif

#define HACDBG_TRACE_VERSION                  1u
#define HACDBG_TRACE_MAX_CPUS                 256u
#define HACDBG_TRACE_REASON_COUNT             16u
#define HACDBG_TRACE_EVENTS_PER_CPU           16u
#define HACDBG_TRACE_MAX_EVENTS               256u
#define HACDBG_TRACE_DEFAULT_SAMPLE_RATE      64u
#define HACDBG_TRACE_ALL_CPUS                 0xFFFFFFFFu
#define HACDBG_TRACE_EVENT_MASK_ALL           ((1u << HACDBG_TRACE_REASON_COUNT) - 1u)

//
// trace_control flags. DISABLE, ENABLE_COUNTERS and ENABLE_EVENTS change the
// capture state. RESET, SET_SAMPLE_RATE and SET_EVENT_MASK only perform their
// named action when present. Setting an enable bit without another action
// retains the current sampling rate and event mask.
//
#define HACDBG_TRACE_CONTROL_ENABLE_COUNTERS  (1u << 0)
#define HACDBG_TRACE_CONTROL_ENABLE_EVENTS    (1u << 1)
#define HACDBG_TRACE_CONTROL_RESET            (1u << 2)
#define HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE  (1u << 3)
#define HACDBG_TRACE_CONTROL_SET_EVENT_MASK   (1u << 4)
#define HACDBG_TRACE_CONTROL_DISABLE          (1u << 5)

#define HACDBG_TRACE_FLAG_COUNTERS_ENABLED    (1u << 0)
#define HACDBG_TRACE_FLAG_EVENTS_ENABLED      (1u << 1)

#define HACDBG_TRACE_EVENT_FLAG_ENTRY_FAILURE (1u << 0)

//
// Vendor-neutral exit reason buckets. The driver maps its vendor-specific
// exit code to these values. The numbers are part of the shared ABI.
//
#define HACDBG_TRACE_REASON_OTHER             0u
#define HACDBG_TRACE_REASON_CPUID             1u
#define HACDBG_TRACE_REASON_MSR               2u
#define HACDBG_TRACE_REASON_NESTED_PAGE_FAULT 3u
#define HACDBG_TRACE_REASON_IO                4u
#define HACDBG_TRACE_REASON_EXCEPTION         5u
#define HACDBG_TRACE_REASON_HALT              6u
#define HACDBG_TRACE_REASON_SHUTDOWN          7u
#define HACDBG_TRACE_REASON_INTERRUPT_WINDOW  8u
#define HACDBG_TRACE_REASON_EXTERNAL_INTERRUPT 9u
#define HACDBG_TRACE_REASON_PREEMPTION_TIMER  10u
#define HACDBG_TRACE_REASON_VMX_INSTRUCTION   11u
#define HACDBG_TRACE_REASON_SVM_INSTRUCTION   12u
#define HACDBG_TRACE_REASON_XSETBV            13u
#define HACDBG_TRACE_REASON_INVD              14u
#define HACDBG_TRACE_REASON_MONITOR_TRAP      15u

#define HACDBG_TRACE_BACKEND_AMD              1u
#define HACDBG_TRACE_BACKEND_INTEL            2u

typedef struct _HACDBG_TRACE_CPU
{
    hacdbg_trace_uint64_t TotalExits;
    hacdbg_trace_uint64_t ReasonCounts[HACDBG_TRACE_REASON_COUNT];
    hacdbg_trace_uint32_t DroppedEvents;
    hacdbg_trace_uint32_t CpuIndex;
} HACDBG_TRACE_CPU;

typedef struct _HACDBG_TRACE_EVENT
{
    hacdbg_trace_uint64_t Tsc;
    hacdbg_trace_uint64_t Rip;
    hacdbg_trace_uint64_t Cr3;
    hacdbg_trace_uint64_t ExitInfo1;
    hacdbg_trace_uint64_t ExitInfo2;
    hacdbg_trace_uint64_t DurationTsc;
    hacdbg_trace_uint32_t CpuIndex;
    hacdbg_trace_uint32_t Reason;
    hacdbg_trace_uint32_t Backend;
    hacdbg_trace_uint32_t Flags;
} HACDBG_TRACE_EVENT;

typedef struct _HACDBG_TRACE_SNAPSHOT
{
    hacdbg_trace_uint64_t CapturedTsc;
    hacdbg_trace_uint64_t TotalExits;
    hacdbg_trace_uint64_t DroppedEvents;
    hacdbg_trace_uint32_t Version;
    hacdbg_trace_uint32_t CpuCount;
    hacdbg_trace_uint32_t EventCount;
    hacdbg_trace_uint32_t Flags;
    HACDBG_TRACE_CPU Cpu[HACDBG_TRACE_MAX_CPUS];
    HACDBG_TRACE_EVENT Events[HACDBG_TRACE_MAX_EVENTS];
} HACDBG_TRACE_SNAPSHOT;

#ifdef __cplusplus
static_assert(sizeof(HACDBG_TRACE_CPU) == 144, "trace CPU ABI changed");
static_assert(sizeof(HACDBG_TRACE_EVENT) == 64, "trace event ABI changed");
static_assert(sizeof(HACDBG_TRACE_SNAPSHOT) == 53288, "trace snapshot ABI changed");
#else
_Static_assert(sizeof(HACDBG_TRACE_CPU) == 144, "trace CPU ABI changed");
_Static_assert(sizeof(HACDBG_TRACE_EVENT) == 64, "trace event ABI changed");
_Static_assert(sizeof(HACDBG_TRACE_SNAPSHOT) == 53288, "trace snapshot ABI changed");
#endif
