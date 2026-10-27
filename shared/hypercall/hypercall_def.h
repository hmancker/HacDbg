#pragma once
#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
typedef std::uint64_t hypercall_uint64_t;
#else
#include <stddef.h>
typedef unsigned long long hypercall_uint64_t;
#endif
#include "../structures/memory_operation.h"

#ifdef __cplusplus
enum class hypercall_type_t : std::uint64_t
#else
typedef enum _hypercall_type_t
#endif
{
    guest_physical_memory_operation,
    guest_virtual_memory_operation,
    translate_guest_virtual_address,
    read_guest_cr3,
    add_slat_code_hook,
    remove_slat_code_hook,
    hide_guest_physical_page,
    log_current_state,
    flush_logs,
    get_heap_free_page_count,
    flush_slat_cache,
    breakpoint_pause_poll,
    breakpoint_resume,
    query_hypervisor_version,
    trace_control,
    trace_read
#ifdef __cplusplus
};
#else
} hypercall_type_t;
#endif

#ifdef __cplusplus
static_assert(static_cast<std::uint64_t>(hypercall_type_t::trace_control) == 14,
              "hypercall trace_control number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::trace_read) == 15,
              "hypercall trace_read number changed");
#else
_Static_assert(trace_control == 14, "hypercall trace_control number changed");
_Static_assert(trace_read == 15, "hypercall trace_read number changed");
#endif

// log_current_state with this bit set is a breakpoint hit. The stub pushes
// rcx, rdx, then r8. rdx holds the CR3 filter (0 logs every CR3) and r8 holds
// the breakpoint address to record.
#ifdef __cplusplus
constexpr std::uint64_t hypercall_log_breakpoint_flag = 1;
#else
#define hypercall_log_breakpoint_flag 1
#endif

#pragma warning(push)
#pragma warning(disable: 4201)

#ifdef __cplusplus
constexpr std::uint64_t hypercall_primary_key = 0x4E47;
constexpr std::uint64_t hypercall_secondary_key = 0x7F;

// Eight bytes immediately before a pause latch that lives outside a hook
// shadow. The bytes are HACLATCH. The main SLAT root maps that page, so the
// parked guest and the resume write see the same qword.
constexpr std::uint64_t pause_latch_signature = 0x484354414C434148ull;

// breakpoint_resume call_reserved_data. 0 publishes the latch as 1.
// 1 drops the pause because the owner thread is gone and will not confirm.
constexpr std::uint64_t breakpoint_resume_publish = 0;
constexpr std::uint64_t breakpoint_resume_abandon = 1;

// flush_logs call_reserved_data. 0 copies the log ring. The call-type field
// is 4 bits and 0..15 are already assigned, so the notify page shares this call.
// 1 registers the caller's HACDBG_LOG_NOTIFY. 2 drops that registration.
constexpr std::uint64_t flush_logs_register_notify = 1;
constexpr std::uint64_t flush_logs_unregister_notify = 2;

// Bytes copied inside one CPUID vmexit. The copy runs in Hyper-V's vmexit
// handler, so a longer exit can stall the guest long enough to bugcheck.
constexpr std::uint64_t hypercall_memory_chunk_size = 0x10000;
#else
#define hypercall_primary_key 0x4E47
#define hypercall_secondary_key 0x7F
#define pause_latch_signature 0x484354414C434148ull
#define breakpoint_resume_publish 0
#define breakpoint_resume_abandon 1
#define flush_logs_register_notify 1
#define flush_logs_unregister_notify 2
#define hypercall_memory_chunk_size 0x10000
#endif

//
// Debugger page registered through flush_logs. After each appended log the
// hypervisor writes sequence, then sequence_copy, with the same value. A
// reader that observes equal fields has a complete value. key is chosen by
// the debugger and checked before every write so a reused CR3 is ignored.
//
typedef struct _HACDBG_LOG_NOTIFY
{
    hypercall_uint64_t key;
    hypercall_uint64_t sequence;
    hypercall_uint64_t sequence_copy;
} HACDBG_LOG_NOTIFY;

#ifdef __cplusplus
static_assert(sizeof(HACDBG_LOG_NOTIFY) == 24, "log notify ABI changed");
static_assert(offsetof(HACDBG_LOG_NOTIFY, sequence) == 8, "log notify ABI changed");
static_assert(offsetof(HACDBG_LOG_NOTIFY, sequence_copy) == 16, "log notify ABI changed");
#else
_Static_assert(sizeof(HACDBG_LOG_NOTIFY) == 24, "log notify ABI changed");
_Static_assert(offsetof(HACDBG_LOG_NOTIFY, sequence) == 8, "log notify ABI changed");
_Static_assert(offsetof(HACDBG_LOG_NOTIFY, sequence_copy) == 16, "log notify ABI changed");
#endif

#ifdef __cplusplus
union hypercall_info_t
#else
typedef union _hypercall_info_t
#endif
{
    hypercall_uint64_t value;

    struct
    {
        hypercall_uint64_t primary_key : 16;
#ifdef __cplusplus
        hypercall_type_t call_type : 4;
#else
        hypercall_uint64_t call_type : 4;
#endif
        hypercall_uint64_t secondary_key : 7;
        hypercall_uint64_t call_reserved_data : 37;
    };
#ifdef __cplusplus
};
#else
} hypercall_info_t;
#endif

#ifdef __cplusplus
union virt_memory_op_hypercall_info_t
#else
typedef union _virt_memory_op_hypercall_info_t
#endif
{
    hypercall_uint64_t value;

    struct
    {
        hypercall_uint64_t primary_key : 16;
#ifdef __cplusplus
        hypercall_type_t call_type : 4;
#else
        hypercall_uint64_t call_type : 4;
#endif
        hypercall_uint64_t secondary_key : 7;
#ifdef __cplusplus
        memory_operation_t memory_operation : 1;
#else
        hypercall_uint64_t memory_operation : 1;
#endif
        hypercall_uint64_t address_of_page_directory : 36; // we will construct the other cr3 (aside from the caller process) involved in the operation from this
    };
#ifdef __cplusplus
};
#else
} virt_memory_op_hypercall_info_t;
#endif

#ifdef __cplusplus
static_assert(sizeof(hypercall_info_t) == sizeof(std::uint64_t), "hypercall ABI changed");
static_assert(sizeof(virt_memory_op_hypercall_info_t) == sizeof(std::uint64_t), "hypercall ABI changed");
#else
_Static_assert(sizeof(hypercall_info_t) == 8, "hypercall ABI changed");
_Static_assert(sizeof(virt_memory_op_hypercall_info_t) == 8, "hypercall ABI changed");
#endif

#pragma warning(pop)
