#pragma once
#ifdef __cplusplus
#include <cstdint>
typedef std::uint64_t hypercall_uint64_t;
#else
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
    query_hypervisor_version
#ifdef __cplusplus
};
#else
} hypercall_type_t;
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

// Bytes copied inside one CPUID vmexit. The copy runs in Hyper-V's vmexit
// handler, so a longer exit can stall the guest long enough to bugcheck.
constexpr std::uint64_t hypercall_memory_chunk_size = 0x10000;
#else
#define hypercall_primary_key 0x4E47
#define hypercall_secondary_key 0x7F
#define hypercall_memory_chunk_size 0x10000
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
