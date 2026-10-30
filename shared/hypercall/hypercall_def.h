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
#include "../structures/trap_frame.h"

#ifdef __cplusplus
enum class hypercall_type_t : std::uint64_t
#else
typedef enum _hypercall_type_t
#endif
{
    guest_physical_memory_operation = 0,
    guest_virtual_memory_operation = 1,
    translate_guest_virtual_address = 2,
    read_guest_cr3 = 3,
    slat = 4,
    log_current_state = 5,
    flush_logs = 6,
    breakpoint = 7,
    trace = 8
#ifdef __cplusplus
};
#else
} hypercall_type_t;
#endif

#ifdef __cplusplus
static_assert(static_cast<std::uint64_t>(hypercall_type_t::guest_physical_memory_operation) == 0,
              "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::guest_virtual_memory_operation) == 1,
              "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::translate_guest_virtual_address) == 2,
              "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::read_guest_cr3) == 3,
              "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::slat) == 4, "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::log_current_state) == 5,
              "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::flush_logs) == 6, "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::breakpoint) == 7, "hypercall number changed");
static_assert(static_cast<std::uint64_t>(hypercall_type_t::trace) == 8, "hypercall number changed");
#else
_Static_assert(guest_physical_memory_operation == 0, "hypercall number changed");
_Static_assert(guest_virtual_memory_operation == 1, "hypercall number changed");
_Static_assert(translate_guest_virtual_address == 2, "hypercall number changed");
_Static_assert(read_guest_cr3 == 3, "hypercall number changed");
_Static_assert(slat == 4, "hypercall number changed");
_Static_assert(log_current_state == 5, "hypercall number changed");
_Static_assert(flush_logs == 6, "hypercall number changed");
_Static_assert(breakpoint == 7, "hypercall number changed");
_Static_assert(trace == 8, "hypercall number changed");
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

// slat call_reserved_data. 0 installs a code hook. 1 removes one. 2 hides a
// page. 3 refreshes hook copies and the SLAT TLB. 4 returns free SLAT pages.
constexpr std::uint64_t slat_add_hook = 0;
constexpr std::uint64_t slat_remove_hook = 1;
constexpr std::uint64_t slat_hide_page = 2;
constexpr std::uint64_t slat_flush = 3;
constexpr std::uint64_t slat_free_page_count = 4;

// breakpoint call_reserved_data. 0 is the guest pause poll. 1 publishes the
// latch as 1. 2 drops the pause because the owner thread is gone.
constexpr std::uint64_t breakpoint_pause_poll = 0;
constexpr std::uint64_t breakpoint_resume_publish = 1;
constexpr std::uint64_t breakpoint_resume_abandon = 2;

// flush_logs call_reserved_data. 0 copies the kernel log ring. 1 registers
// the caller's HACDBG_LOG_MAILBOX. 2 drops that registration. 3 writes
// HACDBG_VERSION_INFO into the caller buffer.
constexpr std::uint64_t flush_logs_register_mailbox = 1;
constexpr std::uint64_t flush_logs_unregister_mailbox = 2;
constexpr std::uint64_t flush_logs_query_version = 3;

// trace call_reserved_data. 0 changes capture state. 1 copies a snapshot.
constexpr std::uint64_t trace_control_op = 0;
constexpr std::uint64_t trace_read_op = 1;

// Bytes copied inside one CPUID vmexit. The copy runs in Hyper-V's vmexit
// handler, so a longer exit can stall the guest long enough to bugcheck.
constexpr std::uint64_t hypercall_memory_chunk_size = 0x10000;
#else
#define hypercall_primary_key 0x4E47
#define hypercall_secondary_key 0x7F
#define pause_latch_signature 0x484354414C434148ull
#define slat_add_hook 0
#define slat_remove_hook 1
#define slat_hide_page 2
#define slat_flush 3
#define slat_free_page_count 4
#define breakpoint_pause_poll 0
#define breakpoint_resume_publish 1
#define breakpoint_resume_abandon 2
#define flush_logs_register_mailbox 1
#define flush_logs_unregister_mailbox 2
#define flush_logs_query_version 3
#define trace_control_op 0
#define trace_read_op 1
#define hypercall_memory_chunk_size 0x10000
#endif

// Records that follow the 32-byte header. trap_frame_log_t is 0xb8 bytes.
// 131072 records is about 24 MiB. A reader that falls behind by less than one
// lap still copies every record. One record is left unpublished to the reader
// so the slot being written is not consumed.
#define HACDBG_LOG_MAILBOX_CAPACITY 131072
#define HACDBG_LOG_MAILBOX_HEADER_BYTES 32
#define HACDBG_LOG_MAILBOX_RECORD_BYTES 0xb8

//
// Debugger mailbox registered through flush_logs. The header is 32 bytes and
// records[HACDBG_LOG_MAILBOX_CAPACITY] follow it. Each record is
// HACDBG_LOG_MAILBOX_RECORD_BYTES. After the record bytes are stored, the
// hypervisor writes producer, then producer_copy, with the same count of
// records ever published. A reader that observes equal fields has a complete
// count. key is chosen by the debugger and checked before every write so a
// reused CR3 is ignored. capacity is HACDBG_LOG_MAILBOX_CAPACITY; any other
// value is rejected. The debugger and the driver must be built from the same
// header. An older driver rejects this capacity and the debugger falls back
// to the kernel log ring.
//
typedef struct _HACDBG_LOG_MAILBOX
{
    hypercall_uint64_t key;
    hypercall_uint64_t capacity;
    hypercall_uint64_t producer;
    hypercall_uint64_t producer_copy;
    unsigned char records[HACDBG_LOG_MAILBOX_CAPACITY * HACDBG_LOG_MAILBOX_RECORD_BYTES];
} HACDBG_LOG_MAILBOX;

#ifdef __cplusplus
static_assert(sizeof(trap_frame_log_t) == HACDBG_LOG_MAILBOX_RECORD_BYTES, "log mailbox record size changed");
static_assert(sizeof(HACDBG_LOG_MAILBOX) ==
                  HACDBG_LOG_MAILBOX_HEADER_BYTES +
                      (HACDBG_LOG_MAILBOX_CAPACITY * HACDBG_LOG_MAILBOX_RECORD_BYTES),
              "log mailbox ABI changed");
static_assert(offsetof(HACDBG_LOG_MAILBOX, capacity) == 8, "log mailbox ABI changed");
static_assert(offsetof(HACDBG_LOG_MAILBOX, producer) == 16, "log mailbox ABI changed");
static_assert(offsetof(HACDBG_LOG_MAILBOX, producer_copy) == 24, "log mailbox ABI changed");
static_assert(offsetof(HACDBG_LOG_MAILBOX, records) == HACDBG_LOG_MAILBOX_HEADER_BYTES,
              "log mailbox ABI changed");
#else
_Static_assert(sizeof(trap_frame_log_t) == HACDBG_LOG_MAILBOX_RECORD_BYTES, "log mailbox record size changed");
_Static_assert(sizeof(HACDBG_LOG_MAILBOX) ==
                   HACDBG_LOG_MAILBOX_HEADER_BYTES +
                       (HACDBG_LOG_MAILBOX_CAPACITY * HACDBG_LOG_MAILBOX_RECORD_BYTES),
               "log mailbox ABI changed");
_Static_assert(offsetof(HACDBG_LOG_MAILBOX, capacity) == 8, "log mailbox ABI changed");
_Static_assert(offsetof(HACDBG_LOG_MAILBOX, producer) == 16, "log mailbox ABI changed");
_Static_assert(offsetof(HACDBG_LOG_MAILBOX, producer_copy) == 24, "log mailbox ABI changed");
_Static_assert(offsetof(HACDBG_LOG_MAILBOX, records) == HACDBG_LOG_MAILBOX_HEADER_BYTES,
               "log mailbox ABI changed");
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
