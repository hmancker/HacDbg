#pragma once
#ifdef __cplusplus
#include <cstdint>
typedef std::uint64_t hacdbg_uint64_t;
#else
typedef unsigned long long hacdbg_uint64_t;
#endif

struct trap_frame_t
{
    hacdbg_uint64_t rax;
    hacdbg_uint64_t rcx;
    hacdbg_uint64_t rdx;
    hacdbg_uint64_t rbx;
    hacdbg_uint64_t rsp;
    hacdbg_uint64_t rbp;
    hacdbg_uint64_t rsi;
    hacdbg_uint64_t rdi;
    hacdbg_uint64_t r8;
    hacdbg_uint64_t r9;
    hacdbg_uint64_t r10;
    hacdbg_uint64_t r11;
    hacdbg_uint64_t r12;
    hacdbg_uint64_t r13;
    hacdbg_uint64_t r14;
    hacdbg_uint64_t r15;
};

#ifdef __cplusplus
constexpr std::uint64_t trap_frame_log_stack_data_count = 5;
#else
#define trap_frame_log_stack_data_count 5
#endif

#ifdef __cplusplus
struct trap_frame_log_t : trap_frame_t
{
    hacdbg_uint64_t rip;
    hacdbg_uint64_t cr3;

    hacdbg_uint64_t stack_data[trap_frame_log_stack_data_count];
};
#else
typedef struct trap_frame_log_t
{
    hacdbg_uint64_t rax;
    hacdbg_uint64_t rcx;
    hacdbg_uint64_t rdx;
    hacdbg_uint64_t rbx;
    hacdbg_uint64_t rsp;
    hacdbg_uint64_t rbp;
    hacdbg_uint64_t rsi;
    hacdbg_uint64_t rdi;
    hacdbg_uint64_t r8;
    hacdbg_uint64_t r9;
    hacdbg_uint64_t r10;
    hacdbg_uint64_t r11;
    hacdbg_uint64_t r12;
    hacdbg_uint64_t r13;
    hacdbg_uint64_t r14;
    hacdbg_uint64_t r15;
    hacdbg_uint64_t rip;
    hacdbg_uint64_t cr3;
    hacdbg_uint64_t stack_data[trap_frame_log_stack_data_count];
} trap_frame_log_t;
#endif

struct nmi_trap_frame_t
{
    hacdbg_uint64_t rax;
    hacdbg_uint64_t rcx;
    hacdbg_uint64_t rdx;
    hacdbg_uint64_t rbx;
    hacdbg_uint64_t rbp;
    hacdbg_uint64_t rsi;
    hacdbg_uint64_t rdi;
    hacdbg_uint64_t r8;
    hacdbg_uint64_t r9;
    hacdbg_uint64_t r10;
    hacdbg_uint64_t r11;
    hacdbg_uint64_t r12;
    hacdbg_uint64_t r13;
    hacdbg_uint64_t r14;
    hacdbg_uint64_t r15;

    hacdbg_uint64_t rip;
    hacdbg_uint64_t cs;
    hacdbg_uint64_t rflags;
    hacdbg_uint64_t rsp;
    hacdbg_uint64_t ss;
};

#ifdef __cplusplus
static_assert(sizeof(trap_frame_t) == 0x80, "trap frame ABI changed");
static_assert(sizeof(trap_frame_log_t) == 0xb8, "trap frame log ABI changed");
#else
_Static_assert(sizeof(struct trap_frame_t) == 0x80, "trap frame ABI changed");
_Static_assert(sizeof(trap_frame_log_t) == 0xb8, "trap frame log ABI changed");
#endif
