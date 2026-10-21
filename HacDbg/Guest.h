/**
 * @file Guest.h
 * @brief Vendor-neutral guest register view used by hypercall dispatch.
 *
 * @author HacDbg
 */

#pragma once

#include "Types.h"

/**
 * @brief General-purpose registers saved across a VM exit.
 */
typedef struct _HACDBG_GUEST_REGISTERS
{
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rsp;
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
} HACDBG_GUEST_REGISTERS;

/**
 * @brief Guest state a hypercall can read without knowing the vendor control block.
 */
typedef struct _HACDBG_GUEST_VIEW
{
    HACDBG_GUEST_REGISTERS* Registers;
    UINT64 Cr3;
    UINT64 Rip;
    BOOLEAN InGuest;
} HACDBG_GUEST_VIEW;
