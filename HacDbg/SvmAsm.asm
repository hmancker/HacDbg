;
; @file       SvmAsm.asm
;
; @brief      Host stack switch, VMRUN loop, and guest register transfer.
;
; @author     HacDbg
;
; @copyright  Copyright (c) 2017-2020, Satoshi Tanda. Portions adapted from
;             SimpleSvm under the MIT license.
;

extern SvmHandleVmExit:proc

.code

VMCB_STATE_SAVE_AREA_OFFSET equ 400h

SvmLaunchVm proc
        mov     r8, rcx
        mov     rsp, rdx
        sub     rsp, 100h
        mov     [rsp+0F0h], r8
        mov     rax, [r8+40h]
        mov     [rsp+0F8h], rax

SvmLaunchLoop:
        mov     r11, [rsp+0F0h]
        mov     rax, [r11+58h]
        mov     rcx, [r11+60h]
        mov     rdx, [r11+68h]
        mov     rbx, [r11+70h]
        mov     rbp, [r11+80h]
        mov     rsi, [r11+88h]
        mov     rdi, [r11+90h]
        mov     r8,  [r11+98h]
        mov     r9,  [r11+0A0h]
        mov     r10, [r11+0A8h]
        mov     r12, [r11+0B8h]
        mov     r13, [r11+0C0h]
        mov     r14, [r11+0C8h]
        mov     r15, [r11+0D0h]
        mov     r11, [r11+0B0h]

        mov     rax, [rsp+0F8h]
        ; INVARIANT: RAX is this processor's 4 KiB-aligned guest VMCB physical
        ; address, EFER.SVME is set, and GIF is clear or enabled as required.
        vmload  rax
        vmrun   rax
        mov     rax, [rsp+0F8h]
        vmsave  rax

        push    r11
        mov     r11, [rsp+8+0F0h]

        mov     [r11+60h], rcx
        mov     [r11+68h], rdx
        mov     [r11+70h], rbx
        mov     [r11+80h], rbp
        mov     [r11+88h], rsi
        mov     [r11+90h], rdi
        mov     [r11+98h], r8
        mov     [r11+0A0h], r9
        mov     [r11+0A8h], r10
        mov     [r11+0B8h], r12
        mov     [r11+0C0h], r13
        mov     [r11+0C8h], r14
        mov     [r11+0D0h], r15

        mov     r10, [r11]
        mov     rcx, [r10+VMCB_STATE_SAVE_AREA_OFFSET+1F8h]
        mov     [r11+58h], rcx
        mov     rcx, [r10+VMCB_STATE_SAVE_AREA_OFFSET+1D8h]
        mov     [r11+78h], rcx

        mov     r10, r11
        pop     r11
        mov     [r10+0B0h], r11

        ; Guest RAX/RDX/R11 are already stored. rdtsc may clobber RAX and RDX.
        cmp     byte ptr [r10+130h], 0
        je      SvmExitNoTsc
        rdtsc
        shl     rdx, 32
        or      rax, rdx
        mov     [r10+0E0h], rax
SvmExitNoTsc:
        mov     rax, [r10]
        mov     [rsp+0D0h], rax
        lea     rax, [r10+58h]
        mov     [rsp+0D8h], rax
        mov     [rsp+0E0h], r10
        mov     byte ptr [rsp+0E8h], 0

        movaps  xmmword ptr [rsp+20h], xmm0
        movaps  xmmword ptr [rsp+30h], xmm1
        movaps  xmmword ptr [rsp+40h], xmm2
        movaps  xmmword ptr [rsp+50h], xmm3
        movaps  xmmword ptr [rsp+60h], xmm4
        movaps  xmmword ptr [rsp+70h], xmm5

        mov     rcx, rsp
        add     rcx, 0D0h
        call    SvmHandleVmExit

        movaps  xmm0, xmmword ptr [rsp+20h]
        movaps  xmm1, xmmword ptr [rsp+30h]
        movaps  xmm2, xmmword ptr [rsp+40h]
        movaps  xmm3, xmmword ptr [rsp+50h]
        movaps  xmm4, xmmword ptr [rsp+60h]
        movaps  xmm5, xmmword ptr [rsp+70h]

        test    al, al
        jnz     SvmLaunchDone
        jmp     SvmLaunchLoop

SvmLaunchDone:
        mov     r10, [rsp+0F0h]
        mov     r11, [r10]
        mov     rax, [r11+VMCB_STATE_SAVE_AREA_OFFSET+150h]
        mov     cr3, rax
        mov     rdx, [r11+VMCB_STATE_SAVE_AREA_OFFSET+1D8h]
        sub     rdx, 16
        mov     rax, [r11+VMCB_STATE_SAVE_AREA_OFFSET+178h]
        mov     [rdx+8], rax
        mov     rax, [r11+VMCB_STATE_SAVE_AREA_OFFSET+170h]
        mov     [rdx], rax
        mov     [rsp+0E8h], rdx

        mov     rax, [r10+58h]
        mov     rcx, [r10+60h]
        mov     rdx, [r10+68h]
        mov     rbx, [r10+70h]
        mov     rbp, [r10+80h]
        mov     rsi, [r10+88h]
        mov     rdi, [r10+90h]
        mov     r8,  [r10+98h]
        mov     r9,  [r10+0A0h]
        mov     r12, [r10+0B8h]
        mov     r13, [r10+0C0h]
        mov     r14, [r10+0C8h]
        mov     r15, [r10+0D0h]
        mov     r11, [r10+0B0h]
        mov     r10, [r10+0A8h]
        mov     rsp, [rsp+0E8h]
        popfq
        ret
SvmLaunchVm endp

end
