;
; @file       VmxAsm.asm
;
; @brief      VMX enter, VM-exit register save, and INVEPT.
;
; @author     HacDbg
;

extern VmxHandleVmExit:proc
extern VmxAbortToGuest:proc

.code

; VMX_PROCESSOR_CONTEXT offsets. Keep these identical to the C assertions.
VMX_GUEST_CR3     equ 80h
VMX_GUEST_RIP     equ 88h
VMX_GUEST_RSP     equ 90h
VMX_GUEST_RFLAGS  equ 98h

VmxReadTr proc
        str     ax
        ret
VmxReadTr endp

VmxReadLdtr proc
        sldt    ax
        ret
VmxReadLdtr endp

HacDbgVmxOn proc
        ; INVARIANT: RCX points at the 4 KiB-aligned VMXON physical address.
        ; CR4.VMXE is set and IA32_FEATURE_CONTROL allows VMX outside SMX.
        vmxon   qword ptr [rcx]
        jc      HacDbgVmxOnFail
        jz      HacDbgVmxOnFail
        xor     eax, eax
        ret
HacDbgVmxOnFail:
        mov     eax, 1
        ret
HacDbgVmxOn endp

VmxClear proc
        ; INVARIANT: RCX points at this processor's 4 KiB-aligned VMCS
        ; physical address. The processor is in VMX operation.
        vmclear qword ptr [rcx]
        jc      VmxClearFail
        jz      VmxClearFail
        xor     eax, eax
        ret
VmxClearFail:
        mov     eax, 1
        ret
VmxClear endp

VmxPtrld proc
        ; INVARIANT: RCX points at this processor's VMCS physical address.
        ; The VMCS is clear and is not active on another logical processor.
        vmptrld qword ptr [rcx]
        jc      VmxPtrldFail
        jz      VmxPtrldFail
        xor     eax, eax
        ret
VmxPtrldFail:
        mov     eax, 1
        ret
VmxPtrld endp

HacDbgVmxOff proc
        ; INVARIANT: This processor is in VMX root operation and is not in SMM.
        vmxoff
        ret
HacDbgVmxOff endp

VmxInvept proc
        sub     rsp, 28h
        mov     [rsp], rdx
        mov     qword ptr [rsp+8], 0
        ; INVARIANT: The processor is in VMX operation. RDX is an EPTP value
        ; that belongs to this hypervisor, not to the guest.
        invept  rcx, oword ptr [rsp]
        add     rsp, 28h
        jc      VmxInveptFail
        jz      VmxInveptFail
        xor     eax, eax
        ret
VmxInveptFail:
        mov     eax, 1
        ret
VmxInvept endp

; RCX is the processor context. RDX is the host RSP, and [RDX] holds that context.
VmxLaunchVm proc
        mov     r10, rsp
        mov     rsp, rdx
        ; INVARIANT: The current VMCS belongs to this processor. Guest RIP is
        ; the instruction after RtlCaptureContext. Host RIP is VmxExitEntry.
        vmlaunch
        mov     rsp, r10
        xor     eax, eax
        ret
VmxLaunchVm endp

; Host RIP. [RSP] is the processor context. Guest general registers are live.
VmxExitEntry proc
        push    rax
        push    rcx
        mov     rcx, [rsp+16]
        mov     rax, [rsp+8]
        mov     [rcx+0], rax
        mov     rax, [rsp]
        mov     [rcx+8], rax
        mov     [rcx+10h], rdx
        mov     [rcx+18h], rbx
        mov     [rcx+28h], rbp
        mov     [rcx+30h], rsi
        mov     [rcx+38h], rdi
        mov     [rcx+40h], r8
        mov     [rcx+48h], r9
        mov     [rcx+50h], r10
        mov     [rcx+58h], r11
        mov     [rcx+60h], r12
        mov     [rcx+68h], r13
        mov     [rcx+70h], r14
        mov     [rcx+78h], r15
        mov     r12, rcx
        cmp     byte ptr [r12+178h], 0
        je      VmxExitNoSample
        rdtsc
        shl     rdx, 32
        or      rax, rdx
        mov     [r12+128h], rax
VmxExitNoSample:
        sub     rsp, 28h
        mov     rcx, r12
        call    VmxHandleVmExit
        add     rsp, 28h
        test    al, al
        jnz     VmxExitLeave

        cmp     byte ptr [r12+178h], 0
        je      VmxExitNoOffset
        mov     rax, 2010h
        mov     rcx, [r12+130h]
        vmwrite rax, rcx
VmxExitNoOffset:
        mov     rax, [r12+0]
        mov     rcx, [r12+8]
        mov     rdx, [r12+10h]
        mov     rbx, [r12+18h]
        mov     rbp, [r12+28h]
        mov     rsi, [r12+30h]
        mov     rdi, [r12+38h]
        mov     r8,  [r12+40h]
        mov     r9,  [r12+48h]
        mov     r10, [r12+50h]
        mov     r11, [r12+58h]
        mov     r13, [r12+68h]
        mov     r14, [r12+70h]
        mov     r15, [r12+78h]
        mov     r12, [r12+60h]
        add     rsp, 16
        ; INVARIANT: The current VMCS is still this processor's VMCS, and the
        ; guest instruction pointer has been advanced or an event was injected.
        vmresume
        mov     rcx, [rsp]
        sub     rsp, 28h
        call    VmxAbortToGuest
        add     rsp, 28h
        mov     r12, rax

VmxExitLeave:
        mov     rax, [r12+VMX_GUEST_CR3]
        mov     cr3, rax
        mov     r11, [r12+VMX_GUEST_RSP]
        sub     r11, 32
        mov     rax, [r12+58h]
        mov     [r11], rax
        mov     rax, [r12+50h]
        mov     [r11+8], rax
        mov     rax, [r12+VMX_GUEST_RFLAGS]
        mov     [r11+16], rax
        mov     rax, [r12+VMX_GUEST_RIP]
        mov     [r11+24], rax
        mov     rax, [r12+0]
        mov     rcx, [r12+8]
        mov     rdx, [r12+10h]
        mov     rbx, [r12+18h]
        mov     rbp, [r12+28h]
        mov     rsi, [r12+30h]
        mov     rdi, [r12+38h]
        mov     r8,  [r12+40h]
        mov     r9,  [r12+48h]
        mov     r13, [r12+68h]
        mov     r14, [r12+70h]
        mov     r15, [r12+78h]
        mov     r10, r11
        mov     r12, [r12+60h]
        mov     rsp, r10
        pop     r11
        pop     r10
        popfq
        ret
VmxExitEntry endp

end
