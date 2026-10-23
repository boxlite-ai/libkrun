/* SPDX-License-Identifier: Apache-2.0 */
/* Real-mode fixture loaded at 0x1000. Entry offsets: 0, 0x200, 0x300, 0x400.
 * Each continuation CPU owns [0x8000 + id*64]: counter, failure, boot count.
 * Timer counter is 0x9000; IVT vectors 0x20/0x30 are installed by the test.
 * Legacy entry 0x800: COM1 output and scratch, counter 0x9000, and an i8042
 * reset once the host sets [0x9006]; the counter keeps moving after the
 * reset until the vCPU is stopped.
 */
.intel_syntax noprefix
.code16
.text
    cli
    mov si, bx
    shl si, 6
    add si, 0x8000
    inc word ptr [si+4]
    mov sp, si
    add sp, 0x2000
    mov eax, cr0
    and eax, 0xfffffffb
    or eax, 2
    mov cr0, eax
    mov eax, cr4
    or eax, 0x600
    mov cr4, eax
    mov eax, 0x10203040
    movd xmm0, eax
    mov dx, 0x55aa
    call continuation
failed:
    mov word ptr [si+2], 1
    jmp failed
continuation:
    push dx
    mov bp, sp
counter_loop:
    cmp word ptr ss:[bp], 0x55aa
    jne failed
    cmp dx, 0x55aa
    jne failed
    movd eax, xmm0
    cmp eax, 0x10203040
    jne failed
    inc word ptr [si]
    jmp counter_loop

.org 0x200
    cli
    mov sp, 0xa000
    mov al, 0x11
    out 0x20, al
    out 0xa0, al
    mov al, 0x20
    out 0x21, al
    mov al, 0x28
    out 0xa1, al
    mov al, 4
    out 0x21, al
    mov al, 2
    out 0xa1, al
    mov al, 1
    out 0x21, al
    out 0xa1, al
    mov al, 0xfe
    out 0x21, al
    mov al, 0xff
    out 0xa1, al
    mov al, 0x36
    out 0x43, al
    mov ax, 11932
    out 0x40, al
    mov al, ah
    out 0x40, al
    sti
pit_wait:
    hlt
    jmp pit_wait

.org 0x300
    cli
    mov sp, 0xa000
    mov al, 0xff
    out 0x21, al
    out 0xa1, al
    mov byte ptr [0x9002], 0
    call enable_x2apic
    mov ecx, 0x83e
    mov eax, 0xb
    wrmsr
    mov ecx, 0x832
    mov eax, 0x20030
    wrmsr
    mov ecx, 0x838
    mov eax, 10000000
    wrmsr
    sti
lapic_wait:
    hlt
    jmp lapic_wait

.org 0x400
    cli
    mov sp, 0xa000
    mov al, 0xff
    out 0x21, al
    out 0xa1, al
    mov byte ptr [0x9002], 1
    call enable_x2apic
    mov ecx, 0x832
    mov eax, 0x40030
    wrmsr
    call arm_deadline
    sti
deadline_wait:
    hlt
    jmp deadline_wait
arm_deadline:
    rdtsc
    add eax, 100000000
    adc edx, 0
    mov ecx, 0x6e0
    wrmsr
    ret

.org 0x500
    cli
    mov sp, 0xa000
    mov al, 0xff
    out 0x21, al
    out 0xa1, al
    mov byte ptr [0x9002], 0
    call enable_x2apic
    mov ecx, 0x83e
    mov eax, 0xb
    wrmsr
    mov ecx, 0x832
    mov eax, 0x30
    wrmsr
    mov ecx, 0x838
    mov eax, 1000000000
    wrmsr
    mov word ptr [0x9004], 1
    sti
one_shot_wait:
    hlt
    jmp one_shot_wait

.org 0x580
    cli
    mov sp, 0xa000
    mov al, 0xff
    out 0x21, al
    out 0xa1, al
    mov byte ptr [0x9002], 0
    call enable_x2apic
    mov ecx, 0x832
    mov eax, 0x40030
    wrmsr
    rdtsc
    add eax, 1000000000
    adc edx, 0
    mov ecx, 0x6e0
    wrmsr
    mov word ptr [0x9004], 1
    sti
one_deadline_wait:
    hlt
    jmp one_deadline_wait

.org 0x600
    push ax
    inc word ptr [0x9000]
    mov al, 0x20
    out 0x20, al
    pop ax
    iret

.org 0x680
    inc word ptr [0x9000]
    mov ecx, 0x80b
    xor eax, eax
    xor edx, edx
    wrmsr
    cmp byte ptr [0x9002], 0
    je timer_done
    call arm_deadline
timer_done:
    iret

.org 0x700
enable_x2apic:
    mov ecx, 0x1b
    rdmsr
    or eax, 0xc00
    wrmsr
    mov ecx, 0x80f
    mov eax, 0x1ff
    xor edx, edx
    wrmsr
    ret

.org 0x780
    cli
    mov word ptr [0x9004], 1
halted_forever:
    hlt
    jmp halted_forever

.org 0x800
    cli
    mov dx, 0x3f8
    mov al, 0x4b
    out dx, al
    mov dx, 0x3ff
    mov al, 0x5a
    out dx, al
legacy_loop:
    inc word ptr [0x9000]
    cmp word ptr [0x9006], 0
    je legacy_loop
    mov al, 0xfe
    out 0x64, al
legacy_reset:
    inc word ptr [0x9000]
    jmp legacy_reset
