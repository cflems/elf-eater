global _start
section .text

_start:
    mov rdi, "./clonez"
    push rdi
    xor byte [rsp+7], "z"
    mov rdi, rsp
    xor rax, rax
    mov al, 0x2
    xor rsi, rsi
    mov sil, 0x41
    xor rdx, rdx
    mov dx, 0x1ed
    syscall
    mov rdi, rax

    pop rax
    xor rax, rax

; ELF Headers

    ; 0-63 = ELF Header; 64-119 = Program Header
    sub rsp, headsz

    ; e_ident (16)
    mov byte [rsp], 0x7f
    mov byte [rsp+1], 0x45
    mov byte [rsp+2], 0x4c
    mov byte [rsp+3], 0x46
    mov byte [rsp+4], 0x02 ; 64-bit
    mov byte [rsp+5], 0x01 ; little-endian (2=big)
    mov byte [rsp+6], 0x01
    mov byte [rsp+7], 0xff
    xor byte [rsp+7], 0xff

    mov qword [rsp+8], 0xffffffffffffffff
    xor qword [rsp+8], 0xffffffffffffffff

    ; e_type (2)
    mov al, 0x2 ; executable
    mov word [rsp+0x10], ax

    ; e_machine (2)
    mov al, 0x3e ; x86_64
    mov word [rsp+0x12], ax

    ; e_version (4)
    mov al, 0x1 ; non-invalid version
    mov dword [rsp+0x14], eax

    ; e_entry (8) [virtual address]
    mov ax, 0xbeef
    shl rax, 12
    mov al, headsz
    mov qword [rsp+0x18], rax
    xor rax, rax

    ; e_phoff (8) [program header offset]
    mov al, 0x40 ; 64
    mov qword [rsp+0x20], rax

    ; e_shoff (8) [section header offset]
    xor al, al ; no section header
    mov qword [rsp+0x28], rax

    ; e_flags (4)
    xor al, al ; no flags
    mov dword [rsp+0x30], eax

    ; e_ehsize (2)
    mov al, 0x40 ; 64 (constant)
    mov word [rsp+0x34], ax

    ; e_phentsize (2)
    mov al, 0x38 ; 56 (constant)
    mov word [rsp+0x36], ax

    ; e_phnum (2)
    mov al, 0x1 ; number of SEGMENTS
    mov word [rsp+0x38], ax

    ; e_shentsize (2)
    mov al, 0x40 ; 64 (constant)
    mov word [rsp+0x3a], ax

    ; e_shnum (2)
    xor al, al
    mov word [rsp+0x3c], ax

    ; e_shstrndx (2)
    xor al, al
    mov word [rsp+0x3e], ax

; PROGRAM HEADER TABLE
    ; nasm puts program header segment before this but imma skip

    ; p_type (4)
    mov al, 0x1 ; PT_LOAD
    mov dword [rsp+0x40], eax

    ; p_flags (4)
    mov al, 0x5 ; PF_R | PF_X -- text segment
    mov dword [rsp+0x44], eax

    ; p_offset (8)
    xor al, al ; combined header size
    mov qword [rsp+0x48], rax

    ; p_vaddr (8)
    mov word ax, 0xbeef ; arbitrary
    shl rax, 12
    mov qword [rsp+0x50], rax

    ; p_paddr (8)
    ; not relevant on linux, compiler copies vaddr
    mov qword [rsp+0x58], rax
    xor rax, rax
    
    ; p_filesz (8)
    mov word ax, fullsz
    mov qword [rsp+0x60], rax

    ; p_memsz (8)
    ; limited reasons for this to differ from filesz
    mov qword [rsp+0x68], rax

    ; p_align (8)
    mov ah, 0x10 ; 0x1000
    mov qword [rsp+0x70], rax ; align to the page size

    xor rax, rax
    mov al, 0x1
    mov rsi, rsp
    xor rdx, rdx
    mov dl, headsz
    syscall

    xor rax, rax
    mov al, 0x1
    lea rsi, [rel _start]
    mov dx, progsz
    syscall

    xor rax, rax
    mov al, 0x3
    syscall

    xor rax, rax
    xor rdi, rdi
    mov al, 0x3c
    syscall

    headsz equ 0x78
    progsz equ $ - _start
    fullsz equ headsz + progsz
