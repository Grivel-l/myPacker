[bits 64]

section .text
  push rax
  push rdi
  push rsi
  push rdx
  push rbp
  mov rbp, rsp
  call init
  sub rax, $
  mov r12, rax
  mov rax, 1
  mov rdi, 1
  mov rsi, r12
  add rsi, msg
  mov rdx, 11
  syscall
  mov rsp, rbp
  mov rdx, 0x7  ; PROT_READ | PROT_WRITE | PROT_EXEC
  call mprotect
  mov rdx, 0x5  ; PROT_READ | PROT_EXEC
  call mprotect
  pop rbp
  pop rdx
  pop rsi
  pop rdi
  pop rax
  jmp dataend ; Jump to the intruction which will make the jump back to the oep
  mprotect:
    mov rax, 10
    mov rdi, r12
    add rdi, dataend + 1 ; Text section address
    mov rsi, r12
    add rsi, dataend + 8 ; Code section size
    syscall
    ret
  init:
    mov rax, [rsp]
    ret

section .data
  msg db "HelloWorld", 10
  dataend
