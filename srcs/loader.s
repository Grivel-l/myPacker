[bits 64]

section .text
  nop
  call put
  msg:
    db "....WOODY....", 10
  put:
    mov rsi, [rsp]
    mov rax, 1
    mov rdi, 1
    mov rdx, 14
    syscall
  call exit
  exit:
    mov rax, 60
    mov rdi, 0
    syscall

