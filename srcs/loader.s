[bits 64]

section .text
  nop
  nop
  nop
  nop
  call put
  call exit

  msg:
    db "HelloWorld", 10
  put:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, 11
    syscall
    ret

  exit:
    int3
    mov rax, 60
    mov rdi, 0
    syscall
