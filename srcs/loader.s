[bits 64]

section .text
  push rax
  push rdi
  push rsi
  push rdx
  push rbp
  mov rbp, rsp
  call put
  msg:
    db "HelloWorld", 10
  put:
    mov rax, 1
    mov rdi, 1
    mov rsi, [rsp]
    mov rdx, 11
    syscall
  mov rsp, rbp
  pop rbp
  pop rdx
  pop rsi
  pop rdi
  pop rax
