[bits 64]

section .text
  nop
  int3
  push rax
  push rdi
  push rsi
  push rdx
  call put
  msg:
    db "....WOODY....", 10
  put:
    mov rax, 1
    mov rdi, 1
    mov rsi, [rsp]
    mov rdx, 14
    syscall
  pop rdx
  pop rsi
  pop rdi
  pop rax
  int3
  push 0x1168
  ret
