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
  mov rsi, rax
  add rsi, msg
  mov rax, 1
  mov rdi, 1
  mov rdx, 11
  syscall
  mov rsp, rbp
  pop rbp
  pop rdx
  pop rsi
  pop rdi
  pop rax
  jmp msg + jumpSize ; Jump to the intruction which will make the jump back to the oep
  init:
    mov rax, [rsp]
    ret

section .data
  datastart
  msg db "HelloWorld", 10
  jumpSize equ $ - datastart
