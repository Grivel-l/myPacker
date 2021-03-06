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
  mov rdx, msgEnd - msg
  syscall
  mov rdx, 0x7  ; PROT_READ | PROT_WRITE | PROT_EXEC
  call mprotect
  call decrypt
  mov rdx, 0x5  ; PROT_READ | PROT_EXEC
  call mprotect
  mov rsp, rbp
  pop rbp
  pop rdx
  pop rsi
  pop rdi
  pop rax
  jmp dataend ; Jump to the intruction which will make the jump back to the oep
  mprotect:
    mov rax, r12
    add rax, dataend + 24 ; Text section address
    mov rax, [rax]
    mov rdi, r12
    sub rdi, rax
    call alignValue
    mov rax, 10
    mov rsi, r12
    add rsi, dataend + 12 ; Code section size
    mov rsi, [rsi]
    syscall
    ret
  alignValue:
    mov rcx, r12
    add rcx, dataend + 20 ; Page size
    mov ecx, [rcx]
    sub rcx, 1
    mov rax, rdi
    not rcx
    and rax, rcx
    mov rdi, rax
    ret
  decrypt:
    mov rax, r12
    add rax, dataend + 24 ; Text section address
    mov rax, [rax]
    mov rdx, r12
    sub rdx, rax
    mov rdi, 0
    mov rsi, r12
    add rsi, dataend + 12 ; Code section size
    loop:
      cmp rdi, [rsi]
      je endLoop
      xor byte [rdx], 0xa5
      add rdx, 1
      add rdi, 1
      jmp loop
    endLoop:
    ret
  init:
    mov rax, [rsp]
    ret

section .data
  msg db "HelloWorld", 10
  msgEnd
  dataend
