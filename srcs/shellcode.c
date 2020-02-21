#include "packer.h"

static int  patchShellcode(t_header *shellcode, t_header *header, size_t ep) {
  int         address;
  char        ins[12];
  char        *content;
  Elf64_Xword textSize;

  address = -((ep + shellcode->size) - header->header->e_entry + 5);
  ins[0] = 0xe9;
  ins[1] = (address >> 0) & 0xff;
  ins[2] = (address >> 8) & 0xff;
  ins[3] = (address >> 16) & 0xff;
  ins[4] = (address >> 24) & 0xff;
  ins[5] = 0x0;
  ins[6] = 0x0;
  ins[7] = 0x0;
  textSize = getTextSize(header->header);
  // TODO Should write this on 8 bytes
  ins[8] = (textSize >> 0) & 0xff;
  ins[9] = (textSize >> 8) & 0xff;
  ins[10] = (textSize >> 16) & 0xff;
  ins[11] = (textSize >> 24) & 0xff;
  if ((content = mmap(NULL, shellcode->size + sizeof(ins), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(content, shellcode->header, shellcode->size);
  memcpy(content + shellcode->size, ins, sizeof(ins));
  munmap(shellcode->header, shellcode->size);
  shellcode->size += sizeof(ins);
  shellcode->header = (Elf64_Ehdr *)content;
  return (0);
}

static int  getShellcode(t_header *shellcode, t_header *header, size_t ep) {
  int             fd;
  struct stat     stats;

  if (system("nasm -w-orphan-labels -o loader srcs/loader.s") == -1)
    return (-1);
  if (stat("loader", &stats) == -1)
    return (-1);
  shellcode->size = stats.st_size;
  if ((fd = open("loader", O_RDONLY)) == -1)
    return (-1);
  if ((shellcode->header = mmap(NULL, shellcode->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
  {
    close(fd);
    return (-1);
  }
  close(fd);
  return (patchShellcode(shellcode, header, V_ADDR + ep));
}

int  appendShellcode(t_header *header) {
  unsigned char *bin;
  size_t        offset;
  size_t        offset2;
  t_header      shellcode;

  offset2 = header->size;
  if (getShellcode(&shellcode, header, offset2) == -1)
    return (-1);
  if ((bin = mmap(NULL, header->size + shellcode.size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  offset = 0;
  append(bin, header->header, header->size, &offset);
  append(bin, shellcode.header, shellcode.size, &offset);
  munmap(header->header, header->size);
  header->header = (Elf64_Ehdr *)bin;
  header->size += shellcode.size;
  munmap(shellcode.header, shellcode.size);
  header->header->e_entry = V_ADDR + offset2;
  return (0);
}

