#include "packer.h"

static int  patchShellcode(t_header *shellcode, size_t oep, size_t ep) {
  char    ins[5];
  char    *header;
  size_t  address;

  address = -(ep - oep + shellcode->size + 5);
  ins[0] = 0xe9;
  ins[1] = (address >> 0) & 0xff;
  ins[2] = (address >> 8) & 0xff;
  ins[3] = (address >> 16) & 0xff;
  ins[4] = (address >> 24) & 0xff;
  if ((header = mmap(NULL, shellcode->size + 5, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(header, shellcode->header, shellcode->size);
  memcpy(header + shellcode->size, ins, 5);
  munmap(shellcode->header, shellcode->size);
  shellcode->size += 5;
  shellcode->header = (Elf64_Ehdr *)header;
  return (0);
}

static int  getShellcode(t_header *shellcode, size_t oep, size_t ep) {
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
  return (patchShellcode(shellcode, oep, 0xc000000 + ep));
}

int  appendShellcode(t_header *header) {
  unsigned char *bin;
  size_t        offset;
  size_t        offset2;
  t_header      shellcode;

  offset2 = header->size;
  if (getShellcode(&shellcode, header->header->e_entry, offset2) == -1)
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
  header->header->e_entry = 0xc000000 + offset2;
  return (0);
}

