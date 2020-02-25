#include "packer.h"

static int  patchShellcode(t_header *shellcode, t_header *header, size_t ep) {
  size_t      address;
  char        params[24];
  char        *content;
  Elf64_Xword textSize;
  int         pagesize;

  pagesize = getpagesize();
  address = -(ep - header->header->e_entry + shellcode->size + 5);
  params[0] = 0xe9;
  params[1] = (address >> 0) & 0xff;
  params[2] = (address >> 8) & 0xff;
  params[3] = (address >> 16) & 0xff;
  params[4] = (address >> 24) & 0xff;
  params[5] = (address >> 32) & 0xff;
  params[6] = (address >> 40) & 0xff;
  params[7] = (address >> 48) & 0xff;
  params[8] = (address >> 56) & 0xff;
  params[9] = 0x0;
  params[10] = 0x0;
  params[11] = 0x0;
  textSize = getTextSize(header->header);
  params[12] = (textSize >> 0) & 0xff;
  params[13] = (textSize >> 8) & 0xff;
  params[14] = (textSize >> 16) & 0xff;
  params[15] = (textSize >> 24) & 0xff;
  params[16] = (textSize >> 32) & 0xff;
  params[17] = (textSize >> 40) & 0xff;
  params[18] = (textSize >> 48) & 0xff;
  params[19] = (textSize >> 56) & 0xff;
  params[20] = (pagesize >> 0) & 0xff;
  params[21] = (pagesize >> 8) & 0xff;
  params[22] = (pagesize >> 16) & 0xff;
  params[23] = (pagesize >> 24) & 0xff;
  if ((content = mmap(NULL, shellcode->size + sizeof(params), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(content, shellcode->header, shellcode->size);
  memcpy(content + shellcode->size, params, sizeof(params));
  munmap(shellcode->header, shellcode->size);
  shellcode->size += sizeof(params);
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

