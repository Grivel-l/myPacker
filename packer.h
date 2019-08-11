#ifndef PACKER_H
# define PACKER_H

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include <stdlib.h>

typedef struct  s_header {
    size_t      size;
    Elf64_Ehdr  *header;
}               t_header;

typedef struct  s_cave  {
    size_t      size;
    size_t      offset;
}               t_cave;

int             getHeader(int fd, const char *path, t_header *header);

int             addStr(t_header *header);
int             addSection(t_header *header,  Elf64_Shdr *newSection);
void            *getSectionHeader(Elf64_Ehdr *header, const char *section);
void            obfuscateSection(Elf64_Ehdr *header, Elf64_Shdr *section);

Elf64_Phdr      *getSegment(t_header *header, Elf64_Word type);
Elf64_Phdr      *getLastSegment(t_header *header, Elf64_Word type);

#endif
