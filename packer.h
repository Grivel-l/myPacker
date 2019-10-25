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

int             getShellcode(t_header *shellcode);

void            append(void *bin, void *toAppend, size_t size, size_t *offset);
void            updateOffsets(t_header *header, size_t offset, size_t toAdd, size_t isSection);
void            updateOffsets2(t_header *header, size_t offset, size_t toAdd, size_t isSection);

int             addStr(t_header *header);
int             setNewEP(t_header *header);
int             addSectionHeader(t_header *header,  Elf64_Shdr *newSection);
void            *getSectionHeader(Elf64_Ehdr *header, const char *section);
void            obfuscateSection(Elf64_Ehdr *header, Elf64_Shdr *section);

Elf64_Phdr      *getSegment(t_header *header, Elf64_Word type);
Elf64_Phdr      *getLastSegment(t_header *header, Elf64_Word type);
Elf64_Phdr      *getFlaggedSegment(t_header *header, Elf64_Word type, Elf64_Word flag);

#endif
