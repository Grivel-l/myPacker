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

// TODO Replace this value
#define V_ADDR 0xc000000

int             appendShellcode(t_header *header);

void            append(void *bin, void *toAppend, size_t size, size_t *offset);

int             noteToLoad(t_header *header);

#endif
