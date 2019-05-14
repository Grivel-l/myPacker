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

typedef struct  t_header {
    size_t      size;
    Elf64_Ehdr  *header;
}               s_header;

#endif
