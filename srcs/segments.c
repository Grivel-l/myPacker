#include "packer.h"

Elf64_Phdr  *getSegment(t_header *header, Elf64_Word type) {
    size_t      i;
    Elf64_Phdr  *program;

    i = 0;
    while (i < header->header->e_phnum) {
        program = (void *)(header->header) + header->header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_type == type)
            return (program);
        i += 1;
    }
    return (NULL);
}