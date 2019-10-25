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

Elf64_Phdr  *getFlaggedSegment(t_header *header, Elf64_Word type, Elf64_Word flag) {
    size_t      i;
    Elf64_Phdr  *segment;

    i = 0;
    while (i < header->header->e_phnum) {
        segment = (void *)(header->header) + header->header->e_phoff + i * sizeof(Elf64_Phdr);
        if (segment->p_type == type && (segment->p_flags & flag) == flag)
            return (segment);
        i += 1;
    }
    return (NULL);
}

Elf64_Phdr  *getLastSegment(t_header *header, Elf64_Word type) {
    size_t      i;
    Elf64_Phdr  *tmp;
    Elf64_Phdr  *program;

    i = 0;
    tmp = NULL;
    while (i < header->header->e_phnum) {
        program = (void *)(header->header) + header->header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_type == type)
            tmp = program;
        i += 1;
    }
    return (tmp);
}

int       noteToLoad(t_header *header) {
    Elf64_Phdr  *phdr;
    Elf64_Shdr  *shdr;

    shdr = getSectionHeader(header->header, ".packed");
    phdr = ((void *)header->header) + header->header->e_phoff;
    // TODO Loop over phdr nbr
    while (phdr->p_type != PT_NOTE)
      phdr = ((void *)phdr) + sizeof(Elf64_Phdr);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    phdr->p_offset = shdr->sh_offset;
    // TODO Better vaddr/Update too in updateEP
    phdr->p_vaddr = 0xc000000 + shdr->sh_offset;
    phdr->p_paddr = shdr->sh_offset;
    phdr->p_filesz = shdr->sh_size;
    phdr->p_memsz = shdr->sh_size;
    return (0);
}
