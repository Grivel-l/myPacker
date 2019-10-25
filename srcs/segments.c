#include "packer.h"

int       noteToLoad(t_header *header) {
    Elf64_Phdr  *phdr;

    phdr = ((void *)header->header) + header->header->e_phoff;
    // TODO Loop over phdr nbr
    while (phdr->p_type != PT_NOTE)
      phdr = ((void *)phdr) + sizeof(Elf64_Phdr);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    // TODO replace 0xc000000
    phdr->p_offset = header->header->e_entry - 0xc000000;
    phdr->p_vaddr = header->header->e_entry;
    phdr->p_paddr = header->header->e_entry - 0xc000000;
    phdr->p_filesz = header->header->e_entry - 0xc000000;
    phdr->p_memsz = header->header->e_entry - 0xc000000;
    return (0);
}
