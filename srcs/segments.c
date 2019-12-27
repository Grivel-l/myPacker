#include "packer.h"

int       noteToLoad(t_header *header) {
    Elf64_Half  i;
    Elf64_Phdr  *phdr;

    phdr = ((void *)header->header) + header->header->e_phoff;
    i = 0;
    while (i < header->header->e_phnum) {
      if (phdr->p_type == PT_NOTE)
        break ;
      i += 1;
      phdr += 1;
    }
    if (i == header->header->e_phnum)
      return (-1);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    phdr->p_offset = header->header->e_entry - V_ADDR;
    phdr->p_vaddr = header->header->e_entry;
    phdr->p_paddr = header->header->e_entry - V_ADDR;
    phdr->p_filesz = header->header->e_entry - V_ADDR;
    phdr->p_memsz = header->header->e_entry - V_ADDR;
    return (0);
}
