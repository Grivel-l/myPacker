#include "packer.h"

Elf64_Xword   getTextSize(Elf64_Ehdr *header) {
  Elf64_Shdr  *section;
  char        *strTable;

  section = ((void *)header) + header->e_shoff;
  strTable = (void *)header + ((section + header->e_shstrndx)->sh_offset);
  while (strcmp(strTable + section->sh_name, ".text") != 0)
    section += 1;
  return (section->sh_size);
}
