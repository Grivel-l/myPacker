#include "packer.h"

Elf64_Shdr  *getTextSection(Elf64_Ehdr *header) {
  size_t      i;
  Elf64_Shdr  *section;
  char        *strTable;

  i = 0;
  section = ((void *)header) + header->e_shoff;
  strTable = (void *)header + ((section + header->e_shstrndx)->sh_offset);
  while (i < header->e_shnum) {
    if (strcmp(strTable + section->sh_name, ".text") == 0)
      return (section);
    section += 1;
    i += 1;
  }
  return (NULL);
}
