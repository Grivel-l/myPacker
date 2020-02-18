#include "packer.h"

Elf64_Shdr  *getTextSection(t_header *header) {
  size_t      i;
  Elf64_Shdr  *section;
  char        *stringTable;

  section = ((void *)(header->header) + header->header->e_shoff + sizeof(Elf64_Shdr) * header->header->e_shstrndx);
  stringTable = (char *)((void *)header->header + section->sh_offset);
  section = (void *)(header->header) + header->header->e_shoff;
  i = 0;
  while (i < header->header->e_shnum) {
    if (strcmp(stringTable + section->sh_name, ".text") == 0)
        return (section);
    section += 1;
    i += 1;
  }
  return (NULL);
}

int   encryptText(t_header *header) {
  Elf64_Xword i;
  char        *tmp;
  Elf64_Shdr  *text;

  if ((text = getTextSection(header)) == NULL)
    return (-1);
  i = 0;
  while (i < text->sh_size) {
    tmp = ((void *)header->header) + text->sh_offset + i;
    (void)tmp;
    /* *tmp ^= 0xa5; */
    i += 1;
  }
  return (0);
}
