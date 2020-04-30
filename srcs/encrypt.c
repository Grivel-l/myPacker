#include "packer.h"

int   encryptText(t_header *header) {
  Elf64_Xword i;
  char        *tmp;
  Elf64_Shdr  *text;

  if ((text = getTextSection(header->header)) == NULL)
    return (-1);
  i = 0;
  while (i < text->sh_size) {
    tmp = ((void *)header->header) + text->sh_offset + i;
    *tmp ^= 0xa5;
    i += 1;
  }
  return (0);
}
