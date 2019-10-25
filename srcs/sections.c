#include "packer.h"

void    *getSectionHeader(Elf64_Ehdr *header, const char *section) {
    Elf64_Half  i;
    Elf64_Shdr  *strTable;
    Elf64_Shdr  *secHeader;

    secHeader = ((void *)header) + header->e_shoff;
    strTable = secHeader + header->e_shstrndx;
    i = 0;
    // TODO loop over strtable size instead of section's nbr
    while (i < header->e_shnum) {
        if (strcmp(section, (((void *)header) + strTable->sh_offset + (secHeader + i)->sh_name)) == 0)
            return (secHeader + i);
        i += 1;
    }
    return (NULL);
}

int  addSectionFile(t_header *header) {
    unsigned char          *bin;
    size_t        offset;
    size_t        offset2;
    Elf64_Shdr    *section;
    t_header      shellcode;

    if (getShellcode(&shellcode) == -1)
      return (-1);
    if ((bin = mmap(NULL, header->size + shellcode.size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
      return (-1);
    offset = 0;
    offset2 = header->header->e_shoff + sizeof(Elf64_Shdr) * header->header->e_shnum;
    append(bin, header->header, offset2 - 1, &offset);
    append(bin, shellcode.header, shellcode.size, &offset);
    append(bin, ((void *)header->header) + offset2 - 1, header->size - (offset2 - 1), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += shellcode.size;
    updateOffsets(header, offset2, shellcode.size, 0);
    section = getSectionHeader(header->header, ".packed");
    section->sh_addr = offset2;
    section->sh_offset = offset2;
    section->sh_size = shellcode.size;
    return (0);
}

int         addStr(t_header *header) {
    char          *bin;
    size_t        length;
    size_t        offset;
    size_t        offset2;
    Elf64_Shdr    *shstrtab;

    length = strlen(".packed") + 1;
    if ((bin = mmap(NULL, header->size + length, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    offset = 0;
    shstrtab = ((void *)header->header) + header->header->e_shoff + header->header->e_shstrndx * sizeof(Elf64_Shdr);
    offset2 = shstrtab->sh_offset + shstrtab->sh_size;
    shstrtab->sh_size += length;
    append(bin, header->header, shstrtab->sh_offset + shstrtab->sh_size - length, &offset);
    append(bin, ".packed", length, &offset);
    append(bin, ((void *)header->header) + shstrtab->sh_offset + (shstrtab->sh_size - length), header->size - (offset - length), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += length;
    updateOffsets2(header, offset2, length, 0);
    return (0);
}

int         addSectionHeader(t_header *header, Elf64_Shdr *newSection) {
    char        *bin;
    size_t      length;
    size_t      offset;
    size_t      offset2;
    
    length = sizeof(Elf64_Shdr);
    if ((bin = mmap(NULL, header->size + length, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    header->header->e_shnum += 1;
    header->header->e_shstrndx += 1;
    offset = 0;
    // TODO Better way to handle this
    offset2 = header->header->e_shoff + sizeof(Elf64_Shdr) * (header->header->e_shnum - 1) - sizeof(Elf64_Shdr) * 3;
    append(bin, header->header, offset2, &offset);
    append(bin, newSection, length, &offset);
    append(bin, ((void *)header->header) + offset2, header->size - offset2, &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += length;
    updateOffsets2(header, offset2, length, 1);
    return (0);
}
