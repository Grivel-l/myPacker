#include "packer.h"

void    *getSectionHeader(Elf64_Ehdr *header, const char *section) {
    Elf64_Half  i;
    Elf64_Shdr  *strTable;
    Elf64_Shdr  *secHeader;

    secHeader = ((void *)header) + header->e_shoff;
    strTable = secHeader + header->e_shstrndx;
    i = 0;
    while (i < header->e_shnum) {
        if (strcmp(section, ((void *)header + strTable->sh_offset + (secHeader + i)->sh_name)) == 0)
            return (secHeader + i);
        i += 1;
    }
    return (NULL);
}

void        obfuscateSection(Elf64_Ehdr *header, Elf64_Shdr *section) {
    size_t  i;
    char    *tmp;

    i = 0;
    while (i < section->sh_size) {
        tmp = ((void *)header + section->sh_offset + i);
        *tmp ^= 0xa5;
        i += 1;
    }
}

static void append(void *bin, void *toAppend, size_t size, size_t *offset) {
    memcpy(bin + *offset, toAppend, size);
    *offset += size;
}

static void updateSectionOffsets(t_header *header) {
    size_t      i;
    Elf64_Shdr  *tmp;

    i = 0;
    while (i < header->header->e_shnum) {
        tmp = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        if (tmp->sh_addr != 0 && tmp->sh_addr > header->size - header->header->e_shnum * sizeof(Elf64_Shdr))
            tmp->sh_addr += sizeof(Elf64_Shdr);
        if (tmp->sh_offset > header->size - header->header->e_shnum * sizeof(Elf64_Shdr))
            tmp->sh_offset += sizeof(Elf64_Shdr);
        if (tmp->sh_link != SHN_UNDEF)
            tmp->sh_link += 1;
        i += 1;
    }
}

int         addSection(t_header *header, Elf64_Shdr *newSection) {
    char        *bin;
    size_t      offset;

    if ((bin = mmap(NULL, header->size + sizeof(Elf64_Shdr), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    updateSectionOffsets(header);
    header->header->e_shstrndx += 1;
    header->header->e_shnum += 1;
    offset = 0;
    append(bin, header->header, header->size - (header->header->e_shnum - 1) * sizeof(Elf64_Shdr), &offset);
    append(bin, newSection, sizeof(Elf64_Shdr), &offset);
    append(bin, (void *)header->header + header->size - (header->header->e_shnum - 1) * sizeof(Elf64_Shdr), (header->header->e_shnum - 1) * sizeof(Elf64_Shdr), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += sizeof(Elf64_Shdr);
    return (0);
}
