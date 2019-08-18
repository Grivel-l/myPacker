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

static void updateOffsets(t_header *header, size_t offset, size_t toAdd, size_t isSection) {
    size_t      i;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    if (header->header->e_entry >= offset)
      header->header->e_entry += toAdd;
    if (header->header->e_phoff >= offset)
      header->header->e_phoff += toAdd;
    if (header->header->e_shoff >= offset)
      header->header->e_shoff += toAdd;
    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        program = ((void *)header->header) + header->header->e_phoff + i * sizeof(Elf64_Ehdr);
        if (section->sh_offset >= offset)
            section->sh_offset += toAdd;
        // TODO Better way to handle this
        if (section->sh_link != SHN_UNDEF && isSection)
            section->sh_link += 1;
        i += 1;
    }
}

static int  getShellcode(t_header *shellcode) {
    int             fd;
    struct stat     stats;

    if (system("nasm -o loader srcs/loader.s") == -1)
        return (-1);
    if (stat("loader", &stats) == -1)
        return (-1);
    shellcode->size = stats.st_size;
    if ((fd = open("loader", O_RDONLY)) == -1)
        return (-1);
    if ((shellcode->header = mmap(NULL, shellcode->size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        close(fd);
        return (-1);
    }
    close(fd);
    return (0);
}
    /* dprintf(1, "Success, v_addr: %p\n", NULL + loadSegment->p_vaddr); */
    /* memcpy(ep, loader, stats.st_size); */

/* kk */
    /* void        *ep; */
    /* Elf64_Phdr  *loadSegment; */

    /* dprintf(2, "Original entry point: %p\n", NULL + header->header->e_entry); */
    /* if ((loadSegment = getSegment(header, PT_LOAD)) == NULL) */
    /*     return (-1); */
    /* // dprintf(1, "New entry point is: %p\n", NULL + cc.offset); */
    /* // ep = ((void *)header->header) + cc.offset; */

    /* // header->header->e_entry = cc.offset + loadSegment->p_vaddr; */
    /* // dprintf(1, "Copied to %p\n", NULL + cc.offset + loadSegment->p_vaddr); */
    /* /1* munmap(loader, stats.st_size); *1/ */
    /* return (0); */

static int  addSectionFile(t_header *header) {
    char          *bin;
    size_t        offset;
    size_t        offset2;
    Elf64_Shdr    *section;
    t_header      shellcode;

    if (getShellcode(&shellcode) == -1)
      return (-1);
    if ((bin = mmap(NULL, header->size + shellcode.size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
      return (-1);
    offset = 0;
    offset2 = header->header->e_shoff + header->header->e_shnum * header->header->e_shentsize;
    append(bin, header->header, offset2 - 1, &offset);
    append(bin, shellcode.header, shellcode.size, &offset);
    append(bin, ((void *)header->header) + offset2, header->size - (offset2 - 1), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += shellcode.size;
    updateOffsets(header, offset2, shellcode.size, 0);
    section = getSectionHeader(header->header, ".packed");
    section->sh_offset = offset2;
    section->sh_size = shellcode.size;
    munmap(shellcode.header, shellcode.size);
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
    shstrtab->sh_size += length;
    offset2 = shstrtab->sh_offset + shstrtab->sh_size - length;
    append(bin, header->header, shstrtab->sh_offset + shstrtab->sh_size - length, &offset);
    append(bin, ".packed", length, &offset);
    append(bin, ((void *)header->header) + shstrtab->sh_offset + (shstrtab->sh_size - length), header->size - (offset - length), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += length;
    updateOffsets(header, offset2, length, 0);
    return (0);
}

int         addSection(t_header *header, Elf64_Shdr *newSection) {
    char        *bin;
    size_t      offset;
    size_t      offset2;
    
    if ((bin = mmap(NULL, header->size + sizeof(Elf64_Shdr), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    header->header->e_shnum += 1;
    header->header->e_shstrndx += 1;
    offset = 0;
    offset2 = header->header->e_shoff + sizeof(Elf64_Shdr);
    append(bin, header->header, header->header->e_shoff + sizeof(Elf64_Shdr), &offset);
    append(bin, newSection, sizeof(Elf64_Shdr), &offset);
    append(bin, ((void *)header->header) + header->header->e_shoff + sizeof(Elf64_Shdr), header->size - (header->header->e_shoff + sizeof(Elf64_Shdr)), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += sizeof(Elf64_Shdr);
    updateOffsets(header, offset2, sizeof(Elf64_Shdr), 1);
    return (addSectionFile(header));
}
