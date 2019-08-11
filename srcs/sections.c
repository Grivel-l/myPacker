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

static void updateOffsets(t_header *header) {
    size_t      i;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    if (header->header->e_entry > header->header->e_shoff + sizeof(Elf64_Shdr))
      header->header->e_entry += sizeof(Elf64_Shdr);
    if (header->header->e_phoff > header->header->e_shoff + sizeof(Elf64_Shdr))
      header->header->e_phoff += sizeof(Elf64_Shdr);
    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        program = ((void *)header->header) + header->header->e_phoff + i * sizeof(Elf64_Ehdr);
        if (section->sh_addr != 0 && section->sh_addr > header->header->e_shoff + sizeof(Elf64_Shdr))
            section->sh_addr += sizeof(Elf64_Shdr);
        if (section->sh_offset > header->header->e_shoff + sizeof(Elf64_Shdr))
            section->sh_offset += sizeof(Elf64_Shdr);
        if (section->sh_link != SHN_UNDEF)
            section->sh_link += 1;
        /* if (program->p_offset != 0 && header->header->e_shoff + sizeof(Elf64_Shdr)) */
        /*     program->p_offset += sizeof(Elf64_Shdr); */
        if (program->p_vaddr > header->header->e_shoff + sizeof(Elf64_Shdr))
            program->p_vaddr += sizeof(Elf64_Shdr);
        if (program->p_paddr > header->header->e_shoff + sizeof(Elf64_Shdr))
            program->p_paddr += sizeof(Elf64_Shdr);
        i += 1;
    }
}

// TODO Just set execution flag on right section
void    setPermissions(t_header *header, Elf32_Off addr) {
    size_t      i;
    Elf64_Shdr  *section;

    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        /* if (section->sh_offset <= addr && section->sh_offset + section->sh_size >= addr) */
        (void)addr;
        section->sh_flags |= SHF_EXECINSTR;
        i += 1;
    }
}

t_cave      get_cave(t_header *header) {
    t_cave  cc;
    size_t  tmp;
    size_t  offset;

    tmp = 0;
    offset = 0;
    cc.size = 0;
    while (offset < header->size) {
        if (((char *)header->header)[offset] != 0) {
            if (tmp != 0 && tmp > cc.size) {
                cc.size = tmp;
                cc.offset = offset - tmp;
            }
            tmp = 0;
        }
        else
            tmp += 1;
        offset += 1;
    }
    if (tmp > cc.size) {
        cc.size = tmp;
        cc.offset = offset - tmp;
    }
    return (cc);
}

static int  addSectionFile(t_header *header, t_cave cc) {
    int         fd;
    void        *ep;
    Elf64_Phdr  *loadSegment;

    dprintf(2, "Original entry point: %p\n", NULL + header->header->e_entry);
    setPermissions(header, cc.offset);
    if ((loadSegment = getSegment(header, PT_LOAD)) == NULL)
        return (-1);
    dprintf(1, "New entry point is: %p\n", NULL + cc.offset);
    ep = ((void *)header->header) + cc.offset;
    struct stat     stats;
    unsigned char   *loader;

    if (system("nasm -o loader srcs/loader.s") == -1)
        return (-1);
    if (stat("loader", &stats) == -1)
        return (-1);
    if ((fd = open("loader", O_RDONLY)) == -1)
        return (-1);
    if ((loader = mmap(NULL, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        close(fd);
        return (-1);
    }
    close(fd);
    dprintf(1, "Success, v_addr: %p\n", NULL + loadSegment->p_vaddr);
    memcpy(ep, loader, stats.st_size);
    header->header->e_entry = cc.offset + loadSegment->p_vaddr;
    dprintf(1, "Copied to %p\n", NULL + cc.offset + loadSegment->p_vaddr);
    /* munmap(loader, stats.st_size); */
    return (0);
}

int         addSection(t_header *header, Elf64_Shdr *newSection) {
    char        *bin;
    size_t      offset;
    
    if ((bin = mmap(NULL, header->size + sizeof(Elf64_Shdr), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    header->header->e_shnum += 1;
    header->header->e_shstrndx += 1;
    offset = 0;
    append(bin, header->header, header->header->e_shoff + sizeof(Elf64_Shdr), &offset);
    append(bin, newSection, sizeof(Elf64_Shdr), &offset);
    append(bin, ((void *)header->header) + header->header->e_shoff + sizeof(Elf64_Shdr), header->size - (header->header->e_shoff + sizeof(Elf64_Shdr)), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += sizeof(Elf64_Shdr);
    updateOffsets(header);
    return (0);
    return (addSectionFile(header, get_cave(header)));
}
