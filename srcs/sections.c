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

void    setPermissions(t_header *header, Elf32_Off addr) {
    size_t      i;
    Elf64_Shdr  *section;

    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset < addr && section->sh_offset + section->sh_size > addr)
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
        else if (((char *)header->header)[offset] == 0)
            tmp += 1;
        offset += 1;
    }
    if (tmp > cc.size) {
        cc.size = tmp;
        cc.offset = offset - tmp;
    }
    return (cc);
}

/* void    insertSectionFile(t_header *header, Elf32_Off addr, Elf64_Xword size) { */
/*     char    *bin; */
/*     size_t  offset; */

/*     if ((bin = mmap(NULL, header->size + 300, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED) */
/*         return ; */
/*     checkSectionPermissions(header, addr); */
/*     offset = 0; */
/*     append(bin, header->header, addr + size, &offset); */
/*     memset(bin + offset, 0, 300); */
/*     offset += 300; */
/*     append(bin, ((void *)header->header) + offset - 300, header->size - offset - 300, &offset); */
/*     munmap(header->header, header->size); */
/*     header->header = (Elf64_Ehdr *)bin; */
/*     header->size += 300; */
/* } */

static int  addSectionFile(t_header *header, t_cave cc) {
    void        *ep;
    Elf64_Phdr  *loadSegment;

    dprintf(2, "Original entry point: %p\n", NULL + header->header->e_entry);
    setPermissions(header, cc.offset);
    if ((loadSegment = getSegment(header, PT_LOAD)) == NULL)
        return (-1);
    dprintf(1, "New entry point is: %lx\n", cc.offset);
    ep = ((void *)header->header) + cc.offset;
    char yo[] = {0x48, 0xc7, 0xc0, 0x00, 0x22, 0x00, 0x00, 0xff, 0xe0, 0xb8, 0x00, 0x00, 0x00, 0x00};
    memcpy(ep, yo, 14);
    header->header->e_entry = cc.offset + loadSegment->p_vaddr;
    dprintf(1, "Copied to %p\n", NULL + cc.offset + loadSegment->p_vaddr);
    (void)yo;
    (void)ep;
    return (0);
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
    return (addSectionFile(header, get_cave(header)));
}
