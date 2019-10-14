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
    size_t      size;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    /* dprintf(2, "Updating offsets of %zu\n", toAdd); */
    dprintf(2, "Updating offsets\n");
    if (header->header->e_entry >= offset)
      header->header->e_entry += toAdd;
    if (header->header->e_phoff >= offset)
      header->header->e_phoff += toAdd;
    if (header->header->e_shoff >= offset)
      header->header->e_shoff += toAdd;
    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset >= offset)
            section->sh_offset += toAdd;
        if (section->sh_addr >= offset)
            section->sh_addr += toAdd;
        // TODO Better way to handle this
        if (section->sh_link != SHN_UNDEF && isSection && section->sh_link >= header->header->e_shnum - 3)
            section->sh_link += 1;
        if (section->sh_type == SHT_REL) {
            Elf64_Rel *rel;
            size = 0;
            while (size < section->sh_size) {
              rel = ((void *)header->header) + section->sh_offset + (sizeof(Elf64_Rel) * (size / sizeof(Elf64_Rel)));
              if (rel->r_offset >= offset)
                rel->r_offset += toAdd;
              size += sizeof(Elf64_Rel);
            }
        } else if (section->sh_type == SHT_RELA) {
            Elf64_Rela  *rela;
            size = 0;
            while (size < section->sh_size) {
              rela = ((void *)header->header) + section->sh_offset + (sizeof(Elf64_Rela) * (size / sizeof(Elf64_Rela)));
              if (rela->r_offset >= offset)
                rela->r_offset += toAdd;
              size += sizeof(Elf64_Rela);
            }
        } else if (section->sh_type == SHT_DYNAMIC) {
            Elf64_Dyn *dyn;
            size = 0;
            while (size < section->sh_size) {
              dyn = ((void *)header->header) + section->sh_offset + (sizeof(Elf64_Dyn) * (size / sizeof(Elf64_Dyn)));
              if (dyn->d_un.d_ptr >= offset) {
                dyn->d_un.d_ptr += toAdd;
              }
              size += sizeof(Elf64_Dyn);
            }
            /* Elf64_Move  *move; */
            /* move = ((void *)header->header) + dyn->d_un.d_ptr; */
            /* if (move->m_poffset >= offset) */
            /*   move->m_poffset += toAdd; */
        } else if (section->sh_type == SHT_GNU_verdef) {
            Elf64_Verdef  *verdef;
            verdef = ((void *)header->header) + section->sh_offset;
            if (section->sh_offset < offset && verdef->vd_aux >= offset)
              verdef->vd_aux += toAdd;
            if (section->sh_offset < offset && verdef->vd_next >= offset)
              verdef->vd_aux += toAdd;
        } else if (section->sh_type == SHT_SYMTAB) {
          Elf64_Xword size;
          Elf64_Sym   *symbol;
          size = 0;
          while (size < section->sh_size) {
            symbol = ((void *)header->header) + section->sh_offset + size;
            if (symbol->st_value >= offset) {
              symbol->st_value += toAdd;
            }
            size += sizeof(Elf64_Sym);
          }
        }
        i += 1;
    }
    i = 0;
    while (i < header->header->e_phnum) {
        program = ((void *)header->header) + header->header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_offset >= offset)
            program->p_offset += toAdd;
        if (program->p_vaddr >= offset)
            program->p_vaddr += toAdd;
        if (program->p_paddr >= offset)
            program->p_paddr += toAdd;
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
    if ((shellcode->header = mmap(NULL, shellcode->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
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

    /* dprintf(2, "Original entry point: %p\n", NULL + header->header->e_entry); */
    /* // dprintf(1, "New entry point is: %p\n", NULL + cc.offset); */
    /* // ep = ((void *)header->header) + cc.offset; */

    /* // header->header->e_entry = cc.offset + loadSegment->p_vaddr; */
    /* // dprintf(1, "Copied to %p\n", NULL + cc.offset + loadSegment->p_vaddr); */
    /* /1* munmap(loader, stats.st_size); *1/ */
    /* return (0); */

static int  addSectionFile(t_header *header) {
    unsigned char          *bin;
    size_t        offset;
    size_t        offset2;
    Elf64_Shdr    *section;
    t_header      shellcode;

    if (getShellcode(&shellcode) == -1)
      return (-1);
    shellcode.size += 24;
    if ((bin = mmap(NULL, header->size + shellcode.size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
      return (-1);
    offset = 0;
    section = getSectionHeader(header->header, ".text");
    dprintf(2, "Text offset before anything: %p\n", section->sh_offset);
    offset2 = section->sh_offset;
    /* ((char *)header->header)[offset2] = ((char *)shellcode.header)[0]; */
    /* dprintf(2, "Shellcode size: %zu\n", shellcode.size); */
    append(bin, header->header, offset2 - 1, &offset);
    memset(shellcode.header, 0, shellcode.size);
    append(bin, shellcode.header, shellcode.size, &offset);
    append(bin, ((void *)header->header) + offset2 - 1, header->size - (offset2 - 1), &offset);
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += shellcode.size;
    updateOffsets(header, offset2, shellcode.size, 0);
    /* section = ((void *)header->header) + header->header->e_shoff + sizeof(Elf64_Shdr); */
    section = getSectionHeader(header->header, ".text");
    dprintf(2, "Text offset after adding section content: %p\n", section->sh_offset);
    /* section->sh_offset = ((int)section->sh_offset) + shellcode.size; */
    /* section->sh_addr += shellcode.size; */
    section = getSectionHeader(header->header, ".packed");
    section->sh_addr = offset2;
    section->sh_offset = offset2;
    section->sh_size = shellcode.size;
    return (setNewEP(header));
}

int         setNewEP(t_header *header) {
    Elf64_Shdr  *packed;
    Elf64_Phdr  *loadSegment;

    if ((loadSegment = getFlaggedSegment(header, PT_LOAD, PF_X)) == NULL)
      return (-1);
    packed = getSectionHeader(header->header, ".packed");
    loadSegment->p_memsz += packed->sh_size;
    loadSegment->p_filesz += packed->sh_size;
    if ((loadSegment = getSegment(header, PT_LOAD)) == NULL)
      return (-1);
    packed = getSectionHeader(header->header, ".text");
    header->header->e_entry = packed->sh_offset + loadSegment->p_vaddr;
    /* packed = getSectionHeader(header->header, ".text"); */
    /* header->header->e_entry = packed->sh_offset + loadSegment->p_vaddr; */
    dprintf(2, "New entry point: %p\n", header->header->e_entry);
    return (0);
}

int         addStr(t_header *header) {
    char          *bin;
    size_t        length;
    size_t        offset;
    size_t        offset2;
    Elf64_Shdr    *shstrtab;

    // TODO remove alignment
    length = strlen(".packed        ") + 1;
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
    updateOffsets(header, offset2, length, 1);
    return (addSectionFile(header));
}
