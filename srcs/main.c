#include "packer.h"

static void findLibcStart(t_header *header) {
    size_t      i;
    size_t      index;
    Elf64_Sym   *symbol;
    Elf64_Shdr  *section;
    char        *strtable;

    index = 0;
    section = ((void *)header->header) + header->header->e_shoff + header->header->e_shstrndx * sizeof(Elf64_Shdr);
    strtable = ((void *)header->header) + section->sh_offset;
    section = ((void *)header->header) + header->header->e_shoff;
    while (index < header->header->e_shnum) {
      if (section->sh_type == SHT_SYMTAB || section->sh_type == SHT_DYNSYM) {
        i = 0;
        while (i < section->sh_size) {
          symbol = ((void *)header->header) + section->sh_offset + sizeof(Elf64_Sym) * (i / sizeof(Elf64_Sym));
          dprintf(1, "Symbol: %s, Value: %i\n", strtable + symbol->st_name, symbol->st_size);
          i += sizeof(Elf64_Sym);
        }
      }
      index += 1;
      section += 1;
    }
}

int         getHeader(int fd, const char *path, t_header *header) {
    size_t      opened;
    struct stat stats;

    if (stat(path, &stats) == -1)
        return (-1);
    header->size = stats.st_size;
    opened = 0;
    if (fd == -1) {
        if ((fd = open(path, O_RDONLY)) == -1)
            return (-1);
        opened = 1;
    }
    if ((header->header = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        return (-1);
    if (opened)
        close(fd);
    return (0);
}

static int  checkFileType(unsigned char mnum[EI_NIDENT]) {
    if (mnum[EI_MAG0] == ELFMAG0 &&
        mnum[EI_MAG1] == ELFMAG1 &&
        mnum[EI_MAG2] == ELFMAG2 &&
        mnum[EI_MAG3] == ELFMAG3) {
        return (0);
    }
    return (-1);
}

/* static void *getSegmentHeader(Elf64_Ehdr *header, Elf64_Word type) { */
/*     Elf64_Half  i; */
/*     Elf64_Phdr  *last; */
/*     Elf64_Phdr  *segHeader; */

/*     last = NULL; */
/*     segHeader = ((void *)header) + header->e_phoff; */
/*     i = 0; */
/*     while (i < header->e_phnum) { */
/*         if (type == (segHeader + i)->p_type) { */
/*             last = segHeader + i; */
/*         } */
/*         i += 1; */
/*     } */
/*     return (last); */
/* } */

int writeToFile(t_header header) {
    int     fd;

    if ((fd = open("./packed", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
        return (-1);
    if (write(fd, header.header, header.size) == -1)
        return (-1);
    close(fd);
    return (0);
}

/* static Elf64_Shdr   createEP(t_header header) { */
/*     Elf64_Shdr  ep; */

/*     ep.sh_type = SHT_PROGBITS; */
/*     ep.sh_flags = SHF_EXECINSTR | SHF_ALLOC; */
/*     /1* ep.sh_addr *1/ */
/*     /1* ep.sh_offset *1/ */
/*     /1* ep.sh_size *1/ */
/*     ep.sh_link = 0; */
/*     ep.sh_info = 0; */
/*     ep.sh_addralign = 0; */
/*     ep.sh_entsize = 0; */
/*     return (ep); */
/* } */

int main(int argc, char **argv) {
    int         fd;
    t_header    header;
    Elf64_Shdr  newSection;

    if (argc != 2) {
        dprintf(2, "Usage: myPacker arg\n");
        return (1);
    }
    if ((fd = open(argv[1], O_RDONLY)) == -1)
        return (1);
    if (getHeader(fd, argv[1], &header) == -1) {
        close(fd);
        dprintf(2, "Couldn't get header %s\n", strerror(errno));
        return (1);
    }
    close(fd);
    if (checkFileType(header.header->e_ident) == -1) {
        dprintf(2, "File is not an elf file\n");
        return (1);
    }
    errno = 0;
    if (addStr(&header) == -1) {
      dprintf(2, "Couldn't add str\n");
      return (1);
    }
    Elf64_Shdr  *yo;
    yo = getSectionHeader(header.header, ".text");
    newSection = *yo;
    newSection.sh_name = 259;
    newSection.sh_name = 259;
    newSection.sh_type = SHT_PROGBITS;
    newSection.sh_flags = SHF_ALLOC | SHF_EXECINSTR;

    if (addSection(&header, &newSection) == -1) {
        dprintf(2, "Error occured during getting %s\n", strerror(errno));
        return (1);
    }
    if (writeToFile(header) == -1) {
        dprintf(1, "%s\n", strerror(errno));
        return (1);
    }
    munmap(header.header, header.size);
    dprintf(2, "Done\n");
    return (0);
}
