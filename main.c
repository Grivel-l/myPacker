#include "packer.h"

static int  getHeader(int fd, const char *path, s_header *header) {
    struct stat stats;

    if (stat(path, &stats) == -1)
        return (-1);
    header->size = stats.st_size;
    if ((header->header = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        return (-1);
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

static void *getSectionHeader(Elf64_Ehdr *header, const char *section) {
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

int writeToFile(s_header header) {
    int     fd;

    if ((fd = open("./packed", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
        return (-1);
    if (write(fd, header.header, header.size) == -1)
        return (-1);
    close(fd);
    return (0);
}

static void obfuscateSection(Elf64_Ehdr *header, Elf64_Shdr *section) {
    size_t  i;
    char    *tmp;

    i = 0;
    while (i < section->sh_size) {
        tmp = ((void *)header + section->sh_offset + i);
        *tmp ^= 0xa5;
        i += 1;
    }
}

/* static Elf64_Shdr   createEP(s_header header) { */
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

static int  addSection(s_header *header) {
    char        *bin;
    size_t      tableSize;
    Elf64_Ehdr  *binHeader;
    Elf64_Shdr  *secHeader;
    Elf64_Shdr  *cpy;

    if ((cpy = getSectionHeader(header->header, ".text")) == NULL) {
        return (-1);
    }
    tableSize = sizeof(Elf64_Shdr);
    binHeader = header->header;
    if ((bin = mmap(NULL, header->size + tableSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    secHeader = (void *)binHeader + binHeader->e_shoff + binHeader->e_shentsize * binHeader->e_shnum;
    memcpy(bin, binHeader, ((void *)secHeader) - ((void *)binHeader));
    memcpy(bin + (((void *)secHeader) - ((void *)binHeader)), cpy, sizeof(Elf64_Shdr));
    memcpy(bin + (((void *)secHeader) - ((void *)binHeader)) + sizeof(Elf64_Shdr), secHeader, header->size - (((void *)secHeader) - ((void *)binHeader)));
    header->header = (Elf64_Ehdr *)bin;
    header->size += tableSize;
    if (binHeader->e_phoff > binHeader->e_shoff)
        binHeader->e_phoff += tableSize;
    binHeader->e_shnum += 1;
    return (0);
}

int main(int argc, char **argv) {
    int         fd;
    s_header    header;
    Elf64_Shdr  *section;

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
    if ((section = getSectionHeader(header.header, ".text")) == NULL) {
        dprintf(2, "No text section in file\n");
        return (1);
    }
    /* obfuscateSection(header.header, section); */
    (void)obfuscateSection;
    /* createEP(header); */
    errno = 0;
    if (addSection(&header) == -1) {
        dprintf(2, "Error occured during getting %s\n", strerror(errno));
    }
    if (writeToFile(header) == -1) {
        dprintf(1, "%s\n", strerror(errno));
        return (1);
    }
    munmap(header.header, header.size);
    return (0);
}

