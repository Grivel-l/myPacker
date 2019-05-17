#include "packer.h"

static int  getHeader(int fd, const char *path, t_header *header) {
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

static void *getSegmentHeader(Elf64_Ehdr *header, Elf64_Word type) {
    Elf64_Half  i;
    Elf64_Phdr  *last;
    Elf64_Phdr  *segHeader;

    last = NULL;
    segHeader = ((void *)header) + header->e_phoff;
    i = 0;
    while (i < header->e_phnum) {
        if (type == (segHeader + i)->p_type) {
            last = segHeader + i;
        }
        i += 1;
    }
    return (last);
}

int writeToFile(t_header header) {
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

static int  addSection(t_header *header) {
    size_t      i;
    char        *bin;
    Elf64_Shdr  *cpy;
    Elf64_Shdr  *tmp;
    t_header    shellcode;
    size_t      offset;

    if (getHeader(-1, "./yo", &shellcode) == -1)
        return (-1);
    if ((cpy = getSectionHeader(header->header, ".fini")) == NULL) {
        return (-1);
    }
    if ((tmp = getSectionHeader(shellcode.header, ".text")) == NULL) {
        return (-1);
    }
    if ((bin = mmap(NULL, header->size + shellcode.size + sizeof(Elf64_Shdr), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
        return (-1);
    (void)tmp;
    /* tmp->sh_size = cpy->sh_size; */
    /* tmp->sh_name = cpy->sh_name; */
    /* cpy->sh_offset = offset; */
    /* cpy->sh_addr = (Elf64_Addr)(bin + offset); */
    /* tmp = cpy->sh_addr; */
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
    offset = 0;
    header->header->e_shstrndx += 1;
    header->header->e_shnum += 1;
    memcpy(bin, header->header, header->size - (header->header->e_shnum - 1) * sizeof(Elf64_Shdr));
    offset += header->size - (header->header->e_shnum - 1) * sizeof(Elf64_Shdr);
    /* memcpy(bin + offset, cpy, sizeof(Elf64_Shdr)); */
    /* (void)cpy; */
    /* memset(bin + offset, cpy, sizeof(Elf64_Shdr)); */
    memcpy(bin + offset, cpy, sizeof(Elf64_Shdr));
    offset += sizeof(Elf64_Shdr);
    memcpy(bin + offset, (void *)header->header + header->size - (header->header->e_shnum - 1) * sizeof(Elf64_Shdr), (header->header->e_shnum - 1) * sizeof(Elf64_Shdr));
    munmap(header->header, header->size);
    header->header = (Elf64_Ehdr *)bin;
    header->size += sizeof(Elf64_Shdr);
    (void)getSegmentHeader;

    /* offset += sizeof(Elf64_Shdr); */
    /* memcpy(bin + offset, ((void *)(header->header)) + header->header->e_shoff, (header->header->e_shnum - 1) * sizeof(Elf64_Shdr)); */
    /* header->header->e_entry = tmp; */
    /* (void)getSegmentHeader; */
    
    /* Elf64_Phdr *tmp = getSegmentHeader(shellcode.header, PT_LOAD); */
    /* tableSize = sizeof(Elf64_Shdr); */
    /* binHeader = header->header; */
    /* cpy->sh_size = shellcode.size; */
    /* cpy->sh_offset = header->size + tableSize; */
    /* secSize = cpy->sh_size; */
    /* secHeader = (void *)binHeader + binHeader->e_shoff + binHeader->e_shentsize * binHeader->e_shnum; */
    /* cpy->sh_addr = (Elf64_Addr)(bin + header->size + tableSize); */
    /* memcpy(bin, binHeader, ((void *)secHeader) - ((void *)binHeader)); */
    /* memcpy(bin + (((void *)secHeader) - ((void *)binHeader)), cpy, sizeof(Elf64_Shdr)); */
    /* header->size += sizeof(Elf64_Shdr); */
    /* memcpy(bin + (((void *)secHeader) - ((void *)binHeader)) + sizeof(Elf64_Shdr), secHeader, header->size - (((void *)secHeader) - ((void *)binHeader))); */
    /* memcpy(bin + header->size - header->header->e_shnum * sizeof(Elf64_Shdr) + shellcode.size, */ 
    /* memcpy(bin + header->size - header->header->e_shnum * sizeof(Elf64_Shdr), shellcode.header, shellcode.size); */
    /* /1* memcpy(bin + header->size + tableSize, shellcode.header, shellcode.size); *1/ */
    /* binHeader = header->header; */
    /* header->size += tableSize + secSize; */
    /* if (binHeader->e_phoff > binHeader->e_shoff) */
    /*     binHeader->e_phoff += tableSize; */
    /* binHeader->e_shnum += 1; */
    /* binHeader->e_entry = (Elf64_Addr)((void *)tmp->p_vaddr); */
    return (0);
}

int main(int argc, char **argv) {
    int         fd;
    t_header    header;
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
        return (1);
    }
    if (writeToFile(header) == -1) {
        dprintf(1, "%s\n", strerror(errno));
        return (1);
    }
    munmap(header.header, header.size);
    return (0);
}

