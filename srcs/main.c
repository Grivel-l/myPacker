#include "packer.h"

static int         getHeader(int fd, const char *path, t_header *header) {
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

int writeToFile(t_header header) {
    int     fd;

    if ((fd = open("./packed", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH | S_IROTH)) == -1)
        return (-1);
    if (write(fd, header.header, header.size) == -1)
        return (-1);
    close(fd);
    return (0);
}

int main(int argc, char **argv) {
    int         fd;
    t_header    header;

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
    if (appendShellcode(&header) == -1)
      return (1);
    if (noteToLoad(&header) == -1)
      return (1);
    if (writeToFile(header) == -1)
      return (1);
    munmap(header.header, header.size);
    return (0);
}
