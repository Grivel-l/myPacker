#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <elf.h>

static void *getHeader(int fd, const char *path) {
    void        *content;
    struct stat stats;

    if (stat(path, &stats) == -1)
        return (NULL);
    if ((content = mmap(NULL, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        return (NULL);
    return (content);
}

static int  checkFileType(unsigned char mnum[EI_NIDENT]) {
    if (mnum[EI_MAG0] == ELFMAG0 &&
        mnum[EI_MAG1] == ELFMAG1 &&
        mnum[EI_MAG2] == ELFMAG2 &&
        mnum[EI_MAG3] == ELFMAG3) {
        dprintf(1, "File is an elf file\n");
        return (0);
    }
    return (-1);
}

int main(int argc, char **argv) {
    int         fd;
    Elf64_Ehdr  *header;

    if (argc != 2) {
        dprintf(2, "Usage: myPacker arg\n");
        return (1);
    }
    if ((fd = open(argv[1], O_RDONLY)) == -1)
        return (1);
    if ((header = getHeader(fd, argv[1])) == NULL) {
        close(fd);
        dprintf(2, "Couldn't get header %s\n", strerror(errno));
        return (1);
    }
    close(fd);
    if (checkFileType(header->e_ident) == -1)
        return (1);
    return (0);
}

