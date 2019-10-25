#include "packer.h"

int  getShellcode(t_header *shellcode) {
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

