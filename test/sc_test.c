#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *sc = mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (sc == MAP_FAILED) { perror("mmap"); return 1; }
    if ((long)fread(sc, 1, len, f) != len) { perror("fread"); return 1; }
    fclose(f);

    printf("[sc_test] executing shellcode (%ld bytes)\n", len);

    ((void (*)(void))sc)();

    printf("[sc_test] done\n");
    munmap(sc, len);
    return 0;
}
