#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/mman.h>

#include "../packer/llbin.h"

extern uintptr_t srei_load(const uint8_t *data, size_t data_len,
                            uint32_t func_hash,
                            const void *user_data, uint32_t user_data_len,
                            void *(*dlsym_fn)(void *, const char *),
                            uint32_t flags);

static uint32_t hash_name(const char *name)
{
    uint32_t hash = 0;
    const unsigned char *p = (const unsigned char *)name;
    do {
        hash = (hash >> 13) | (hash << 19);
        hash += *p;
        p++;
    } while (*(p - 1) != 0);
    return hash;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    if (flen <= 0) { fclose(f); return NULL; }
    *out_len = (size_t)flen;
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)flen);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)flen, f) != (size_t)flen) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: native_loader <file.llbin> [function_name] [user_data]\n");
        return 1;
    }

    const char *func_name = argc >= 3 ? argv[2] : "payload_run";
    const char *user_msg = argc >= 4 ? argv[3] : "hello from native_loader";
    uint32_t user_len = (uint32_t)strlen(user_msg);

    size_t len;
    uint8_t *data = read_file(argv[1], &len);
    if (!data) {
        fprintf(stderr, "Failed to read %s\n", argv[1]);
        return 1;
    }

    uint32_t fhash = hash_name(func_name);

    printf("[native_loader] loading %s (%zu bytes), hash=0x%08x\n",
           argv[1], len, fhash);

    uintptr_t base = srei_load(data, len, fhash, user_msg, user_len,
                                dlsym, 0);

    if (base == 0) {
        fprintf(stderr, "[native_loader] srei_load failed\n");
        free(data);
        return 1;
    }

    printf("[native_loader] loaded at %p\n", (void *)base);

    free(data);
    return 0;
}
