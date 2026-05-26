#ifndef SREI_SELFRESOLVE_H
#define SREI_SELFRESOLVE_H

#include <stdint.h>
#include <stddef.h>
#include "syscall.h"

#define EI_NIDENT     16
#define ELFMAG0       0x7f
#define ELFMAG1       'E'
#define ELFMAG2       'L'
#define ELFMAG3       'F'
#define ELFCLASS64    2
#define PT_LOAD       1
#define PT_DYNAMIC    2
#define DT_NULL       0
#define DT_STRTAB     5
#define DT_SYMTAB     6
#define DT_GNU_HASH   0x6ffffef5

#define SREI_MAX_LIBS 32

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr_C;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr_C;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} Elf64_Dyn_C;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym_C;

typedef void *(*srei_dlsym_fn)(void *, const char *);

static inline int inline_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int inline_strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == 0) return 0;
    }
    return 0;
}

static inline uint32_t elf_gnu_hash(const char *name)
{
    uint32_t h = 5381;
    const unsigned char *p = (const unsigned char *)name;
    for (; *p; p++)
        h = (h << 5) + h + *p;
    return h;
}

static inline int isxdigit_c(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline uint64_t parse_hex64(const char *s, const char **end)
{
    uint64_t v = 0;
    while (isxdigit_c(*s)) {
        v <<= 4;
        if (*s >= '0' && *s <= '9') v += *s - '0';
        else if (*s >= 'a' && *s <= 'f') v += *s - 'a' + 10;
        else v += *s - 'A' + 10;
        s++;
    }
    *end = s;
    return v;
}

struct srei_lib_cache {
    uintptr_t load_bias;
    Elf64_Sym_C *symtab;
    const char  *strtab;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t *buckets;
    uint32_t *chain;
    int parsed;
};

struct srei_resolver {
    int initialized;
    struct srei_lib_cache libs[SREI_MAX_LIBS];
    uint32_t nlibs;
    uint32_t libc_idx;
};

static inline void srei_resolver_init(struct srei_resolver *r)
{
    for (uint32_t i = 0; i < (uint32_t)sizeof(*r); i++)
        ((uint8_t *)r)[i] = 0;
}

static inline int srei_parse_lib(struct srei_lib_cache *lib, uintptr_t base)
{
    uint8_t *mbase = (uint8_t *)base;
    if (mbase[0] != ELFMAG0 || mbase[1] != ELFMAG1 ||
        mbase[2] != ELFMAG2 || mbase[3] != ELFMAG3)
        return -1;

    Elf64_Ehdr_C *ehdr = (Elf64_Ehdr_C *)mbase;
    if (ehdr->e_ident[4] != ELFCLASS64)
        return -1;

    Elf64_Phdr_C *phdrs = (Elf64_Phdr_C *)(mbase + ehdr->e_phoff);

    uint64_t elf_lo = (uint64_t)-1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_vaddr < elf_lo)
            elf_lo = phdrs[i].p_vaddr;
    }

    Elf64_Dyn_C *dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC)
            dyn = (Elf64_Dyn_C *)(mbase + (phdrs[i].p_vaddr - elf_lo));
    }

    if (!dyn) return -1;

    uint32_t *gnu_hash = NULL;
    Elf64_Sym_C *symtab = NULL;
    const char *strtab = NULL;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:   symtab   = (Elf64_Sym_C *)(uintptr_t)dyn[i].d_val; break;
        case DT_STRTAB:   strtab   = (const char *)(uintptr_t)dyn[i].d_val; break;
        case DT_GNU_HASH: gnu_hash = (uint32_t *)(uintptr_t)dyn[i].d_val; break;
        }
    }

    if (!symtab || !strtab || !gnu_hash) return -1;

    uint32_t nbuckets  = gnu_hash[0];
    uint32_t symoffset = gnu_hash[1];
    uint32_t bloom_sz  = gnu_hash[2];

    lib->load_bias = (uintptr_t)(base - elf_lo);
    lib->symtab    = symtab;
    lib->strtab    = strtab;
    lib->nbuckets  = nbuckets;
    lib->symoffset = symoffset;
    lib->buckets   = &gnu_hash[4 + bloom_sz * 2];
    lib->chain     = &gnu_hash[4 + bloom_sz * 2 + nbuckets];
    lib->parsed    = 1;
    return 0;
}

static inline void *srei_resolve_in_lib(struct srei_lib_cache *lib,
                                         const char *name)
{
    if (!lib->parsed || !lib->symtab || !lib->strtab ||
        !lib->buckets || !lib->chain)
        return NULL;

    uint32_t h = elf_gnu_hash(name);
    uint32_t idx = lib->buckets[h % lib->nbuckets];

    if (idx != 0) {
        for (;;) {
            uint32_t cv = lib->chain[idx - lib->symoffset];
            if ((cv | 1) == (h | 1)) {
                Elf64_Sym_C *sym = &lib->symtab[idx];
                if (sym->st_shndx != 0 &&
                    inline_strcmp(lib->strtab + sym->st_name, name) == 0) {
                    return (void *)(lib->load_bias + sym->st_value);
                }
            }
            if (cv & 1)
                break;
            idx++;
        }
    }

    return NULL;
}

static inline void srei_resolver_setup(struct srei_resolver *r)
{
    if (r->initialized) return;
    r->initialized = 1;

    long fd = sys_open("/proc/self/maps", 0, 0);
    if (fd < 0) return;

    char buf[4096];
    long total = 0;
    long n;

    while ((n = sys_read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
        total += n;
    sys_close(fd);
    buf[total] = 0;

    char *line = buf;
    const char *last_path = NULL;
    while (line && *line && r->nlibs < SREI_MAX_LIBS) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        int has_nl = (*nl == '\n');
        if (has_nl) *nl = 0;

        const char *p = line;
        const char *endptr;
        uint64_t start = parse_hex64(p, &endptr);

        if (*endptr == '-') {
            parse_hex64(endptr + 1, &endptr);

            int spaces = 0;
            const char *path = NULL;
            for (p = line; *p; p++) {
                if (*p == ' ') {
                    spaces++;
                    while (*(p + 1) == ' ') p++;
                    if (spaces == 5) { path = p + 1; break; }
                }
            }

            if (path && *path == '/') {
                if (last_path && inline_strcmp(path, last_path) == 0)
                    goto next_line;
                last_path = path;

                uint32_t idx = r->nlibs;

                const char *basename = path;
                for (const char *s = path; *s; s++)
                    if (*s == '/') basename = s + 1;

                if (!r->libc_idx &&
                    (inline_strncmp(basename, "libc-", 5) == 0 ||
                     inline_strncmp(basename, "libc.so", 7) == 0)) {
                    r->libc_idx = idx + 1;
                }

                if (srei_parse_lib(&r->libs[idx], (uintptr_t)start) == 0) {
                    r->nlibs++;
                    if (r->libc_idx == idx + 1 && idx != 0) {
                        struct srei_lib_cache tmp = r->libs[0];
                        r->libs[0] = r->libs[idx];
                        r->libs[idx] = tmp;
                        r->libc_idx = 1;
                    }
                }
            }
        }

    next_line:
        line = has_nl ? nl + 1 : nl;
    }
}

static inline void *srei_resolve(struct srei_resolver *r, const char *name)
{
    srei_resolver_setup(r);

    if (r->libc_idx && r->libs[0].parsed) {
        void *sym = srei_resolve_in_lib(&r->libs[0], name);
        if (sym) return sym;
    }

    for (uint32_t i = 1; i < r->nlibs; i++) {
        if (r->libs[i].parsed) {
            void *sym = srei_resolve_in_lib(&r->libs[i], name);
            if (sym) return sym;
        }
    }

    return NULL;
}

static inline srei_dlsym_fn srei_self_resolve(void)
{
    static struct srei_resolver cache;
    srei_resolver_init(&cache);
    return (srei_dlsym_fn)0;
}

#endif
