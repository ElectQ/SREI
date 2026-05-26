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

static inline uintptr_t srei_find_lib_base(const char *libname, size_t libname_len)
{
    long fd = sys_open("/proc/self/maps", 0, 0);
    if (fd < 0)
        return 0;

    char buf[4096];
    long total = 0;
    long n;
    uintptr_t result = 0;

    while ((n = sys_read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
        total += n;
    sys_close(fd);
    buf[total] = 0;

    char *line = buf;
    while (line && *line && !result) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        int has_nl = (*nl == '\n');
        if (has_nl) *nl = 0;

        const char *p = line;
        const char *endptr;
        uint64_t start = parse_hex64(p, &endptr);

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
            const char *basename = path;
            for (const char *s = path; *s; s++)
                if (*s == '/') basename = s + 1;
            if (inline_strncmp(basename, libname, libname_len) == 0)
                result = (uintptr_t)start;
        }

        line = has_nl ? nl + 1 : nl;
    }

    return result;
}

struct srei_resolver {
    uintptr_t libc_base;
    int initialized;
    Elf64_Sym_C *symtab;
    const char  *strtab;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t *buckets;
    uint32_t *chain;
};

static inline void srei_resolver_init(struct srei_resolver *r)
{
    r->libc_base = 0;
    r->initialized = 0;
    r->symtab = NULL;
    r->strtab = NULL;
    r->nbuckets = 0;
    r->symoffset = 0;
    r->buckets = NULL;
    r->chain = NULL;
}

static inline void srei_resolver_setup(struct srei_resolver *r)
{
    if (r->initialized) return;
    r->initialized = 1;

    r->libc_base = srei_find_lib_base("libc-", 5);
    if (!r->libc_base)
        r->libc_base = srei_find_lib_base("libc.so", 7);
    if (!r->libc_base)
        return;

    uint8_t *base = (uint8_t *)r->libc_base;
    if (base[0] != ELFMAG0 || base[1] != ELFMAG1 || base[2] != ELFMAG2 || base[3] != ELFMAG3)
        return;

    Elf64_Ehdr_C *ehdr = (Elf64_Ehdr_C *)base;
    if (ehdr->e_ident[4] != ELFCLASS64)
        return;

    Elf64_Phdr_C *phdrs = (Elf64_Phdr_C *)(base + ehdr->e_phoff);
    Elf64_Dyn_C *dyn = NULL;
    uint64_t elf_lo = (uint64_t)-1;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_vaddr < elf_lo)
            elf_lo = phdrs[i].p_vaddr;
        if (phdrs[i].p_type == PT_DYNAMIC)
            dyn = (Elf64_Dyn_C *)(base + (phdrs[i].p_vaddr - elf_lo));
    }

    if (!dyn) return;

    uint32_t *gnu_hash = NULL;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:   r->symtab = (Elf64_Sym_C *)(uintptr_t)dyn[i].d_val; break;
        case DT_STRTAB:   r->strtab = (const char *)(uintptr_t)dyn[i].d_val; break;
        case DT_GNU_HASH: gnu_hash  = (uint32_t *)(uintptr_t)dyn[i].d_val; break;
        default: break;
        }
    }

    if (!r->symtab || !r->strtab || !gnu_hash)
        return;

    r->nbuckets  = gnu_hash[0];
    r->symoffset = gnu_hash[1];
    uint32_t bloom_sz = gnu_hash[2];

    r->buckets = &gnu_hash[4 + bloom_sz * 2];
    r->chain   = &r->buckets[r->nbuckets];
}

static inline void *srei_resolve(struct srei_resolver *r, const char *name)
{
    srei_resolver_setup(r);

    if (!r->symtab || !r->strtab || !r->buckets || !r->chain)
        return NULL;

    uint32_t h = elf_gnu_hash(name);
    uint32_t idx = r->buckets[h % r->nbuckets];

    if (idx != 0) {
        for (;;) {
            uint32_t cv = r->chain[idx - r->symoffset];
            if ((cv | 1) == (h | 1)) {
                Elf64_Sym_C *sym = &r->symtab[idx];
                if (sym->st_shndx != 0 &&
                    inline_strcmp(r->strtab + sym->st_name, name) == 0) {
                    return (void *)(uintptr_t)(r->libc_base + sym->st_value);
                }
            }
            if (cv & 1)
                break;
            idx++;
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
