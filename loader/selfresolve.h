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
#define DT_HASH       4
#define DT_GNU_HASH   0x6ffffef5

#define STT_GNU_IFUNC 10

#define SREI_MAX_LIBS 16
#define SREI_MAPS_BUF 8192

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
    uint32_t *sysv_chain;
    uint64_t *bloom;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    int parsed;
    int has_gnu_hash;
};

struct srei_resolver {
    int initialized;
    struct srei_lib_cache libs[SREI_MAX_LIBS];
    uint32_t nlibs;
    uint32_t libc_idx;
    uint32_t libdl_idx;
    void *linker_dlopen;
};

static inline void srei_resolver_init(struct srei_resolver *r)
{
    for (uint32_t i = 0; i < (uint32_t)sizeof(*r); i++)
        ((uint8_t *)r)[i] = 0;
}

static inline uintptr_t dyn_ptr(uint64_t d_val, uintptr_t load_bias)
{
    if (d_val >= load_bias)
        return (uintptr_t)d_val;
    return load_bias + (uintptr_t)d_val;
}

static inline void srei_init_hash_cache(struct srei_lib_cache *lib,
                                         uint32_t *gnu_hash,
                                         uint32_t *sysv_hash)
{
    if (gnu_hash) {
        uint32_t nbuckets  = gnu_hash[0];
        uint32_t symoffset = gnu_hash[1];
        uint32_t bloom_sz  = gnu_hash[2];
        uint32_t bloom_sh  = gnu_hash[3];
        lib->nbuckets     = nbuckets;
        lib->symoffset    = symoffset;
        lib->bloom        = (uint64_t *)&gnu_hash[4];
        lib->bloom_size   = bloom_sz;
        lib->bloom_shift  = bloom_sh;
        lib->buckets      = &gnu_hash[4 + bloom_sz * 2];
        lib->chain        = &gnu_hash[4 + bloom_sz * 2 + nbuckets];
        lib->has_gnu_hash = 1;
    } else {
        uint32_t nbuckets = sysv_hash[0];
        lib->nbuckets     = nbuckets;
        lib->symoffset    = 0;
        lib->buckets      = &sysv_hash[2];
        lib->sysv_chain   = &sysv_hash[2 + nbuckets];
        lib->has_gnu_hash = 0;
    }
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

    uintptr_t load_bias = (uintptr_t)(base - elf_lo);

    uint32_t *gnu_hash = NULL;
    uint32_t *sysv_hash = NULL;
    Elf64_Sym_C *symtab = NULL;
    const char *strtab = NULL;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:   symtab    = (Elf64_Sym_C *)dyn_ptr(dyn[i].d_val, load_bias); break;
        case DT_STRTAB:   strtab    = (const char *)dyn_ptr(dyn[i].d_val, load_bias); break;
        case DT_GNU_HASH: gnu_hash  = (uint32_t *)dyn_ptr(dyn[i].d_val, load_bias); break;
        case DT_HASH:     sysv_hash = (uint32_t *)dyn_ptr(dyn[i].d_val, load_bias); break;
        }
    }

    if (!symtab || !strtab || (!gnu_hash && !sysv_hash)) return -1;

    lib->load_bias = load_bias;
    lib->symtab    = symtab;
    lib->strtab    = strtab;

    srei_init_hash_cache(lib, gnu_hash, sysv_hash);

    lib->parsed = 1;
    return 0;
}

static inline int srei_parse_dynamic(struct srei_lib_cache *lib,
                                      uintptr_t load_bias,
                                      Elf64_Dyn_C *dyn)
{
    uint32_t *gnu_hash = NULL;
    uint32_t *sysv_hash = NULL;
    Elf64_Sym_C *symtab = NULL;
    const char *strtab = NULL;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:   symtab    = (Elf64_Sym_C *)dyn_ptr(dyn[i].d_val, load_bias); break;
        case DT_STRTAB:   strtab    = (const char *)dyn_ptr(dyn[i].d_val, load_bias); break;
        case DT_GNU_HASH: gnu_hash  = (uint32_t *)dyn_ptr(dyn[i].d_val, load_bias); break;
        case DT_HASH:     sysv_hash = (uint32_t *)dyn_ptr(dyn[i].d_val, load_bias); break;
        }
    }

    if (!symtab || !strtab || (!gnu_hash && !sysv_hash)) return -1;

    lib->load_bias = load_bias;
    lib->symtab    = symtab;
    lib->strtab    = strtab;

    srei_init_hash_cache(lib, gnu_hash, sysv_hash);

    lib->parsed = 1;
    return 0;
}

static inline void *srei_resolve_in_lib(struct srei_lib_cache *lib,
                                         const char *name)
{
    if (!lib->parsed || !lib->symtab || !lib->strtab || !lib->buckets)
        return NULL;

    Elf64_Sym_C *found = NULL;

    if (lib->has_gnu_hash) {
        uint32_t h = elf_gnu_hash(name);

        if (lib->bloom && lib->bloom_size) {
            uint64_t word = lib->bloom[(h >> 6) % lib->bloom_size];
            uint64_t mask = (1ULL << (h & 63)) |
                            (1ULL << ((h >> lib->bloom_shift) & 63));
            if ((word & mask) != mask)
                return NULL;
        }

        uint32_t idx = lib->buckets[h % lib->nbuckets];

        if (idx != 0) {
            for (;;) {
                uint32_t cv = lib->chain[idx - lib->symoffset];
                if ((cv | 1) == (h | 1)) {
                    Elf64_Sym_C *sym = &lib->symtab[idx];
                    if (sym->st_shndx != 0 &&
                        inline_strcmp(lib->strtab + sym->st_name, name) == 0) {
                        found = sym;
                        break;
                    }
                }
                if (cv & 1)
                    break;
                idx++;
            }
        }
    } else {
        uint32_t h = elf_gnu_hash(name);
        uint32_t idx = lib->buckets[h % lib->nbuckets];

        while (idx != 0) {
            Elf64_Sym_C *sym = &lib->symtab[idx];
            if (sym->st_shndx != 0 &&
                inline_strcmp(lib->strtab + sym->st_name, name) == 0) {
                found = sym;
                break;
            }
            idx = lib->sysv_chain[idx];
        }
    }

    if (!found)
        return NULL;

    void *addr = (void *)(lib->load_bias + found->st_value);
    if ((found->st_info & 0xf) == STT_GNU_IFUNC) {
        typedef void *(*ifunc_resolver)(void);
        addr = ((ifunc_resolver)addr)();
    }
    return addr;
}

static inline int srei_is_libc(const char *basename)
{
    return inline_strncmp(basename, "libc-", 5) == 0 ||
           inline_strncmp(basename, "libc.so", 7) == 0 ||
           inline_strncmp(basename, "ld-musl-", 8) == 0;
}

static inline int srei_is_libdl(const char *basename)
{
    return inline_strncmp(basename, "libdl-", 6) == 0 ||
           inline_strncmp(basename, "libdl.so", 8) == 0;
}

static inline void srei_try_setup_linkmap(struct srei_resolver *r)
{
    long fd = sys_open("/proc/self/auxv", 0, 0);
    if (fd < 0) return;

    uint64_t auxv[64];
    long n = sys_read(fd, (char *)auxv, sizeof(auxv));
    sys_close(fd);
    if (n < 16) return;

    uintptr_t ld_base = 0;
    for (long i = 0; i + 1 < n / 8; i += 2) {
        if (auxv[i] == 7) {
            ld_base = (uintptr_t)auxv[i + 1];
            break;
        }
    }
    if (!ld_base) return;

    struct srei_lib_cache ld_cache;
    for (uint32_t i = 0; i < (uint32_t)sizeof(ld_cache); i++)
        ((uint8_t *)&ld_cache)[i] = 0;

    if (srei_parse_lib(&ld_cache, ld_base) != 0) return;

    void *r_debug_addr = srei_resolve_in_lib(&ld_cache, "_r_debug");
    if (!r_debug_addr) return;

    r->linker_dlopen = srei_resolve_in_lib(&ld_cache, "dlopen");

    void *map = *(void **)((uint8_t *)r_debug_addr + 8);
    if (!map) return;

    while (map && r->nlibs < SREI_MAX_LIBS) {
        uintptr_t l_addr = *(uintptr_t *)map;
        char *l_name = *(char **)((uint8_t *)map + 8);
        Elf64_Dyn_C *l_ld = *(Elf64_Dyn_C **)((uint8_t *)map + 16);
        void *l_next = *(void **)((uint8_t *)map + 24);

        if (l_ld && l_name && l_name[0]) {
            const char *basename = l_name;
            for (const char *s = l_name; *s; s++)
                if (*s == '/') basename = s + 1;

            uint32_t idx = r->nlibs;

            if (!r->libc_idx && srei_is_libc(basename))
                r->libc_idx = idx + 1;

            if (!r->libdl_idx && srei_is_libdl(basename))
                r->libdl_idx = idx + 1;

            if (srei_parse_dynamic(&r->libs[idx], l_addr, l_ld) == 0) {
                r->nlibs++;
                if (r->libc_idx == idx + 1 && idx != 0) {
                    struct srei_lib_cache tmp = r->libs[0];
                    r->libs[0] = r->libs[idx];
                    r->libs[idx] = tmp;
                    r->libc_idx = 1;
                    if (r->libdl_idx == 1)
                        r->libdl_idx = idx + 1;
                }
            }
        }

        map = l_next;
    }
}

static inline void srei_try_setup_maps(struct srei_resolver *r)
{
    long fd = sys_open("/proc/self/maps", 0, 0);
    if (fd < 0) return;

    char buf[SREI_MAPS_BUF];
    long total = 0;
    long n;

    while (total < SREI_MAPS_BUF - 1 &&
           (n = sys_read(fd, buf + total, SREI_MAPS_BUF - 1 - total)) > 0)
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

                const char *basename = path;
                for (const char *s = path; *s; s++)
                    if (*s == '/') basename = s + 1;

                uint32_t idx = r->nlibs;

                if (!r->libc_idx && srei_is_libc(basename))
                    r->libc_idx = idx + 1;

                if (!r->libdl_idx && srei_is_libdl(basename))
                    r->libdl_idx = idx + 1;

                if (srei_parse_lib(&r->libs[idx], (uintptr_t)start) == 0) {
                    r->nlibs++;
                    if (r->libc_idx == idx + 1 && idx != 0) {
                        struct srei_lib_cache tmp = r->libs[0];
                        r->libs[0] = r->libs[idx];
                        r->libs[idx] = tmp;
                        r->libc_idx = 1;
                        if (r->libdl_idx == 1)
                            r->libdl_idx = idx + 1;
                    }
                }
            }
        }

    next_line:
        line = has_nl ? nl + 1 : nl;
    }
}

static inline void srei_resolver_setup(struct srei_resolver *r)
{
    if (r->initialized) return;
    r->initialized  = 1;
    r->nlibs        = 0;
    r->libc_idx     = 0;
    r->libdl_idx    = 0;
    r->linker_dlopen = NULL;

    srei_try_setup_linkmap(r);

    if (r->nlibs == 0)
        srei_try_setup_maps(r);
}

static inline void *srei_resolve(struct srei_resolver *r, const char *name)
{
    srei_resolver_setup(r);

    if (r->libc_idx && r->libs[0].parsed) {
        void *sym = srei_resolve_in_lib(&r->libs[0], name);
        if (sym) return sym;
    }

    uint32_t start = r->libc_idx ? 1 : 0;
    for (uint32_t i = start; i < r->nlibs; i++) {
        if (r->libs[i].parsed) {
            void *sym = srei_resolve_in_lib(&r->libs[i], name);
            if (sym) return sym;
        }
    }

    return NULL;
}

#endif
