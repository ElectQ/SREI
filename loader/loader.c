#include <stddef.h>
#include "llbin.h"
#include "syscall.h"
#include "resolve.h"
#include "selfresolve.h"

#define LLBIN_RTLD_DEFAULT ((void *)0xffffffffffffffffUL)
#define SREI_CLEARHEADER 0x1
#define SREI_CLEARMEMORY 0x2

static inline void inline_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

static inline size_t inline_strlen(const char *s)
{
    size_t i;
    for (i = 0; s[i] != '\0'; i++)
        ;
    return i;
}

typedef void *(*srei_dlsym_fn)(void *, const char *);
typedef void (*srei_init_fn)(void);
typedef void (*srei_export_fn)(const void *, uint32_t);

__attribute__((section(".text.entry")))
uintptr_t srei_load(const uint8_t *data, size_t data_len,
                    uint32_t func_hash,
                    const void *user_data, uint32_t user_data_len,
                    srei_dlsym_fn dlsym_fn, uint32_t flags)
{
    const struct llbin_header *hdr;
    uint8_t *base;
    intptr_t slide;
    const struct llbin_fixup *fixups;
    const struct llbin_import *imports;
    const char *strings;
    const struct llbin_segment *segs;
    const struct llbin_init *inits;
    const struct llbin_export *exports;
    uint32_t i;
    long mmap_ret;
    const char *name;
    void *sym;
    uint64_t *slot;
    struct srei_resolver resolver;

    if (!dlsym_fn) {
        srei_resolver_init(&resolver);
    }

    if (data_len < sizeof(struct llbin_header))
        return 0;

    hdr = (const struct llbin_header *)data;

    if (hdr->magic != LLBIN_MAGIC || hdr->version != LLBIN_VERSION)
        return 0;

    if ((uint64_t)hdr->image_off + hdr->image_size > (uint64_t)data_len)
        return 0;

    if ((uint64_t)hdr->fixup_off +
        (uint64_t)hdr->fixup_count * sizeof(struct llbin_fixup) > (uint64_t)data_len)
        return 0;

    mmap_ret = sys_mmap(NULL, (size_t)hdr->image_size,
                        SYS_PROT_READ | SYS_PROT_WRITE,
                        SYS_MAP_PRIVATE | SYS_MAP_ANONYMOUS, -1, 0);
    if (mmap_ret < 0)
        return 0;

    base = (uint8_t *)(uintptr_t)mmap_ret;

    inline_memcpy(base, data + hdr->image_off, (size_t)hdr->image_size);

    slide = (intptr_t)((uintptr_t)base - (uintptr_t)hdr->preferred_base);
    fixups = (const struct llbin_fixup *)(data + hdr->fixup_off);
    imports = (const struct llbin_import *)(data + hdr->import_off);
    strings = (const char *)(data + hdr->strings_off);

    for (i = 0; i < hdr->fixup_count; i++) {
        const struct llbin_fixup *f = &fixups[i];
        slot = (uint64_t *)(base + f->offset);

        if (f->type == LLBIN_FIXUP_REBASE) {
            *slot += (uint64_t)slide;
        } else if (f->type == LLBIN_FIXUP_IMPORT) {
            if (f->import_idx >= hdr->import_count)
                continue;
            name = strings + imports[f->import_idx].name_off;

            if (dlsym_fn) {
                sym = dlsym_fn(LLBIN_RTLD_DEFAULT, name);
            } else {
                sym = srei_resolve(&resolver, name);
            }

            if (sym)
                *slot = (uint64_t)(uintptr_t)sym + (uint64_t)f->addend;
        }
    }

    __builtin___clear_cache((char *)base, (char *)(base + hdr->image_size));

    segs = (const struct llbin_segment *)(data + hdr->strings_off + hdr->strings_size);
    for (i = 0; i < hdr->seg_count; i++) {
        if (segs[i].prot && segs[i].size > 0)
            sys_mprotect(base + segs[i].offset, (size_t)segs[i].size,
                         (long)segs[i].prot);
    }

    if (hdr->init_count > 0) {
        inits = (const struct llbin_init *)(data + hdr->init_off);
        for (i = 0; i < hdr->init_count; i++) {
            srei_init_fn fn = (srei_init_fn)(base + inits[i].offset);
            fn();
        }
    }

    if (func_hash != 0 && hdr->export_count > 0) {
        exports = (const struct llbin_export *)(data + hdr->export_off);
        for (i = 0; i < hdr->export_count; i++) {
            name = strings + exports[i].name_off;
            if (srei_hash_name(name) == func_hash) {
                srei_export_fn fn = (srei_export_fn)(base + exports[i].addr_off);
                fn(user_data, user_data_len);
                break;
            }
        }
    }

    if (flags & SREI_CLEARHEADER) {
        uint32_t hdr_sz = (uint32_t)sizeof(struct llbin_header);
        for (i = 0; i < hdr_sz; i++)
            ((uint8_t *)(uintptr_t)data)[i] = 0;
    }

    if (flags & SREI_CLEARMEMORY) {
        sys_mprotect((void *)(uintptr_t)data, (size_t)data_len, SYS_PROT_READ | SYS_PROT_WRITE);
        for (i = 0; i < (uint32_t)data_len; i++)
            ((uint8_t *)(uintptr_t)data)[i] = 0;
        sys_mprotect((void *)(uintptr_t)data, (size_t)data_len, SYS_PROT_NONE);
    }

    return (uintptr_t)base;
}
