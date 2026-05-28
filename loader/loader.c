#include <stddef.h>
#include "llbin.h"
#include "syscall.h"
#include "resolve.h"
#include "selfresolve.h"

#define LLBIN_RTLD_DEFAULT ((void *)0xffffffffffffffffUL)
#define SREI_CLEARHEADER 0x1
#define SREI_CLEARMEMORY 0x2
#define SREI_TLS_SENTINEL 0xFFFEUL

static inline void inline_memcpy(void *dst, const void *src, size_t n)
{
    uint64_t *d8 = (uint64_t *)dst;
    const uint64_t *s8 = (const uint64_t *)src;
    size_t words = n >> 3;
    size_t i;
    for (i = 0; i < words; i++)
        d8[i] = s8[i];
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (i = words << 3; i < n; i++)
        d[i] = s[i];
}

typedef void *(*srei_dlsym_fn)(void *, const char *);
typedef void *(*srei_dlopen_fn)(const char *, int);
typedef void (*srei_init_fn)(void);
typedef void (*srei_export_fn)(const void *, uint32_t);
typedef void *(*srei_ifunc_resolver_fn)(void);
typedef void (*srei_register_frame_fn)(const void *);
typedef unsigned long srei_pthread_key_t;
typedef int (*srei_pthread_key_create_fn)(srei_pthread_key_t *, void (*)(void *));
typedef void *(*srei_pthread_getspecific_fn)(srei_pthread_key_t);
typedef int (*srei_pthread_setspecific_fn)(srei_pthread_key_t, const void *);
typedef void *(*srei_tls_get_addr_fn)(unsigned long *);

static srei_tls_get_addr_fn srei_tls_real_fn;
static srei_pthread_getspecific_fn srei_tls_getspecific_fn;
static srei_pthread_setspecific_fn srei_tls_setspecific_fn;
static srei_pthread_key_t srei_tls_key;
static int srei_tls_key_init;
static const uint8_t *srei_tls_init_img;
static uint32_t srei_tls_init_sz;
static uint32_t srei_tls_total_sz;
static void *srei_tls_fallback_block;

__attribute__((used))
static void *srei_tls_get_addr(unsigned long *ti)
{
    if (ti[0] != SREI_TLS_SENTINEL) {
        if (srei_tls_real_fn)
            return srei_tls_real_fn(ti);
        return (void *)0;
    }

    void *block = (void *)0;
    if (srei_tls_key_init)
        block = srei_tls_getspecific_fn(srei_tls_key);
    else if (srei_tls_fallback_block)
        block = srei_tls_fallback_block;

    if (!block) {
        long ret = sys_mmap((void *)0, (size_t)srei_tls_total_sz,
                            SYS_PROT_READ | SYS_PROT_WRITE,
                            SYS_MAP_PRIVATE | SYS_MAP_ANONYMOUS, -1, 0);
        if (ret < 0)
            return (void *)0;
        block = (void *)(uintptr_t)ret;
        if (srei_tls_init_sz > 0)
            inline_memcpy(block, srei_tls_init_img, (size_t)srei_tls_init_sz);
        {
            uint32_t j;
            uint8_t *p = (uint8_t *)block + srei_tls_init_sz;
            for (j = srei_tls_init_sz; j < srei_tls_total_sz; j++)
                p[j - srei_tls_init_sz] = 0;
        }
        if (srei_tls_key_init)
            srei_tls_setspecific_fn(srei_tls_key, block);
        else
            srei_tls_fallback_block = block;
    }

    return (void *)((uintptr_t)block + (uintptr_t)ti[1]);
}

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
    const uint32_t *needed;
    uint32_t i;
    long mmap_ret;
    const char *name;
    void *sym;
    uint64_t *slot;
    struct srei_resolver resolver;
    srei_dlopen_fn libc_dlopen;

    if (!dlsym_fn) {
        srei_resolver_init(&resolver);
        srei_resolver_setup(&resolver);
        libc_dlopen = NULL;

        if (resolver.libdl_idx && resolver.libs[resolver.libdl_idx - 1].parsed) {
            libc_dlopen = (srei_dlopen_fn)srei_resolve_in_lib(
                &resolver.libs[resolver.libdl_idx - 1], "dlopen");
        }

        if (!libc_dlopen && resolver.libc_idx && resolver.libs[0].parsed) {
            libc_dlopen = (srei_dlopen_fn)srei_resolve_in_lib(
                &resolver.libs[0], "__libc_dlopen_mode");
        }

        if (!libc_dlopen && resolver.linker_dlopen)
            libc_dlopen = (srei_dlopen_fn)resolver.linker_dlopen;
    } else {
        libc_dlopen = NULL;
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

    if (!dlsym_fn && hdr->needed_count > 0 && libc_dlopen) {
        needed = (const uint32_t *)(data + hdr->needed_off);
        int dlopen_flags = 0x2 | 0x100;
        if (!resolver.libdl_idx)
            dlopen_flags |= (int)0x80000000;
        for (i = 0; i < hdr->needed_count; i++) {
            libc_dlopen(strings + needed[i], dlopen_flags);
        }
        resolver.initialized = 0;
        srei_resolver_setup(&resolver);
    }

    if (dlsym_fn && hdr->needed_count > 0) {
        srei_dlopen_fn dlopen_via_dlsym =
            (srei_dlopen_fn)dlsym_fn(LLBIN_RTLD_DEFAULT, "dlopen");
        if (dlopen_via_dlsym) {
            needed = (const uint32_t *)(data + hdr->needed_off);
            for (i = 0; i < hdr->needed_count; i++) {
                dlopen_via_dlsym(strings + needed[i], 0x2 | 0x100);
            }
        }
    }

    if (hdr->tls_total_size > 0) {
        srei_pthread_key_create_fn key_create = (void *)0;
        if (dlsym_fn) {
            key_create = (srei_pthread_key_create_fn)dlsym_fn(
                LLBIN_RTLD_DEFAULT, "pthread_key_create");
            srei_tls_getspecific_fn = (srei_pthread_getspecific_fn)dlsym_fn(
                LLBIN_RTLD_DEFAULT, "pthread_getspecific");
            srei_tls_setspecific_fn = (srei_pthread_setspecific_fn)dlsym_fn(
                LLBIN_RTLD_DEFAULT, "pthread_setspecific");
        } else {
            key_create = (srei_pthread_key_create_fn)srei_resolve(
                &resolver, "pthread_key_create");
            srei_tls_getspecific_fn = (srei_pthread_getspecific_fn)srei_resolve(
                &resolver, "pthread_getspecific");
            srei_tls_setspecific_fn = (srei_pthread_setspecific_fn)srei_resolve(
                &resolver, "pthread_setspecific");
        }
        if (key_create) {
            key_create(&srei_tls_key, (void (*)(void *))0);
            srei_tls_key_init = 1;
        }
        srei_tls_init_img = (const uint8_t *)(base + hdr->tls_init_off);
        srei_tls_init_sz = hdr->tls_init_size;
        srei_tls_total_sz = hdr->tls_total_size;
    }

    for (i = 0; i < hdr->fixup_count; i++) {
        const struct llbin_fixup *f = &fixups[i];
        slot = (uint64_t *)(base + f->offset);

        if (f->type == LLBIN_FIXUP_REBASE) {
            *slot += (uint64_t)slide;
        } else if (f->type == LLBIN_FIXUP_IRELATIVE) {
            srei_ifunc_resolver_fn resolver =
                (srei_ifunc_resolver_fn)((uintptr_t)*slot + (uintptr_t)slide);
            *slot = (uint64_t)(uintptr_t)resolver();
        } else if (f->type == LLBIN_FIXUP_IMPORT) {
            if (f->import_idx >= hdr->import_count)
                continue;
            name = strings + imports[f->import_idx].name_off;

            if (dlsym_fn) {
                sym = dlsym_fn(LLBIN_RTLD_DEFAULT, name);
            } else {
                sym = srei_resolve(&resolver, name);
            }

            if (hdr->tls_total_size > 0 && sym) {
                const char *n2 = name;
                int is_tga = (n2[0] == '_' && n2[1] == '_' &&
                              n2[2] == 't' && n2[3] == 'l' &&
                              n2[4] == 's' && n2[5] == '_' &&
                              n2[6] == 'g' && n2[7] == 'e' &&
                              n2[8] == 't' && n2[9] == '_' &&
                              n2[10] == 'a' && n2[11] == 'd' &&
                              n2[12] == 'd' && n2[13] == 'r' &&
                              n2[14] == '\0');
                if (is_tga) {
                    srei_tls_real_fn = (srei_tls_get_addr_fn)(uintptr_t)sym;
                    sym = (void *)(uintptr_t)srei_tls_get_addr;
                }
            }

            if (sym)
                *slot = (uint64_t)(uintptr_t)sym + (uint64_t)f->addend;
        } else if (f->type == LLBIN_FIXUP_TLS_MODULE) {
            *slot = (uint64_t)SREI_TLS_SENTINEL;
        }
    }

    __builtin___clear_cache((char *)base, (char *)(base + hdr->image_size));

    segs = (const struct llbin_segment *)(data + hdr->strings_off + hdr->strings_size);
    for (i = 0; i < hdr->seg_count; i++) {
        if ((segs[i].prot & LLBIN_SEG_RELRO) && segs[i].size > 0)
            sys_mprotect(base + segs[i].offset, (size_t)segs[i].size, SYS_PROT_READ);
    }
    for (i = 0; i < hdr->seg_count; i++) {
        if (segs[i].prot & LLBIN_SEG_RELRO)
            continue;
        long prot = (long)(segs[i].prot & ~LLBIN_SEG_RELRO);
        if (prot && segs[i].size > 0)
            sys_mprotect(base + segs[i].offset, (size_t)segs[i].size, prot);
    }

    if (hdr->eh_frame_size > 0) {
        srei_register_frame_fn reg_frame = NULL;
        if (dlsym_fn)
            reg_frame = (srei_register_frame_fn)dlsym_fn(
                LLBIN_RTLD_DEFAULT, "__register_frame");
        else
            reg_frame = (srei_register_frame_fn)srei_resolve(
                &resolver, "__register_frame");
        if (reg_frame)
            reg_frame((const void *)(base + hdr->eh_frame_off));
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
