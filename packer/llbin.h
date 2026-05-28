#ifndef LLBIN_H
#define LLBIN_H

#include <stdint.h>

#define LLBIN_MAGIC     0x4E424C4C
#define LLBIN_VERSION   5

#define LLBIN_FIXUP_REBASE      0
#define LLBIN_FIXUP_IMPORT      1
#define LLBIN_FIXUP_IRELATIVE   2
#define LLBIN_FIXUP_TLS_MODULE  3
#define LLBIN_FIXUP_TLS_OFFSET  4

#define LLBIN_SEG_RELRO        0x100

#define SREI_CLEARHEADER    0x1
#define SREI_CLEARMEMORY    0x2

struct llbin_header {
    uint32_t magic;
    uint32_t version;
    uint32_t arch;
    uint32_t flags;
    uint64_t entry_off;
    uint64_t image_size;
    uint64_t preferred_base;
    uint32_t image_off;
    uint32_t fixup_off;
    uint32_t fixup_count;
    uint32_t import_off;
    uint32_t import_count;
    uint32_t strings_off;
    uint32_t strings_size;
    uint32_t seg_count;
    uint32_t init_off;
    uint32_t init_count;
    uint32_t export_off;
    uint32_t export_count;
    uint32_t needed_off;
    uint32_t needed_count;
    uint32_t fini_off;
    uint32_t fini_count;
    uint32_t eh_frame_off;
    uint32_t eh_frame_size;
    uint32_t tls_init_off;
    uint32_t tls_init_size;
    uint32_t tls_total_size;
    uint32_t tls_align;
};

struct llbin_segment {
    uint32_t offset;
    uint32_t size;
    uint32_t prot;
    uint32_t pad;
};

struct llbin_fixup {
    uint32_t offset;
    uint8_t  type;
    uint8_t  reserved;
    uint16_t import_idx;
    int64_t  addend;
};

struct llbin_import {
    uint32_t name_off;
    uint32_t flags;
};

struct llbin_init {
    uint64_t offset;
};

struct llbin_export {
    uint32_t name_off;
    uint32_t flags;
    uint64_t addr_off;
};

#endif
