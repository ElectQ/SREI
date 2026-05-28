#include "llbin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

#if __SIZEOF_POINTER__ == 8
#define Elf_Ehdr    Elf64_Ehdr
#define Elf_Phdr    Elf64_Phdr
#define Elf_Shdr    Elf64_Shdr
#define Elf_Dyn     Elf64_Dyn
#define Elf_Sym     Elf64_Sym
#define Elf_Rela    Elf64_Rela
#define Elf_Rel     Elf64_Rel
#define Elf_Addr    Elf64_Addr
#define ELF_R_TYPE  ELF64_R_TYPE
#define ELF_R_SYM   ELF64_R_SYM
#define ELFCLASS_NATIVE ELFCLASS64
#else
#define Elf_Ehdr    Elf32_Ehdr
#define Elf_Phdr    Elf32_Phdr
#define Elf_Shdr    Elf32_Shdr
#define Elf_Dyn     Elf32_Dyn
#define Elf_Sym     Elf32_Sym
#define Elf_Rela    Elf32_Rela
#define Elf_Rel     Elf32_Rel
#define Elf_Addr    Elf32_Addr
#define ELF_R_TYPE  ELF32_R_TYPE
#define ELF_R_SYM   ELF32_R_SYM
#define ELFCLASS_NATIVE ELFCLASS32
#endif

#if defined(__mips__)
#ifndef R_MIPS_GLOB_DAT
#define R_MIPS_GLOB_DAT 51
#endif
#ifndef R_MIPS_JUMP_SLOT
#define R_MIPS_JUMP_SLOT 127
#endif
#endif

#ifndef CPU_TYPE_X86_64
#define CPU_TYPE_X86_64  0x01000007
#endif
#ifndef CPU_TYPE_ARM64
#define CPU_TYPE_ARM64   0x0100000C
#endif

#define MAX_SEGS    32
#define MAX_FIXUPS  131072
#define MAX_IMPORTS 4096
#define MAX_STRINGS 131072
#define MAX_INITS   256
#define MAX_EXPORTS 1024

struct seg_info {
    char     name[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t initprot;
};

static struct seg_info     segs[MAX_SEGS];
static uint32_t            nsegs;
static uint64_t            base_vmaddr;
static uint64_t            total_size;

static uint8_t            *image;

static struct llbin_fixup  fixups[MAX_FIXUPS];
static uint32_t            nfixups;
static uint32_t            nrebase_fixups;
static uint32_t            nirel_fixups;

static struct llbin_import imports[MAX_IMPORTS];
static uint32_t            nimports;

static char                strtab[MAX_STRINGS];
static uint32_t            strtab_len;

static uint64_t            entry_off;
static int                 has_entry;

static struct llbin_init   inits[MAX_INITS];
static uint32_t            ninits;

static struct llbin_init   finis[MAX_INITS];
static uint32_t            nfinis;

static struct llbin_export exports[MAX_EXPORTS];
static uint32_t            nexports;

#define MAX_NEEDED 32
static uint32_t            needed_str[MAX_NEEDED];
static uint32_t            nneeded;
static const char         *elf_dynstr;

#ifndef SHF_ALLOC
#define SHF_ALLOC 0x2
#endif
static uint32_t            eh_frame_off;
static uint32_t            eh_frame_size;

static uint32_t            tls_init_off;
static uint32_t            tls_init_size;
static uint32_t            tls_total_size;
static uint32_t            tls_align;

static void die(const char *msg)
{
    fprintf(stderr, "llpack: %s\n", msg);
    exit(1);
}

static uint32_t add_string(const char *s)
{
    size_t len = strlen(s) + 1;
    if (strtab_len + len > MAX_STRINGS)
        die("string table overflow");
    uint32_t off = strtab_len;
    memcpy(strtab + off, s, len);
    strtab_len += (uint32_t)len;
    return off;
}

static uint16_t find_or_add_import_raw(const char *name)
{
    for (uint32_t i = 0; i < nimports; i++) {
        if (strcmp(strtab + imports[i].name_off, name) == 0)
            return (uint16_t)i;
    }

    if (nimports >= MAX_IMPORTS)
        die("import table overflow");

    uint16_t idx = (uint16_t)nimports;
    imports[nimports].name_off = add_string(name);
    imports[nimports].flags    = 0;
    nimports++;
    return idx;
}

static void add_fixup(uint32_t offset, uint8_t type,
                      uint16_t import_idx, int64_t addend)
{
    if (nfixups >= MAX_FIXUPS)
        die("fixup table overflow");

    fixups[nfixups].offset     = offset;
    fixups[nfixups].type       = type;
    fixups[nfixups].reserved   = 0;
    fixups[nfixups].import_idx = import_idx;
    fixups[nfixups].addend     = addend;
    if (type == LLBIN_FIXUP_REBASE)
        nrebase_fixups++;
    else if (type == LLBIN_FIXUP_IRELATIVE)
        nirel_fixups++;
    nfixups++;
}

static int build_image_elf(const uint8_t *buf, size_t len)
{
    if (len < sizeof(Elf_Ehdr))
        return -1;

    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS_NATIVE)
        die("ELF class does not match native pointer size");
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC)
        die("input must be ET_DYN or ET_EXEC");

    uint64_t lo = UINT64_MAX, hi = 0;
    nsegs = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if ((uint64_t)ehdr->e_phoff + (i + 1) * ehdr->e_phentsize > len)
            die("program header extends past EOF");

        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD)
            continue;

        if (nsegs >= MAX_SEGS) die("too many segments");

        segs[nsegs].vmaddr   = phdr->p_vaddr;
        segs[nsegs].vmsize   = phdr->p_memsz;
        segs[nsegs].fileoff  = phdr->p_offset;
        segs[nsegs].filesize = phdr->p_filesz;
        segs[nsegs].initprot = 0;
        if (phdr->p_flags & PF_R) segs[nsegs].initprot |= 1;
        if (phdr->p_flags & PF_W) segs[nsegs].initprot |= 2;
        if (phdr->p_flags & PF_X) segs[nsegs].initprot |= 4;
        snprintf(segs[nsegs].name, 16, "LOAD%u", nsegs);
        nsegs++;

        if (phdr->p_vaddr < lo)
            lo = phdr->p_vaddr;
        if (phdr->p_vaddr + phdr->p_memsz > hi)
            hi = phdr->p_vaddr + phdr->p_memsz;
    }

    if (lo >= hi) die("no PT_LOAD segments");

    base_vmaddr = lo;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type == PT_GNU_RELRO) {
            if (nsegs >= MAX_SEGS) die("too many segments");
            segs[nsegs].vmaddr   = phdr->p_vaddr;
            segs[nsegs].vmsize   = phdr->p_memsz;
            segs[nsegs].fileoff  = phdr->p_offset;
            segs[nsegs].filesize = phdr->p_filesz;
            segs[nsegs].initprot = 4 | LLBIN_SEG_RELRO;
            snprintf(segs[nsegs].name, 16, "RELRO");
            nsegs++;
            break;
        }
    }
    total_size  = ((hi - lo) + 0xFFFULL) & ~0xFFFULL;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type == 7) {
            tls_init_off   = (uint32_t)(phdr->p_vaddr - base_vmaddr);
            tls_init_size  = (uint32_t)phdr->p_filesz;
            tls_total_size = (uint32_t)phdr->p_memsz;
            tls_align      = (uint32_t)phdr->p_align;
            break;
        }
    }

    image = calloc(1, (size_t)total_size);
    if (!image) die("out of memory");

    for (uint32_t i = 0; i < nsegs; i++) {
        if (segs[i].filesize == 0) continue;
        if (segs[i].fileoff + segs[i].filesize > len)
            die("segment extends past end of file");

        uint64_t dest = segs[i].vmaddr - base_vmaddr;
        memcpy(image + dest, buf + segs[i].fileoff, (size_t)segs[i].filesize);
    }

    entry_off = ehdr->e_entry - base_vmaddr;
    has_entry = 1;

    return 0;
}

static int process_fixups_elf(const uint8_t *buf, size_t len)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    const Elf_Phdr *dyn_phdr = NULL;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type == PT_DYNAMIC) {
            dyn_phdr = phdr;
            break;
        }
    }

    if (!dyn_phdr) {
        printf("  no PT_DYNAMIC -- static binary, no fixups\n");
        return 0;
    }

    uint64_t dyn_off = dyn_phdr->p_vaddr - base_vmaddr;
    const Elf_Dyn *dyn = (const Elf_Dyn *)(image + dyn_off);

    uint64_t rela_addr = 0, rela_sz = 0, rela_ent = 0;
    uint64_t rel_addr = 0, rel_sz = 0, rel_ent = 0;
    uint64_t jmprel_addr = 0, pltrelsz = 0;
    int      pltrel_type = DT_RELA;
    uint64_t symtab_addr = 0, strtab_addr = 0;

    for (const Elf_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_RELA:     rela_addr   = d->d_un.d_ptr; break;
        case DT_RELASZ:   rela_sz     = d->d_un.d_val; break;
        case DT_RELAENT:  rela_ent    = d->d_un.d_val; break;
        case DT_REL:      rel_addr    = d->d_un.d_ptr; break;
        case DT_RELSZ:    rel_sz      = d->d_un.d_val; break;
        case DT_RELENT:   rel_ent     = d->d_un.d_val; break;
        case DT_JMPREL:   jmprel_addr = d->d_un.d_ptr; break;
        case DT_PLTRELSZ: pltrelsz    = d->d_un.d_val; break;
        case DT_PLTREL:   pltrel_type = (int)d->d_un.d_val; break;
        case DT_SYMTAB:   symtab_addr = d->d_un.d_ptr; break;
        case DT_STRTAB:   strtab_addr = d->d_un.d_ptr; break;
        case DT_NEEDED:
            if (nneeded < MAX_NEEDED)
                needed_str[nneeded++] = (uint32_t)d->d_un.d_val;
            break;
        }
    }

    (void)len;

    const Elf_Sym *symtab = symtab_addr ?
        (const Elf_Sym *)(image + symtab_addr - base_vmaddr) : NULL;
    const char *dynstr = strtab_addr ?
        (const char *)(image + strtab_addr - base_vmaddr) : NULL;
    elf_dynstr = dynstr;

    uint16_t machine = ehdr->e_machine;

    #define IS_RELATIVE(m, t, s) ( \
        ((m) == EM_X86_64  && (t) == R_X86_64_RELATIVE) || \
        ((m) == EM_AARCH64 && (t) == R_AARCH64_RELATIVE) || \
        ((m) == EM_386     && (t) == R_386_RELATIVE) || \
        ((m) == EM_ARM     && (t) == R_ARM_RELATIVE) || \
        ((m) == EM_MIPS    && (t) == R_MIPS_REL32 && (s) == 0) || \
        ((m) == EM_SPARC   && (t) == R_SPARC_RELATIVE) )

    #define IS_IRELATIVE(m, t) ( \
        ((m) == EM_X86_64  && (t) == R_X86_64_IRELATIVE) || \
        ((m) == EM_AARCH64 && (t) == R_AARCH64_IRELATIVE) || \
        ((m) == EM_386     && (t) == R_386_IRELATIVE) || \
        ((m) == EM_ARM     && (t) == R_ARM_IRELATIVE) || \
        ((m) == EM_SPARC   && (t) == R_SPARC_IRELATIVE) )

    #define IS_IMPORT(m, t, s) ( \
        ((m) == EM_X86_64  && ((t) == R_X86_64_GLOB_DAT || \
                               (t) == R_X86_64_JUMP_SLOT || \
                               (t) == R_X86_64_64)) || \
        ((m) == EM_AARCH64 && ((t) == R_AARCH64_GLOB_DAT || \
                               (t) == R_AARCH64_JUMP_SLOT || \
                               (t) == R_AARCH64_ABS64)) || \
        ((m) == EM_386     && ((t) == R_386_GLOB_DAT || \
                               (t) == R_386_JMP_SLOT || \
                               (t) == R_386_32)) || \
        ((m) == EM_ARM     && ((t) == R_ARM_GLOB_DAT || \
                               (t) == R_ARM_JUMP_SLOT || \
                               (t) == R_ARM_ABS32)) || \
        ((m) == EM_MIPS    && ((t) == R_MIPS_32 || \
                               (t) == R_MIPS_GLOB_DAT || \
                               (t) == R_MIPS_JUMP_SLOT || \
                               ((t) == R_MIPS_REL32 && (s) > 0))) || \
        ((m) == EM_SPARC   && ((t) == R_SPARC_GLOB_DAT || \
                                (t) == R_SPARC_JMP_SLOT || \
                                (t) == R_SPARC_32)) )

    #define IS_TLS_MODULE(m, t) ( \
        ((m) == EM_X86_64  && (t) == R_X86_64_DTPMOD64) || \
        ((m) == EM_AARCH64 && (t) == R_AARCH64_TLS_DTPMOD64) || \
        ((m) == EM_386     && (t) == R_386_TLS_DTPMOD32) || \
        ((m) == EM_ARM     && (t) == R_ARM_TLS_DTPMOD32) )

    #define IS_TLS_OFFSET(m, t) ( \
        ((m) == EM_X86_64  && ((t) == R_X86_64_DTPOFF64 || (t) == R_X86_64_TPOFF64)) || \
        ((m) == EM_AARCH64 && ((t) == R_AARCH64_TLS_DTPREL64 || (t) == R_AARCH64_TLS_TPREL64)) || \
        ((m) == EM_386     && ((t) == R_386_TLS_DTPOFF32 || (t) == R_386_TLS_TPOFF32)) || \
        ((m) == EM_ARM     && ((t) == R_ARM_TLS_DTPOFF32 || (t) == R_ARM_TLS_TPOFF32)) )

    size_t slot_sz = sizeof(Elf_Addr);

    if (rela_addr && rela_sz && rela_ent) {
        uint64_t count = rela_sz / rela_ent;
        const Elf_Rela *tbl =
            (const Elf_Rela *)(image + rela_addr - base_vmaddr);

        printf("  processing DT_RELA (%llu entries)\n",
               (unsigned long long)count);

        for (uint64_t i = 0; i < count; i++) {
            uint32_t type = ELF_R_TYPE(tbl[i].r_info);
            uint32_t sym  = ELF_R_SYM(tbl[i].r_info);
            uint64_t off  = tbl[i].r_offset - base_vmaddr;

            if (IS_RELATIVE(machine, type, sym)) {
                Elf_Addr val = (Elf_Addr)tbl[i].r_addend;
                memcpy(image + off, &val, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
            } else if (IS_IRELATIVE(machine, type)) {
                Elf_Addr val = (Elf_Addr)tbl[i].r_addend;
                memcpy(image + off, &val, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_IRELATIVE, 0, 0);
            } else if (IS_IMPORT(machine, type, sym) &&
                       symtab && dynstr && sym > 0) {
                if (symtab[sym].st_shndx != 0) {
                    Elf_Addr val = symtab[sym].st_value + (Elf_Addr)tbl[i].r_addend;
                    memcpy(image + off, &val, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
                } else {
                    const char *name = dynstr + symtab[sym].st_name;
                    uint16_t idx = find_or_add_import_raw(name);
                    Elf_Addr zero = 0;
                    memcpy(image + off, &zero, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                              tbl[i].r_addend);
                }
            } else if (IS_TLS_MODULE(machine, type)) {
                Elf_Addr zero = 0;
                memcpy(image + off, &zero, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_TLS_MODULE, 0, 0);
            } else if (IS_TLS_OFFSET(machine, type)) {
                if (sym > 0 && symtab && symtab[sym].st_shndx != 0) {
                    Elf_Addr val = symtab[sym].st_value + (Elf_Addr)tbl[i].r_addend;
                    memcpy(image + off, &val, slot_sz);
                } else if (sym == 0) {
                    Elf_Addr val = (Elf_Addr)tbl[i].r_addend;
                    memcpy(image + off, &val, slot_sz);
                } else {
                    Elf_Addr zero = 0;
                    memcpy(image + off, &zero, slot_sz);
                }
                add_fixup((uint32_t)off, LLBIN_FIXUP_TLS_OFFSET, 0,
                          (int64_t)tbl[i].r_addend);
            }
        }
    }

    if (rel_addr && rel_sz && rel_ent) {
        uint64_t count = rel_sz / rel_ent;
        const Elf_Rel *tbl =
            (const Elf_Rel *)(image + rel_addr - base_vmaddr);

        printf("  processing DT_REL (%llu entries)\n",
               (unsigned long long)count);

        for (uint64_t i = 0; i < count; i++) {
            uint32_t type = ELF_R_TYPE(tbl[i].r_info);
            uint32_t sym  = ELF_R_SYM(tbl[i].r_info);
            uint64_t off  = tbl[i].r_offset - base_vmaddr;

            if (IS_RELATIVE(machine, type, sym)) {
                add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
            } else if (IS_IRELATIVE(machine, type)) {
                add_fixup((uint32_t)off, LLBIN_FIXUP_IRELATIVE, 0, 0);
            } else if (IS_IMPORT(machine, type, sym) &&
                       symtab && dynstr && sym > 0) {
                if (symtab[sym].st_shndx != 0) {
                    Elf_Addr val = symtab[sym].st_value;
                    memcpy(image + off, &val, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
                } else {
                    Elf_Addr addend;
                    memcpy(&addend, image + off, slot_sz);
                    const char *name = dynstr + symtab[sym].st_name;
                    uint16_t idx = find_or_add_import_raw(name);
                    Elf_Addr zero = 0;
                    memcpy(image + off, &zero, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                              (int64_t)addend);
                }
            } else if (IS_TLS_MODULE(machine, type)) {
                Elf_Addr zero = 0;
                memcpy(image + off, &zero, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_TLS_MODULE, 0, 0);
            } else if (IS_TLS_OFFSET(machine, type)) {
                if (sym > 0 && symtab && symtab[sym].st_shndx != 0) {
                    Elf_Addr val = symtab[sym].st_value;
                    memcpy(image + off, &val, slot_sz);
                } else if (sym == 0) {
                } else {
                    Elf_Addr zero = 0;
                    memcpy(image + off, &zero, slot_sz);
                }
                add_fixup((uint32_t)off, LLBIN_FIXUP_TLS_OFFSET, 0, 0);
            }
        }
    }

    if (jmprel_addr && pltrelsz) {
        if (pltrel_type == DT_RELA) {
            uint64_t count = pltrelsz / sizeof(Elf_Rela);
            const Elf_Rela *tbl =
                (const Elf_Rela *)(image + jmprel_addr - base_vmaddr);

            printf("  processing DT_JMPREL/RELA (%llu entries)\n",
                   (unsigned long long)count);

            for (uint64_t i = 0; i < count; i++) {
                uint32_t type = ELF_R_TYPE(tbl[i].r_info);
                uint32_t sym_idx = ELF_R_SYM(tbl[i].r_info);
                uint64_t off = tbl[i].r_offset - base_vmaddr;

                if (IS_IRELATIVE(machine, type)) {
                    Elf_Addr val = (Elf_Addr)tbl[i].r_addend;
                    memcpy(image + off, &val, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_IRELATIVE, 0, 0);
                } else if (symtab && dynstr && sym_idx > 0) {
                    if (symtab[sym_idx].st_shndx != 0) {
                        Elf_Addr val = symtab[sym_idx].st_value + (Elf_Addr)tbl[i].r_addend;
                        memcpy(image + off, &val, slot_sz);
                        add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
                    } else {
                        const char *name = dynstr + symtab[sym_idx].st_name;
                        uint16_t idx = find_or_add_import_raw(name);
                        Elf_Addr zero = 0;
                        memcpy(image + off, &zero, slot_sz);
                        add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                                  tbl[i].r_addend);
                    }
                }
            }
        } else {
            uint64_t count = pltrelsz / sizeof(Elf_Rel);
            const Elf_Rel *tbl =
                (const Elf_Rel *)(image + jmprel_addr - base_vmaddr);

            printf("  processing DT_JMPREL/REL (%llu entries)\n",
                   (unsigned long long)count);

            for (uint64_t i = 0; i < count; i++) {
                uint32_t type = ELF_R_TYPE(tbl[i].r_info);
                uint32_t sym_idx = ELF_R_SYM(tbl[i].r_info);
                uint64_t off = tbl[i].r_offset - base_vmaddr;

                if (IS_IRELATIVE(machine, type)) {
                    add_fixup((uint32_t)off, LLBIN_FIXUP_IRELATIVE, 0, 0);
                } else if (symtab && dynstr && sym_idx > 0) {
                    if (symtab[sym_idx].st_shndx != 0) {
                        Elf_Addr val = symtab[sym_idx].st_value;
                        memcpy(image + off, &val, slot_sz);
                        add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
                    } else {
                        const char *name = dynstr + symtab[sym_idx].st_name;
                        uint16_t idx = find_or_add_import_raw(name);
                        Elf_Addr addend;
                        memcpy(&addend, image + off, slot_sz);
                        Elf_Addr zero = 0;
                        memcpy(image + off, &zero, slot_sz);
                        add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                                  (int64_t)addend);
                    }
                }
            }
        }
    }

    #undef IS_RELATIVE
    #undef IS_IRELATIVE
    #undef IS_IMPORT
    #undef IS_TLS_MODULE
    #undef IS_TLS_OFFSET

    return 0;
}

static int process_inits_elf(const uint8_t *buf, size_t len)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;
    (void)len;

    const Elf_Phdr *dyn_phdr = NULL;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type == PT_DYNAMIC) {
            dyn_phdr = phdr;
            break;
        }
    }

    if (!dyn_phdr)
        return 0;

    uint64_t dyn_off = dyn_phdr->p_vaddr - base_vmaddr;
    const Elf_Dyn *dyn = (const Elf_Dyn *)(image + dyn_off);

    uint64_t dt_init = 0, dt_init_array = 0, dt_init_arraysz = 0;
    uint64_t dt_fini = 0, dt_fini_array = 0, dt_fini_arraysz = 0;

    for (const Elf_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_INIT:         dt_init         = d->d_un.d_ptr; break;
        case DT_INIT_ARRAY:   dt_init_array   = d->d_un.d_ptr; break;
        case DT_INIT_ARRAYSZ: dt_init_arraysz = d->d_un.d_val; break;
        case DT_FINI:         dt_fini         = d->d_un.d_ptr; break;
        case DT_FINI_ARRAY:   dt_fini_array   = d->d_un.d_ptr; break;
        case DT_FINI_ARRAYSZ: dt_fini_arraysz = d->d_un.d_val; break;
        }
    }

    if (dt_init != 0) {
        if (ninits >= MAX_INITS)
            die("init table overflow");
        inits[ninits].offset = dt_init - base_vmaddr;
        ninits++;
    }

    if (dt_init_array != 0 && dt_init_arraysz != 0) {
        uint64_t arr_fileoff = 0;
        for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
            const Elf_Phdr *phdr =
                (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
            if (phdr->p_type == PT_LOAD &&
                dt_init_array >= phdr->p_vaddr &&
                dt_init_array < phdr->p_vaddr + phdr->p_memsz) {
                arr_fileoff = dt_init_array - phdr->p_vaddr + phdr->p_offset;
                break;
            }
        }
        if (arr_fileoff == 0) arr_fileoff = dt_init_array;

        uint32_t count = (uint32_t)(dt_init_arraysz / sizeof(Elf_Addr));
        const Elf_Addr *entries = (const Elf_Addr *)(buf + arr_fileoff);

        for (uint32_t i = 0; i < count; i++) {
            if (entries[i] == 0) continue;
            if (ninits >= MAX_INITS)
                die("init table overflow");
            inits[ninits].offset = (uint64_t)entries[i] - base_vmaddr;
            ninits++;
        }
    }

    if (dt_fini != 0) {
        if (nfinis < MAX_INITS) {
            finis[nfinis].offset = dt_fini - base_vmaddr;
            nfinis++;
        }
    }

    if (dt_fini_array != 0 && dt_fini_arraysz != 0) {
        uint64_t arr_fileoff = 0;
        for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
            const Elf_Phdr *phdr =
                (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
            if (phdr->p_type == PT_LOAD &&
                dt_fini_array >= phdr->p_vaddr &&
                dt_fini_array < phdr->p_vaddr + phdr->p_memsz) {
                arr_fileoff = dt_fini_array - phdr->p_vaddr + phdr->p_offset;
                break;
            }
        }
        if (arr_fileoff == 0) arr_fileoff = dt_fini_array;

        uint32_t count = (uint32_t)(dt_fini_arraysz / sizeof(Elf_Addr));
        const Elf_Addr *entries = (const Elf_Addr *)(buf + arr_fileoff);

        for (uint32_t i = 0; i < count; i++) {
            if (entries[i] == 0) continue;
            if (nfinis >= MAX_INITS)
                die("fini table overflow");
            finis[nfinis].offset = (uint64_t)entries[i] - base_vmaddr;
            nfinis++;
        }
    }

    return 0;
}

static int process_exports_elf(const uint8_t *buf, size_t len)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
        return 0;

    if (ehdr->e_shoff + (uint64_t)ehdr->e_shnum * ehdr->e_shentsize > len)
        return 0;

    const Elf_Shdr *shdrs = (const Elf_Shdr *)(buf + ehdr->e_shoff);

    const Elf_Shdr *dynsym_shdr = NULL;
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym_shdr = &shdrs[i];
            break;
        }
    }

    if (!dynsym_shdr || dynsym_shdr->sh_entsize == 0)
        return 0;

    if (dynsym_shdr->sh_offset + dynsym_shdr->sh_size > len)
        return 0;

    if (dynsym_shdr->sh_link >= ehdr->e_shnum)
        return 0;

    const Elf_Shdr *dynstr_shdr = &shdrs[dynsym_shdr->sh_link];
    const char *dynstr = (const char *)(buf + dynstr_shdr->sh_offset);

    uint32_t nsyms = (uint32_t)(dynsym_shdr->sh_size / dynsym_shdr->sh_entsize);
    const Elf_Sym *syms = (const Elf_Sym *)(buf + dynsym_shdr->sh_offset);

    for (uint32_t i = 0; i < nsyms; i++) {
        if (syms[i].st_shndx == SHN_UNDEF) continue;
        if (syms[i].st_value == 0) continue;
        if ((syms[i].st_other & 0x3) != 0) continue;

        const char *name = dynstr + syms[i].st_name;
        if (name[0] == '_' || name[0] == '\0') continue;

        if (nexports >= MAX_EXPORTS)
            die("export table overflow");

        exports[nexports].name_off = add_string(name);
        exports[nexports].flags    = 0;
        exports[nexports].addr_off = syms[i].st_value - base_vmaddr;
        nexports++;
    }

    return 0;
}

static int process_eh_frame_elf(const uint8_t *buf, size_t len)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
        ehdr->e_shstrndx == 0 || ehdr->e_shstrndx >= ehdr->e_shnum)
        return 0;

    if (ehdr->e_shoff + (uint64_t)ehdr->e_shnum * ehdr->e_shentsize > len)
        return 0;

    const Elf_Shdr *shdrs = (const Elf_Shdr *)(buf + ehdr->e_shoff);
    const Elf_Shdr *shstrtab_shdr = &shdrs[ehdr->e_shstrndx];

    if (shstrtab_shdr->sh_offset + shstrtab_shdr->sh_size > len)
        return 0;

    const char *shstrs = (const char *)(buf + shstrtab_shdr->sh_offset);
    uint64_t shstrs_size = shstrtab_shdr->sh_size;

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_name + 10 > shstrs_size)
            continue;
        if (memcmp(shstrs + shdrs[i].sh_name, ".eh_frame\0", 10) != 0)
            continue;
        if (!(shdrs[i].sh_flags & SHF_ALLOC))
            continue;
        if (shdrs[i].sh_size == 0)
            continue;

        uint64_t off = shdrs[i].sh_addr - base_vmaddr;
        if (off + shdrs[i].sh_size > total_size) {
            printf("  warning: .eh_frame extends past image\n");
            continue;
        }

        eh_frame_off  = (uint32_t)off;
        eh_frame_size = (uint32_t)shdrs[i].sh_size;
        break;
    }

    return 0;
}

static int write_llbin(const char *path)
{
    struct llbin_header hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic          = LLBIN_MAGIC;
    hdr.version        = LLBIN_VERSION;
#if defined(__arm64__) || defined(__aarch64__)
    hdr.arch           = CPU_TYPE_ARM64;
#elif defined(__x86_64__)
    hdr.arch           = CPU_TYPE_X86_64;
#elif defined(__i386__)
    hdr.arch           = 0x00000007;
#elif defined(__arm__)
    hdr.arch           = 0x0000000C;
#elif defined(__mips__)
    hdr.arch           = 0x00000008;
#elif defined(__sparc__)
    hdr.arch           = 0x00000002;
#else
    hdr.arch           = 0;
#endif
    hdr.entry_off      = entry_off;
    hdr.image_size     = total_size;
    hdr.preferred_base = base_vmaddr;

    hdr.image_off    = (uint32_t)sizeof(hdr);
    hdr.fixup_off    = hdr.image_off + (uint32_t)total_size;
    hdr.fixup_count  = nfixups;
    hdr.import_off   = hdr.fixup_off +
                       nfixups * (uint32_t)sizeof(struct llbin_fixup);
    hdr.import_count = nimports;
    hdr.strings_off  = hdr.import_off +
                       nimports * (uint32_t)sizeof(struct llbin_import);
    hdr.strings_size = strtab_len;

    struct llbin_segment llsegs[MAX_SEGS];
    uint32_t llseg_count = 0;
    for (uint32_t i = 0; i < nsegs; i++) {
        if (segs[i].vmsize == 0 || segs[i].vmaddr < base_vmaddr)
            continue;
        llsegs[llseg_count].offset = (uint32_t)(segs[i].vmaddr - base_vmaddr);
        llsegs[llseg_count].size   = (uint32_t)segs[i].vmsize;
        llsegs[llseg_count].prot   = segs[i].initprot;
        llsegs[llseg_count].pad    = 0;
        llseg_count++;
    }
    hdr.seg_count = llseg_count;

    uint32_t seg_table_off = hdr.strings_off + strtab_len;
    hdr.init_off    = seg_table_off +
                      llseg_count * (uint32_t)sizeof(struct llbin_segment);
    hdr.init_count  = ninits;
    hdr.export_off  = hdr.init_off +
                      ninits * (uint32_t)sizeof(struct llbin_init);
    hdr.export_count = nexports;
    hdr.needed_off  = hdr.export_off +
                      nexports * (uint32_t)sizeof(struct llbin_export);
    hdr.needed_count = nneeded;
    hdr.fini_off    = hdr.needed_off +
                      nneeded * (uint32_t)sizeof(uint32_t);
    hdr.fini_count = nfinis;
    hdr.eh_frame_off  = eh_frame_off;
    hdr.eh_frame_size = eh_frame_size;
    hdr.tls_init_off   = tls_init_off;
    hdr.tls_init_size  = tls_init_size;
    hdr.tls_total_size = tls_total_size;
    hdr.tls_align      = tls_align;

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }

    fwrite(&hdr,    sizeof(hdr),                    1,        f);
    fwrite(image,   1,                              (size_t)total_size, f);
    fwrite(fixups,  sizeof(struct llbin_fixup),      nfixups,  f);
    fwrite(imports, sizeof(struct llbin_import),     nimports, f);
    fwrite(strtab,  1,                               strtab_len, f);
    if (llseg_count > 0)
        fwrite(llsegs, sizeof(struct llbin_segment), llseg_count, f);
    if (ninits > 0)
        fwrite(inits, sizeof(struct llbin_init),     ninits,    f);
    if (nexports > 0)
        fwrite(exports, sizeof(struct llbin_export), nexports,  f);
    if (nneeded > 0)
        fwrite(needed_str, sizeof(uint32_t), nneeded, f);
    if (nfinis > 0)
        fwrite(finis, sizeof(struct llbin_init), nfinis, f);

    fclose(f);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: llpack <input.so> <output.llbin>\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }

    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    if (flen <= 0) die("empty or unreadable input");
    size_t len = (size_t)flen;
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(len);
    if (!buf) die("out of memory");
    if (fread(buf, 1, len, f) != len) die("short read");
    fclose(f);

    printf("llpack: %s (%zu bytes)\n", argv[1], len);

    if (build_image_elf(buf, len) < 0)
        die("build_image_elf failed");

    printf("  base=0x%llx  size=0x%llx  entry=0x%llx\n",
           (unsigned long long)base_vmaddr,
           (unsigned long long)total_size,
           (unsigned long long)entry_off);
    printf("  segments: %u\n", nsegs);
    for (uint32_t i = 0; i < nsegs; i++)
        printf("    [%u] %-16.16s  vmaddr=0x%llx  size=0x%llx\n",
               i, segs[i].name,
               (unsigned long long)segs[i].vmaddr,
               (unsigned long long)segs[i].vmsize);

    if (process_fixups_elf(buf, len) < 0)
        die("process_fixups_elf failed");

    printf("  fixups:  %u (%u rebase, %u import, %u ifunc)\n", nfixups,
           nrebase_fixups, nfixups - nrebase_fixups - nirel_fixups,
           nirel_fixups);
    printf("  imports: %u\n", nimports);
    for (uint32_t i = 0; i < nimports; i++)
        printf("    [%u] %s\n", i, strtab + imports[i].name_off);

    if (process_inits_elf(buf, len) < 0)
        die("process_inits_elf failed");

    printf("  inits:   %u\n", ninits);
    for (uint32_t i = 0; i < ninits; i++)
        printf("    [%u] offset=0x%llx\n", i,
               (unsigned long long)inits[i].offset);

    if (nfinis > 0) {
        printf("  finis:   %u\n", nfinis);
        for (uint32_t i = 0; i < nfinis; i++)
            printf("    [%u] offset=0x%llx\n", i,
                   (unsigned long long)finis[i].offset);
    }

    if (process_exports_elf(buf, len) < 0)
        die("process_exports_elf failed");

    printf("  exports: %u\n", nexports);
    for (uint32_t i = 0; i < nexports; i++)
        printf("    [%u] %s @ 0x%llx\n", i,
               strtab + exports[i].name_off,
               (unsigned long long)exports[i].addr_off);

    if (process_eh_frame_elf(buf, len) < 0)
        die("process_eh_frame_elf failed");

    if (eh_frame_size > 0)
        printf("  eh_frame: offset=0x%x size=0x%x\n", eh_frame_off, eh_frame_size);
    else
        printf("  eh_frame: (none)\n");

    if (tls_total_size > 0)
        printf("  tls: init_off=0x%x init_size=0x%x total=0x%x align=0x%x\n",
               tls_init_off, tls_init_size, tls_total_size, tls_align);
    else
        printf("  tls: (none)\n");

    if (nneeded > 0 && elf_dynstr) {
        for (uint32_t i = 0; i < nneeded; i++)
            needed_str[i] = add_string(elf_dynstr + needed_str[i]);
        printf("  needed:  %u\n", nneeded);
        for (uint32_t i = 0; i < nneeded; i++)
            printf("    [%u] %s\n", i, strtab + needed_str[i]);
    }

    if (write_llbin(argv[2]) < 0)
        die("write_llbin failed");

    uint32_t llseg_count = 0;
    for (uint32_t i = 0; i < nsegs; i++) {
        if (segs[i].vmsize == 0 || segs[i].vmaddr < base_vmaddr)
            continue;
        llseg_count++;
    }

    uint64_t out_size = (uint64_t)sizeof(struct llbin_header) +
                        total_size +
                        (uint64_t)nfixups  * sizeof(struct llbin_fixup) +
                        (uint64_t)nimports * sizeof(struct llbin_import) +
                        strtab_len +
                        (uint64_t)llseg_count * sizeof(struct llbin_segment) +
                        (uint64_t)ninits   * sizeof(struct llbin_init) +
                         (uint64_t)nexports * sizeof(struct llbin_export) +
                         (uint64_t)nneeded  * sizeof(uint32_t) +
                         (uint64_t)nfinis   * sizeof(struct llbin_init);
    printf("  output: %s (%llu bytes)\n", argv[2], (unsigned long long)out_size);

    free(buf);
    free(image);
    return 0;
}
