#!/usr/bin/env python3
"""Pure Python ELF to llbin v2 converter for SREI.

Converts ELF shared libraries (.so) into the llbin format understood
by the SREI loader shellcode. No external binaries required.
"""

import struct

LLBIN_MAGIC = 0x4E424C4C
LLBIN_VERSION = 2
LLBIN_FIXUP_REBASE = 0
LLBIN_FIXUP_IMPORT = 1

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

ELF_MAGIC = b'\x7fELF'
ELFCLASS64 = 2
ELFCLASS32 = 1
ET_DYN = 3
ET_EXEC = 2

EM_X86_64 = 62
EM_AARCH64 = 183
EM_386 = 3
EM_ARM = 40
EM_MIPS = 8
EM_SPARC = 2

PT_LOAD = 1
PT_DYNAMIC = 2
PF_R = 1
PF_W = 2
PF_X = 4

DT_NULL = 0
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23
DT_INIT = 12
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27

SHT_DYNSYM = 11
SHN_UNDEF = 0

R_X86_64_64 = 1
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8

R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027

R_386_32 = 1
R_386_GLOB_DAT = 6
R_386_JMP_SLOT = 7
R_386_RELATIVE = 8

R_ARM_ABS32 = 2
R_ARM_GLOB_DAT = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23

PAGE_ALIGN = 0xFFF

ARCH_MAP = {
    EM_X86_64: CPU_TYPE_X86_64,
    EM_AARCH64: CPU_TYPE_ARM64,
    EM_386: 0x00000007,
    EM_ARM: 0x0000000C,
    EM_MIPS: 0x00000008,
    EM_SPARC: 0x00000002,
}

LLBIN_HEADER_FMT = '<IIIIQQQIIIIIIIIIIII'
LLBIN_HEADER_SIZE = struct.calcsize(LLBIN_HEADER_FMT)

LLBIN_FIXUP_FMT = '<IBBhq'
LLBIN_FIXUP_SIZE = struct.calcsize(LLBIN_FIXUP_FMT)

LLBIN_IMPORT_FMT = '<II'
LLBIN_SEGMENT_FMT = '<IIII'
LLBIN_INIT_FMT = '<Q'
LLBIN_EXPORT_FMT = '<IIQ'


class PackerState(object):
    __slots__ = ('image', 'base_vmaddr', 'total_size', 'entry_off',
                 'segments', 'fixups', 'imports', 'inits', 'exports',
                 'strtab', 'arch', 'is_64', 'e_machine')

    def __init__(self):
        self.image = bytearray()
        self.base_vmaddr = 0
        self.total_size = 0
        self.entry_off = 0
        self.segments = []
        self.fixups = []
        self.imports = []
        self.inits = []
        self.exports = []
        self.strtab = bytearray()
        self.arch = 0
        self.is_64 = True
        self.e_machine = 0

    def find_or_add_import(self, name):
        for i, imp_name in enumerate(self.imports):
            if imp_name == name:
                return i
        idx = len(self.imports)
        self.imports.append(name)
        return idx

    def add_fixup(self, offset, ftype, import_idx=0, addend=0):
        self.fixups.append((offset, ftype, import_idx, addend))

    def add_string(self, s):
        off = len(self.strtab)
        self.strtab.extend(s.encode('ascii') + b'\x00')
        return off


def _is_relative(machine, rtype, rsym):
    if machine == EM_X86_64:
        return rtype == R_X86_64_RELATIVE
    if machine == EM_AARCH64:
        return rtype == R_AARCH64_RELATIVE
    if machine == EM_386:
        return rtype == R_386_RELATIVE
    if machine == EM_ARM:
        return rtype == R_ARM_RELATIVE
    return False


def _is_import(machine, rtype, rsym):
    if machine == EM_X86_64:
        return rtype in (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_64)
    if machine == EM_AARCH64:
        return rtype in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64)
    if machine == EM_386:
        return rtype in (R_386_GLOB_DAT, R_386_JMP_SLOT, R_386_32)
    if machine == EM_ARM:
        return rtype in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_ABS32)
    return False


def build_image_elf(st, data):
    if len(data) < 16:
        raise ValueError("too small for ELF header")
    if data[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")

    ei_class = data[4]
    st.is_64 = (ei_class == ELFCLASS64)

    if st.is_64:
        if len(data) < 64:
            raise ValueError("too small for ELF64 header")
        (e_type, e_machine, _, e_entry, e_phoff, _, _, _,
         e_phentsize, e_phnum) = struct.unpack_from('<HHIQQQIHHH', data, 16)
    else:
        if len(data) < 52:
            raise ValueError("too small for ELF32 header")
        (e_type, e_machine, _, e_entry, e_phoff, _, _, _,
         e_phentsize, e_phnum) = struct.unpack_from('<HHIIIIIHHHH', data, 16)

    if e_type not in (ET_DYN, ET_EXEC):
        raise ValueError("unsupported ELF type %d" % e_type)

    st.e_machine = e_machine
    st.arch = ARCH_MAP.get(e_machine, 0)

    lo, hi = (1 << 64), 0
    phdrs = []

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if st.is_64:
            (p_type, p_flags, p_offset, p_vaddr, _,
             p_filesz, p_memsz, _) = struct.unpack_from('<IIQQQQQQ', data, off)
        else:
            (p_type, p_offset, p_vaddr, _,
             p_filesz, p_memsz, p_flags, _) = struct.unpack_from('<IIIIIIII', data, off)

        phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

        if p_type == PT_LOAD and p_memsz > 0:
            lo = min(lo, p_vaddr)
            hi = max(hi, p_vaddr + p_memsz)

    if lo >= hi:
        raise ValueError("no loadable segments")

    lo &= ~PAGE_ALIGN
    hi = (hi + PAGE_ALIGN) & ~PAGE_ALIGN

    st.base_vmaddr = lo
    st.total_size = hi - lo
    st.image = bytearray(st.total_size)
    st.entry_off = e_entry - lo

    for (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz) in phdrs:
        if p_type != PT_LOAD or p_memsz == 0:
            continue

        dest = p_vaddr - lo
        if p_filesz > 0:
            if p_offset + p_filesz > len(data):
                raise ValueError("segment extends past EOF")
            st.image[dest:dest + p_filesz] = data[p_offset:p_offset + p_filesz]

        prot = 0
        if p_flags & PF_R:
            prot |= 1
        if p_flags & PF_W:
            prot |= 2
        if p_flags & PF_X:
            prot |= 4

        st.segments.append((p_vaddr, p_memsz, p_offset, p_filesz, prot))


def _find_dynamic_in_elf(st, data):
    if st.is_64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if st.is_64:
            p_type = struct.unpack_from('<I', data, off)[0]
            if p_type == PT_DYNAMIC:
                p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
                p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
                return p_vaddr, p_filesz
        else:
            p_type = struct.unpack_from('<I', data, off)[0]
            if p_type == PT_DYNAMIC:
                p_vaddr = struct.unpack_from('<I', data, off + 8)[0]
                p_filesz = struct.unpack_from('<I', data, off + 16)[0]
                return p_vaddr, p_filesz

    return 0, 0


def _parse_dynamic_entries(st, data):
    dyn_vaddr, dyn_filesz = _find_dynamic_in_elf(st, data)
    if dyn_vaddr == 0:
        return {}

    dyn_off = dyn_vaddr - st.base_vmaddr
    result = {}

    if st.is_64:
        fmt = '<qQ'
        entry_sz = 16
    else:
        fmt = '<iI'
        entry_sz = 8

    pos = dyn_off
    end = dyn_off + dyn_filesz
    while pos + entry_sz <= end:
        d_tag, d_val = struct.unpack_from(fmt, st.image, pos)
        pos += entry_sz
        if d_tag == DT_NULL:
            break
        result[d_tag] = d_val

    return result


def _find_phdr_for_vaddr(st, data, vaddr):
    if st.is_64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if st.is_64:
            p_type, _, p_offset = struct.unpack_from('<IIQ', data, off)
            p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
            p_memsz = struct.unpack_from('<Q', data, off + 40)[0]
        else:
            p_type, p_offset, p_vaddr = struct.unpack_from('<III', data, off)
            p_memsz = struct.unpack_from('<I', data, off + 20)[0]

        if p_type == PT_LOAD and p_memsz > 0:
            if p_vaddr <= vaddr < p_vaddr + p_memsz:
                return p_vaddr, p_offset

    return None


def _read_sym_name(st, sym_idx, symtab_off, strtab_off):
    if symtab_off <= 0 or strtab_off <= 0 or sym_idx == 0:
        return None

    if st.is_64:
        sym_entry = symtab_off + sym_idx * 24
    else:
        sym_entry = symtab_off + sym_idx * 16

    if sym_entry + 4 > len(st.image):
        return None

    st_name = struct.unpack_from('<I', st.image, sym_entry)[0]
    name_start = strtab_off + st_name

    if name_start >= len(st.image):
        return None

    try:
        name_end = st.image.index(0, name_start)
    except ValueError:
        return None

    name = st.image[name_start:name_end].decode('ascii')
    return name if name else None


def process_elf_relocations(st, data):
    dyn = _parse_dynamic_entries(st, data)
    if not dyn:
        return

    rela_addr = dyn.get(DT_RELA, 0)
    rela_sz = dyn.get(DT_RELASZ, 0)
    rela_ent = dyn.get(DT_RELAENT, 24 if st.is_64 else 12)
    rel_addr = dyn.get(DT_REL, 0)
    rel_sz = dyn.get(DT_RELSZ, 0)
    rel_ent = dyn.get(DT_RELENT, 16 if st.is_64 else 8)
    jmprel_addr = dyn.get(DT_JMPREL, 0)
    pltrelsz = dyn.get(DT_PLTRELSZ, 0)
    pltrel_type = dyn.get(DT_PLTREL, DT_RELA)
    symtab_addr = dyn.get(DT_SYMTAB, 0)
    strtab_addr = dyn.get(DT_STRTAB, 0)

    symtab_off = symtab_addr - st.base_vmaddr if symtab_addr else 0
    strtab_off = strtab_addr - st.base_vmaddr if strtab_addr else 0

    def r_sym(info):
        return info >> 32 if st.is_64 else info >> 8

    def r_type(info):
        return info & 0xffffffff if st.is_64 else info & 0xff

    slot_sz = 8 if st.is_64 else 4
    slot_fmt = '<Q' if st.is_64 else '<I'
    slot_mask = (1 << (slot_sz * 8)) - 1

    def process_rela(table_addr, table_sz):
        if table_addr == 0 or table_sz == 0 or rela_ent == 0:
            return
        count = table_sz // rela_ent
        table_off = table_addr - st.base_vmaddr
        rela_fmt = '<QQq' if st.is_64 else '<IIi'

        for i in range(count):
            off = table_off + i * rela_ent
            r_offset, r_info, r_addend = struct.unpack_from(rela_fmt, st.image, off)
            rt = r_type(r_info)
            rs = r_sym(r_info)
            img_off = r_offset - st.base_vmaddr

            if _is_relative(st.e_machine, rt, rs):
                struct.pack_into(slot_fmt, st.image, img_off,
                                 r_addend & slot_mask)
                st.add_fixup(img_off, LLBIN_FIXUP_REBASE)
            elif _is_import(st.e_machine, rt, rs):
                name = _read_sym_name(st, rs, symtab_off, strtab_off)
                if name:
                    idx = st.find_or_add_import(name)
                    struct.pack_into(slot_fmt, st.image, img_off, 0)
                    st.add_fixup(img_off, LLBIN_FIXUP_IMPORT, idx, r_addend)

    def process_rel(table_addr, table_sz):
        if table_addr == 0 or table_sz == 0 or rel_ent == 0:
            return
        count = table_sz // rel_ent
        table_off = table_addr - st.base_vmaddr
        rel_fmt = '<QQ' if st.is_64 else '<II'

        for i in range(count):
            off = table_off + i * rel_ent
            r_offset, r_info = struct.unpack_from(rel_fmt, st.image, off)
            rt = r_type(r_info)
            rs = r_sym(r_info)
            img_off = r_offset - st.base_vmaddr

            if _is_relative(st.e_machine, rt, rs):
                st.add_fixup(img_off, LLBIN_FIXUP_REBASE)
            elif _is_import(st.e_machine, rt, rs):
                addend = struct.unpack_from(slot_fmt, st.image, img_off)[0]
                name = _read_sym_name(st, rs, symtab_off, strtab_off)
                if name:
                    idx = st.find_or_add_import(name)
                    struct.pack_into(slot_fmt, st.image, img_off, 0)
                    st.add_fixup(img_off, LLBIN_FIXUP_IMPORT, idx, addend)

    process_rela(rela_addr, rela_sz)
    process_rel(rel_addr, rel_sz)

    if jmprel_addr and pltrelsz:
        if pltrel_type == DT_RELA:
            process_rela(jmprel_addr, pltrelsz)
        else:
            process_rel(jmprel_addr, pltrelsz)


def process_elf_inits(st, data):
    dyn = _parse_dynamic_entries(st, data)
    if not dyn:
        return

    dt_init = dyn.get(DT_INIT, 0)
    dt_init_array = dyn.get(DT_INIT_ARRAY, 0)
    dt_init_arraysz = dyn.get(DT_INIT_ARRAYSZ, 0)

    if dt_init != 0:
        st.inits.append(dt_init - st.base_vmaddr)

    if dt_init_array != 0 and dt_init_arraysz != 0:
        result = _find_phdr_for_vaddr(st, data, dt_init_array)
        if result:
            seg_vaddr, seg_offset = result
            arr_fileoff = dt_init_array - seg_vaddr + seg_offset
        else:
            arr_fileoff = dt_init_array

        ptr_sz = 8 if st.is_64 else 4
        ptr_fmt = '<Q' if st.is_64 else '<I'
        count = dt_init_arraysz // ptr_sz

        for i in range(count):
            pos = arr_fileoff + i * ptr_sz
            if pos + ptr_sz > len(data):
                break
            entry = struct.unpack_from(ptr_fmt, data, pos)[0]
            if entry == 0:
                continue
            st.inits.append(entry - st.base_vmaddr)


def process_elf_exports(st, data):
    if st.is_64:
        if len(data) < 64:
            return
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]
    else:
        if len(data) < 52:
            return
        e_shoff = struct.unpack_from('<I', data, 32)[0]
        e_shentsize = struct.unpack_from('<H', data, 46)[0]
        e_shnum = struct.unpack_from('<H', data, 48)[0]

    if e_shoff == 0 or e_shnum == 0:
        return
    if e_shoff + e_shnum * e_shentsize > len(data):
        return

    dynsym_shdr_off = None
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_type = struct.unpack_from('<I', data, sh_off + 4)[0]
        if sh_type == SHT_DYNSYM:
            dynsym_shdr_off = sh_off
            break

    if dynsym_shdr_off is None:
        return

    if st.is_64:
        (_, sh_type, _, _, sh_offset, sh_size,
         sh_link, _, _, sh_entsize) = struct.unpack_from(
            '<IIQQQQIIQQ', data, dynsym_shdr_off)
    else:
        (_, sh_type, _, _, sh_offset, sh_size,
         sh_link, _, _, sh_entsize) = struct.unpack_from(
            '<IIIIIIIIII', data, dynsym_shdr_off)

    if sh_entsize == 0 or sh_offset + sh_size > len(data):
        return
    if sh_link >= e_shnum:
        return

    dynstr_shdr_off = e_shoff + sh_link * e_shentsize
    if st.is_64:
        dynstr_offset = struct.unpack_from('<Q', data, dynstr_shdr_off + 24)[0]
        dynstr_size = struct.unpack_from('<Q', data, dynstr_shdr_off + 32)[0]
    else:
        dynstr_offset = struct.unpack_from('<I', data, dynstr_shdr_off + 16)[0]
        dynstr_size = struct.unpack_from('<I', data, dynstr_shdr_off + 20)[0]

    if dynstr_offset + dynstr_size > len(data):
        return

    dynstr = data[dynstr_offset:dynstr_offset + dynstr_size]
    nsyms = sh_size // sh_entsize

    for i in range(nsyms):
        sym_off = sh_offset + i * sh_entsize
        if st.is_64:
            st_name = struct.unpack_from('<I', data, sym_off)[0]
            st_other = struct.unpack_from('<B', data, sym_off + 5)[0]
            st_shndx = struct.unpack_from('<H', data, sym_off + 6)[0]
            st_value = struct.unpack_from('<Q', data, sym_off + 8)[0]
        else:
            st_name = struct.unpack_from('<I', data, sym_off)[0]
            st_other = struct.unpack_from('<B', data, sym_off + 5)[0]
            st_shndx = struct.unpack_from('<H', data, sym_off + 6)[0]
            st_value = struct.unpack_from('<I', data, sym_off + 8)[0]

        if st_shndx == SHN_UNDEF:
            continue
        if st_value == 0:
            continue
        if (st_other & 0x3) != 0:
            continue

        if st_name >= len(dynstr):
            continue
        nul = dynstr.find(b'\x00', st_name)
        if nul < 0:
            continue
        name = dynstr[st_name:nul].decode('ascii')

        if not name or name[0] == '_':
            continue

        name_off = st.add_string(name)
        st.exports.append((name_off, 0, st_value - st.base_vmaddr))


def write_llbin(st):
    import_entries = []
    for imp_name in st.imports:
        name_off = st.add_string(imp_name)
        import_entries.append((name_off, 0))

    hdr_size = LLBIN_HEADER_SIZE
    fixup_size = LLBIN_FIXUP_SIZE
    import_size = struct.calcsize(LLBIN_IMPORT_FMT)
    segment_size = struct.calcsize(LLBIN_SEGMENT_FMT)
    init_size = struct.calcsize(LLBIN_INIT_FMT)
    export_size = struct.calcsize(LLBIN_EXPORT_FMT)

    seg_entries = []
    for (vmaddr, vmsize, fileoff, filesize, prot) in st.segments:
        if vmsize == 0 or vmaddr < st.base_vmaddr:
            continue
        seg_entries.append((vmaddr - st.base_vmaddr, vmsize, prot, 0))

    image_off = hdr_size
    fixup_off = image_off + st.total_size
    import_off = fixup_off + len(st.fixups) * fixup_size
    strings_off = import_off + len(import_entries) * import_size
    seg_table_off = strings_off + len(st.strtab)
    init_off = seg_table_off + len(seg_entries) * segment_size
    export_off = init_off + len(st.inits) * init_size

    hdr = struct.pack(LLBIN_HEADER_FMT,
                      LLBIN_MAGIC, LLBIN_VERSION, st.arch, 0,
                      st.entry_off, st.total_size, st.base_vmaddr,
                      image_off,
                      fixup_off, len(st.fixups),
                      import_off, len(import_entries),
                      strings_off, len(st.strtab),
                      len(seg_entries),
                      init_off, len(st.inits),
                      export_off, len(st.exports))

    out = bytearray()
    out += hdr
    out += st.image

    for (offset, ftype, import_idx, addend) in st.fixups:
        out += struct.pack(LLBIN_FIXUP_FMT,
                           offset, ftype, 0, import_idx, addend)

    for (name_off, flags) in import_entries:
        out += struct.pack(LLBIN_IMPORT_FMT, name_off, flags)

    out += st.strtab

    for (offset, size, prot, pad) in seg_entries:
        out += struct.pack(LLBIN_SEGMENT_FMT, offset, size, prot, pad)

    for init_offset in st.inits:
        out += struct.pack(LLBIN_INIT_FMT, init_offset)

    for (name_off, flags, addr_off) in st.exports:
        out += struct.pack(LLBIN_EXPORT_FMT, name_off, flags, addr_off)

    return bytes(out)


def convert_elf_to_llbin(data, verbose=False):
    st = PackerState()
    build_image_elf(st, data)

    if verbose:
        print("  base=0x%x  size=0x%x  entry=0x%x" % (
            st.base_vmaddr, st.total_size, st.entry_off))
        print("  segments: %d" % len(st.segments))
        for i, (vmaddr, vmsize, fileoff, filesize, prot) in enumerate(st.segments):
            print("    [%d] vmaddr=0x%x  size=0x%x" % (i, vmaddr, vmsize))

    process_elf_relocations(st, data)

    if verbose:
        nrebase = sum(1 for f in st.fixups if f[1] == LLBIN_FIXUP_REBASE)
        nimport = sum(1 for f in st.fixups if f[1] == LLBIN_FIXUP_IMPORT)
        print("  fixups:  %d (%d rebase, %d import)" % (
            len(st.fixups), nrebase, nimport))
        print("  imports: %d" % len(st.imports))
        for i, name in enumerate(st.imports):
            print("    [%d] %s" % (i, name))

    process_elf_inits(st, data)

    if verbose:
        print("  inits:   %d" % len(st.inits))
        for i, off in enumerate(st.inits):
            print("    [%d] offset=0x%x" % (i, off))

    process_elf_exports(st, data)

    if verbose:
        print("  exports: %d" % len(st.exports))
        for i, (name_off, flags, addr_off) in enumerate(st.exports):
            print("    [%d] @ 0x%x" % (i, addr_off))

    result = write_llbin(st)

    if verbose:
        print("  output: %d bytes" % len(result))

    return result
