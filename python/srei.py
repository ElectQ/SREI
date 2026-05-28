#!/usr/bin/env python3
"""SREI — Shellcode Reflective ELF Injection.

Converts Linux shared libraries (.so) into position-independent shellcode
for in-memory execution. Self-contained pure Python — no external binaries.
"""

from __future__ import print_function
import struct
import sys
import os

try:
    from .llpack import convert_elf_to_llbin, LLBIN_MAGIC, LLBIN_VERSION
    from .llpack import LLBIN_HEADER_FMT, LLBIN_HEADER_SIZE
    from .llpack import LLBIN_FIXUP_FMT, LLBIN_IMPORT_FMT, LLBIN_SEGMENT_FMT
    from .llpack import LLBIN_INIT_FMT, LLBIN_EXPORT_FMT
except ImportError:
    from llpack import convert_elf_to_llbin, LLBIN_MAGIC, LLBIN_VERSION
    from llpack import LLBIN_HEADER_FMT, LLBIN_HEADER_SIZE
    from llpack import LLBIN_FIXUP_FMT, LLBIN_IMPORT_FMT, LLBIN_SEGMENT_FMT
    from llpack import LLBIN_INIT_FMT, LLBIN_EXPORT_FMT

try:
    from .loader_bytes import LOADER_X86_64
except ImportError:
    try:
        from loader_bytes import LOADER_X86_64
    except ImportError:
        LOADER_X86_64 = None

SREI_CLEARHEADER = 0x1
SREI_CLEARMEMORY = 0x2


def rotr32(val, shift):
    val &= 0xFFFFFFFF
    return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF


def hash_name(name):
    h = 0
    for b in name.encode('utf-8') + b'\x00':
        h = rotr32(h, 13)
        h = (h + b) & 0xFFFFFFFF
    return h


def build_bootstrap_x64(loader_size, llbin_size, func_hash, user_data_len, flags):
    # srei_load(data, data_len, func_hash, user_data, user_data_len, dlsym_fn, flags)
    # SysV AMD64: rdi, rsi, rdx, rcx, r8, r9, [rsp+8]

    # Build bootstrap with placeholder offsets first to get final size
    bs = bytearray()

    # call $+5 / pop rax  — rax = address of this instruction
    bs += b'\xe8\x00\x00\x00\x00'  # 5 bytes
    bs += b'\x58'                    # 1 byte (rax = &byte[5])
    # total so far: 6

    # lea rdi, [rax + llbin_offset]  — arg1: data
    bs += b'\x48\x8d\xb8'            # 3 bytes
    llbin_off_patch = len(bs)
    bs += b'\x00\x00\x00\x00'        # 4 bytes (placeholder)
    # total: 13

    # mov esi, llbin_size  — arg2: data_len
    bs += b'\xbe'
    bs += struct.pack('<I', llbin_size)
    # total: 18

    # mov edx, func_hash  — arg3
    bs += b'\xba'
    bs += struct.pack('<I', func_hash)
    # total: 23

    # lea rcx, [rax + user_data_offset]  — arg4: user_data
    bs += b'\x48\x8d\x88'
    user_data_off_patch = len(bs)
    bs += b'\x00\x00\x00\x00'
    # total: 30

    # mov r8d, user_data_len  — arg5
    bs += b'\x41\xb8'
    bs += struct.pack('<I', user_data_len)
    # total: 36

    # xor r9d, r9d  — arg6: dlsym_fn = NULL (self-resolve)
    bs += b'\x45\x31\xc9'
    # total: 39

    # Stack frame for alignment + flags
    bs += b'\x55'                  # push rbp
    bs += b'\x48\x89\xe5'         # mov rbp, rsp
    bs += b'\x48\x83\xe4\xf0'     # and rsp, -16
    bs += b'\x48\x83\xec\x20'     # sub rsp, 0x20
    # total: 51

    # mov dword [rsp], flags  — arg7 on stack (becomes [rsp+8] after call)
    bs += b'\xc7\x04\x24'
    bs += struct.pack('<I', flags)
    # total: 58

    # call loader (relative)
    call_off = len(bs)
    bs += b'\xe8'
    call_target_patch = len(bs)
    bs += b'\x00\x00\x00\x00'
    # total: 63

    # epilogue
    bs += b'\x48\x89\xec'         # mov rsp, rbp
    bs += b'\x5d'                  # pop rbp
    bs += b'\xc3'                  # ret
    # total: 68

    bs_size = len(bs)

    # Patch offsets: rax = &byte[5], loader at bs_size, llbin at bs_size + loader_size
    rax_base = 5
    llbin_offset = (bs_size - rax_base) + loader_size
    user_data_offset = llbin_offset + llbin_size
    call_target = (bs_size - rax_base) - (call_off + 5 - rax_base)

    struct.pack_into('<i', bs, llbin_off_patch, llbin_offset)
    struct.pack_into('<i', bs, user_data_off_patch, user_data_offset)
    struct.pack_into('<i', bs, call_target_patch, call_target)

    return bytes(bs)


def convert_to_shellcode(so_bytes, func_hash=0, user_data=b'', flags=0):
    """Convert an ELF shared library to position-independent shellcode.

    Args:
        so_bytes: Raw bytes of the ELF .so file.
        func_hash: ROTR13 hash of the exported function to call (0 = skip).
        user_data: Optional bytes to pass to the exported function.
        flags: Bitmask of SREI_CLEARHEADER and/or SREI_CLEARMEMORY.

    Returns:
        Shellcode bytes ready for execution.
    """
    if LOADER_X86_64 is None:
        raise ImportError(
            "loader_bytes.py not found. Run 'make embed' first.")

    llbin_data = convert_elf_to_llbin(so_bytes)

    loader_size = len(LOADER_X86_64)
    llbin_size = len(llbin_data)

    bootstrap = build_bootstrap_x64(
        loader_size, llbin_size, func_hash, len(user_data), flags)

    result = bytearray()
    result += bootstrap
    result += LOADER_X86_64
    result += llbin_data
    result += user_data

    return bytes(result)


def format_raw(data):
    return data


def format_string(data):
    return ''.join('\\x%02x' % b for b in data).encode('ascii')


def format_c(data):
    parts = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        line = ', '.join('0x%02x' % b for b in chunk)
        parts.append('    ' + line)
    return b'{\n' + b',\n'.join(parts) + b'\n}'


def format_python(data):
    return repr(data).encode('ascii')


FORMATTERS = {
    'raw': format_raw,
    'string': format_string,
    'c': format_c,
    'python': format_python,
}


def cmd_pack(args):
    with open(args.input, 'rb') as f:
        so_bytes = f.read()

    func_hash = 0
    if args.function:
        func_hash = hash_name(args.function)

    user_data = b''
    if args.user_data:
        user_data = args.user_data.encode('utf-8')

    flags = 0
    if args.clear_header:
        flags |= SREI_CLEARHEADER
    if args.clear_memory:
        flags |= SREI_CLEARMEMORY

    sc = convert_to_shellcode(so_bytes, func_hash, user_data, flags)

    fmt = args.format or 'raw'
    formatter = FORMATTERS.get(fmt)
    if formatter is None:
        print("Unknown format: %s" % fmt, file=sys.stderr)
        return 1

    output = formatter(sc)

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(output)
        print("Wrote %d bytes to %s" % (len(output), args.output))
    else:
        outpath = args.input.rsplit('.', 1)[0] + '.bin'
        with open(outpath, 'wb') as f:
            f.write(output)
        print("Wrote %d bytes to %s" % (len(output), outpath))

    if func_hash:
        print("Function '%s' hash: 0x%08x" % (args.function, func_hash))

    return 0


def cmd_hash(args):
    for name in args.names:
        h = hash_name(name)
        print("0x%08x  %s" % (h, name))
    return 0


def cmd_info(args):
    with open(args.file, 'rb') as f:
        data = f.read()

    if len(data) < 4:
        print("File too small")
        return 1

    magic = struct.unpack_from('<I', data, 0)[0]

    if magic == LLBIN_MAGIC:
        _print_llbin_info(data)
    elif data[:4] == b'\x7fELF':
        _print_elf_info(data)
    else:
        print("Unknown format (magic=0x%08x)" % magic)
        return 1

    return 0


def _print_llbin_info(data):
    if len(data) < LLBIN_HEADER_SIZE:
        print("Truncated llbin")
        return

    fields = struct.unpack_from(LLBIN_HEADER_FMT, data, 0)
    (magic, version, arch, flags,
     entry_off, image_size, preferred_base,
     image_off,
     fixup_off, fixup_count,
     import_off, import_count,
     strings_off, strings_size,
     seg_count,
     init_off, init_count,
     export_off, export_count,
     needed_off, needed_count,
     fini_off, fini_count,
     eh_frame_off, eh_frame_size,
     tls_init_off, tls_init_size,
     tls_total_size, tls_align) = fields

    arch_names = {
        0x01000007: 'x86_64',
        0x0100000C: 'arm64',
        0x00000007: 'i386',
        0x0000000C: 'arm',
        0x00000008: 'mips',
        0x00000002: 'sparc',
    }
    arch_name = arch_names.get(arch, '0x%x' % arch)

    print("llbin v%d (%s)" % (version, arch_name))
    print("  image_size:     0x%x (%d)" % (image_size, image_size))
    print("  preferred_base: 0x%x" % preferred_base)
    print("  entry_off:      0x%x" % entry_off)
    print("  flags:          0x%x" % flags)
    print("  fixups:         %d" % fixup_count)
    print("  imports:        %d" % import_count)
    print("  segments:       %d" % seg_count)
    print("  inits:          %d" % init_count)
    print("  exports:        %d" % export_count)
    print("  needed:         %d" % needed_count)
    print("  finis:          %d" % fini_count)
    if eh_frame_size > 0:
        print("  eh_frame:       off=0x%x size=0x%x" % (eh_frame_off, eh_frame_size))
    if tls_total_size > 0:
        print("  tls:            init_off=0x%x init_size=0x%x total=0x%x align=0x%x" % (
            tls_init_off, tls_init_size, tls_total_size, tls_align))
    print("  total size:     %d" % len(data))

    if import_count > 0 and strings_off + strings_size <= len(data):
        strtab = data[strings_off:strings_off + strings_size]
        print()
        print("  Imports:")
        for i in range(import_count):
            off = import_off + i * struct.calcsize(LLBIN_IMPORT_FMT)
            name_off = struct.unpack_from('<I', data, off)[0]
            if name_off < len(strtab):
                end = strtab.index(b'\x00', name_off)
                name = strtab[name_off:end].decode('ascii')
                print("    [%d] %s  (hash=0x%08x)" % (i, name, hash_name(name)))

    if export_count > 0 and strings_off + strings_size <= len(data):
        strtab = data[strings_off:strings_off + strings_size]
        print()
        print("  Exports:")
        for i in range(export_count):
            off = export_off + i * struct.calcsize(LLBIN_EXPORT_FMT)
            name_off, eflags, addr_off = struct.unpack_from(LLBIN_EXPORT_FMT, data, off)
            if name_off < len(strtab):
                end = strtab.index(b'\x00', name_off)
                name = strtab[name_off:end].decode('ascii')
                print("    [%d] %s @ 0x%x  (hash=0x%08x)" % (
                    i, name, addr_off, hash_name(name)))

    if seg_count > 0:
        print()
        print("  Segments:")
        seg_table_off = strings_off + strings_size
        for i in range(seg_count):
            off = seg_table_off + i * struct.calcsize(LLBIN_SEGMENT_FMT)
            soff, sz, prot, pad = struct.unpack_from(LLBIN_SEGMENT_FMT, data, off)
            pstr = ''
            if prot & 1: pstr += 'r'
            if prot & 2: pstr += 'w'
            if prot & 4: pstr += 'x'
            if not pstr: pstr = '---'
            print("    [%d] offset=0x%x size=0x%x prot=%s" % (i, soff, sz, pstr))

    if init_count > 0:
        print()
        print("  Init functions:")
        for i in range(init_count):
            off = init_off + i * struct.calcsize(LLBIN_INIT_FMT)
            (ioff,) = struct.unpack_from(LLBIN_INIT_FMT, data, off)
            print("    [%d] offset=0x%x" % (i, ioff))

    if needed_count > 0 and strings_off + strings_size <= len(data):
        strtab = data[strings_off:strings_off + strings_size]
        print()
        print("  DT_NEEDED:")
        for i in range(needed_count):
            off = needed_off + i * 4
            (name_off,) = struct.unpack_from('<I', data, off)
            if name_off < len(strtab):
                end = strtab.index(b'\x00', name_off)
                name = strtab[name_off:end].decode('ascii')
                print("    [%d] %s" % (i, name))


def _print_elf_info(data):
    if len(data) < 16:
        print("Truncated ELF")
        return

    ei_class = data[4]
    is_64 = (ei_class == 2)

    if is_64:
        e_type, e_machine = struct.unpack_from('<HH', data, 16)
        e_entry = struct.unpack_from('<Q', data, 24)[0]
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 54)
    else:
        e_type, e_machine = struct.unpack_from('<HH', data, 16)
        e_entry = struct.unpack_from('<I', data, 24)[0]
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 42)

    arch_map = {
        62: "x86_64", 183: "aarch64", 3: "i386",
        40: "arm", 8: "mips", 2: "sparc",
    }
    arch = arch_map.get(e_machine, '0x%x' % e_machine)
    etype = {2: "ET_EXEC", 3: "ET_DYN"}.get(e_type, str(e_type))

    print("ELF%s %s (%s), %d bytes" % (
        '64' if is_64 else '32', etype, arch, len(data)))
    print("  entry: 0x%x" % e_entry)

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is_64:
            p_type, p_flags, p_offset, p_vaddr = struct.unpack_from(
                '<IIqq', data, off)
            p_filesz, p_memsz = struct.unpack_from('<QQ', data, off + 32)
        else:
            p_type, p_offset, p_vaddr, _ = struct.unpack_from(
                '<IIII', data, off)
            p_filesz, p_memsz, p_flags, _ = struct.unpack_from(
                '<IIII', data, off + 16)

        ptypes = {1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP'}
        pname = ptypes.get(p_type, '0x%x' % p_type)

        if p_type == 1:
            flags_str = ''
            if p_flags & 1: flags_str += 'R'
            if p_flags & 2: flags_str += 'W'
            if p_flags & 4: flags_str += 'X'
            print("  %s  vaddr=0x%x  memsz=0x%x  filesz=0x%x  %s" % (
                pname, p_vaddr, p_memsz, p_filesz, flags_str))
        elif p_type == 2:
            print("  %s  vaddr=0x%x" % (pname, p_vaddr))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog='srei',
        description='Shellcode Reflective ELF Injection')
    sub = parser.add_subparsers(dest='command')

    # pack subcommand
    p_pack = sub.add_parser('pack', help='Convert .so to shellcode')
    p_pack.add_argument('input', help='Input .so file')
    p_pack.add_argument('-o', '--output', help='Output file')
    p_pack.add_argument('-f', '--function', help='Exported function to call')
    p_pack.add_argument('-u', '--user-data', help='User data string')
    p_pack.add_argument('--clear-header', action='store_true',
                        help='Erase llbin header after loading')
    p_pack.add_argument('--clear-memory', action='store_true',
                        help='Erase shellcode after loading')
    p_pack.add_argument('--format', choices=['raw', 'string', 'c', 'python'],
                        default='raw', help='Output format (default: raw)')
    p_pack.set_defaults(func=cmd_pack)

    # hash subcommand
    p_hash = sub.add_parser('hash', help='Compute ROTR13 hash for symbol names')
    p_hash.add_argument('names', nargs='+', help='Symbol names')
    p_hash.set_defaults(func=cmd_hash)

    # info subcommand
    p_info = sub.add_parser('info', help='Show info about .so or .llbin file')
    p_info.add_argument('file', help='Input file')
    p_info.set_defaults(func=cmd_info)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
