#!/usr/bin/env python3
import struct
import sys

LLBIN_MAGIC = 0x4E424C4C
LLBIN_VERSION = 2

LLBIN_HEADER_FMT = '<IIIIQQQIIIIIIIIIIII'
LLBIN_HEADER_SIZE = struct.calcsize(LLBIN_HEADER_FMT)

LLBIN_FIXUP_FMT = '<IBBhq'

LLBIN_IMPORT_FMT = '<II'

LLBIN_SEGMENT_FMT = '<IIII'

LLBIN_INIT_FMT = '<Q'

LLBIN_EXPORT_FMT = '<IIQ'

def read_cstring(data, offset):
    end = data.index(b'\x00', offset)
    return data[offset:end].decode('utf-8', errors='replace')

def info(path):
    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < LLBIN_HEADER_SIZE:
        print("File too small")
        return 1

    fields = struct.unpack_from(LLBIN_HEADER_FMT, data, 0)

    magic, version, arch, flags = fields[0:4]
    entry_off, image_size, preferred_base = fields[4:7]
    image_off = fields[7]
    fixup_off, fixup_count = fields[8], fields[9]
    import_off, import_count = fields[10], fields[11]
    strings_off, strings_size = fields[12], fields[13]
    seg_count = fields[14]
    init_off, init_count = fields[15], fields[16]
    export_off, export_count = fields[17], fields[18]

    if magic != LLBIN_MAGIC:
        print(f"Not an llbin file (magic=0x{magic:08x})")
        return 1

    print(f"llbin version {version}")
    print(f"  arch:            0x{arch:08x}")
    print(f"  flags:           0x{flags:08x}")
    print(f"  entry:           0x{entry_off:x}")
    print(f"  image_size:      0x{image_size:x} ({image_size})")
    print(f"  preferred_base:  0x{preferred_base:x}")
    print(f"  image_off:       0x{image_off:x}")
    print(f"  fixups:          {fixup_count}  (off=0x{fixup_off:x})")
    print(f"  imports:         {import_count}  (off=0x{import_off:x})")
    print(f"  strings:         {strings_size} bytes  (off=0x{strings_off:x})")
    print(f"  segments:        {seg_count}")
    print(f"  inits:           {init_count}  (off=0x{init_off:x})")
    print(f"  exports:         {export_count}  (off=0x{export_off:x})")
    print(f"  total file size: {len(data)}")

    if import_count > 0:
        print()
        print("  Imports:")
        for i in range(import_count):
            off = import_off + i * struct.calcsize(LLBIN_IMPORT_FMT)
            name_off, iflags = struct.unpack_from(LLBIN_IMPORT_FMT, data, off)
            name = read_cstring(data, strings_off + name_off)
            print(f"    [{i}] {name}")

    if export_count > 0:
        print()
        print("  Exports:")
        for i in range(export_count):
            off = export_off + i * struct.calcsize(LLBIN_EXPORT_FMT)
            name_off, eflags, addr_off = struct.unpack_from(LLBIN_EXPORT_FMT, data, off)
            name = read_cstring(data, strings_off + name_off)
            print(f"    [{i}] {name} @ 0x{addr_off:x}")

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
            print(f"    [{i}] offset=0x{soff:x} size=0x{sz:x} prot={pstr}")

    if init_count > 0:
        print()
        print("  Init functions:")
        for i in range(init_count):
            off = init_off + i * struct.calcsize(LLBIN_INIT_FMT)
            (ioff,) = struct.unpack_from(LLBIN_INIT_FMT, data, off)
            print(f"    [{i}] offset=0x{ioff:x}")

    return 0

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} info <file.llbin>")
        return 1

    cmd = sys.argv[1]
    if cmd == 'info':
        return info(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
