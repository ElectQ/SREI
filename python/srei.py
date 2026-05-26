#!/usr/bin/env python3
import struct
import sys
import os

LLBIN_MAGIC = 0x4E424C4C
LLBIN_VERSION = 2

LLBIN_FIXUP_REBASE = 0
LLBIN_FIXUP_IMPORT = 1

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

LLBIN_HEADER_FMT = '<IIIIQQQIIIIIIIIIIIII'
LLBIN_HEADER_SIZE = struct.calcsize(LLBIN_HEADER_FMT)

LLBIN_FIXUP_FMT = '<IBBhq'
LLBIN_FIXUP_SIZE = struct.calcsize(LLBIN_FIXUP_FMT)

LLBIN_IMPORT_FMT = '<II'

LLBIN_SEGMENT_FMT = '<IIII'

LLBIN_INIT_FMT = '<Q'

LLBIN_EXPORT_FMT = '<IIQ'

def parse_llbin(data):
    if len(data) < LLBIN_HEADER_SIZE:
        raise ValueError("data too short for llbin header")

    hdr = struct.unpack_from(LLBIN_HEADER_FMT, data, 0)

    return {
        'magic': hdr[0],
        'version': hdr[1],
        'arch': hdr[2],
        'flags': hdr[3],
        'entry_off': hdr[4],
        'image_size': hdr[5],
        'preferred_base': hdr[6],
        'image_off': hdr[7],
        'fixup_off': hdr[8],
        'fixup_count': hdr[9],
        'import_off': hdr[10],
        'import_count': hdr[11],
        'strings_off': hdr[12],
        'strings_size': hdr[13],
        'seg_count': hdr[14],
        'init_off': hdr[15],
        'init_count': hdr[16],
        'export_off': hdr[17],
        'export_count': hdr[18],
    }

def get_exports(data, hdr):
    exports = []
    strings = data[hdr['strings_off']:hdr['strings_off'] + hdr['strings_size']]

    for i in range(hdr['export_count']):
        off = hdr['export_off'] + i * struct.calcsize(LLBIN_EXPORT_FMT)
        name_off, flags, addr_off = struct.unpack_from(LLBIN_EXPORT_FMT, data, off)

        end = strings.index(b'\x00', name_off)
        name = strings[name_off:end].decode('utf-8', errors='replace')
        exports.append((name, addr_off, hash_name(name)))

    return exports

def build_bootstrap_x64(dll_offset, func_hash, user_data_offset, user_data_len, flags):
    bs = bytearray()

    bs += b'\xe8\x00\x00\x00\x00'
    bs += b'\x59'

    bs += b'\x49\x89\xc8'

    bs += b'\xba'
    bs += struct.pack('<I', func_hash)

    bs += b'\x49\x81\xc0'
    bs += struct.pack('<I', user_data_offset)

    bs += b'\x41\xb9'
    bs += struct.pack('<I', user_data_len)

    bs += b'\x56'
    bs += b'\x48\x89\xe6'
    bs += b'\x48\x83\xe4\xf0'
    bs += b'\x48\x83\xec\x30'

    bs += b'\x48\x89\x4c\x24\x28'
    bs += b'\x48\x81\xc1'
    bs += struct.pack('<I', dll_offset)

    bs += b'\xc7\x44\x24\x20'
    bs += struct.pack('<I', flags)

    remaining = len(bs) + 5 - len(bs)
    call_off = len(bs)
    bs += b'\xe8'
    bs += struct.pack('<I', 0)
    bs += b'\x48\x89\xf4'
    bs += b'\x5e'
    bs += b'\xc3'

    call_target = len(bs) - (call_off + 5)
    struct.pack_into('<I', bs, call_off + 1, call_target)

    return bytes(bs)

def convert_to_shellcode(dll_bytes, func_hash=0, user_data=b'', flags=0):
    try:
        import subprocess
        llpack = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'packer', 'llpack')
        if not os.path.isfile(llpack):
            llpack = 'llpack'

        import tempfile
        fd_in, in_path = tempfile.mkstemp(suffix='.so')
        fd_out, out_path = tempfile.mkstemp(suffix='.llbin')
        os.close(fd_in)
        os.close(fd_out)

        with open(in_path, 'wb') as f:
            f.write(dll_bytes)

        r = subprocess.run([llpack, in_path, out_path],
                           capture_output=True, text=True)
        print(r.stdout, end='')

        if r.returncode != 0:
            print(r.stderr, end='', file=sys.stderr)
            raise RuntimeError("llpack failed")

        with open(out_path, 'rb') as f:
            llbin_data = f.read()

        os.unlink(in_path)
        os.unlink(out_path)

    except Exception:
        print("[srei] llpack not available, using raw ELF as payload", file=sys.stderr)
        llbin_data = dll_bytes

    loader_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'bin', 'loader_x86_64.bin')
    try:
        with open(loader_path, 'rb') as f:
            loader_bytes = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("loader_x86_64.bin not found. Run 'make' first.")

    dll_offset = len(loader_bytes)
    user_data_offset = dll_offset + len(llbin_data)

    bootstrap = build_bootstrap_x64(dll_offset, func_hash,
                                     user_data_offset, len(user_data), flags)

    result = bytearray()
    result += bootstrap
    result += loader_bytes
    result += llbin_data
    result += user_data

    return bytes(result)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.so> [output.bin] [function_name] [user_data]")
        return 1

    with open(sys.argv[1], 'rb') as f:
        dll_bytes = f.read()

    func_name = sys.argv[3] if len(sys.argv) > 3 else ''
    func_hash = hash_name(func_name) if func_name else 0
    user_data = sys.argv[4].encode() if len(sys.argv) > 4 else b''

    sc = convert_to_shellcode(dll_bytes, func_hash, user_data, 0)

    out_path = sys.argv[2] if len(sys.argv) > 2 else sys.argv[1].rsplit('.', 1)[0] + '.bin'
    with open(out_path, 'wb') as f:
        f.write(sc)

    print(f"[+] Wrote {len(sc)} bytes to {out_path}")
    if func_name:
        print(f"[+] Function '{func_name}' hash: 0x{func_hash:08x}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
