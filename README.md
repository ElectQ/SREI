# SREI — Shellcode Reflective ELF Injection

Linux equivalent of [sRDI](https://github.com/monoxgas/sRDI). Converts shared libraries (.so) into position-independent shellcode for in-memory loading without touching disk.

## Architecture

```
┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐
│Bootstrap │→ │  Loader   │→ │  llbin     │→ │  User    │
│(asm,69B) │  │(PIC,~1KB)│  │  payload   │  │  data    │
└──────────┘  └──────────┘  └───────────┘  └──────────┘
```

- **llpack** — ELF → llbin converter (C tool, extracts fixups, imports, constructors, exports)
- **Loader** — PIC shellcode loader (no libc, direct syscalls, ~1KB)
- **Bootstrap** — Sets up registers, calls loader with correct arguments
- **srei.py** — Python wrapper that assembles the final shellcode blob

## llbin Format (v2)

Pre-processed flat binary with fixup tables, avoiding runtime ELF parsing:

```
[llbin_header]      — 88 bytes
[flat image]        — page-aligned, segments laid out flat
[fixup table]       — rebase + import fixups
[import table]      — symbol names for dlsym resolution
[string table]      — all names
[segment table]     — protection info per segment
[init table]        — constructor function offsets
[export table]      — exported symbol offsets
```

## Build

```bash
make
```

## Test

```bash
make test
```

## Usage

### C packer + native loader
```bash
./packer/llpack payload.so payload.llbin
./native/native_loader payload.llbin
```

### Python (full shellcode blob)
```bash
python3 python/srei.py payload.so output.bin payload_run "user data"
```

### Inspect llbin
```bash
python3 python/lltool.py info payload.llbin
```

## Loader Steps

1. Validate llbin header
2. mmap RW memory for image
3. Copy flat image
4. Apply REBASE fixups (slide = base - preferred_base)
5. Apply IMPORT fixups (resolve via dlsym)
6. Flush icache
7. Set segment protections (mprotect)
8. Call init/constructor functions
9. Find and call exported function by hash

## Phase 1 (Current)

- x86_64 Linux
- dlsym passed as parameter (covers injection/evasion scenarios)
- llbin v2 format with init/export tables

## Phase 2 (Planned)

- aarch64, i386, arm, mips, sparc
- Self-resolve dlsym via auxv/proc maps (no external dependencies)
- Encryption/compression of payload

## Directory Layout

```
SREI/
├── packer/         llpack.c, llbin.h
├── loader/         loader.c, syscall.h, resolve.h, linker.ld
├── bootstrap/      bootstrap_x86_64.asm
├── python/         srei.py, lltool.py
├── native/         native_loader.c
├── test/           payload.c
├── bin/            compiled loader binary
└── Makefile
```

## License

MIT
