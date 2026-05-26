OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(_srei_loader)

SECTIONS
{
    . = 0;
    .text : {
        *(.text)
        *(.text.*)
    }
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }
    .data : {
        *(.data)
        *(.data.*)
    }
    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.got)
        *(.got.plt)
        *(.plt)
    }
}
