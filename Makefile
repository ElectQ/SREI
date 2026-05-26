CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -O2
LDFLAGS =

all: packer/llpack bin/loader_x86_64.bin test/libpayload.so test/payload.llbin native/native_loader

packer/llpack: packer/llpack.c packer/llbin.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

loader/loader.o: loader/loader.c loader/syscall.h loader/resolve.h packer/llbin.h
	$(CC) $(CFLAGS) -fPIC -ffreestanding -nostdlib -c -Ipacker -o $@ $<

bin/loader_x86_64.bin: loader/loader.o loader/linker.ld
	@mkdir -p bin
	ld.gold -shared -nostdlib -s -T loader/linker.ld -o $@ $<

test/libpayload.so: test/payload.c
	@mkdir -p test
	$(CC) $(CFLAGS) -shared -fPIC -fuse-ld=gold -o $@ $<

test/payload.llbin: test/libpayload.so packer/llpack
	./packer/llpack $< $@

native/native_loader: native/native_loader.c loader/loader.c loader/syscall.h loader/resolve.h packer/llbin.h
	$(CC) $(CFLAGS) -Ipacker -o $@ native/native_loader.c loader/loader.c -ldl

clean:
	rm -f packer/llpack loader/loader.o bin/loader_x86_64.bin
	rm -f test/libpayload.so test/payload.llbin
	rm -f native/native_loader

.PHONY: all clean packer/loader loader test_so native_loader test

test: test/payload.llbin native/native_loader
	./native/native_loader test/payload.llbin
