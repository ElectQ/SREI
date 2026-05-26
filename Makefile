CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -O2
LDFLAGS =

all: packer/llpack bin/loader_x86_64.bin test/libpayload.so test/payload.llbin native/native_loader bin/sc_test

packer/llpack: packer/llpack.c packer/llbin.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

loader/loader.o: loader/loader.c loader/syscall.h loader/resolve.h loader/selfresolve.h packer/llbin.h
	$(CC) $(CFLAGS) -fPIC -ffreestanding -nostdlib -c -Ipacker -o $@ $<

bin/loader_x86_64.elf: loader/loader.o loader/linker.ld
	@mkdir -p bin
	ld.gold -shared -nostdlib -s -T loader/linker.ld -o $@ $<

bin/loader_x86_64.bin: bin/loader_x86_64.elf
	objcopy -O binary -j .text -j .rodata $< $@
	@echo "  loader: `wc -c < $@` bytes"

test/libpayload.so: test/payload.c
	@mkdir -p test
	$(CC) $(CFLAGS) -shared -fPIC -fuse-ld=gold -o $@ $<

test/payload.llbin: test/libpayload.so packer/llpack
	./packer/llpack $< $@

native/native_loader: native/native_loader.c loader/loader.c loader/syscall.h loader/resolve.h loader/selfresolve.h packer/llbin.h
	$(CC) $(CFLAGS) -Ipacker -o $@ native/native_loader.c loader/loader.c -ldl

bin/sc_test: test/sc_test.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $<

embed: bin/loader_x86_64.bin
	@python3 -c "d=open('bin/loader_x86_64.bin','rb').read();f=open('python/loader_bytes.py','w');f.write('# AUTO-GENERATED - run make embed to update\nLOADER_X86_64 = %r\n' % d);f.close();print('embedded %d bytes into python/loader_bytes.py' % len(d))"

clean:
	rm -f packer/llpack loader/loader.o bin/loader_x86_64.elf bin/loader_x86_64.bin
	rm -f test/libpayload.so test/payload.llbin
	rm -f native/native_loader
	rm -f python/loader_bytes.py

.PHONY: all clean embed packer/loader loader test_so native_loader test

test/test_selfresolve: test/test_selfresolve.c loader/loader.c loader/syscall.h loader/resolve.h loader/selfresolve.h packer/llbin.h
	$(CC) $(CFLAGS) -Ipacker -o $@ test/test_selfresolve.c loader/loader.c -ldl

test: test/payload.llbin native/native_loader test/test_selfresolve bin/sc_test
	@$(MAKE) embed
	@echo "=== Test 1: dlsym parameter ==="
	./native/native_loader test/payload.llbin
	@echo ""
	@echo "=== Test 2: self-resolve (NULL dlsym) ==="
	./test/test_selfresolve test/payload.llbin
	@echo ""
	@echo "=== Test 3: Python pipeline (self-contained) ==="
	python3 python/srei.py pack test/libpayload.so -o /tmp/srei_test.bin -f payload_run -u "hello from python"
	/tmp/sc_test /tmp/srei_test.bin
	@echo ""
	@echo "=== Test 4: Python hash utility ==="
	python3 python/srei.py hash payload_run
	@echo ""
	@echo "=== Test 5: Python info ==="
	python3 python/srei.py info test/payload.llbin | head -5
	@echo ""
	@echo "All tests passed!"
