all: test

#wrt0.o: wrt0.S
#	nasm -O0 -g -f elf64 -o wrt0.o wrt0.S

test.wasm: test.wat
	wat2wasm test.wat

test.S: wasm2native.pl test.wasm
	./wasm2native.pl test.wasm >test.S

test.o: test.S
	nasm -O0 -g -f elf64 -o test.o test.S

test: test.o
	gcc -g -no-pie -o test ./test.o -lc

clean:
	rm -f wrt0.o test.o test.S test

.PHONY: all clean
