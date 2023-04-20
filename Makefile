all: adder-test adder.so

adder-test: adder-test.c
	gcc -rdynamic -ggdb -o adder-test adder-test.c

adder.so: adder.o
	ld -shared -o adder.so adder.o

adder.o: adder.S
	nasm -O0 -g -f elf64 -F dwarf -o adder.o adder.S

adder.S: wasm2native.pl test_parachain_adder.wasm
	./wasm2native.pl --runtime=pvf test_parachain_adder.wasm >adder.S

clean:
	rm -f adder.so adder.o adder.S adder-test

.PHONY: all clean
