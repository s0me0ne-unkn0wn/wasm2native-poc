#!/bin/bash

for test in tests/*; do
	pushd $test
	rm -f test.wasm test.S test.o test
	wat2wasm test.wat || exit 1
	../../wasm2native.pl test.wasm >test.S || exit 1
	nasm -O0 -g -f elf64 -o test.o test.S || exit 1
	gcc -g -pie -o test ./test.o -lc || exit 1
	result=$(./test) || exit 1
	test "$result" = "42" || exit 1 && echo "Test $test: success"
	popd
done
