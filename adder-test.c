#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>

static unsigned char *memory;
static const char *levels = "0123456";

void ext_logging_log_version_1(uint32_t level, uint64_t target_p, uint64_t message_p) {
	uint32_t target_len = (target_p >> 32);
	target_p &= 0xFFFFFFFF;
	uint32_t message_len = (message_p >> 32);
	message_p &= 0xFFFFFFFF;

	// Poor man's printf to avoid the neccessity of stack alignment for now
	putchar('L');
	putchar(levels[level]);
	putchar(':');
	putchar(' ');
	putchar('[');
	for(int i = 0; i < target_len; i++) putchar(*(memory + target_p + i));
	putchar(']');
	putchar(' ');
	for(int i = 0; i < message_len; i++) putchar(*(memory + message_p + i));
	putchar('\n');
}

int main(int argc, char **argv) {
	void (*pvf_init)();
	uint64_t (*validate_block)(uint32_t, uint32_t);
	uint64_t *heap_base;
	void *adder;

	adder = dlopen("./adder.so", RTLD_NOW);
	if(!adder) {
		fprintf(stderr, "%s\n", dlerror());
		exit(1);
	}

	dlerror();

	memory = (unsigned char *) dlsym(adder, "memory");
	if(!memory) {
		fprintf(stderr, "Cannot resolve 'memory'\n");
		exit(1);
	}
	validate_block = (uint64_t (*)(uint32_t, uint32_t)) dlsym(adder, "validate_block");
	if(!validate_block) {
		fprintf(stderr, "Cannot resolve 'validate_block'\n");
		exit(1);
	}
	pvf_init = (void (*)()) dlsym(adder, "init_pvf");
	if(!pvf_init) {
		fprintf(stderr, "Cannot resolve 'pvf_init'\n");
		exit(1);
	}
	heap_base = (uint64_t *) dlsym(adder, "__heap_base");
	if(!heap_base) {
		fprintf(stderr, "Cannot resolve 'heap_base'\n");
		exit(1);
	}

	(*pvf_init)();

	FILE *f_data = fopen("data.bin", "r");
	if(!f_data) {
		fprintf(stderr, "Cannot open 'data.bin'\n");
		exit(1);
	}
	fseek(f_data, 0, SEEK_END);
	long data_len = ftell(f_data);
	fseek(f_data, 0, SEEK_SET);
	fread(memory + *heap_base, 1, data_len, f_data);
	fclose(f_data);

	uint64_t res = (*validate_block)((uint32_t) *heap_base, (uint32_t) data_len);
	uint32_t res_len = (res >> 32);
	res &= 0xFFFFFFFF;

	FILE *f_res = fopen("res.bin", "w");
	if(!f_res) {
		fprintf(stderr, "Cannot open 'res.bin'\n");
		exit(1);
	}
	fwrite(memory + res, 1, res_len, f_res);
	fclose(f_res);

	dlclose(adder);
	return 0;
}
