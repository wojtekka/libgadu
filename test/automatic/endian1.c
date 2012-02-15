#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "libgadu.h"
#include "internal.h"

#ifdef HAVE_UINT64_T
static void test_gg_fix64(void)
{
	const char *source = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88";
	uint64_t value;

	memcpy(&value, source, sizeof(value));

	if (gg_fix64(value) != 0x8899aabbccddeeff) {
		fprintf(stderr, "gg_fix64 failed\n");
		exit(1);
	}
}
#endif

static void test_gg_fix32(void)
{
	const char *source = "\xee\xdd\xcc\xbb";
	uint32_t value;

	memcpy(&value, source, sizeof(value));

	if (gg_fix32(value) != 0xbbccddee) {
		fprintf(stderr, "gg_fix32 failed\n");
		exit(1);
	}
}

static void test_gg_fix16(void)
{
	const char *source = "\xdd\xcc";
	uint16_t value;

	memcpy(&value, source, sizeof(value));

	if (gg_fix16(value) != 0xccdd) {
		fprintf(stderr, "gg_fix16 failed\n");
		exit(1);
	}
}

int main(void)
{
#ifdef HAVE_UINT64_T
	test_gg_fix64();
#endif
	test_gg_fix32();
	test_gg_fix16();

	return 0;
}

