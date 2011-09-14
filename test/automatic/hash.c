#include <stdio.h>
#include <stdlib.h>
#include <libgadu.h>

struct test {
	const char *password;
	uint32_t seed;
	const char *result;
};

struct test tests[] = {
	{ "AAAA", 0x41414141, "c08598945e566e4e53cf3654c922fa98003bf2f9" },
	{ "test", 0x41424344, "459d3fbcfd3a91ef4fe64e151d950e0997af4ba4" },
};

int main(void)
{
	unsigned int i, j;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		uint8_t result[20];

		gg_login_hash_sha1(tests[i].password, tests[i].seed, result);

		for (j = 0; j < 20; j++) {
			unsigned int byte;

			sscanf(tests[i].result + j * 2, "%02x", &byte);

			if (byte != result[j]) {
				printf("hash %d failed: \"%s\", 0x%08x\n", i, tests[i].password, tests[i].seed);
				exit(1);
			}
		}
	}

	return 0;
}
