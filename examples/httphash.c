#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libgadu.h"

int main(int argc, char **argv)
{
	char buf[100];
	int i;

	if (argc == 4 && !strcmp(argv[1], "-l")) {
		unsigned long seed;
		uint8_t hash[20];

		seed = strtoul(argv[2], NULL, 0);
		gg_login_hash_sha1(argv[3], seed, hash);

		for (i = 0; i < 20; i++)
			printf("%02x ", hash[i]);

		printf("\n");

		return 0;
	}

	if (argc > 2 && !strcmp(argv[1], "-b")) {
		int count = argc - 3;
		uint32_t val = atoi(argv[2]);

		for (i = 0; i < (1 << count); i++) {
			char *args[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
			uint32_t res;
			int c = 0, j;

			if (i & 1)
				args[c++] = argv[3];
			if (i & 2)
				args[c++] = argv[4];
			if (i & 4)
				args[c++] = argv[5];
			if (i & 8)
				args[c++] = argv[6];
			if (i & 16)
				args[c++] = argv[7];
			if (i & 32)
				args[c++] = argv[8];
			if (i & 64)
				args[c++] = argv[9];
			if (i & 128)
				args[c++] = argv[10];
				
			strcpy(buf, "");
		
			for (j = 0; j < c; j++)
				strcat(buf, "s");

			res = gg_http_hash(buf, args[0], args[1], args[2], args[3], args[4], args[5], args[6], NULL);

			printf("%s %s %s %s %s %s %s %s", buf, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);

			if (res == val)
				printf(" MATCH!\n");
			else
				printf("\n");
		}

		return 0;
	}

	if (argc < 2 || argc > 10) {
		fprintf(stderr, "użycie: %s <kolejne> [wyrazy] [do] [hasha]\n", argv[0]);
		return 1;
	}

	strcpy(buf, "");
	
	for (i = 1; i < argc; i++)
		strcat(buf, "s");

	printf("%s\n", buf);
	
	printf("%u\n", gg_http_hash(buf, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10]));

	return 0;
}

