/*
 *  (C) Copyright 2001-2006 Wojtek Kaniewski <wojtekka@irc.pl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License Version
 *  2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "libgadu.h"
#include "internal.h"
#include "fileio.h"

static inline int
gg_mkstemp(char *path)
{
	mode_t old_umask, file_mask;
	int ret;

	file_mask = S_IRWXO | S_IRWXG;
	old_umask = umask(file_mask);
#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500)
	ret = mkstemp(path);
#else
#ifdef _WIN32
	if (_mktemp_s(path, strlen(path) + 1) != 0)
#else
	/* coverity[secure_temp : FALSE]
	 *
	 * mktemp may be unsafe, because it creates files with predictable
	 * names, but it's not a real problem for automatic tests.
	 */
	if (strcmp(mktemp(path), "") == 0)
#endif
		ret = -1;
	else
		ret = open(path, O_EXCL | O_RDWR | O_CREAT, file_mask);
#endif
	umask(old_umask);

	return ret;
}

static char *sha1_to_string(uint8_t *sha1)
{
	static char str[41];
	size_t i;

	for (i = 0; i < 20; i++)
		sprintf(str + i * 2, "%02x", sha1[i]);

	return str;
}

static int sha1_compare(uint8_t *sha1, const char *str)
{
	size_t i;

	for (i = 0; i < 20; i++) {
		unsigned int byte;

		sscanf(str + i * 2, "%02x", &byte);

		if (byte != sha1[i])
			return 0;
	}

	return 1;
}

struct login_hash {
	const char *password;
	uint32_t seed;
	const char *expect;
};

struct login_hash login_hashes[] = {
	{ "AAAA", 0x41414141, "c08598945e566e4e53cf3654c922fa98003bf2f9" },
	{ "test", 0x41424344, "459d3fbcfd3a91ef4fe64e151d950e0997af4ba4" },
};

static void test_login_hash(const char *password, uint32_t seed, const char *expect)
{
	uint8_t result[20];

	if (gg_login_hash_sha1_2(password, seed, result) == -1) {
		fprintf(stderr, "gg_login_hash_sha1_2() failed for \"%s\", 0x%08x\n", password, seed);
		exit(1);
	}

	if (!sha1_compare(result, expect)) {
		printf("hash failed for \"%s\", 0x%08x, expected %s, got %s\n",
			password, seed, expect, sha1_to_string(result));
		exit(1);
	}
}

struct file_hash {
	unsigned int megs;
	const char *expect;
};

struct file_hash file_hashes[] = {
	{ 0, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
	{ 1, "ad03e557eeed1f108ed9f5a54f9d0255f69c168e" },
	{ 2, "45afb38af4ba1e161f6fde18818a4acbe87a1c88" },
	{ 9, "940a5611380985416844aa6fb3767b38e4aac59f" },
	{ 10, "8f7659b0fa3994fcce2be062bbea0d183e9bc44e" },
	{ 11, "43c12a04edda27d2a87c8c85aa5680bf36bdb0c0" },
	{ 12, "f40bdc59b7b073735e6e53ce9fa67f17978ef236" },
};

static void test_file_hash(unsigned int megs, const char *expect)
{
	int fd;
	size_t i;
	char name[32];
	uint8_t result[20];

	strcpy(name, "hash.XXXXXX");

	fd = gg_mkstemp(name);

	if (fd == -1) {
		fprintf(stderr, "Unable to create temporary file\n");
		exit(1);
	}

	for (i = 1; i <= megs; i++) {
		unsigned char j;

		if (lseek(fd, i * 1048756 - 1, SEEK_SET) == (off_t) -1) {
			fprintf(stderr, "Unable to seek past end of file\n");
			goto fail;
		}

		j = i;

		if (write(fd, &j, sizeof(j)) != sizeof(j)) {
			fprintf(stderr, "Unable to write past end of file\n");
			goto fail;
		}
	}

	if (gg_file_hash_sha1(fd, result) == -1) {
		fprintf(stderr, "gg_file_hash_sha1() failed for %d megs\n", megs);
		goto fail;
	}

	if (!sha1_compare(result, expect)) {
		printf("hash failed for %d mesgs, expected %s, got %s\n", megs, expect, sha1_to_string(result));
		goto fail;
	}

	close(fd);
	unlink(name);
	return;

fail:
	close(fd);
	unlink(name);
	exit(1);
}

int main(void)
{
	unsigned int i;

	for (i = 0; i < sizeof(login_hashes) / sizeof(login_hashes[0]); i++)
		test_login_hash(login_hashes[i].password, login_hashes[i].seed, login_hashes[i].expect);

	for (i = 0; i < sizeof(file_hashes) / sizeof(file_hashes[0]); i++)
		test_file_hash(file_hashes[i].megs, file_hashes[i].expect);

	return 0;
}
