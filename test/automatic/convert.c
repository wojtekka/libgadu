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

/* Obecne testy to tylko podstawa. Powinno być jeszcze:
 * - testowanie całego zakresu CP1250,
 * - testowanie reakcji na znaki unikodowe spoza CP1250,
 * - testowanie reakcji na znaki unikodowe >65535 (są ignorowane),
 * - testowanie reakcji na nieprawidłowe sekwencje UTF-8,
 * - testowanie cięcia tekstów na wejściu i wyjściu,
 * - testowanie czy cięcie nie potnie znaków UTF-8 w środku,
 * - ...
 * TODO ograniczanie stringów
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "encoding.h"

struct test_data
{
	int line;
	const char *src;
	const char *dst;
	ssize_t src_len;
	ssize_t dst_len;
};

#define TEST(src, dst) { __LINE__, src, dst, -1, -1 }
#define TEST_SIZE(src, dst, src_len, dst_len) \
	{ __LINE__, src, dst, src_len, dst_len }

static const struct test_data utf8_to_cp1250[] =
{
	TEST("zażółć gęślą jaźń", "za\xbf\xf3\xb3\xe6 g\xea\x9cl\xb9 ja\x9f\xf1"),

	TEST("\xc0", "?"),
	TEST("\xc0test", "?test"),
	TEST("\xc0\x80", "?"),
	TEST("\xc0\x80test", "?test"),
	TEST("\xc0\x80\x80", "?"),
	TEST("\xc0\x80\x80test", "?test"),
	TEST("\xc0\x80\x80\x80", "?"),
	TEST("\xc0\x80\x80\x80test", "?test"),
	TEST("\xc0\x80\x80\x80\x80", "?"),
	TEST("\xc0\x80\x80\x80\x80test", "?test"),
	TEST("\xc0\x80\x80\x80\x80\x80", "?"),
	TEST("\xc0\x80\x80\x80\x80\x80test", "?test"),
	TEST("\xc0\x80\x80\x80\x80\x80\x80", "?"),
	TEST("\xc0\x80\x80\x80\x80\x80\x80test", "?test"),
	TEST("\xc0\x80\x80\x80\x80\x80\x80\x80", "?"),
	TEST("\xc0\x80\x80\x80\x80\x80\x80\x80test", "?test"),

	TEST("\xc1", "?"),
	TEST("\xc1test", "?test"),
	TEST("\xc1\x80", "?"),
	TEST("\xc1\x80test", "?test"),

	TEST("\xc0\xc1", "??"),
	TEST("\xc0\xc1test", "??test"),
	TEST("\xc0test\xc1test", "?test?test"),
	TEST("\xc0\x80\xc1\x80test", "??test"),
	TEST("\xc0\x80test\xc1\x80test", "?test?test"),

	TEST("\xe0", "?"),
	TEST("\xe0test", "?test"),
	TEST("\xe0\x80", "?"),
	TEST("\xe0\x80test", "?test"),
	TEST("\xe0\x80\x80", "?"),
	TEST("\xe0\x80\x80test", "?test"),

	TEST("\xf0", "?"),
	TEST("\xf0test", "?test"),
	TEST("\xf0\x80", "?"),
	TEST("\xf0\x80test", "?test"),
	TEST("\xf0\x80\x80", "?"),
	TEST("\xf0\x80\x80test", "?test"),
	TEST("\xf0\x80\x80\x80", "?"),
	TEST("\xf0\x80\x80\x80test", "?test"),

	TEST("\xf5", "?"),
	TEST("\xf5test", "?test"),
	TEST("\xf5\x80", "?"),
	TEST("\xf5\x80test", "?test"),
	TEST("\xf5\x80\x80", "?"),
	TEST("\xf5\x80\x80test", "?test"),
	TEST("\xf5\x80\x80\x80", "?"),
	TEST("\xf5\x80\x80\x80test", "?test"),

	TEST("\xf8", "?"),
	TEST("\xf8test", "?test"),
	TEST("\xf8\x80", "?"),
	TEST("\xf8\x80test", "?test"),
	TEST("\xf8\x80\x80", "?"),
	TEST("\xf8\x80\x80test", "?test"),
	TEST("\xf8\x80\x80\x80", "?"),
	TEST("\xf8\x80\x80\x80test", "?test"),
	TEST("\xf8\x80\x80\x80\x80", "?"),
	TEST("\xf8\x80\x80\x80\x80test", "?test"),

	TEST("\xfc", "?"),
	TEST("\xfctest", "?test"),
	TEST("\xfc\x80", "?"),
	TEST("\xfc\x80test", "?test"),
	TEST("\xfc\x80\x80", "?"),
	TEST("\xfc\x80\x80test", "?test"),
	TEST("\xfc\x80\x80\x80", "?"),
	TEST("\xfc\x80\x80\x80test", "?test"),
	TEST("\xfc\x80\x80\x80\x80", "?"),
	TEST("\xfc\x80\x80\x80\x80test", "?test"),
	TEST("\xfc\x80\x80\x80\x80\x80", "?"),
	TEST("\xfc\x80\x80\x80\x80\x80test", "?test"),

	TEST("\xfe", "?"),
	TEST("\xfetest", "?test"),
	TEST("\xff", "?"),
	TEST("\xfftest", "?test"),

	TEST("\xef\xbb\xbf", ""),
	TEST("\xef\xbb\xbftest", "test"),
};

static const struct test_data cp1250_to_utf8[] =
{
	TEST("za\xbf\xf3\xb3\xe6 g\xea\x9cl\xb9 ja\x9f\xf1", "zażółć gęślą jaźń"),
};

static void test_utf8_to_cp1250(const struct test_data *t)
{
	char *res;

	res = gg_encoding_convert(t->src, GG_ENCODING_UTF8, GG_ENCODING_CP1250, t->src_len, t->dst_len);

	if (strcmp(res, t->dst) != 0) {
		printf("utf8->cp1250: line %d, input=\"%s\", output=\"%s\", "
			"match=\"%s\", src_len=%d, dst_len=%d\n",
			t->line, t->src, res, t->dst,
			(int)t->src_len, (int)t->dst_len);
		exit(1);
	}

	free(res);
}

static void test_cp1250_to_utf8(const struct test_data *t)
{
	char *res;

	res = gg_encoding_convert(t->src, GG_ENCODING_CP1250, GG_ENCODING_UTF8, t->src_len, t->dst_len);

	if (strcmp(res, t->dst) != 0) {
		printf("cp1250->utf8: line %d, input=\"%s\", output=\"%s\", "
			"match=\"%s\", src_len=%d, dst_len=%d\n",
			t->line, t->src, res, t->dst,
			(int)t->src_len, (int)t->dst_len);
		exit(1);
	}

	free(res);
}

int main(void)
{
	size_t i;

	for (i = 0; i < sizeof(cp1250_to_utf8) / sizeof(cp1250_to_utf8[0]); i++)
		test_cp1250_to_utf8(&cp1250_to_utf8[i]);

	for (i = 0; i < sizeof(utf8_to_cp1250) / sizeof(utf8_to_cp1250[0]); i++)
		test_utf8_to_cp1250(&utf8_to_cp1250[i]);

	printf("okay\n");

	return 0;
}
