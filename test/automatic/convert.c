// Obecne testy to tylko podstawa. Powinno być jeszcze:
// - testowanie całego zakresu CP1250,
// - testowanie reakcji na znaki unikodowe spoza CP1250,
// - testowanie reakcji na znaki unikodowe >65535 (są ignorowane),
// - testowanie reakcji na nieprawidłowe sekwencje UTF-8,
// - testowanie cięcia tekstów na wejściu i wyjściu,
// - testowanie czy cięcie nie potnie znaków UTF-8 w środku,
// - ...
// TODO ograniczanie stringów


#include "encoding.h"

struct test_data
{
	const char *src;
	const char *dst;
	ssize_t src_len;
	ssize_t dst_len;
};

#define TEST(src,dst) { src, dst, -1, -1 }
#define TEST_SIZE(src,dst,src_len,dst_len) { src, dst, src_len, dst_len }

const struct test_data utf8_to_cp1250[] =
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

const struct test_data cp1250_to_utf8[] =
{
	TEST("za\xbf\xf3\xb3\xe6 g\xea\x9cl\xb9 ja\x9f\xf1", "zażółć gęślą jaźń"),
};

void test_utf8(const char *input, const char *match, int src_len, int dst_len)
{
	char *output;

	output = gg_encoding_convert(input, GG_ENCODING_UTF8, GG_ENCODING_CP1250, src_len, dst_len);

	if (strcmp(output, match) != 0) {
		printf("utf8->cp1250: input=\"%s\", output=\"%s\", match=\"%s\", src_len=%d, dst_len=%d\n", input, output, match, src_len, dst_len);
		exit(1);
	}

	free(output);
}

void test_cp1250(const char *input, const char *match, int src_len, int dst_len)
{
	char *output;

	output = gg_encoding_convert(input, GG_ENCODING_CP1250, GG_ENCODING_UTF8, src_len, dst_len);

	if (strcmp(output, match) != 0) {
		printf("cp1250->utf8: input=\"%s\", output=\"%s\", match=\"%s\", src_len=%d, dst_len=%d\n", input, output, match, src_len, dst_len);
		exit(1);
	}

	free(output);
}

int main(void)
{
	int i;

	for (i = 0; i < sizeof(cp1250_to_utf8) / sizeof(cp1250_to_utf8[0]); i++)
		test_cp1250(cp1250_to_utf8[i].src, cp1250_to_utf8[i].dst, cp1250_to_utf8[i].src_len, cp1250_to_utf8[i].dst_len);

	for (i = 0; i < sizeof(utf8_to_cp1250) / sizeof(utf8_to_cp1250[0]); i++)
		test_cp1250(utf8_to_cp1250[i].src, utf8_to_cp1250[i].dst, utf8_to_cp1250[i].src_len, utf8_to_cp1250[i].dst_len);

	printf("okay\n");

	return 0;
}
