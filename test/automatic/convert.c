// Obecne testy to tylko podstawa. Powinno być jeszcze:
// - testowanie całego zakresu CP1250,
// - testowanie reakcji na znaki unikodowe spoza CP1250,
// - testowanie reakcji na znaki unikodowe >65535 (są ignorowane),
// - testowanie reakcji na nieprawidłowe sekwencje UTF-8,
// - testowanie cięcia tekstów na wejściu i wyjściu,
// - testowanie czy cięcie nie potnie znaków UTF-8 w środku,
// - ...

#include "encoding.h"

void test_utf8(const char *input, int src_len, int dst_len, const char *match)
{
	char *output;

	output = gg_encoding_convert(input, GG_ENCODING_UTF8, GG_ENCODING_CP1250, src_len, dst_len);

	if (strcmp(output, match) != 0) {
		printf("utf8->cp1250: input=\"%s\", output=\"%s\", match=\"%s\", src_len=%d, dst_len=%d\n", input, output, match, src_len, dst_len);
		exit(1);
	}

	free(output);
}

void test_cp1250(const char *input, int src_len, int dst_len, const char *match)
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
	test_utf8("zażółć gęślą jaźń", -1, -1, "za\xbf\xf3\xb3\xe6 g\xea\x9cl\xb9 ja\x9f\xf1");

	test_utf8("\xc0", -1, -1, "?");
	test_utf8("\xc0test", -1, -1, "?test");
	test_utf8("\xc0\x80", -1, -1, "?");
	test_utf8("\xc0\x80test", -1, -1, "?test");
	test_utf8("\xc0\x80\x80", -1, -1, "?");
	test_utf8("\xc0\x80\x80test", -1, -1, "?test");
	test_utf8("\xc0\x80\x80\x80", -1, -1, "?");
	test_utf8("\xc0\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xc0\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xc0\x80\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xc0\x80\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xc0\x80\x80\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xc0\x80\x80\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xc0\x80\x80\x80\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xc0\x80\x80\x80\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xc0\x80\x80\x80\x80\x80\x80\x80test", -1, -1, "?test");

	test_utf8("\xc1", -1, -1, "?");
	test_utf8("\xc1test", -1, -1, "?test");
	test_utf8("\xc1\x80", -1, -1, "?");
	test_utf8("\xc1\x80test", -1, -1, "?test");

	test_utf8("\xc0\xc1", -1, -1, "??");
	test_utf8("\xc0\xc1test", -1, -1, "??test");
	test_utf8("\xc0test\xc1test", -1, -1, "?test?test");
	test_utf8("\xc0\x80\xc1\x80test", -1, -1, "??test");
	test_utf8("\xc0\x80test\xc1\x80test", -1, -1, "?test?test");

	test_utf8("\xe0", -1, -1, "?");
	test_utf8("\xe0test", -1, -1, "?test");
	test_utf8("\xe0\x80", -1, -1, "?");
	test_utf8("\xe0\x80test", -1, -1, "?test");
	test_utf8("\xe0\x80\x80", -1, -1, "?");
	test_utf8("\xe0\x80\x80test", -1, -1, "?test");

	test_utf8("\xf0", -1, -1, "?");
	test_utf8("\xf0test", -1, -1, "?test");
	test_utf8("\xf0\x80", -1, -1, "?");
	test_utf8("\xf0\x80test", -1, -1, "?test");
	test_utf8("\xf0\x80\x80", -1, -1, "?");
	test_utf8("\xf0\x80\x80test", -1, -1, "?test");
	test_utf8("\xf0\x80\x80\x80", -1, -1, "?");
	test_utf8("\xf0\x80\x80\x80test", -1, -1, "?test");

	test_utf8("\xf5", -1, -1, "?");
	test_utf8("\xf5test", -1, -1, "?test");
	test_utf8("\xf5\x80", -1, -1, "?");
	test_utf8("\xf5\x80test", -1, -1, "?test");
	test_utf8("\xf5\x80\x80", -1, -1, "?");
	test_utf8("\xf5\x80\x80test", -1, -1, "?test");
	test_utf8("\xf5\x80\x80\x80", -1, -1, "?");
	test_utf8("\xf5\x80\x80\x80test", -1, -1, "?test");

	test_utf8("\xf8", -1, -1, "?");
	test_utf8("\xf8test", -1, -1, "?test");
	test_utf8("\xf8\x80", -1, -1, "?");
	test_utf8("\xf8\x80test", -1, -1, "?test");
	test_utf8("\xf8\x80\x80", -1, -1, "?");
	test_utf8("\xf8\x80\x80test", -1, -1, "?test");
	test_utf8("\xf8\x80\x80\x80", -1, -1, "?");
	test_utf8("\xf8\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xf8\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xf8\x80\x80\x80\x80test", -1, -1, "?test");

	test_utf8("\xfc", -1, -1, "?");
	test_utf8("\xfctest", -1, -1, "?test");
	test_utf8("\xfc\x80", -1, -1, "?");
	test_utf8("\xfc\x80test", -1, -1, "?test");
	test_utf8("\xfc\x80\x80", -1, -1, "?");
	test_utf8("\xfc\x80\x80test", -1, -1, "?test");
	test_utf8("\xfc\x80\x80\x80", -1, -1, "?");
	test_utf8("\xfc\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xfc\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xfc\x80\x80\x80\x80test", -1, -1, "?test");
	test_utf8("\xfc\x80\x80\x80\x80\x80", -1, -1, "?");
	test_utf8("\xfc\x80\x80\x80\x80\x80test", -1, -1, "?test");

	test_utf8("\xfe", -1, -1, "?");
	test_utf8("\xfetest", -1, -1, "?test");
	test_utf8("\xff", -1, -1, "?");
	test_utf8("\xfftest", -1, -1, "?test");

	test_utf8("\xef\xbb\xbf", -1, -1, "");
	test_utf8("\xef\xbb\xbftest", -1, -1, "test");

	test_cp1250("za\xbf\xf3\xb3\xe6 g\xea\x9cl\xb9 ja\x9f\xf1", -1, -1, "zażółć gęślą jaźń");

	// TODO ograniczanie stringów
	
	printf("okay\n");

	return 0;
}
