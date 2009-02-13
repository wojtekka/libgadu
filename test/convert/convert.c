// Obecne testy to tylko podstawa. Powinno być jeszcze:
// - testowanie całego zakresu CP1250,
// - testowanie reakcji na znaki unikodowe spoza CP1250,
// - testowanie reakcji na znaki unikodowe >65535 (są ignorowane),
// - testowanie reakcji na nieprawidłowe sekwencje UTF-8,
// - testowanie cięcia tekstów na wejściu i wyjściu,
// - testowanie czy cięcie nie potnie znaków UTF-8 w środku,
// - ...

#include "encoding.h"

int main(void)
{
	char *tmp1, *tmp2;

	tmp1 = gg_encoding_convert("zażółć gęślą jaźń", GG_ENCODING_UTF8, GG_ENCODING_CP1250, -1, -1);

	printf("1. \"%s\"\n", tmp1);

	if (strcmp(tmp1, "za\xbf\xf3\xb3\xe6 g\xea\x9cl\xb9 ja\x9f\xf1") != 0)
		return 1;

	tmp2 = gg_encoding_convert(tmp1, GG_ENCODING_CP1250, GG_ENCODING_UTF8, -1, -1);

	printf("2. \"%s\"\n", tmp2);

	if (strcmp(tmp2, "zażółć gęślą jaźń") != 0)
		return 1;

	free(tmp1);
	free(tmp2);

	return 0;
}
