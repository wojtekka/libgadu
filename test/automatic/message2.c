#include <stdio.h>
#include <string.h>
#include "message.h"
#include "config.h"
#ifdef HAVE_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

struct test_data
{
	const char *src;
	const char *dst;
	const char *attr;
	size_t attr_len;
};

#define SPAN(text) "<span style=\"color:#000000; font-family:'MS Shell Dlg 2'; font-size:9pt; \">" text "</span>"
#define SPAN_COLOR(color, text) "<span style=\"color:#" color "; font-family:'MS Shell Dlg 2'; font-size:9pt; \">" text "</span>"

const struct test_data text_to_html[] =
{
	/* Typowa wiadomość */
	{ "<bzdura>\n\"ala&ma'kota\"", SPAN("&lt;bzdura&gt;<br>&quot;ala&amp;ma&apos;kota&quot;") },

	/* Obrazek na początku tekstu */
	{ "test", SPAN("<img name=\"8877665544332211\">test"), "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Obrazek na końcu tekstu */
	{ "test", SPAN("test<img name=\"8877665544332211\">"), "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Obrazek w środku tekstu */
	{ "testtest", SPAN("test<img name=\"8877665544332211\">test"), "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Obrazek poza tekstem */
	{ "test", SPAN("test"), "\x05\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, tylko obrazek -- bez <span> */
	{ "", "<img name=\"8877665544332211\">", "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, dwa obrazki -- nadal bez <span> */
	{ "", "<img name=\"8877665544332211\"><img name=\"1122334455667788\">", "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x80\x09\x01\x88\x77\x66\x55\x44\x33\x22\x11", 26 },

	/* Bez tekstu, dwa obrazki, w tym jeden poza */
	{ "", "<img name=\"8877665544332211\">", "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x01\x00\x80\x09\x01\x88\x77\x66\x55\x44\x33\x22\x11", 26 },

	/* Atrybuty na początku, w środku i na końcu tekstu */
	{ "foobarbaz", SPAN("<b>foo</b>") SPAN("<i>bar</i>") SPAN("<u>baz</u>"), "\x00\x00\x01\x03\x00\x02\x06\x00\x04", 9 },

	/* Mieszane atrybuty */
	{ "foobarbaz", SPAN("<b><i>foo</i></b>") SPAN("<b><u>bar</u></b>") SPAN("<i><u>baz</u></i>"), "\x00\x00\x03\x03\x00\x05\x06\x00\x06", 9 },

	/* Wszystkie atrybuty */
	{ "test", SPAN("<b><i><u>test</u></i></b>"), "\x00\x00\x07", 3 },

	/* Zbędne puste atrybuty */
	{ "test", SPAN("test"), "\x00\x00\x00\x02\x00\x00\x04\x00\x00", 9 },

	/* Atrybut na końcu tekstu */
	{ "test", SPAN("test"), "\x04\x00\x01", 3 },

	/* Atrybut poza tekstem */
	{ "test", SPAN("test"), "\x05\x00\x01", 3 },

	/* Kolorowy tekst */
	{ "test", SPAN_COLOR("123456", "test"), "\x00\x00\x08\x12\x34\x56", 6 },

	/* Kolorowy tekst na początku */
	{ "foobarbaz", SPAN_COLOR("123456", "foo") SPAN("barbaz"), "\x00\x00\x08\x12\x34\x56\x03\x00\x08\x00\x00\x00", 12 },

	/* Kolorowy tekst w środku */
	{ "foobarbaz", SPAN("foo") SPAN_COLOR("123456", "bar") SPAN("baz"), "\x03\x00\x08\x12\x34\x56\x06\x00\x08\x00\x00\x00", 12 },

	/* Kolorowy tekst na końcu (niezakończony) */
	{ "foobarbaz", SPAN("foobar") SPAN_COLOR("123456", "baz"), "\x06\x00\x08\x12\x34\x56", 6 },

	/* Kolorowy tekst na końcu (zakończony) */
	{ "foobarbaz", SPAN("foobar") SPAN_COLOR("123456", "baz"), "\x06\x00\x08\x12\x34\x56\x09\x00\x08\x00\x00\x00", 12 },

	/* Atrybuty mocno poza zakresem */
	{ "test", SPAN("test"), "\xff\xff\xff", 3 },

	/* Niekompletny atrybut obrazka */
	{ "test", SPAN("test"), "\x04\x00\x80\x09\x01", 5 },

	/* Niekompletny atrybut obrazka */
	{ "test", SPAN("test"), "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77", 12 },

	/* Atrybut w środku znaku unikodowego */
	{ "żółć", SPAN("<b>ż</b>") SPAN("<i>ółć</i>"), "\x00\x00\x01\x01\x00\x02", 6 },

	/* Błąd zgłoszony na ekg-users <5b601e1c.7feabed5.4bfaf8b6.1410c@o2.pl> */
	{ "testboldatest", SPAN("test") SPAN("<b>bolda</b>") SPAN("test"), "\x04\x00\x01\x09\x00\x00", 6 },

	/* Pusty tekst. Oryginalny klient co prawda nie wysyła pustego tekstu,
	 * ale przy wiadomości zawierającej jedynie obrazek, nie dokleja tagów
	 * <span>, więc improwizujemy. */
	{ "", "" },
};

const struct test_data html_to_text[] =
{
	/* Typowa wiadomość */
	{ SPAN("&lt;bzdura&gt;<br>&quot;ala&amp;ma&apos;kota&quot;"), "<bzdura>\n\"ala&ma'kota\"" },

	/* Niepoprawny tag */
	{ "<<<test>>>", ">>" },

	/* Tagi do wycięcia */
	{ "<foo>bar</baz>", "bar" },

	/* Poprawne encje */
	{ "&lt;&amp;&quot;&apos;&nbsp;&gt;", "<&\"'\xc2\xa0>" },

	/* Niepoprawne encje */
	{ "test&test;test&#123;test&#xabc;test", "test?test?test?test" },

	/* Różne warianty <br> */
	{ "a<br>b<br/>c<br />d", "a\nb\nc\nd" },

	/* Niepoprawne tagi */
	{ "<foo&bar;baz><foo\"bar><foo<bar>", "" },

	/* Niedokończona encja */
	{ "http://test/foo?ala=1&ma=2&kota=3", "http://test/foo?ala=1&ma=2&kota=3" },

	/* Pusty tekst */
	{ "", "" },
};

static void test_text_to_html(const char *input, const char *attr, size_t attr_len, const char *output)
{
	char *result;
	size_t len;
	char *tmp;
#ifdef HAVE_LIBXML2
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc;
#endif

	len = gg_message_text_to_html(NULL, input, attr, attr_len);

	result = malloc(len + 1);

	if (result == NULL) {
		perror("malloc");
		exit(1);
	}

	gg_message_text_to_html(result, input, attr, attr_len);

	printf("text: \"%s\"", input);
	if (attr != NULL) {
		int i;

		printf(" + attr:");
		for (i = 0; i < attr_len; i++)
			printf(" %02x", (unsigned char) attr[i]);
	}
	printf("\n");
	printf("output: \"%s\"\n", result);

	if (strcmp(result, output) != 0) {
		printf("expected: \"%s\"\n", output);
		free(result);
		exit(1);
	}

#ifdef HAVE_LIBXML2
	// Doklej <html></html>, żeby mieć tag dokumentu.

	tmp = realloc(result, strlen(result) + strlen("<html></html>") + 1);

	if (tmp == NULL) {
		perror("realloc");
		free(result);
		exit(1);
	}

	result = tmp;

	memmove(result + strlen("<html>"), result, strlen(result) + 1);
	memcpy(result, "<html>", strlen("<html>"));
	strcat(result, "</html>");

	// Zamień <br> na <x/>, żeby parser się nie wywalił.

	while ((tmp = strstr(result, "<br>")) != NULL)
		memcpy(tmp, "<x/>", 4);

	// Zamień <img ...> na <xx .../>, żeby parser się nie wywalił.

	while ((tmp = strstr(result, "<img ")) != NULL) {
		memcpy(tmp + 1, "xx", 2);
		memmove(tmp + 3, tmp + 4, 25);
		tmp[27] = '/';
	}

	// Parsuj!

	ctxt = xmlNewParserCtxt();

	if (ctxt == NULL) {
		perror("xmlNewParserCtxt");
		exit(1);
	}

	doc = xmlCtxtReadMemory(ctxt, result, strlen(result), "", NULL, 0);

	if (doc == NULL) {
		printf("expected not well-formed XML\n");
		free(result);
		xmlFreeParserCtxt(ctxt);
		exit(1);
	}

	xmlFreeDoc(doc);

	xmlFreeParserCtxt(ctxt);
#endif

	printf("correct\n\n");
	free(result);
}

static void test_html_to_text(const char *input, const char *output, const char *attr, size_t attr_len)
{
	char *result;
	size_t len;

	len = gg_message_html_to_text(NULL, input);

	result = malloc(len + 1);

	if (result == NULL) {
		perror("gg_message_html_to_text");
		exit(1);
	}

	gg_message_html_to_text(result, input);

	printf("html: \"%s\"\n", input);
	printf("output: \"%s\"\n", result);

	if (strcmp(result, output) == 0) {
		printf("correct\n\n");
		free(result);
	} else {
		printf("expected: \"%s\"\n", output);
		free(result);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int i;

	for (i = 0; i < sizeof(text_to_html) / sizeof(text_to_html[0]); i++)
		test_text_to_html(text_to_html[i].src, text_to_html[i].attr, text_to_html[i].attr_len, text_to_html[i].dst);

	for (i = 0; i < sizeof(html_to_text) / sizeof(html_to_text[0]); i++)
		test_html_to_text(html_to_text[i].src, html_to_text[i].dst, html_to_text[i].attr, html_to_text[i].attr_len);

	return 0;
}
