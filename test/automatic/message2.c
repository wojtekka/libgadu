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
#include <string.h>
#include "libgadu.h"
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
	gg_encoding_t encoding;
	const char *attr;
	size_t attr_len;
};

#define SPAN(text) "<span style=\"color:#000000; " \
	"font-family:'MS Shell Dlg 2'; font-size:9pt; \">" text "</span>"
#define SPAN_COLOR(color, text) "<span style=\"color:#" color "; " \
	"font-family:'MS Shell Dlg 2'; font-size:9pt; \">" text "</span>"

const struct test_data text_to_html[] =
{
	/* style:maxlinelength:start-ignore */

	/* Typowa wiadomość */
	{ "<bzdura>\n\"ala&ma'kota\"", SPAN("&lt;bzdura&gt;<br>&quot;ala&amp;ma&apos;kota&quot;"), GG_ENCODING_UTF8, NULL, 0 },

	/* Obrazek na początku tekstu */
	{ " test", "<img name=\"8877665544332211\">" SPAN("test"), GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Obrazek na początku tekstu, dokładnie tak jak wysyła oryginalny klient */
	{ "\xa0test", "<img name=\"8877665544332211\">" SPAN("test"), GG_ENCODING_CP1250, "\x01\x00\x08\x00\x00\x00\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 19 },

	/* Obrazek na końcu tekstu */
	{ "test", SPAN("test<img name=\"8877665544332211\">"), GG_ENCODING_UTF8, "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Obrazek na końcu tekstu, dokładnie tak jak wysyła oryginalny klient */
	{ "test\xa0", SPAN("test<img name=\"8877665544332211\">"), GG_ENCODING_CP1250, "\x00\x00\x08\x00\x00\x00\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 19 },

	/* Obrazek w środku tekstu */
	{ "test test", SPAN("test<img name=\"8877665544332211\">test"), GG_ENCODING_UTF8, "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Obrazek w środku tekstu, tekst na końcu formatowany */
	{ "test test foo", SPAN("test<img name=\"8877665544332211\">test <b>foo</b>"), GG_ENCODING_UTF8, "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x0a\x00\x01", 16 },

	/* Obrazek w środku tekstu, tekst na końcu formatowany, dokładnie tak jak wysyła oryginalny klient */
	{ "test\xa0test foo", SPAN("test<img name=\"8877665544332211\">test <b>foo</b>"), GG_ENCODING_CP1250, "\x00\x00\x08\x00\x00\x00\x05\x00\x08\x00\x00\x00\x0a\x00\x09\x00\x00\x00\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 31 },

	/* Obrazek poza tekstem */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\x05\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, tylko obrazek -- bez <span> */
	{ "", "<img name=\"8877665544332211\">", GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, tylko obrazek -- bez <span>, przypadek raczej egzotyczny */
	{ "ż", "<img name=\"8877665544332211\">", GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, tylko obrazek -- bez <span>, dokładnie tak jak wysyła oryginalny klient */
	{ "\xa0", "<img name=\"8877665544332211\">", GG_ENCODING_CP1250, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, dwa obrazki -- nadal bez <span> */
	{ "", "<img name=\"8877665544332211\"><img name=\"1122334455667788\">", GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x80\x09\x01\x88\x77\x66\x55\x44\x33\x22\x11", 26 },

	/* Bez tekstu, dwa obrazki -- nadal bez <span>, dokładnie tak jak wysyła oryginalny klient */
	{ "\xa0\xa0", "<img name=\"8877665544332211\"><img name=\"1122334455667788\">", GG_ENCODING_CP1250, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x01\x00\x80\x09\x01\x88\x77\x66\x55\x44\x33\x22\x11", 26 },

	/* Bez tekstu, dwa obrazki, w tym jeden poza */
	{ "", "<img name=\"8877665544332211\">", GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x01\x00\x80\x09\x01\x88\x77\x66\x55\x44\x33\x22\x11", 26 },

	/* Atrybuty na początku, w środku i na końcu tekstu */
	{ "foobarbaz", SPAN("<b>foo</b><i>bar</i><u>baz</u>"), GG_ENCODING_UTF8, "\x00\x00\x01\x03\x00\x02\x06\x00\x04", 9 },

	/* Mieszane atrybuty */
	{ "foobarbaz", SPAN("<b><i>foo</i></b><b><u>bar</u></b><i><u>baz</u></i>"), GG_ENCODING_UTF8, "\x00\x00\x03\x03\x00\x05\x06\x00\x06", 9 },

	/* Wszystkie atrybuty */
	{ "test", SPAN("<b><i><u>test</u></i></b>"), GG_ENCODING_UTF8, "\x00\x00\x07", 3 },

	/* Zbędne puste atrybuty */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\x00\x00\x00\x02\x00\x00\x04\x00\x00", 9 },

	/* Atrybut na końcu tekstu */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\x04\x00\x01", 3 },

	/* Atrybut poza tekstem */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\x05\x00\x01", 3 },

	/* Kolorowy tekst */
	{ "test", SPAN_COLOR("123456", "test"), GG_ENCODING_UTF8, "\x00\x00\x08\x12\x34\x56", 6 },

	/* Kolorowy tekst na początku */
	{ "foobarbaz", SPAN_COLOR("123456", "foo") SPAN("barbaz"), GG_ENCODING_UTF8, "\x00\x00\x08\x12\x34\x56\x03\x00\x08\x00\x00\x00", 12 },

	/* Kolorowy tekst w środku */
	{ "foobarbaz", SPAN("foo") SPAN_COLOR("123456", "bar") SPAN("baz"), GG_ENCODING_UTF8, "\x03\x00\x08\x12\x34\x56\x06\x00\x08\x00\x00\x00", 12 },

	/* Kolorowy tekst na końcu (niezakończony) */
	{ "foobarbaz", SPAN("foobar") SPAN_COLOR("123456", "baz"), GG_ENCODING_UTF8, "\x06\x00\x08\x12\x34\x56", 6 },

	/* Kolorowy tekst na końcu (zakończony) */
	{ "foobarbaz", SPAN("foobar") SPAN_COLOR("123456", "baz"), GG_ENCODING_UTF8, "\x06\x00\x08\x12\x34\x56\x09\x00\x08\x00\x00\x00", 12 },

	/* Atrybuty mocno poza zakresem */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\xff\xff\xff", 3 },

	/* Niekompletny atrybut obrazka */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\x04\x00\x80\x09\x01", 5 },

	/* Niekompletny atrybut obrazka */
	{ "test", SPAN("test"), GG_ENCODING_UTF8, "\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77", 12 },

	/* Atrybut w środku znaku unikodowego */
	{ "żółć", SPAN("<b>ż</b><i>ółć</i>"), GG_ENCODING_UTF8, "\x00\x00\x01\x01\x00\x02", 6 },

	/* To samo co wyżej, ale kodowanie CP1250 */
	{ "\xbf\xf4\xb3\xe6", SPAN("<b>\xbf</b><i>\xf4\xb3\xe6</i>"), GG_ENCODING_CP1250, "\x00\x00\x01\x01\x00\x02", 6 },

	/* Błąd zgłoszony na ekg-users <5b601e1c.7feabed5.4bfaf8b6.1410c@o2.pl> */
	{ "testboldatest", SPAN("test<b>bolda</b>test"), GG_ENCODING_UTF8, "\x04\x00\x01\x09\x00\x00", 6 },

	/* Pusty tekst. Oryginalny klient co prawda nie wysyła pustego tekstu,
	 * ale przy wiadomości zawierającej jedynie obrazek, nie dokleja tagów
	 * <span>, więc improwizujemy. */
	{ "", "", GG_ENCODING_UTF8, NULL, 0 },

	/* style:maxlinelength:end-ignore */
};

const struct test_data html_to_text[] =
{
	/* style:maxlinelength:start-ignore */

	/* Typowa wiadomość */
	{ SPAN("&lt;bzdura&gt;<br>&quot;ala&amp;ma&apos;kota&quot;"), "<bzdura>\n\"ala&ma'kota\"", GG_ENCODING_UTF8, "\x00\x00\x08\x00\x00\x00", 6 },

	/* Niepoprawny tag */
	{ "<<<test>>>", ">>", GG_ENCODING_UTF8, NULL, 0 },

	/* Tagi do wycięcia */
	{ "<foo>bar</baz>", "bar", GG_ENCODING_UTF8, NULL, 0 },

	/* Poprawne encje, UTF-8 */
	{ "&lt;&amp;&quot;&apos;&nbsp;&gt;", "<&\"'\xc2\xa0>", GG_ENCODING_UTF8, NULL, 0 },

	/* Poprawne encje, CP1250 */
	{ "&lt;&amp;&quot;&apos;&nbsp;&gt;", "<&\"'\xa0>", GG_ENCODING_CP1250, NULL, 0 },

	/* Niepoprawne encje */
	{ "test&test;test&#123;test&#xabc;test", "test?test?test?test", GG_ENCODING_UTF8, NULL, 0 },

	/* Różne warianty <br> */
	{ "a<br>b<br/>c<br />d", "a\nb\nc\nd", GG_ENCODING_UTF8, NULL, 0 },

	/* Niepoprawne tagi */
	{ "<foo&bar;baz><foo\"bar><foo<bar>", "", GG_ENCODING_UTF8, NULL, 0 },

	/* Niedokończona encja */
	{ "http://test/foo?ala=1&ma=2&kota=3", "http://test/foo?ala=1&ma=2&kota=3", GG_ENCODING_UTF8, NULL, 0 },

	/* Obrazek na początku tekstu, przed <span> */
	{ "<img name=\"8877665544332211\">" SPAN("test"), "\xc2\xa0test", GG_ENCODING_UTF8, "\x01\x00\x08\x00\x00\x00\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 19 },

	/* Obrazek na początku tekstu, wewnątrz <span> */
	{ SPAN("<img name=\"8877665544332211\">test"), "\xc2\xa0test", GG_ENCODING_UTF8, "\x01\x00\x08\x00\x00\x00\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 19 },

	/* Obrazek na końcu tekstu */
	{ SPAN("test<img name=\"8877665544332211\">"), "test\xc2\xa0", GG_ENCODING_UTF8, "\x00\x00\x08\x00\x00\x00\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 19 },

	/* Obrazek w środku tekstu, tekst na końcu formatowany, UTF-8 */
	{ SPAN("test<img name=\"8877665544332211\">test <b>foo</b>"), "test\xc2\xa0test foo", GG_ENCODING_UTF8, "\x00\x00\x08\x00\x00\x00\x05\x00\x08\x00\x00\x00\x0a\x00\x09\x00\x00\x00\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 31 },

	/* Obrazek w środku tekstu, tekst na końcu formatowany, CP1250 */
	{ SPAN("test<img name=\"8877665544332211\">test <b>foo</b>"), "test\xa0test foo", GG_ENCODING_CP1250, "\x00\x00\x08\x00\x00\x00\x05\x00\x08\x00\x00\x00\x0a\x00\x09\x00\x00\x00\x04\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 31 },

	/* Bez tekstu, tylko obrazek */
	{ "<img name=\"8877665544332211\">", "\xc2\xa0", GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88", 13 },

	/* Bez tekstu, dwa obrazki */
	{ "<img name=\"8877665544332211\"><img name=\"1122334455667788\">", "\xc2\xa0\xc2\xa0", GG_ENCODING_UTF8, "\x00\x00\x80\x09\x01\x11\x22\x33\x44\x55\x66\x77\x88\x01\x00\x80\x09\x01\x88\x77\x66\x55\x44\x33\x22\x11", 26 },

	/* Atrybuty na początku, w środku i na końcu tekstu */
	{ SPAN("<b>foo</b><i>bar</i><u>baz</u>"), "foobarbaz", GG_ENCODING_UTF8, "\x00\x00\x09\x00\x00\x00\x03\x00\x0a\x00\x00\x00\x06\x00\x0c\x00\x00\x00", 18 },

	/* Mieszane atrybuty */
	{ SPAN("<b><i>foo</i></b><b><u>bar</u></b><i><u>baz</u></i>"), "foobarbaz", GG_ENCODING_UTF8, "\x00\x00\x0b\x00\x00\x00\x03\x00\x0d\x00\x00\x00\x06\x00\x0e\x00\x00\x00", 18 },

	/* Mieszane atrybuty, udziwnione i nie do końca poprawne */
	{ SPAN("</i><b><i>foo</i><b><b><u>bar</u></b></b></b><i><u>baz</u></i>"), "foobarbaz", GG_ENCODING_UTF8, "\x00\x00\x0b\x00\x00\x00\x03\x00\x0d\x00\x00\x00\x06\x00\x0e\x00\x00\x00", 18 },

	/* Wszystkie atrybuty */
	{ SPAN("<b><i><u>test</u></i></b>"), "test", GG_ENCODING_UTF8, "\x00\x00\x0f\x00\x00\x00", 6 },

	/* Kolorowy tekst */
	{ SPAN_COLOR("123456", "test"), "test", GG_ENCODING_UTF8, "\x00\x00\x08\x12\x34\x56", 6 },

	/* Kolorowy tekst na początku */
	{ SPAN_COLOR("123456", "foo") SPAN("barbaz"), "foobarbaz", GG_ENCODING_UTF8, "\x00\x00\x08\x12\x34\x56\x03\x00\x08\x00\x00\x00", 12 },

	/* Kolorowy tekst w środku */
	{ SPAN("foo") SPAN_COLOR("123456", "bar") SPAN("baz"), "foobarbaz", GG_ENCODING_UTF8, "\x00\x00\x08\x00\x00\x00\x03\x00\x08\x12\x34\x56\x06\x00\x08\x00\x00\x00", 18 },

	/* Kolorowy tekst na końcu */
	{ SPAN("foobar") SPAN_COLOR("123456", "baz"), "foobarbaz", GG_ENCODING_UTF8, "\x00\x00\x08\x00\x00\x00\x06\x00\x08\x12\x34\x56", 12 },

	/* Różne kolory, do tego pogrubienie */
	{ SPAN("<b><span style=\"color:#ff0000;\">red, bold; </span>no color, bold; <span style=\"color:#0000ff;\">blue, bold; </span></b>no color"), "red, bold; no color, bold; blue, bold; no color", GG_ENCODING_UTF8, "\x00\x00\x09\xff\x00\x00\x0b\x00\x01\x1b\x00\x09\x00\x00\xff\x27\x00\x00", 18 },

	/* Atrybut "w środku" znaku unikodowego */
	{ SPAN("<b>ż</b><i>ółć</i>"), "żółć", GG_ENCODING_UTF8, "\x00\x00\x09\x00\x00\x00\x01\x00\x0a\x00\x00\x00", 12 },

	/* To co wyżej, ale CP1250 */
	{ SPAN("<b>\xbf</b><i>\xf4\xb3\xe6</i>"), "\xbf\xf4\xb3\xe6", GG_ENCODING_CP1250, "\x00\x00\x09\x00\x00\x00\x01\x00\x0a\x00\x00\x00", 12 },

	/* Błąd zgłoszony na ekg-users <5b601e1c.7feabed5.4bfaf8b6.1410c@o2.pl>, tym razem z drugiej strony */
	{ SPAN("test<b>bolda</b>test"), "testboldatest", GG_ENCODING_UTF8, "\x00\x00\x08\x00\x00\x00\x04\x00\x09\x00\x00\x00\x09\x00\x08\x00\x00\x00", 18 },

	/* Przed r1239 tag <bot/> był interpretowany jak bold */
	{ "<bot body=\"&lt;html/&gt;\">test</bot>test", "testtest", GG_ENCODING_UTF8, NULL, 0 },

	/* Pusty tekst */
	{ "", "", GG_ENCODING_UTF8, NULL, 0 },

	/* style:maxlinelength:end-ignore */
};

static void test_text_to_html(const char *input, const unsigned char *attr,
	size_t attr_len, const char *output, gg_encoding_t encoding)
{
	char *result;
	size_t len;
#ifdef HAVE_LIBXML2
	char *tmp;
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc;
#endif

	len = gg_message_text_to_html(NULL, input, encoding, attr, attr_len);

	result = malloc(len + 1);

	if (result == NULL) {
		perror("malloc");
		exit(1);
	}

	gg_message_text_to_html(result, input, encoding, attr, attr_len);

	printf("text: \"%s\"", input);
	if (attr != NULL) {
		size_t i;

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
	/* Doklej <html></html>, żeby mieć tag dokumentu. */

	if (encoding == GG_ENCODING_CP1250) {
		tmp = realloc(result, strlen(result) +
			strlen("<?xml version=\"1.0\" "
			"encoding=\"windows-1250\"?><html></html>") + 1);
	} else {
		tmp = realloc(result, strlen(result) + strlen("<html></html>") + 1);
	}

	if (tmp == NULL) {
		perror("realloc");
		free(result);
		exit(1);
	}

	result = tmp;

	if (encoding == GG_ENCODING_CP1250) {
		const char *xmls = "<?xml version=\"1.0\" encoding=\"windows-1250\"?><html>";
		memmove(result + strlen(xmls), result, strlen(result) + 1);
		memcpy(result, xmls, strlen(xmls));
	} else {
		memmove(result + strlen("<html>"), result, strlen(result) + 1);
		memcpy(result, "<html>", strlen("<html>"));
	}
	strcat(result, "</html>");

	/* Zamień <br> na <x/>, żeby parser się nie wywalił. */

	while ((tmp = strstr(result, "<br>")) != NULL)
		memcpy(tmp, "<x/>", 4);

	/* Zamień <img ...> na <xx .../>, żeby parser się nie wywalił. */

	while ((tmp = strstr(result, "<img ")) != NULL) {
		memcpy(tmp + 1, "xx", 2);
		memmove(tmp + 3, tmp + 4, 25);
		tmp[27] = '/';
	}

	/* Parsuj! */

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

static void test_html_to_text(const char *input, const char *output,
	const unsigned char *attr, size_t attr_len, gg_encoding_t encoding)
{
	char *result;
	unsigned char *formats;
	size_t len, fmt_len, fmt_len2, i;
	int formats_match = 0;

	len = gg_message_html_to_text(NULL, NULL, &fmt_len, input, encoding);

	result = malloc(len + 1);

	if (result == NULL) {
		perror("gg_message_html_to_text");
		exit(1);
	}

	formats = malloc(fmt_len);

	if (formats == NULL) {
		perror("gg_message_html_to_text");
		free(result);
		exit(1);
	}

	gg_message_html_to_text(result, formats, &fmt_len2, input, encoding);

	if (fmt_len2 != fmt_len) {
		printf("different format_length computed, first: %lu, "
			"second: %lu\n", (long unsigned int) fmt_len,
			(long unsigned int) fmt_len2);
		free(result);
		free(formats);
		exit(1);
	}

	printf("html: \"%s\"\n", input);
	printf("output: \"%s\"\n", result);

	if (strcmp(result, output) != 0) {
		printf("expected: \"%s\"\n", output);
		free(result);
		free(formats);
		exit(1);
	}

	printf("format attributes:");
	for (i = 0; i < fmt_len; i++)
		printf(" %02x", (unsigned int) formats[i]);
	printf("\n");

	if (attr_len == fmt_len) {
		if (memcmp(attr, formats, fmt_len) == 0)
			formats_match = 1;
	}

	if (!formats_match) {
		/* Zachowaj tę samą długość, co "format attributes" */
		printf("expected\t :");
		for (i = 0; i < attr_len; i++)
			printf(" %02x", (unsigned int) attr[i]);
		printf("\n");
		free(result);
		free(formats);
		exit(1);
	}

	printf("correct\n\n");
	free(result);
	free(formats);
}

int main(int argc, char **argv)
{
	size_t i;

	for (i = 0; i < sizeof(text_to_html) / sizeof(text_to_html[0]); i++) {
		test_text_to_html(text_to_html[i].src,
			(const unsigned char*) text_to_html[i].attr,
			text_to_html[i].attr_len, text_to_html[i].dst,
			text_to_html[i].encoding);
	}

	for (i = 0; i < sizeof(html_to_text) / sizeof(html_to_text[0]); i++) {
		test_html_to_text(html_to_text[i].src, html_to_text[i].dst,
			(const unsigned char*) html_to_text[i].attr,
			html_to_text[i].attr_len, html_to_text[i].encoding);
	}

	return 0;
}
