#include "message.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>

gg_message_t *gg_message_new(void)
{
	gg_message_t *gm;

	gm = malloc(sizeof(gg_message_t));

	if (gm == NULL)
		return NULL;

	memset(gm, 0, sizeof(gg_message_t));

	gm->seq = (uint32_t) -1;

	return gm;
}

int gg_message_init(gg_message_t *gm, int msgclass, int seq, uin_t *recipients, int recipient_count, char *text, char *html, char *attributes, size_t attributes_length)
{
	GG_MESSAGE_CHECK(gm, -1);

	memset(gm, 0, sizeof(gg_message_t));
	gm->recipients = recipients;
	gm->recipient_count = recipient_count;
	gm->text = text;
	gm->html = html;
	gm->attributes = attributes;
	gm->attributes_length = attributes_length;
	gm->msgclass = msgclass;
	gm->seq = seq;

	return 0;
}

void gg_message_free(gg_message_t *gm)
{
	if (gm == NULL) {
		errno = EINVAL;
		return;
	}	

	free(gm->recipients);

	free(gm);
}

int gg_message_set_recipients(gg_message_t *gm, const uin_t *recipients, unsigned int recipient_count)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (recipient_count >= INT_MAX / sizeof(uin_t)) {
		errno = EINVAL;
		return -1;
	}	

	if ((recipients == NULL) || (recipient_count == 0)) {
		free(gm->recipients);
		gm->recipients = NULL;
		gm->recipient_count = 0;
	} else {
		uin_t *tmp;

		tmp = realloc(gm->recipients, recipient_count * sizeof(uin_t));

		if (tmp == NULL)
			return -1;

		memcpy(tmp, recipients, recipient_count * sizeof(uin_t));

		gm->recipients = tmp;
		gm->recipient_count = recipient_count;
	}
	
	return 0;
}

int gg_message_set_recipient(gg_message_t *gm, uin_t recipient)
{
	return gg_message_set_recipients(gm, &recipient, 1);
}

int gg_message_get_recipients(gg_message_t *gm, const uin_t **recipients, unsigned int *recipient_count)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (recipients != NULL)
		*recipients = gm->recipients;

	if (recipient_count != NULL)
		*recipient_count = gm->recipient_count;

	return 0;
}

uin_t gg_message_recipient(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, (uin_t) -1);

	if ((gm->recipients == NULL) || (gm->recipient_count < 1)) {
		// errno = XXX;
		return (uin_t) -1;
	}

	return gm->recipients[0];
}

int gg_message_set_class(gg_message_t *gm, uint32_t msgclass)
{
	GG_MESSAGE_CHECK(gm, -1);

	gm->msgclass = msgclass;

	return 0;
}

uint32_t gg_message_get_class(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, (uint32_t) -1);

	return gm->msgclass;
}

int gg_message_set_seq(gg_message_t *gm, uint32_t seq)
{
	GG_MESSAGE_CHECK(gm, -1);

	gm->seq = seq;

	return 0;
}

uint32_t gg_message_get_seq(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, (uint32_t) -1);

	return gm->seq;
}

int gg_message_set_text(gg_message_t *gm, const char *text)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (text == NULL) {
		free(gm->text);
		gm->text = NULL;
	} else {
		char *tmp;

		tmp = strdup(text);

		if (tmp == NULL)
			return -1;

		free(gm->text);
		gm->text = tmp;
	}

	return 0;
}

const char *gg_message_get_text(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, NULL);

	return gm->text;
}

int gg_message_set_html(gg_message_t *gm, const char *html)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (html == NULL) {
		free(gm->html);
		gm->html = NULL;
	} else {
		char *tmp;

		tmp = strdup(html);

		if (tmp == NULL)
			return -1;

		free(gm->html);
		gm->html = tmp;
	}

	return 0;
}

const char *gg_message_get_html(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, NULL);

	return gm->html;
}

int gg_message_set_attributes(gg_message_t *gm, const char *attributes, size_t length)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (length > 0xfffd) {
		// errno = XXX;
		return -1;
	}

	if ((attributes == NULL) || (length == 0)) {
		free(gm->attributes);
		gm->attributes = NULL;
		gm->attributes_length = 0;
	} else {
		char *tmp;

		tmp = realloc(gm->attributes, length);

		if (tmp == NULL)
			return -1;

		gm->attributes = tmp;
		gm->attributes_length = length;
	}

	return 0;
}

int gg_message_get_attributes(gg_message_t *gm, const char **attributes, size_t *attributes_length)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (attributes != NULL)
		*attributes = gm->attributes;

	if (attributes_length != NULL)
		*attributes_length = gm->attributes_length;

	return 0;
}

/**
 * \brief Zamienia HTML na czysty tekst.
 *
 * \param html Kod źrodłowy
 *
 * \note Funkcja służy do zachowania kompatybilności przy przesyłaniu
 * wiadomości HTML do klientów, które tego formatu nie obsługują. Z tego
 * powodu funkcja nie zachowuje formatowania, a jedynie usuwa tagi i
 * zamienia podstawowe encje na ich odpowiedniki ASCII.
 *
 * \return Zaalokowany bufor z czystym tekstem.
 */
char *gg_message_html_to_text(const char *html)
{
	const char *src, *entity, *tag;
	char *result, *dst;
	size_t len;
	int in_tag, in_entity;

	len = 0;
	in_tag = 0;
	tag = NULL;
	in_entity = 0;
	entity = NULL;

	for (src = html; *src != 0; src++) {
		if (*src == '<') {
			tag = src;
			in_tag = 1;
			continue;
		}

		if (in_tag && (*src == '>')) {
			if (strncmp(tag, "<br", 4) == 0)
				len += 2;
			in_tag = 0;
			continue;
		}

		if (in_tag)
			continue;

		if (*src == '&') {
			in_entity = 1;
			continue;
		}

		if (in_entity && *src == ';') {
			in_entity = 0;
			len++;
			continue;
		}

		if (in_entity && !(isalnum(*src) || *src == '#'))
			in_entity = 0;

		if (in_entity)
			continue;

		len++;
	}

	result = malloc(len + 1);

	if (result == NULL)
		return NULL;

	dst = result;
	in_tag = 0;
	tag = NULL;
	in_entity = 0;
	entity = NULL;

	for (src = html; *src != 0; src++) {
		if (*src == '<') {
			tag = src;
			in_tag = 1;
			continue;
		}

		if (in_tag && (*src == '>')) {
			if (strncmp(tag, "<br", 3) == 0) {
				*dst++ = '\r';
				*dst++ = '\n';
			}
			in_tag = 0;
			continue;
		}

		if (in_tag)
			continue;

		if (*src == '&') {
			in_entity = 1;
			entity = src;
			continue;
		}

		if (in_entity && *src == ';') {
			in_entity = 0;
			if (strncmp(entity, "&lt;", 4) == 0)
				*dst = '<';
			else if (strncmp(entity, "&gt;", 4) == 0)
				*dst = '>';
			else if (strncmp(entity, "&quot;", 6) == 0)
				*dst = '"';
			else if (strncmp(entity, "&apos;", 6) == 0)
				*dst = '\'';
			else if (strncmp(entity, "&amp;", 5) == 0)
				*dst = '&';
			else
				*dst = '?';
			dst++;
			continue;
		}

		if (in_entity && !(isalnum(*src) || *src == '#'))
			in_entity = 0;

		if (in_entity)
			continue;

		*dst++ = *src;
	}

	*dst = 0;

	return result;
}

/** Domyślny początek kodu HTML przy braku atrybutów. */
static const char *gg_message_html_default_prefix = "<span style=\"color:#000000; font-family:'MS Shell Dlg 2'; font-size:9pt; \">";

/** Domyślny koniec kodu HTML przy braku atrybutów. */
static const char *gg_message_html_default_suffix = "</span>";

/**
 * \brief Zamienia czysty tekst z atrybutami na HTML.
 *
 * \param text Treść wiadomości
 * \param attributes Atrybuty wiadomości
 * \param attributes_length Długość bloku atrybutów
 *
 * \note Wynikowy tekst nie jest idealnym kodem HTML, ponieważ ma jak
 * dokładniej odzwierciedlać to, co wygenerowałby oryginalny klient.
 *
 * \warning Obecnie funkcja ignoruje atrybuty tekstu.
 *
 * \return Zaalokowany bufor z tekstem w formacie HTML.
 */
char *gg_message_text_to_html(const char *text, const char *attributes, size_t attributes_length)
{
/*
	const char *src;
	char *result, *dst;
	size_t len, src_ofs, attr_ofs;
	uint8_t attr_last;

	len = 0;
	attr_ofs = 0;
	src_ofs = 0;

	for (src = text; *src != 0; src++, src_ofs++) {
		while ((attr_ofs < attributes_length) && (attributes_length - attr_ofs >= 3)) {
			uint16_t ofs;
			uint8_t attr;

			ofs = (uint16_t) attributes[attr_ofs];
			ofs |= ((uint16_t) attributes[attr_ofs + 1]) << 8;
			attr = (uint8_t) attributes[attr_ofs + 2];

			if (src_ofs != ofs)
				break;

			if (attr & GG_FONT_BOLD) {
				// ...
			}
			if (attr & GG_FONT_ITALIC) {
				// ...
			}
			if (attr & GG_FONT_UNDERLINE) {
				// ...
			}
			if (attr & GG_FONT_COLOR) {
				// ...
				attr_ofs += 3;
			}
			if (attr & GG_FONT_IMAGE) {
				// ...
				attr_ofs += (uint8_t) attributes[attr_ofs + 3] + 1;
				// <img src="12345678">
				len += 32;
			}

			attr_ofs += 3;
		}

		if (*src == '\r')
			continue;

		if (*src == '\n') {
			len += 4;
			continue;
		}

		len++;
	}

	result = malloc(len + 1);

	if (result == NULL)
		return NULL;

	dst = result;

	// ...

	*dst = 0;

	return result;
*/
	const char *src;
	char *result, *dst;
	size_t len;

	len = strlen(gg_message_html_default_prefix) + strlen(gg_message_html_default_suffix);

	for (src = text; *src != 0; src++) {
		if (*src == '<')
			len += 4;
		else if (*src == '>')
			len += 4;
		else if (*src == '"')
			len += 6;
		else if (*src == '\'')
			len += 6;
		else if (*src == '&')
			len += 5;
		if (*src == '\n')
			len += 4;
		if (*src != '\r')
			len++;
	}
	
	result = malloc(len + 1);

	if (result == NULL)
		return NULL;

	dst = result;

	memcpy(dst, gg_message_html_default_prefix, strlen(gg_message_html_default_prefix));
	dst += strlen(gg_message_html_default_prefix);

	for (src = text; *src != 0; src++) {
		if (*src == '<') {
			memcpy(dst, "&lt;", 4);
			dst += 4;
		} else if (*src == '>') {
			memcpy(dst, "&gt;", 4);
			dst += 4;
		} else if (*src == '"') {
			memcpy(dst, "&quot;", 6);
			dst += 6;
		} else if (*src == '\'') {
			memcpy(dst, "&apos;", 6);
			dst += 6;
		} else if (*src == '&') {
			memcpy(dst, "&amp;", 5);
			dst += 5;
		} else if (*src == '\n') {
			memcpy(dst, "<br>", 4);
			dst += 4;
		} else if (*src != '\r') {
			*dst++ = *src;
		}
	}

	memcpy(dst, gg_message_html_default_suffix, strlen(gg_message_html_default_suffix));
	dst += strlen(gg_message_html_default_suffix);

	*dst = 0;

	return result;
}
