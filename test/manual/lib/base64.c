/*
 *  (C) Copyright 2008 Wojtek Kaniewski <wojtekka@irc.pl>
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

#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "config.h"

#ifdef HAVE_OPENSSL

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char *gg_base64_encode(const char *input, ssize_t len)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	char *buf;

	if (len == -1)
		len = strlen(input);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	buf = malloc(bptr->length);
	memcpy(buf, bptr->data, bptr->length - 1);
	buf[bptr->length - 1] = 0;

	BIO_free_all(b64);

	return buf;
}

#else /* HAVE_OPENSSL */

/**
 * \internal Zestaw znaków kodowania base64.
 */
static char gg_base64_charset[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Koduje ciąg znaków do base64.
 *
 * Wynik funkcji należy zwolnić za pomocą \c free.
 *
 * \param buf Bufor z danami do zakodowania
 * \param len Rozmiar bufora lub -1 jesli to zwykly string
 *
 * \return Zaalokowany bufor z zakodowanymi danymi
 *
 * \ingroup helper
 */
char *gg_base64_encode2(const char *buf, ssize_t len)
{
	char *out, *res;
	unsigned int i = 0, j = 0, k = 0;

	if (len == -1)
		len = strlen(buf);

	res = out = malloc((len / 3 + 1) * 4 + 2);

	if (!res)
		return NULL;

	while (j < (size_t)len) {
		switch (i % 4) {
			case 0:
				k = (buf[j] & 252) >> 2;
				break;
			case 1:
				if (j+1 < (size_t)len)
					k = ((buf[j] & 3) << 4) | ((buf[j + 1] & 240) >> 4);
				else
					k = (buf[j] & 3) << 4;

				j++;
				break;
			case 2:
				if (j+1 < (size_t)len)
					k = ((buf[j] & 15) << 2) | ((buf[j + 1] & 192) >> 6);
				else
					k = (buf[j] & 15) << 2;

				j++;
				break;
			case 3:
				k = buf[j++] & 63;
				break;
		}
		*out++ = gg_base64_charset[k];
		i++;
	}

	if (i % 4)
		for (j = 0; j < 4 - (i % 4); j++, out++)
			*out = '=';

	*out = 0;

	return res;
}

/**
 * Dekoduje ciąg znaków zapisany w base64.
 *
 * Wynik funkcji należy zwolnić za pomocą \c free.
 *
 * \param buf Bufor źródłowy z danymi do zdekodowania
 *
 * \return Zaalokowany bufor ze zdekodowanymi danymi
 *
 * \ingroup helper
 */
char *gg_base64_decode(const char *buf)
{
	char *res, *save, *foo, val;
	const char *end;
	unsigned int index = 0;

	if (!buf)
		return NULL;

	save = res = calloc(1, (strlen(buf) / 4 + 1) * 3 + 2);

	if (!save)
		return NULL;

	end = buf + strlen(buf);

	while (*buf && buf < end) {
		if (*buf == '\r' || *buf == '\n') {
			buf++;
			continue;
		}
		if (!(foo = strchr(gg_base64_charset, *buf)))
			foo = gg_base64_charset;
		val = (int)(foo - gg_base64_charset);
		buf++;
		switch (index) {
			case 0:
				*res |= val << 2;
				break;
			case 1:
				*res++ |= val >> 4;
				*res |= val << 4;
				break;
			case 2:
				*res++ |= val >> 2;
				*res |= val << 6;
				break;
			case 3:
				*res++ |= val;
				break;
		}
		index++;
		index %= 4;
	}
	*res = 0;

	return save;
}

#endif /* HAVE_OPENSSL */
