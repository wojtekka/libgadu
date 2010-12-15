/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Robert J. Woźny <speedy@ziew.org>
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

/*
 * Funkcje konwersji między UTF-8 i CP1250 są oparte o kod biblioteki iconv.
 * Informacje o prawach autorskich oryginalnego kodu zamieszczono poniżej:
 *
 * Copyright (C) 1999-2001, 2004 Free Software Foundation, Inc.
 * This file is part of the GNU LIBICONV Library.
 *
 * The GNU LIBICONV Library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * The GNU LIBICONV Library is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the GNU LIBICONV Library; see the file COPYING.LIB.
 * If not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * \file common.c
 *
 * \brief Funkcje wykorzystywane przez różne moduły biblioteki
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef sun
#  include <sys/filio.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libgadu.h"
#include "internal.h"

/**
 * \internal Odpowiednik funkcji \c vsprintf alokujący miejsce na wynik.
 *
 * Funkcja korzysta z funkcji \c vsnprintf, sprawdzając czy dostępna funkcja
 * systemowa jest zgodna ze standardem C99 czy wcześniejszymi.
 *
 * \param format Format wiadomości (zgodny z \c printf)
 * \param ap Lista argumentów (zgodna z \c printf)
 *
 * \return Zaalokowany bufor lub NULL, jeśli zabrakło pamięci.
 *
 * \ingroup helper
 */
char *gg_vsaprintf(const char *format, va_list ap)
{
	int size = 0;
	char *buf = NULL;

#ifdef GG_CONFIG_HAVE_VA_COPY
	va_list aq;

	va_copy(aq, ap);
#else
#  ifdef GG_CONFIG_HAVE___VA_COPY
	va_list aq;

	__va_copy(aq, ap);
#  endif
#endif

#ifndef GG_CONFIG_HAVE_C99_VSNPRINTF
	{
		int res;
		char *tmp;

		size = 128;
		do {
			size *= 2;
			if (!(tmp = realloc(buf, size))) {
				free(buf);
				return NULL;
			}
			buf = tmp;
			res = vsnprintf(buf, size, format, ap);
		} while (res == size - 1 || res == -1);
	}
#else
	{
		char tmp[2];

		/* libce Solarisa przy buforze NULL zawsze zwracają -1, więc
		 * musimy podać coś istniejącego jako cel printf()owania. */
		size = vsnprintf(tmp, sizeof(tmp), format, ap);
		if (!(buf = malloc(size + 1)))
			return NULL;
	}
#endif

#ifdef GG_CONFIG_HAVE_VA_COPY
	vsnprintf(buf, size + 1, format, aq);
	va_end(aq);
#else
#  ifdef GG_CONFIG_HAVE___VA_COPY
	vsnprintf(buf, size + 1, format, aq);
	va_end(aq);
#  else
	vsnprintf(buf, size + 1, format, ap);
#  endif
#endif

	return buf;
}

/**
 * \internal Odpowiednik funkcji \c sprintf alokujący miejsce na wynik.
 *
 * Funkcja korzysta z funkcji \c vsnprintf, sprawdzając czy dostępna funkcja
 * systemowa jest zgodna ze standardem C99 czy wcześniejszymi.
 *
 * \param format Format wiadomości (zgodny z \c printf)
 *
 * \return Zaalokowany bufor lub NULL, jeśli zabrakło pamięci.
 *
 * \ingroup helper
 */
char *gg_saprintf(const char *format, ...)
{
	va_list ap;
	char *res;

	va_start(ap, format);
	res = gg_vsaprintf(format, ap);
	va_end(ap);

	return res;
}

/**
 * \internal Pobiera linię tekstu z bufora.
 *
 * Funkcja niszczy bufor źródłowy bezpowrotnie, dzieląc go na kolejne ciągi
 * znaków i obcina znaki końca linii.
 *
 * \param ptr Wskaźnik do zmiennej, która przechowuje aktualne położenie
 *            w analizowanym buforze
 *
 * \return Wskaźnik do kolejnej linii tekstu lub NULL, jeśli to już koniec
 *         bufora.
 */
char *gg_get_line(char **ptr)
{
	char *foo, *res;

	if (!ptr || !*ptr || !strcmp(*ptr, ""))
		return NULL;

	res = *ptr;

	if (!(foo = strchr(*ptr, '\n')))
		*ptr += strlen(*ptr);
	else {
		size_t len;
		*ptr = foo + 1;
		*foo = 0;

		len = strlen(res);

		if (len > 1 && res[len - 1] == '\r')
			res[len - 1] = 0;
	}

	return res;
}

/**
 * \internal Czyta linię tekstu z gniazda.
 *
 * Funkcja czyta tekst znak po znaku, więc nie jest efektywna, ale dzięki
 * brakowi buforowania, nie koliduje z innymi funkcjami odczytu.
 *
 * \param sock Deskryptor gniazda
 * \param buf Wskaźnik do bufora
 * \param length Długość bufora
 *
 * \return Zwraca \c buf jeśli się powiodło, lub \c NULL w przypadku błędu.
 */
char *gg_read_line(int sock, char *buf, int length)
{
	int ret;

	if (!buf || length < 0)
		return NULL;

	for (; length > 1; buf++, length--) {
		do {
			if ((ret = read(sock, buf, 1)) == -1 && errno != EINTR && errno != EAGAIN) {
				gg_debug(GG_DEBUG_MISC, "// gg_read_line() error on read (errno=%d, %s)\n", errno, strerror(errno));
				*buf = 0;
				return NULL;
			} else if (ret == 0) {
				gg_debug(GG_DEBUG_MISC, "// gg_read_line() eof reached\n");
				*buf = 0;
				return NULL;
			}
		} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

		if (*buf == '\n') {
			buf++;
			break;
		}
	}

	*buf = 0;
	return buf;
}

/**
 * \internal Nawiązuje połączenie TCP.
 *
 * \param addr Wskaźnik na strukturę \c in_addr z adresem serwera
 * \param port Port serwera
 * \param async Flaga asynchronicznego połączenia
 *
 * \return Deskryptor gniazda lub -1 w przypadku błędu
 *
 * \ingroup helper
 */
int gg_connect(void *addr, int port, int async)
{
	int sock, one = 1, errno2;
	struct sockaddr_in sin;
	struct in_addr *a = addr;
	struct sockaddr_in myaddr;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_connect(%s, %d, %d);\n", inet_ntoa(*a), port, async);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_connect() socket() failed (errno=%d, %s)\n", errno, strerror(errno));
		return -1;
	}

	memset(&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;

	myaddr.sin_addr.s_addr = gg_local_ip;

	if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_connect() bind() failed (errno=%d, %s)\n", errno, strerror(errno));
		errno2 = errno;
		close(sock);
		errno = errno2;
		return -1;
	}

	if (async) {
#ifdef FIONBIO
		if (ioctl(sock, FIONBIO, &one) == -1) {
#else
		if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
#endif
			gg_debug(GG_DEBUG_MISC, "// gg_connect() ioctl() failed (errno=%d, %s)\n", errno, strerror(errno));
			errno2 = errno;
			close(sock);
			errno = errno2;
			return -1;
		}
	}

	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = a->s_addr;

	if (connect(sock, (struct sockaddr*) &sin, sizeof(sin)) == -1) {
		if (errno && (!async || errno != EINPROGRESS)) {
			gg_debug(GG_DEBUG_MISC, "// gg_connect() connect() failed (errno=%d, %s)\n", errno, strerror(errno));
			errno2 = errno;
			close(sock);
			errno = errno2;
			return -1;
		}
		gg_debug(GG_DEBUG_MISC, "// gg_connect() connect() in progress\n");
	}

	return sock;
}

/**
 * \internal Usuwa znaki końca linii.
 *
 * Funkcja działa bezpośrednio na buforze.
 *
 * \param line Bufor z tekstem
 *
 * \ingroup helper
 */
void gg_chomp(char *line)
{
	int len;

	if (!line)
		return;

	len = strlen(line);

	if (len > 0 && line[len - 1] == '\n')
		line[--len] = 0;
	if (len > 0 && line[len - 1] == '\r')
		line[--len] = 0;
}

/**
 * \internal Koduje ciąg znaków do postacji adresu HTTP.
 *
 * Zamienia znaki niedrukowalne, spoza ASCII i mające specjalne znaczenie
 * dla protokołu HTTP na encje postaci \c %XX, gdzie \c XX jest szesnastkową
 * wartością znaku.
 * 
 * \param str Ciąg znaków do zakodowania
 *
 * \return Zaalokowany bufor lub \c NULL w przypadku błędu.
 *
 * \ingroup helper
 */
char *gg_urlencode(const char *str)
{
	char *q, *buf, hex[] = "0123456789abcdef";
	const char *p;
	unsigned int size = 0;

	if (!str)
		str = "";

	for (p = str; *p; p++, size++) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == ' ') || (*p == '@') || (*p == '.') || (*p == '-'))
			size += 2;
	}

	if (!(buf = malloc(size + 1)))
		return NULL;

	for (p = str, q = buf; *p; p++, q++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || (*p == '@') || (*p == '.') || (*p == '-'))
			*q = *p;
		else {
			if (*p == ' ')
				*q = '+';
			else {
				*q++ = '%';
				*q++ = hex[*p >> 4 & 15];
				*q = hex[*p & 15];
			}
		}
	}

	*q = 0;

	return buf;
}

/**
 * \internal Wyznacza skrót dla usług HTTP.
 *
 * Funkcja jest wykorzystywana do wyznaczania skrótu adresu e-mail, hasła
 * i innych wartości przekazywanych jako parametry usług HTTP.
 *
 * W parametrze \c format należy umieścić znaki określające postać kolejnych
 * parametrów: \c 's' jeśli parametr jest ciągiem znaków, \c 'u' jeśli jest
 * liczbą.
 *
 * \param format Format kolejnych parametrów (niezgodny z \c printf)
 *
 * \return Wartość skrótu
 */
int gg_http_hash(const char *format, ...)
{
	unsigned int a, c, i, j;
	va_list ap;
	int b = -1;

	va_start(ap, format);

	for (j = 0; j < strlen(format); j++) {
		char *arg, buf[16];

		if (format[j] == 'u') {
			snprintf(buf, sizeof(buf), "%d", va_arg(ap, uin_t));
			arg = buf;
		} else {
			if (!(arg = va_arg(ap, char*)))
				arg = "";
		}

		i = 0;
		while ((c = (unsigned char) arg[i++]) != 0) {
			a = (c ^ b) + (c << 8);
			b = (a >> 24) | (a << 8);
		}
	}

	va_end(ap);

	return (b < 0 ? -b : b);
}

/**
 * \internal Zestaw znaków kodowania base64.
 */
static char gg_base64_charset[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * \internal Koduje ciąg znaków do base64.
 *
 * Wynik funkcji należy zwolnić za pomocą \c free.
 *
 * \param buf Bufor z danami do zakodowania
 *
 * \return Zaalokowany bufor z zakodowanymi danymi
 *
 * \ingroup helper
 */
char *gg_base64_encode(const char *buf)
{
	char *out, *res;
	unsigned int i = 0, j = 0, k = 0, len = strlen(buf);

	res = out = malloc((len / 3 + 1) * 4 + 2);

	if (!res)
		return NULL;

	while (j <= len) {
		switch (i % 4) {
			case 0:
				k = (buf[j] & 252) >> 2;
				break;
			case 1:
				if (j < len)
					k = ((buf[j] & 3) << 4) | ((buf[j + 1] & 240) >> 4);
				else
					k = (buf[j] & 3) << 4;

				j++;
				break;
			case 2:
				if (j < len)
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
 * \internal Dekoduje ciąg znaków zapisany w base64.
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

/**
 * \internal Tworzy nagłówek autoryzacji serwera pośredniczącego.
 *
 * Dane pobiera ze zmiennych globalnych \c gg_proxy_username i
 * \c gg_proxy_password.
 *
 * \return Zaalokowany bufor z tekstem lub NULL, jeśli serwer pośredniczący
 *         nie jest używany lub nie wymaga autoryzacji.
 */
char *gg_proxy_auth()
{
	char *tmp, *enc, *out;
	unsigned int tmp_size;

	if (!gg_proxy_enabled || !gg_proxy_username || !gg_proxy_password)
		return NULL;

	if (!(tmp = malloc((tmp_size = strlen(gg_proxy_username) + strlen(gg_proxy_password) + 2))))
		return NULL;

	snprintf(tmp, tmp_size, "%s:%s", gg_proxy_username, gg_proxy_password);

	if (!(enc = gg_base64_encode(tmp))) {
		free(tmp);
		return NULL;
	}

	free(tmp);

	if (!(out = malloc(strlen(enc) + 40))) {
		free(enc);
		return NULL;
	}

	snprintf(out, strlen(enc) + 40,  "Proxy-Authorization: Basic %s\r\n", enc);

	free(enc);

	return out;
}

/**
 * \internal Tablica pomocnicza do wyznaczania sumy kontrolnej.
 */
static uint32_t gg_crc32_table[256];

/**
 * \internal Flaga wypełnienia tablicy pomocniczej do wyznaczania sumy
 * kontrolnej.
 */
static int gg_crc32_initialized = 0;

/**
 * \internal Tworzy tablicę pomocniczą do wyznaczania sumy kontrolnej.
 */
static void gg_crc32_make_table(void)
{
	uint32_t h = 1;
	unsigned int i, j;

	memset(gg_crc32_table, 0, sizeof(gg_crc32_table));

	for (i = 128; i; i >>= 1) {
		h = (h >> 1) ^ ((h & 1) ? 0xedb88320L : 0);

		for (j = 0; j < 256; j += 2 * i)
			gg_crc32_table[i + j] = gg_crc32_table[j] ^ h;
	}

	gg_crc32_initialized = 1;
}

/**
 * Wyznacza sumę kontrolną CRC32.
 *
 * \param crc Suma kontrola poprzedniego bloku danych lub 0 jeśli liczona
 *            jest suma kontrolna pierwszego bloku
 * \param buf Bufor danych
 * \param len Długość bufora danych
 *
 * \return Suma kontrolna.
 */
uint32_t gg_crc32(uint32_t crc, const unsigned char *buf, int len)
{
	if (!gg_crc32_initialized)
		gg_crc32_make_table();

	if (!buf || len < 0)
		return crc;

	crc ^= 0xffffffffL;

	while (len--)
		crc = (crc >> 8) ^ gg_crc32_table[(crc ^ *buf++) & 0xff];

	return crc ^ 0xffffffffL;
}

/*
 * Local variables:
 * c-indentation-style: k&r
 * c-basic-offset: 8
 * indent-tabs-mode: notnil
 * End:
 *
 * vim: shiftwidth=8:
 */
