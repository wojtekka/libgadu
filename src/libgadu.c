/* $Id$ */

/*
 *  (C) Copyright 2001-2006 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Robert J. Woźny <speedy@ziew.org>
 *                          Arkadiusz Miśkiewicz <arekm@pld-linux.org>
 *                          Tomasz Chiliński <chilek@chilan.com>
 *                          Adam Wysocki <gophi@ekg.chmurka.net>
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

/**
 * \file libgadu.c
 *
 * \brief Główny moduł biblioteki
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef sun
#  include <sys/filio.h>
#endif

#include "compat.h"
#include "libgadu.h"
#include "resolver.h"
#include "message.h"
#include "session.h"

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifdef GG_CONFIG_HAVE_OPENSSL
#  include <openssl/err.h>
#  include <openssl/rand.h>
#endif

/**
 * Poziom rejestracji informacji odpluskwiających. Zmienna jest maską bitową
 * składającą się ze stałych \c GG_DEBUG_...
 *
 * \ingroup debug
 */
int gg_debug_level = 0;

/**
 * Funkcja, do której są przekazywane informacje odpluskwiające. Jeśli zarówno
 * ten \c gg_debug_handler, jak i \c gg_debug_handler_session, są równe
 * \c NULL, informacje są wysyłane do standardowego wyjścia błędu (\c stderr).
 *
 * \param level Poziom rejestracji
 * \param format Format wiadomości (zgodny z \c printf)
 * \param ap Lista argumentów (zgodna z \c printf)
 *
 * \note Funkcja jest przesłaniana przez \c gg_debug_handler_session.
 *
 * \ingroup debug
 */
void (*gg_debug_handler)(int level, const char *format, va_list ap) = NULL;

/**
 * Funkcja, do której są przekazywane informacje odpluskwiające. Jeśli zarówno
 * ten \c gg_debug_handler, jak i \c gg_debug_handler_session, są równe
 * \c NULL, informacje są wysyłane do standardowego wyjścia błędu.
 *
 * \param sess Sesja której dotyczy informacja lub \c NULL
 * \param level Poziom rejestracji
 * \param format Format wiadomości (zgodny z \c printf)
 * \param ap Lista argumentów (zgodna z \c printf)
 *
 * \note Funkcja przesłania przez \c gg_debug_handler_session.
 *
 * \ingroup debug
 */
void (*gg_debug_handler_session)(struct gg_session *sess, int level, const char *format, va_list ap) = NULL;

/**
 * Port gniazda nasłuchującego dla połączeń bezpośrednich.
 * 
 * \ingroup ip
 */
int gg_dcc_port = 0;

/**
 * Adres IP gniazda nasłuchującego dla połączeń bezpośrednich.
 *
 * \ingroup ip
 */
unsigned long gg_dcc_ip = 0;

/**
 * Adres lokalnego interfejsu IP, z którego wywoływane są wszystkie połączenia.
 *
 * \ingroup ip
 */
unsigned long gg_local_ip = 0;

/**
 * Flaga włączenia połączeń przez serwer pośredniczący.
 *
 * \ingroup proxy
 */
int gg_proxy_enabled = 0;

/**
 * Adres serwera pośredniczącego.
 *
 * \ingroup proxy
 */
char *gg_proxy_host = NULL;

/**
 * Port serwera pośredniczącego.
 *
 * \ingroup proxy
 */
int gg_proxy_port = 0;

/**
 * Flaga używania serwera pośredniczącego jedynie dla usług HTTP.
 *
 * \ingroup proxy
 */
int gg_proxy_http_only = 0;

/**
 * Nazwa użytkownika do autoryzacji serwera pośredniczącego.
 *
 * \ingroup proxy
 */
char *gg_proxy_username = NULL;

/**
 * Hasło użytkownika do autoryzacji serwera pośredniczącego.
 *
 * \ingroup proxy
 */
char *gg_proxy_password = NULL;

#ifndef DOXYGEN

#ifndef lint
static char rcsid[]
#ifdef __GNUC__
__attribute__ ((unused))
#endif
= "$Id$";
#endif

#endif /* DOXYGEN */

/**
 * Zwraca wersję biblioteki.
 *
 * \return Wskaźnik na statyczny bufor z wersją biblioteki.
 *
 * \ingroup version
 */
const char *gg_libgadu_version()
{
	return GG_LIBGADU_VERSION;
}

/**
 * Zamienia kolejność bajtów w 32-bitowym słowie.
 *
 * Ze względu na little-endianowość protokołu Gadu-Gadu, na maszynach
 * big-endianowych odwraca kolejność bajtów w słowie.
 *
 * \param x Liczba do zamiany
 *
 * \return Liczba z odpowiednią kolejnością bajtów
 *
 * \ingroup helper
 */
uint32_t gg_fix32(uint32_t x)
{
#ifndef GG_CONFIG_BIGENDIAN
	return x;
#else
	return (uint32_t)
		(((x & (uint32_t) 0x000000ffU) << 24) |
		((x & (uint32_t) 0x0000ff00U) << 8) |
		((x & (uint32_t) 0x00ff0000U) >> 8) |
		((x & (uint32_t) 0xff000000U) >> 24));
#endif
}

/**
 * Zamienia kolejność bajtów w 16-bitowym słowie.
 *
 * Ze względu na little-endianowość protokołu Gadu-Gadu, na maszynach
 * big-endianowych zamienia kolejność bajtów w słowie.
 *
 * \param x Liczba do zamiany
 *
 * \return Liczba z odpowiednią kolejnością bajtów
 *
 * \ingroup helper
 */
uint16_t gg_fix16(uint16_t x)
{
#ifndef GG_CONFIG_BIGENDIAN
	return x;
#else
	return (uint16_t)
		(((x & (uint16_t) 0x00ffU) << 8) |
		((x & (uint16_t) 0xff00U) >> 8));
#endif
}

/**
 * \internal Liczy skrót z hasła i ziarna.
 *
 * \param password Hasło
 * \param seed Ziarno podane przez serwer
 *
 * \return Wartość skrótu
 */
unsigned int gg_login_hash(const unsigned char *password, unsigned int seed)
{
	unsigned int x, y, z;

	y = seed;

	for (x = 0; *password; password++) {
		x = (x & 0xffffff00) | *password;
		y ^= x;
		y += x;
		x <<= 8;
		y ^= x;
		x <<= 8;
		y -= x;
		x <<= 8;
		y ^= x;

		z = y & 0x1F;
		y = (y << z) | (y >> (32 - z));
	}

	return y;
}

/**
 * \internal Odbiera od serwera dane binarne.
 *
 * Funkcja odbiera dane od serwera zajmując się TLS w razie konieczności.
 *
 * \param sess Struktura sesji
 * \param buf Bufor na danymi
 * \param length Długość bufora
 *
 * \return To samo co funkcja systemowa \c read
 */
int gg_read(struct gg_session *sess, char *buf, int length)
{
	int res;

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl) {
		int err;

		res = SSL_read(sess->ssl, buf, length);

		if (res < 0) {
			err = SSL_get_error(sess->ssl, res);

			if (err == SSL_ERROR_WANT_READ)
				errno = EAGAIN;

			return -1;
		}
	} else
#endif
		res = read(sess->fd, buf, length);

	return res;
}

/**
 * \internal Wysyła do serwera dane binarne.
 *
 * Funkcja wysyła dane do serwera zajmując się TLS w razie konieczności.
 *
 * \param sess Struktura sesji
 * \param buf Bufor z danymi
 * \param length Długość bufora
 *
 * \return To samo co funkcja systemowa \c write
 */
int gg_write(struct gg_session *sess, const char *buf, int length)
{
	int res = 0;

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl) {
		int err;

		res = SSL_write(sess->ssl, buf, length);

		if (res < 0) {
			err = SSL_get_error(sess->ssl, res);

			if (err == SSL_ERROR_WANT_WRITE)
				errno = EAGAIN;

			return -1;
		}
	} else
#endif
	{
		if (!sess->async) {
			int written = 0;

			while (written < length) {
				res = write(sess->fd, buf + written, length - written);

				if (res == -1) {
					if (errno != EINTR)
						break;

					continue;
				}

				written += res;
				res = written;
			}
		} else {
			if (!sess->send_buf)
				res = write(sess->fd, buf, length);
			else
				res = 0;

			if (res == -1) {
				if (errno != EAGAIN)
					return res;

				res = 0;
			}

			if (res < length) {
				char *tmp;

				if (!(tmp = realloc(sess->send_buf, sess->send_left + length - res))) {
					errno = ENOMEM;
					return -1;
				}

				sess->send_buf = tmp;

				memcpy(sess->send_buf + sess->send_left, buf + res, length - res);

				sess->send_left += length - res;
			}
		}
	}

	return res;
}

/**
 * \internal Odbiera pakiet od serwera.
 *
 * Funkcja odczytuje nagłówek pakietu, a następnie jego zawartość i zwraca
 * w zaalokowanym buforze.
 *
 * Przy połączeniach asynchronicznych, funkcja może nie być w stanie
 * skompletować całego pakietu -- w takim przypadku zwróci -1, a kodem błędu
 * będzie \c EAGAIN.
 *
 * \param sess Struktura sesji
 *
 * \return Wskaźnik do zaalokowanego bufora
 */
void *gg_recv_packet(struct gg_session *sess)
{
	struct gg_header h;
	char *buf = NULL;
	int ret = 0;
	unsigned int offset, size = 0;

	// XXX w trybie synchronicznym, gdy sess->timeout != -1, wypadałoby
	// zrobić timeout za pomocą select() albo setsockopt(SO_RCVTIMEO)

	// XXX nagłówek i treść pakietu móżna czytać do jednego bufora, nie
	// ma potrzeby utrzymywać sess->header_buf oraz sess->recv_buf

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_recv_packet(%p);\n", sess);

	if (!sess) {
		errno = EFAULT;
		return NULL;
	}

	if (sess->recv_left < 1) {
		if (sess->header_buf) {
			memcpy(&h, sess->header_buf, sess->header_done);
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv: resuming last read (%d bytes left)\n", sizeof(h) - sess->header_done);
			free(sess->header_buf);
			sess->header_buf = NULL;
		} else
			sess->header_done = 0;

		while (sess->header_done < sizeof(h)) {
			ret = gg_read(sess, (char*) &h + sess->header_done, sizeof(h) - sess->header_done);

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv(%d,%p,%d) = %d\n", sess->fd, &h + sess->header_done, sizeof(h) - sess->header_done, ret);

			if (!ret) {
				errno = ECONNRESET;
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv() failed: connection broken\n");
				return NULL;
			}

			if (ret == -1) {
				if (errno == EINTR) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv() interrupted system call, resuming\n");
					continue;
				}

				if (errno == EAGAIN) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv() incomplete header received\n");

					if (!(sess->header_buf = malloc(sess->header_done))) {
						gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv() not enough memory\n");
						return NULL;
					}

					memcpy(sess->header_buf, &h, sess->header_done);

					errno = EAGAIN;

					return NULL;
				}

				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header recv() failed: errno=%d, %s\n", errno, strerror(errno));

				return NULL;
			}

			sess->header_done += ret;

		}

		h.type = gg_fix32(h.type);
		h.length = gg_fix32(h.length);
	} else
		memcpy(&h, sess->recv_buf, sizeof(h));

	/* jakieś sensowne limity na rozmiar pakietu */
	if (h.length > 65535) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() invalid packet length (%d)\n", h.length);
		errno = ERANGE;
		return NULL;
	}

	if (sess->recv_left > 0) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() resuming last gg_recv_packet()\n");
		size = sess->recv_left;
		offset = sess->recv_done;
		buf = sess->recv_buf;
	} else {
		if (!(buf = malloc(sizeof(h) + h.length + 1))) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() not enough memory for packet data\n");
			return NULL;
		}

		memcpy(buf, &h, sizeof(h));

		offset = 0;
		size = h.length;
	}

	while (size > 0) {
		ret = gg_read(sess, buf + sizeof(h) + offset, size);
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() body recv(%d,%p,%d) = %d\n", sess->fd, buf + sizeof(h) + offset, size, ret);
		if (!ret) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() body recv() failed: connection broken\n");
			errno = ECONNRESET;
			return NULL;
		}
		if (ret > -1 && ret <= size) {
			offset += ret;
			size -= ret;
		} else if (ret == -1) {
			int errno2 = errno;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() body recv() failed (errno=%d, %s)\n", errno, strerror(errno));
			errno = errno2;

			if (errno == EAGAIN) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() %d bytes received, %d left\n", offset, size);
				sess->recv_buf = buf;
				sess->recv_left = size;
				sess->recv_done = offset;
				return NULL;
			}
			if (errno != EINTR) {
				free(buf);
				return NULL;
			}
		}
	}

	sess->recv_left = 0;

	if ((gg_debug_level & GG_DEBUG_DUMP)) {
		gg_debug_session(sess, GG_DEBUG_DUMP, "// gg_recv_packet()\n");
		gg_debug_session_dump(sess, GG_DEBUG_DUMP, buf, sizeof(h) + h.length);
	}

	return buf;
}

/**
 * \internal Wysyła pakiet do serwera.
 *
 * Funkcja konstruuje pakiet do wysłania z dowolnej liczby fragmentów. Jeśli
 * rozmiar pakietu jest za duży, by móc go wysłać za jednym razem, pozostała
 * część zostanie zakolejkowana i wysłana, gdy będzie to możliwe.
 *
 * \param sess Struktura sesji
 * \param type Rodzaj pakietu
 * \param ... Lista kolejnych części pakietu (wskaźnik na bufor i długość
 *            typu \c int) zakończona \c NULL
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
int gg_send_packet(struct gg_session *sess, int type, ...)
{
	struct gg_header *h;
	char *tmp;
	unsigned int tmp_length;
	void *payload;
	unsigned int payload_length;
	va_list ap;
	int res;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_packet(%p, 0x%.2x, ...);\n", sess, type);

	tmp_length = sizeof(struct gg_header);

	if (!(tmp = malloc(tmp_length))) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_send_packet() not enough memory for packet header\n");
		return -1;
	}

	va_start(ap, type);

	payload = va_arg(ap, void *);

	while (payload) {
		char *tmp2;

		payload_length = va_arg(ap, unsigned int);

		if (!(tmp2 = realloc(tmp, tmp_length + payload_length))) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_send_packet() not enough memory for payload\n");
			free(tmp);
			va_end(ap);
			return -1;
		}

		tmp = tmp2;

		memcpy(tmp + tmp_length, payload, payload_length);
		tmp_length += payload_length;

		payload = va_arg(ap, void *);
	}

	va_end(ap);

	h = (struct gg_header*) tmp;
	h->type = gg_fix32(type);
	h->length = gg_fix32(tmp_length - sizeof(struct gg_header));

	if ((gg_debug_level & GG_DEBUG_DUMP)) {
		gg_debug_session(sess, GG_DEBUG_DUMP, "// gg_send_packet()\n");
		gg_debug_session_dump(sess, GG_DEBUG_DUMP, tmp, tmp_length);
	}

	res = gg_write(sess, tmp, tmp_length);

	free(tmp);

	if (res == -1) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_send_packet() write() failed. res = %d, errno = %d (%s)\n", res, errno, strerror(errno));
		return -1;
	}

	if (sess->async)
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_send_packet() partial write(), %d sent, %d left, %d total left\n", res, tmp_length - res, sess->send_left);

	if (sess->send_buf)
		sess->check |= GG_CHECK_WRITE;

	return 0;
}

/**
 * Wysyła do serwera pakiet utrzymania połączenia.
 *
 * Klient powinien regularnie co minutę wysyłać pakiet utrzymania połączenia,
 * inaczej serwer uzna, że klient stracił łączność z siecią i zerwie
 * połączenie.
 *
 * \param sess Struktura sesji
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup login
 */
int gg_ping(struct gg_session *sess)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_ping(%p);\n", sess);

	return gg_session_ping(sess);
}

/**
 * Zmienia status użytkownika.
 *
 * \param sess Struktura sesji
 * \param status Nowy status użytkownika
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup status
 */
int gg_change_status(struct gg_session *sess, int status)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_change_status(%p, %d);\n", sess, status);

	return gg_session_set_status(sess, status, NULL, 0);
}

/**
 * Zmienia status użytkownika na status opisowy.
 *
 * \param sess Struktura sesji
 * \param status Nowy status użytkownika
 * \param descr Opis statusu użytkownika
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup status
 */
int gg_change_status_descr(struct gg_session *sess, int status, const char *descr)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_change_status_descr(%p, %d, \"%s\");\n", sess, status, descr);

	return gg_session_set_status(sess, status, descr, 0);
}

/**
 * Zmienia status użytkownika na status opisowy z podanym czasem powrotu.
 *
 * \param sess Struktura sesji
 * \param status Nowy status użytkownika
 * \param descr Opis statusu użytkownika
 * \param time Czas powrotu w postaci uniksowego znacznika czasu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup status
 */
int gg_change_status_descr_time(struct gg_session *sess, int status, const char *descr, int time)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_change_status_descr_time(%p, %d, \"%s\", %d);\n", sess, status, descr, time);

	return gg_session_set_status(sess, status, descr, time);
}

/**
 * Wysyła wiadomość do użytkownika.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipient Numer adresata
 * \param message Treść wiadomości
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message(struct gg_session *sess, int msgclass, uin_t recipient, const unsigned char *message)
{
	gg_message_t gm;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message(%p, %d, %u, %p)\n", sess, msgclass, recipient, message);

	gg_message_init(&gm, msgclass, (uint32_t) -1, &recipient, 1, (char*) message, NULL, NULL, 0, 0);
	return gg_session_send_message(sess, &gm);
}

/**
 * Wysyła wiadomość formatowaną.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipient Numer adresata
 * \param message Treść wiadomości
 * \param format Informacje o formatowaniu
 * \param formatlen Długość informacji o formatowaniu
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_richtext(struct gg_session *sess, int msgclass, uin_t recipient, const unsigned char *message, const unsigned char *format, int formatlen)
{
	gg_message_t gm;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_richtext(%p, %d, %u, %p, %p, %d);\n", sess, msgclass, recipient, message, format, formatlen);

	gg_message_init(&gm, msgclass, (uint32_t) -1, &recipient, 1, (char*) message, NULL, (format != NULL) ? (char*) format + 3 : NULL, (formatlen >= 3) ? formatlen - 3 : 0, 0);
	return gg_session_send_message(sess, &gm);
}

/**
 * Wysyła wiadomość w ramach konferencji.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipient_count Liczba adresatów
 * \param recipients Wskaźnik do tablicy z numerami adresatów
 * \param message Treść wiadomości
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_confer(struct gg_session *sess, int msgclass, int recipient_count, uin_t *recipients, const unsigned char *message)
{
	gg_message_t gm;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_confer(%p, %d, %d, %p, %p);\n", sess, msgclass, recipient_count, recipients, message);

	gg_message_init(&gm, msgclass, (uint32_t) -1, recipients, recipient_count, (char*) message, NULL, NULL, 0, 0);
	return gg_session_send_message(sess, &gm);
}

/**
 * Wysyła wiadomość formatowaną w ramach konferencji.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipient_count Liczba adresatów
 * \param recipients Wskaźnik do tablicy z numerami adresatów
 * \param message Treść wiadomości
 * \param format Informacje o formatowaniu
 * \param formatlen Długość informacji o formatowaniu
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 * 
 * \ingroup messages
 */
int gg_send_message_confer_richtext(struct gg_session *sess, int msgclass, int recipient_count, uin_t *recipients, const unsigned char *message, const unsigned char *format, int formatlen)
{
	gg_message_t gm;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_confer_richtext(%p, %d, %d, %p, %p, %p, %d);\n", sess, msgclass, recipient_count, recipients, message, format, formatlen);

	gg_message_init(&gm, msgclass, (uint32_t) -1, recipients, recipient_count, (char*) message, NULL, (format != NULL) ? (char*) format + 3 : NULL, (formatlen >= 3) ? formatlen - 3 : 0, 0);
	return gg_session_send_message(sess, &gm);
}

/**
 * Wysyła wiadomość binarną przeznaczoną dla klienta.
 *
 * Wiadomości między klientami przesyła się np. w celu wywołania zwrotnego
 * połączenia bezpośredniego. Funkcja zwraca losowy numer sekwencyjny,
 * który można zignorować albo wykorzystać do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipient Numer adresata
 * \param message Treść wiadomości
 * \param message_len Długość wiadomości
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_ctcp(struct gg_session *sess, int msgclass, uin_t recipient, const unsigned char *message, int message_len)
{
	struct gg_send_msg s;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_ctcp(%p, %d, %u, ...);\n", sess, msgclass, recipient);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	s.recipient = gg_fix32(recipient);
	s.seq = gg_fix32(0);
	s.msgclass = gg_fix32(msgclass);

	return gg_send_packet(sess, GG_SEND_MSG, &s, sizeof(s), message, message_len, NULL);
}

/**
 * Wysyła żądanie obrazka o podanych parametrach.
 *
 * Wiadomości obrazkowe nie zawierają samych obrazków, a tylko ich rozmiary
 * i sumy kontrolne. Odbiorca najpierw szuka obrazków w swojej pamięci
 * podręcznej i dopiero gdy ich nie znajdzie, wysyła żądanie do nadawcy.
 * Wynik zostanie przekazany zdarzeniem \c GG_EVENT_IMAGE_REPLY.
 *
 * \param sess Struktura sesji
 * \param recipient Numer adresata
 * \param size Rozmiar obrazka w bajtach
 * \param crc32 Suma kontrola obrazka
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup messages
 */
int gg_image_request(struct gg_session *sess, uin_t recipient, int size, uint32_t crc32)
{
	struct gg_send_msg s;
	struct gg_msg_image_request r;
	char dummy = 0;
	int res;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_image_request(%p, %d, %u, 0x%.4x);\n", sess, recipient, size, crc32);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	s.recipient = gg_fix32(recipient);
	s.seq = gg_fix32(0);
	s.msgclass = gg_fix32(GG_CLASS_MSG);

	r.flag = 0x04;
	r.size = gg_fix32(size);
	r.crc32 = gg_fix32(crc32);

	res = gg_send_packet(sess, GG_SEND_MSG, &s, sizeof(s), &dummy, 1, &r, sizeof(r), NULL);

	if (!res) {
		struct gg_image_queue *q = malloc(sizeof(*q));
		char *buf;

		if (!q) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_image_request() not enough memory for image queue\n");
			return -1;
		}

		buf = malloc(size);
		if (size && !buf)
		{
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_image_request() not enough memory for image\n");
			free(q);
			return -1;
		}

		memset(q, 0, sizeof(*q));

		q->sender = recipient;
		q->size = size;
		q->crc32 = crc32;
		q->image = buf;

		if (!sess->images)
			sess->images = q;
		else {
			struct gg_image_queue *qq;

			for (qq = sess->images; qq->next; qq = qq->next)
				;

			qq->next = q;
		}
	}

	return res;
}

/**
 * Wysyła żądany obrazek.
 *
 * \param sess Struktura sesji
 * \param recipient Numer adresata
 * \param filename Nazwa pliku
 * \param image Bufor z obrazkiem
 * \param size Rozmiar obrazka
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup messages
 */
int gg_image_reply(struct gg_session *sess, uin_t recipient, const char *filename, const char *image, int size)
{
	struct gg_msg_image_reply *r;
	struct gg_send_msg s;
	const char *tmp;
	char buf[1922+64];	// XXX dodać stałe
	int res = -1;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_image_reply(%p, %d, \"%s\", %p, %d);\n", sess, recipient, filename, image, size);

	if (!sess || !filename || !image) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	if (size < 0) {
		errno = EINVAL;
		return -1;
	}

	/* wytnij ścieżki, zostaw tylko nazwę pliku */
	while ((tmp = strrchr(filename, '/')) || (tmp = strrchr(filename, '\\')))
		filename = tmp + 1;

	if (strlen(filename) < 1 || strlen(filename) > 1024) {
		errno = EINVAL;
		return -1;
	}

	s.recipient = gg_fix32(recipient);
	s.seq = gg_fix32(0);
	s.msgclass = gg_fix32(GG_CLASS_MSG);

	buf[0] = 0;
	r = (void*) &buf[1];

	r->flag = 0x05;
	r->size = gg_fix32(size);
	r->crc32 = gg_fix32(gg_crc32(0, (unsigned char*) image, size));

	while (size > 0) {
		int buflen, chunklen;

		/* \0 + struct gg_msg_image_reply */
		buflen = 1 + sizeof(struct gg_msg_image_reply);

		/* w pierwszym kawałku jest nazwa pliku */
		if (r->flag == 0x05) {
			char tmp[17];
			sprintf(tmp, "%08x%08x", gg_crc32(0, (unsigned char*) image, size), size);
			strcpy(buf + buflen, tmp);
			buflen += 17;
		}

		chunklen = (size >= 1922) ? 1922 : size;

		memcpy(buf + buflen, image, chunklen);
		size -= chunklen;
		image += chunklen;

		res = gg_send_packet(sess, GG_SEND_MSG, &s, sizeof(s), buf, buflen + chunklen, NULL);

		if (res == -1)
			break;

		r->flag = 0x06;
	}

	return res;
}

/**
 * Wysyła do serwera listę kontaktów.
 *
 * Funkcja informuje serwer o liście kontaktów, których statusy będą
 * obserwowane lub kontaktów, które bedą blokowane. Dla każdego z \c count
 * kontaktów tablica \c userlist zawiera numer, a tablica \c types rodzaj
 * kontaktu (\c GG_USER_NORMAL, \c GG_USER_OFFLINE, \c GG_USER_BLOCKED).
 *
 * Listę kontaktów należy \b zawsze wysyłać po połączeniu, nawet jeśli
 * jest pusta.
 *
 * \param sess Struktura sesji
 * \param userlist Wskaźnik do tablicy numerów kontaktów
 * \param types Wskaźnik do tablicy rodzajów kontaktów
 * \param count Liczba kontaktów
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_notify_ex(struct gg_session *sess, uin_t *userlist, char *types, int count)
{
	struct gg_notify *n;
	uin_t *u;
	char *t;
	int i, res = 0;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_notify_ex(%p, %p, %p, %d);\n", sess, userlist, types, count);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	if (!userlist || !count)
		return gg_send_packet(sess, GG_LIST_EMPTY, NULL);

	while (count > 0) {
		int part_count, packet_type;

		if (count > 400) {
			part_count = 400;
			packet_type = GG_NOTIFY_FIRST;
		} else {
			part_count = count;
			packet_type = GG_NOTIFY_LAST;
		}

		if (!(n = (struct gg_notify*) malloc(sizeof(*n) * part_count)))
			return -1;

		for (u = userlist, t = types, i = 0; i < part_count; u++, i++) {
			n[i].uin = gg_fix32(*u);
			if (t != NULL)
				n[i].dunno1 = *(t++);
			else
				n[i].dunno1 = GG_USER_NORMAL;
		}

		if (gg_send_packet(sess, packet_type, n, sizeof(*n) * part_count, NULL) == -1) {
			free(n);
			res = -1;
			break;
		}

		count -= part_count;
		userlist += part_count;
		if (types != NULL)
			types += part_count;

		free(n);
	}

	return res;
}

/**
 * Wysyła do serwera listę kontaktów.
 *
 * Funkcja jest odpowiednikiem \c gg_notify_ex(), gdzie wszystkie kontakty
 * są rodzaju \c GG_USER_NORMAL.
 *
 * \param sess Struktura sesji
 * \param userlist Wskaźnik do tablicy numerów kontaktów
 * \param count Liczba kontaktów
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_notify(struct gg_session *sess, uin_t *userlist, int count)
{
	return gg_notify_ex(sess, userlist, NULL, count);
}

/**
 * Dodaje kontakt.
 *
 * Dodaje do listy kontaktów dany numer w trakcie połączenia. Aby zmienić
 * rodzaj kontaktu (np. z normalnego na zablokowany), należy najpierw usunąć
 * poprzedni rodzaj, ponieważ serwer operuje na maskach bitowych.
 *
 * \param sess Struktura sesji
 * \param uin Numer kontaktu
 * \param type Rodzaj kontaktu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_add_notify_ex(struct gg_session *sess, uin_t uin, char type)
{
	struct gg_add_remove a;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_add_notify_ex(%p, %u, %d);\n", sess, uin, type);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	a.uin = gg_fix32(uin);
	a.dunno1 = type;

	return gg_send_packet(sess, GG_ADD_NOTIFY, &a, sizeof(a), NULL);
}

/**
 * Dodaje kontakt.
 *
 * Funkcja jest odpowiednikiem \c gg_add_notify_ex(), gdzie rodzaj wszystkich
 * kontaktów to \c GG_USER_NORMAL.
 *
 * \param sess Struktura sesji
 * \param uin Numer kontaktu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_add_notify(struct gg_session *sess, uin_t uin)
{
	return gg_add_notify_ex(sess, uin, GG_USER_NORMAL);
}

/**
 * Usuwa kontakt.
 *
 * Usuwa z listy kontaktów dany numer w trakcie połączenia.
 *
 * \param sess Struktura sesji
 * \param uin Numer kontaktu
 * \param type Rodzaj kontaktu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_remove_notify_ex(struct gg_session *sess, uin_t uin, char type)
{
	struct gg_add_remove a;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_remove_notify_ex(%p, %u, %d);\n", sess, uin, type);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	a.uin = gg_fix32(uin);
	a.dunno1 = type;

	return gg_send_packet(sess, GG_REMOVE_NOTIFY, &a, sizeof(a), NULL);
}

/**
 * Usuwa kontakt.
 *
 * Funkcja jest odpowiednikiem \c gg_add_notify_ex(), gdzie rodzaj wszystkich
 * kontaktów to \c GG_USER_NORMAL.
 *
 * \param sess Struktura sesji
 * \param uin Numer kontaktu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_remove_notify(struct gg_session *sess, uin_t uin)
{
	return gg_remove_notify_ex(sess, uin, GG_USER_NORMAL);
}

/**
 * Wysyła do serwera zapytanie dotyczące listy kontaktów.
 *
 * Funkcja służy do importu lub eksportu listy kontaktów do serwera.
 * W odróżnieniu od funkcji \c gg_notify(), ta lista kontaktów jest przez
 * serwer jedynie przechowywana i nie ma wpływu na połączenie. Format
 * listy kontaktów jest ignorowany przez serwer, ale ze względu na
 * kompatybilność z innymi klientami, należy przechowywać dane w tym samym
 * formacie co oryginalny klient Gadu-Gadu.
 *
 * Program nie musi się przejmować fragmentacją listy kontaktów wynikającą
 * z protokołu -- wysyła i odbiera kompletną listę.
 *
 * \param gs Struktura sesji
 * \param type Rodzaj zapytania
 * \param request Treść zapytania (może być równe NULL)
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup importexport
 */
int gg_userlist_request(struct gg_session *gs, char type, const char *request)
{
	GG_SESSION_CHECK_CONNECTED(gs, -1);

	return gg_session_contacts_request(gs, type, request);
}

/**
 * Łączy się z serwerem Gadu-Gadu.
 *
 * Przy połączeniu synchronicznym funkcja zakończy działanie po nawiązaniu
 * połączenia lub gdy wystąpi błąd. Po udanym połączeniu należy wywoływać
 * funkcję \c gg_watch_fd(), która odbiera informacje od serwera i zwraca
 * informacje o zdarzeniach.
 *
 * Przy połączeniu asynchronicznym funkcja rozpocznie procedurę połączenia
 * i zwróci zaalokowaną strukturę. Pole \c fd struktury \c gg_session zawiera
 * deskryptor, który należy obserwować funkcją \c select, \c poll lub za
 * pomocą mechanizmów użytej pętli zdarzeń (Glib, Qt itp.). Pole \c check
 * jest maską bitową mówiącą, czy biblioteka chce być informowana o możliwości
 * odczytu danych (\c GG_CHECK_READ) czy zapisu danych (\c GG_CHECK_WRITE).
 * Po zaobserwowaniu zmian na deskryptorze należy wywołać funkcję
 * \c gg_watch_fd(). Podczas korzystania z połączeń asynchronicznych, w trakcie
 * połączenia może zostać stworzony dodatkowy proces rozwiązujący nazwę
 * serwera -- z tego powodu program musi poprawnie obsłużyć sygnał SIGCHLD.
 *
 * \note Po nawiązaniu połączenia z serwerem należy wysłać listę kontaktów
 * za pomocą funkcji \c gg_notify() lub \c gg_notify_ex().
 *
 * \param p Struktura opisująca parametry połączenia. Wymagane pola: uin,
 *          password, async.
 *
 * \return Wskaźnik do zaalokowanej struktury sesji \c gg_session lub NULL
 *         w przypadku błędu.
 *
 * \ingroup login
 */
struct gg_session *gg_login(const struct gg_login_params *p)
{
	struct gg_session *gs = NULL;

	if (p == NULL) {
		gg_debug(GG_DEBUG_FUNCTION, "** gg_login(%p);\n", p);
		errno = EFAULT;
		return NULL;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_login(%p: [uin=%u, async=%d, ...]);\n", p, p->uin, p->async);

	gs = gg_session_new();

	if (gs == NULL) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() not enough memory for session data\n");
		return NULL;
	}

	if (gg_session_set_uin(gs, p->uin) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() invalid uin\n");
		goto fail;
	}

	if (gg_session_set_password(gs, p->password) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() not enough memory or invalid password\n");
		goto fail;
	}

	gg_session_set_async(gs, p->async);

	if (p->status != 0 || p->status_descr != NULL)
		gg_session_set_status(gs, p->status, p->status_descr, 0);

	if (p->hash_type != 0 && gg_session_set_hash_type(gs, p->hash_type)) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() invalid arguments. unknown hash type (%d)\n", p->hash_type);
		errno = EFAULT;
		goto fail;
	}

	gg_session_set_server(gs, p->server_addr, p->server_port);

	if (p->protocol_version != 0)
		gg_session_set_protocol_version(gs, p->protocol_version);
	else
		gg_session_set_protocol_version(gs, 0x2a);	// XXX

	if (p->client_version != NULL)
		gg_session_set_client_version(gs, p->client_version);

	gg_session_set_external_address(gs, p->external_addr, p->external_port);

	gg_session_set_last_message(gs, p->last_sysmsg);

	if (p->image_size != 0)
		gg_session_set_image_size(gs, p->image_size);

	gg_session_set_flag(gs, GG_SESSION_FLAG_ERA_OMNIX, p->era_omnix);

	gg_session_set_flag(gs, GG_SESSION_FLAG_AUDIO, p->has_audio);

	gg_session_set_encoding(gs, p->encoding);

	if (gg_session_set_resolver(gs, p->resolver) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() invalid arguments. unsupported resolver type (%d)\n", p->resolver);
		errno = EFAULT;
		goto fail;
	}

	if (p->tls == 1) {
#ifdef GG_CONFIG_HAVE_OPENSSL
		char buf[1024];

		OpenSSL_add_ssl_algorithms();

		if (!RAND_status()) {
			char rdata[1024];
			struct {
				time_t time;
				void *ptr;
			} rstruct;

			time(&rstruct.time);
			rstruct.ptr = (void *) &rstruct;

			RAND_seed((void *) rdata, sizeof(rdata));
			RAND_seed((void *) &rstruct, sizeof(rstruct));
		}

		gs->ssl_ctx = SSL_CTX_new(TLSv1_client_method());

		if (!gs->ssl_ctx) {
			ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
			gg_debug(GG_DEBUG_MISC, "// gg_login() SSL_CTX_new() failed: %s\n", buf);
			goto fail;
		}

		SSL_CTX_set_verify(gs->ssl_ctx, SSL_VERIFY_NONE, NULL);

		gs->ssl = SSL_new(gs->ssl_ctx);

		if (gs->ssl == NULL) {
			ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
			gg_debug(GG_DEBUG_MISC, "// gg_login() SSL_new() failed: %s\n", buf);
			goto fail;
		}
#else
		gg_debug(GG_DEBUG_MISC, "// gg_login() client requested TLS but no support compiled in\n");
#endif
	}

	if (gg_session_connect(gs) == -1)
		goto fail;

	return gs;

fail:
	gg_session_free(gs);
	return NULL;
}

/**
 * \internal Stub funkcji \c gg_session_disconnect() dla zachowania ABI. 
 *
 * \param gs Struktura sesji
 */
void gg_logoff(struct gg_session *gs)
{
	gg_session_disconnect(gs, 0);
}

/**
 * \internal Stub funkcji \c gg_session_free() dla zachowania ABI. 
 *
 * \param sess Struktura sesji
 */
void gg_free_session(struct gg_session *gs)
{
	return gg_session_free(gs);
}

/* @} */

/*
 * Local variables:
 * c-indentation-style: k&r
 * c-basic-offset: 8
 * indent-tabs-mode: notnil
 * End:
 *
 * vim: shiftwidth=8:
 */
