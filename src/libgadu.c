/* $Id$ */

/*
 *  (C) Copyright 2001-2010 Wojtek Kaniewski <wojtekka@irc.pl>
 *			  Robert J. Woźny <speedy@ziew.org>
 *			  Arkadiusz Miśkiewicz <arekm@pld-linux.org>
 *			  Tomasz Chiliński <chilek@chilan.com>
 *			  Adam Wysocki <gophi@ekg.chmurka.net>
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

#include "strman.h"
#include "network.h"
#ifdef sun
#  include <sys/filio.h>
#endif

#include "libgadu.h"
#include "protocol.h"
#include "resolver.h"
#include "internal.h"
#include "encoding.h"
#include "debug.h"
#include "session.h"
#include "message.h"
#include "deflate.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#ifdef GG_CONFIG_HAVE_GNUTLS
#  include <gnutls/gnutls.h>
#endif
#ifdef GG_CONFIG_HAVE_OPENSSL
#  include <openssl/err.h>
#  include <openssl/rand.h>
#endif

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
#ifndef _WIN32
unsigned long gg_dcc_ip = 0;
#else
uint32_t gg_dcc_ip = 0;
#endif

/**
 * Adres lokalnego interfejsu IP, z którego wywoływane są wszystkie połączenia.
 *
 * \ingroup ip
 */
#ifndef _WIN32
unsigned long gg_local_ip = 0;
#else
uint32_t gg_local_ip = 0;
#endif

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
const char *gg_libgadu_version(void)
{
	return GG_LIBGADU_VERSION;
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
 * Funkcja odbiera dane od serwera zajmując się SSL/TLS w razie konieczności.
 * Obsługuje EINTR, więc użytkownik nie musi się przejmować przerwanymi
 * wywołaniami systemowymi.
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

#ifdef GG_CONFIG_HAVE_GNUTLS
	if (sess->ssl != NULL) {
		for (;;) {
			res = gnutls_record_recv(GG_SESSION_GNUTLS(sess), buf, length);

			if (res < 0) {
				if (!gnutls_error_is_fatal(res) || res == GNUTLS_E_INTERRUPTED)
					continue;

				if (res == GNUTLS_E_AGAIN)
					errno = EAGAIN;
				else
					errno = EINVAL;

				return -1;
			}

			return res;
		}
	}
#endif

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl != NULL) {
		for (;;) {
			int err;

			res = SSL_read(sess->ssl, buf, length);

			if (res < 0) {
				err = SSL_get_error(sess->ssl, res);

				if (err == SSL_ERROR_SYSCALL && errno == EINTR)
					continue;

				if (err == SSL_ERROR_WANT_READ)
					errno = EAGAIN;
				else if (err != SSL_ERROR_SYSCALL)
					errno = EINVAL;

				return -1;
			}

			return res;
		}
	}
#endif

	for (;;) {
		res = recv(sess->fd, buf, length, 0);

		if (res == -1 && errno == EINTR)
			continue;

		return res;
	}
}

/**
 * \internal Wysyła do serwera dane binarne.
 *
 * Funkcja wysyła dane do serwera zajmując się SSL/TLS w razie konieczności.
 * Obsługuje EINTR, więc użytkownik nie musi się przejmować przerwanymi
 * wywołaniami systemowymi.
 *
 * \note Funkcja nie zajmuje się buforowaniem wysyłanych danych (patrz
 * gg_write()).
 *
 * \param sess Struktura sesji
 * \param buf Bufor z danymi
 * \param length Długość bufora
 *
 * \return To samo co funkcja systemowa \c write
 */
static int gg_write_common(struct gg_session *sess, const char *buf, int length)
{
	int res;

#ifdef GG_CONFIG_HAVE_GNUTLS
	if (sess->ssl != NULL) {
		for (;;) {
			res = gnutls_record_send(GG_SESSION_GNUTLS(sess), buf, length);

			if (res < 0) {
				if (!gnutls_error_is_fatal(res) || res == GNUTLS_E_INTERRUPTED)
					continue;

				if (res == GNUTLS_E_AGAIN)
					errno = EAGAIN;
				else
					errno = EINVAL;

				return -1;
			}

			return res;
		}
	}
#endif

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl != NULL) {
		for (;;) {
			int err;

			res = SSL_write(sess->ssl, buf, length);

			if (res < 0) {
				err = SSL_get_error(sess->ssl, res);

				if (err == SSL_ERROR_SYSCALL && errno == EINTR)
					continue;

				if (err == SSL_ERROR_WANT_WRITE)
					errno = EAGAIN;
				else if (err != SSL_ERROR_SYSCALL)
					errno = EINVAL;

				return -1;
			}

			return res;
		}
	}
#endif

	for (;;) {
		res = send(sess->fd, buf, length, 0);

		if (res == -1 && errno == EINTR)
			continue;

		return res;
	}
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

	if (!sess->async) {
		int written = 0;

		while (written < length) {
			res = gg_write_common(sess, buf + written, length - written);

			if (res == -1)
				return -1;

			written += res;
			res = written;
		}
	} else {
		if (sess->send_buf == NULL) {
			res = gg_write_common(sess, buf, length);

			if (res == -1 && errno == EAGAIN)
				res = 0;
			if (res == -1)
				return -1;
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

	return res;
}

/**
 * \internal Odbiera pakiet od serwera.
 *
 * Funkcja odczytuje nagłówek pakietu, a następnie jego zawartość i zwraca
 * w zaalokowanym buforze.
 *
 * Przy połączeniach asynchronicznych, funkcja może nie być w stanie
 * skompletować całego pakietu -- w takim przypadku zwróci \c NULL, a kodem błędu
 * będzie \c EAGAIN.
 *
 * \param sess Struktura sesji
 *
 * \return Wskaźnik do zaalokowanego bufora
 */
void *gg_recv_packet(struct gg_session *sess)
{
	struct gg_header *gh;
	char *packet;
	int res;
	size_t len;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_recv_packet(%p);\n", sess);

	if (sess == NULL) {
		errno = EFAULT;
		return NULL;
	}

	for (;;) {
		if (sess->recv_buf == NULL && sess->recv_done == 0) {
			sess->recv_buf = malloc(sizeof(struct gg_header) + 1);

			if (sess->recv_buf == NULL) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() out of memory\n");
				return NULL;
			}
		}

		gh = (struct gg_header*) sess->recv_buf;

		if ((size_t) sess->recv_done < sizeof(struct gg_header)) {
			len = sizeof(struct gg_header) - sess->recv_done;
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header: %d done, %d to go\n", sess->recv_done, len);
		} else {
			if ((size_t) sess->recv_done >= sizeof(struct gg_header) + gg_fix32(gh->length)) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() and that's it\n");
				break;
			}

			len = sizeof(struct gg_header) + gg_fix32(gh->length) - sess->recv_done;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() payload: %d done, %d length, %d to go\n", sess->recv_done, gg_fix32(gh->length), len);
		}

		res = gg_read(sess, sess->recv_buf + sess->recv_done, len);

		if (res == 0) {
			errno = ECONNRESET;
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() connection broken\n");
			goto fail;
		}

		if (res == -1 && errno == EAGAIN) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() resource temporarily unavailable\n");
			goto eagain;
		}

		if (res == -1) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() read failed: errno=%d, %s\n", errno, strerror(errno));
			goto fail;
		}

		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() read %d bytes\n", res);

		if (sess->recv_done + res == sizeof(struct gg_header)) {
			char *tmp;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() header complete, payload %d bytes\n", gg_fix32(gh->length));

			if (gg_fix32(gh->length == 0))
				break;

			if (gg_fix32(gh->length) > 65535) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() invalid packet length (%d)\n", gg_fix32(gh->length));
				errno = ERANGE;
				goto fail;
			}

			tmp = realloc(sess->recv_buf, sizeof(struct gg_header) + gg_fix32(gh->length) + 1);

			if (tmp == NULL) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_recv_packet() out of memory\n");
				goto fail;
			}

			sess->recv_buf = tmp;
		}

		sess->recv_done += res;
	}

	packet = sess->recv_buf;
	sess->recv_buf = NULL;
	sess->recv_done = 0;

	/* Czasami zakładamy, że teksty w pakietach są zakończone zerem */
	packet[sizeof(struct gg_header) + gg_fix32(gh->length)] = 0;

	gg_debug_session(sess, GG_DEBUG_DUMP, "// gg_recv_packet(type=0x%.2x, length=%d)\n", gg_fix32(gh->type), gg_fix32(gh->length));
	gg_debug_dump(sess, GG_DEBUG_DUMP, packet, sizeof(struct gg_header) + gg_fix32(gh->length));

	gh->type = gg_fix32(gh->type);
	gh->length = gg_fix32(gh->length);

	return packet;

fail:
	free(sess->recv_buf);
	sess->recv_buf = NULL;
	sess->recv_done = 0;

eagain:
	return NULL;
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
 *	    typu \c int) zakończona \c NULL
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

	gg_debug_session(sess, GG_DEBUG_DUMP, "// gg_send_packet(type=0x%.2x, length=%d)\n", gg_fix32(h->type), gg_fix32(h->length));
	gg_debug_dump(sess, GG_DEBUG_DUMP, tmp, tmp_length);

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
 * \internal Funkcja zwrotna sesji.
 *
 * Pole \c callback struktury \c gg_session zawiera wskaźnik do tej funkcji.
 * Wywołuje ona \c gg_watch_fd i zachowuje wynik w polu \c event.
 *
 * \note Korzystanie z tej funkcjonalności nie jest już zalecane.
 *
 * \param sess Struktura sesji
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_session_callback(struct gg_session *sess)
{
	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	return ((sess->event = gg_watch_fd(sess)) != NULL) ? 0 : -1;
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
 *       za pomocą funkcji \c gg_notify() lub \c gg_notify_ex().
 *
 * \note Funkcja zwróci błąd ENOSYS jeśli połączenie SSL było wymagane, ale
 *       obsługa SSL nie jest wkompilowana.
 *
 * \param p Struktura opisująca parametry połączenia. Wymagane pola: uin,
 *	  password, async.
 *
 * \return Wskaźnik do zaalokowanej struktury sesji \c gg_session lub NULL
 *	 w przypadku błędu.
 *
 * \ingroup login
 */
struct gg_session *gg_login(const struct gg_login_params *p)
{
	struct gg_session *sess = NULL;

	if (p == NULL) {
		gg_debug(GG_DEBUG_FUNCTION, "** gg_login(%p);\n", p);
		errno = EFAULT;
		return NULL;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_login(%p: [uin=%u, async=%d, ...]);\n", p, p->uin, p->async);

	sess = malloc(sizeof(struct gg_session));

	if (sess == NULL) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() not enough memory for session data\n");
		goto fail;
	}

	memset(sess, 0, sizeof(struct gg_session));

	if (p->password == NULL || p->uin == 0) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() invalid arguments. uin and password needed\n");
		errno = EFAULT;
		goto fail;
	}

	if (!(sess->password = strdup(p->password))) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() not enough memory for password\n");
		goto fail;
	}

	if (p->hash_type < 0 || p->hash_type > GG_LOGIN_HASH_SHA1) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() invalid arguments. unknown hash type (%d)\n", p->hash_type);
		errno = EFAULT;
		goto fail;
	}

	sess->uin = p->uin;
	sess->state = GG_STATE_RESOLVING;
	sess->check = GG_CHECK_READ;
	sess->timeout = GG_DEFAULT_TIMEOUT;
	sess->async = p->async;
	sess->type = GG_SESSION_GG;
	sess->initial_status = p->status;
	sess->callback = gg_session_callback;
	sess->destroy = gg_free_session;
	sess->port = p->server_port;
	sess->server_addr = p->server_addr;
	sess->external_port = p->external_port;
	sess->external_addr = p->external_addr;
	sess->client_addr = p->client_addr;
	sess->client_port = p->client_port;

	if (p->protocol_features == 0) {
		sess->protocol_features = GG_FEATURE_MSG80 | GG_FEATURE_STATUS80 | GG_FEATURE_DND_FFC | GG_FEATURE_IMAGE_DESCR | GG_FEATURE_UNKNOWN_100 | GG_FEATURE_USER_DATA | GG_FEATURE_MSG_ACK | GG_FEATURE_TYPING_NOTIFICATION;
	} else {
		sess->protocol_features = (p->protocol_features & ~(GG_FEATURE_STATUS77 | GG_FEATURE_MSG77));

		if (!(p->protocol_features & GG_FEATURE_STATUS77))
			sess->protocol_features |= GG_FEATURE_STATUS80;

		if (!(p->protocol_features & GG_FEATURE_MSG77))
			sess->protocol_features |= GG_FEATURE_MSG80;
	}

	if (!(sess->status_flags = p->status_flags))
		sess->status_flags = GG_STATUS_FLAG_UNKNOWN | GG_STATUS_FLAG_SPAM;

	if (!p->protocol_version)
		sess->protocol_version = GG_DEFAULT_PROTOCOL_VERSION;
	else if (p->protocol_version < 0x2e) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() libgadu no longer support protocol < 0x2e\n");
		sess->protocol_version = 0x2e;
	} else
		sess->protocol_version = p->protocol_version;

	sess->client_version = (p->client_version) ? strdup(p->client_version) : NULL;
	sess->last_sysmsg = p->last_sysmsg;
	sess->image_size = p->image_size;
	sess->pid = -1;
	sess->encoding = p->encoding;

	if (gg_session_set_resolver(sess, p->resolver) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_login() invalid arguments. unsupported resolver type (%d)\n", p->resolver);
		errno = EFAULT;
		goto fail;
	}

	if (p->status_descr) {
		sess->initial_descr = gg_encoding_convert(p->status_descr, p->encoding, GG_ENCODING_UTF8, -1, -1);

		if (!sess->initial_descr) {
			gg_debug(GG_DEBUG_MISC, "// gg_login() not enough memory for status\n");
			goto fail;
		}
		
		/* XXX pamiętać, żeby nie ciąć w środku znaku utf-8 */
		
		if (strlen(sess->initial_descr) > GG_STATUS_DESCR_MAXSIZE)
			sess->initial_descr[GG_STATUS_DESCR_MAXSIZE] = 0;
	}

	if (p->tls != GG_SSL_DISABLED) {
#if !defined(GG_CONFIG_HAVE_GNUTLS) && !defined(GG_CONFIG_HAVE_OPENSSL)
		gg_debug(GG_DEBUG_MISC, "// gg_login() client requested TLS but no support compiled in\n");

		if (p->tls == GG_SSL_REQUIRED) {
			errno = ENOSYS;
			goto fail;
		}
#else
		sess->ssl_flag = p->tls;
#endif
	}

	if (p->hash_type)
		sess->hash_type = p->hash_type;
	else
		sess->hash_type = GG_LOGIN_HASH_SHA1;

	if (sess->server_addr == 0) {
		if (gg_proxy_enabled) {
			sess->resolver_host = gg_proxy_host;
			sess->proxy_port = gg_proxy_port;
			sess->state = (sess->async) ? GG_STATE_RESOLVE_PROXY_HUB_ASYNC : GG_STATE_RESOLVE_PROXY_HUB_SYNC;
		} else {
			sess->resolver_host = GG_APPMSG_HOST;
			sess->proxy_port = 0;
			sess->state = (sess->async) ? GG_STATE_RESOLVE_HUB_ASYNC : GG_STATE_RESOLVE_HUB_SYNC;
		}
	} else {
		// XXX inet_ntoa i wielowątkowość
		sess->connect_host = strdup(inet_ntoa(*(struct in_addr*) &sess->server_addr));
		if (sess->connect_host == NULL)
			goto fail;
		sess->connect_index = 0;

		if (gg_proxy_enabled) {
			sess->resolver_host = gg_proxy_host;
			sess->proxy_port = gg_proxy_port;
			if (sess->port == 0)
				sess->connect_port[0] = GG_HTTPS_PORT;
			else
				sess->connect_port[0] = sess->port;
			sess->connect_port[1] = 0;
			sess->state = (sess->async) ? GG_STATE_RESOLVE_PROXY_GG_ASYNC : GG_STATE_RESOLVE_PROXY_GG_SYNC;
		} else {
			sess->resolver_host = sess->connect_host;
			if (sess->port == 0) {
				if (sess->ssl_flag == GG_SSL_DISABLED) {
					sess->connect_port[0] = GG_DEFAULT_PORT;
					sess->connect_port[1] = GG_HTTPS_PORT;
				} else {
					sess->connect_port[0] = GG_HTTPS_PORT;
					sess->connect_port[1] = 0;
				}
			} else {
				sess->connect_port[0] = sess->port;
				sess->connect_port[1] = 0;
			}
			sess->state = (sess->async) ? GG_STATE_RESOLVE_GG_ASYNC : GG_STATE_RESOLVE_GG_SYNC;
		}
	}

	// XXX inaczej gg_watch_fd() wyjdzie z timeoutem
	sess->timeout = GG_DEFAULT_TIMEOUT;

	if (!sess->async) {
		while (!GG_SESSION_IS_CONNECTED(sess)) {
			struct gg_event *ge;

			ge = gg_watch_fd(sess);

			if (ge == NULL) {
				gg_debug(GG_DEBUG_MISC, "// gg_session_connect() critical error in gg_watch_fd()\n");
				goto fail;
			}

			if (ge->type == GG_EVENT_CONN_FAILED) {
				errno = EACCES;
				gg_debug(GG_DEBUG_MISC, "// gg_session_connect() could not login\n");
				gg_event_free(ge);
				goto fail;
			}

			gg_event_free(ge);
		}
	} else {
		struct gg_event *ge;

		ge = gg_watch_fd(sess);

		if (ge == NULL) {
			gg_debug(GG_DEBUG_MISC, "// gg_session_connect() critical error in gg_watch_fd()\n");
			goto fail;
		}

		gg_event_free(ge);
	}

	

	return sess;

fail:
	gg_free_session(sess);

	return NULL;
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

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	return gg_send_packet(sess, GG_PING, NULL);
}

/**
 * Kończy połączenie z serwerem.
 *
 * Funkcja nie zwalnia zasobów, więc po jej wywołaniu należy użyć
 * \c gg_free_session(). Jeśli chce się ustawić opis niedostępności, należy
 * wcześniej wywołać funkcję \c gg_change_status_descr() lub
 * \c gg_change_status_descr_time().
 *
 * \note Jeśli w buforze nadawczym połączenia z serwerem znajdują się jeszcze
 * dane (np. z powodu strat pakietów na łączu), prawdopodobnie zostaną one
 * utracone przy zrywaniu połączenia. Aby mieć pewność, że opis statusu
 * zostanie zachowany, należy ustawić stan \c GG_STATUS_NOT_AVAIL_DESCR
 * za pomocą funkcji \c gg_change_status_descr() i poczekać na zdarzenie
 * \c GG_EVENT_DISCONNECT_ACK.
 *
 * \param sess Struktura sesji
 *
 * \ingroup login
 */
void gg_logoff(struct gg_session *sess)
{
	if (!sess)
		return;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_logoff(%p);\n", sess);

#ifdef GG_CONFIG_HAVE_GNUTLS
	if (sess->ssl != NULL)
		gnutls_bye(GG_SESSION_GNUTLS(sess), GNUTLS_SHUT_RDWR);
#endif

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl != NULL)
		SSL_shutdown(sess->ssl);
#endif

	sess->resolver_cleanup(&sess->resolver, 1);

	if (sess->fd != -1) {
		close(sess->fd);
		sess->fd = -1;
	}

	if (sess->send_buf) {
		free(sess->send_buf);
		sess->send_buf = NULL;
		sess->send_left = 0;
	}
}

/**
 * Zwalnia zasoby używane przez połączenie z serwerem. Funkcję należy wywołać
 * po zamknięciu połączenia z serwerem, by nie doprowadzić do wycieku zasobów
 * systemowych.
 *
 * \param sess Struktura sesji
 *
 * \ingroup login
 */
void gg_free_session(struct gg_session *sess)
{
	struct gg_dcc7 *dcc;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_free_session(%p);\n", sess);

	if (sess == NULL)
		return;

	/* XXX dopisać zwalnianie i zamykanie wszystkiego, co mogło zostać */

	free(sess->resolver_result);
	free(sess->connect_host);
	free(sess->password);
	free(sess->initial_descr);
	free(sess->client_version);
	free(sess->header_buf);
	free(sess->recv_buf);

#ifdef GG_CONFIG_HAVE_GNUTLS
	if (sess->ssl != NULL) {
		gg_session_gnutls_t *tmp;

		tmp = (gg_session_gnutls_t*) sess->ssl;
		gnutls_deinit(tmp->session);
		gnutls_certificate_free_credentials(tmp->xcred);
		gnutls_global_deinit();
		free(sess->ssl);
	}
#endif

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl)
		SSL_free(sess->ssl);

	if (sess->ssl_ctx)
		SSL_CTX_free(sess->ssl_ctx);
#endif

	sess->resolver_cleanup(&sess->resolver, 1);

	if (sess->fd != -1)
		close(sess->fd);

	while (sess->images)
		gg_image_queue_remove(sess, sess->images, 1);

	free(sess->send_buf);

	for (dcc = sess->dcc7_list; dcc; dcc = dcc->next)
		dcc->sess = NULL;

	free(sess);
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

	return gg_change_status_descr(sess, status, NULL);
}

/**
 * Zmienia status użytkownika na status opisowy.
 *
 * \param sess Struktura sesji
 * \param status Nowy status użytkownika
 * \param descr Opis statusu użytkownika (lub \c NULL)
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup status
 */
int gg_change_status_descr(struct gg_session *sess, int status, const char *descr)
{
	struct gg_new_status80 p;
	char *new_descr = NULL;
	int descr_len = 0;
	int res;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_change_status_descr(%p, %d, \"%s\");\n", sess, status, descr);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	sess->status = status;

	if (descr != NULL && sess->encoding != GG_ENCODING_UTF8) {
		new_descr = gg_encoding_convert(descr, GG_ENCODING_CP1250, GG_ENCODING_UTF8, -1, -1);

		if (!new_descr)
			return -1;
	}

	if (descr) {
		descr_len = strlen((new_descr) ? new_descr : descr);

		if (descr_len > GG_STATUS_DESCR_MAXSIZE)
			descr_len = GG_STATUS_DESCR_MAXSIZE;

		/* XXX pamiętać o tym, żeby nie ucinać w środku znaku utf-8 */
	}

	p.status		= gg_fix32(status);
	p.flags			= gg_fix32(sess->status_flags);
	p.description_size	= gg_fix32(descr_len);
	res = gg_send_packet(sess, GG_NEW_STATUS80, 
			&p, sizeof(p), 
			(new_descr) ? new_descr : descr, descr_len,
			NULL);

	free(new_descr);

	if (GG_S_NA(status)) {
		sess->state = GG_STATE_DISCONNECTING;
		sess->timeout = GG_TIMEOUT_DISCONNECT;
	}

	return res;
}

/**
 * Zmienia status użytkownika na status opisowy z podanym czasem powrotu.
 *
 * \param sess Struktura sesji
 * \param status Nowy status użytkownika
 * \param descr Opis statusu użytkownika
 * \param ts Czas powrotu w postaci uniksowego znacznika czasu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup status
 */
int gg_change_status_descr_time(struct gg_session *sess, int status, const char *descr, int ts)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_change_status_descr_time(%p, %d, \"%s\", %d);\n", sess, status, descr, ts);

	return gg_change_status_descr(sess, status, descr);
}

/**
 * Funkcja zmieniająca flagi statusu.
 *
 * \param sess Struktura sesji
 * \param flags Nowe flagi statusu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \note Aby zmiany weszły w życie, należy ponownie ustawić status za pomocą
 * funkcji z rodziny \c gg_change_status().
 *
 * \ingroup status
 */
int gg_change_status_flags(struct gg_session *sess, int flags)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_change_status_flags(%p, 0x%08x);\n", sess, flags);

	if (sess == NULL) {
		errno = EFAULT;
		return -1;
	}

	sess->status_flags = flags;

	return 0;
}

#ifndef DOXYGEN

/**
 * \internal Wysyła wiadomość.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipients_count Liczba adresatów
 * \param recipients Wskaźnik do tablicy z numerami adresatów
 * \param message Treść wiadomości
 * \param format Informacje o formatowaniu
 * \param formatlen Długość informacji o formatowaniu
 * \param html_message Treść wiadomości HTML
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
static int gg_send_message_common(struct gg_session *sess, int msgclass, int recipients_count, uin_t *recipients, const unsigned char *message, const unsigned char *format, int formatlen, const unsigned char *html_message)
{
	struct gg_send_msg80 s80;
	const char *cp_msg = NULL, *utf_html_msg = NULL;
	char *recoded_msg = NULL, *recoded_html_msg = NULL;
	unsigned char *generated_format = NULL;
	int seq_no = -1;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_common(%p, %d, %d, %p, %p, %p, %d, %p);\n", sess, msgclass, recipients_count, recipients, message, format, formatlen, html_message);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	if ((message == NULL && html_message == NULL) || recipients_count <= 0 || recipients_count > 0xffff || recipients == NULL || (format == NULL && formatlen != 0)) {
		errno = EINVAL;
		return -1;
	}

	if (message == NULL) {
		char *tmp_msg;
		size_t len, fmt_len;
		uint16_t fixed_fmt_len;

		len = gg_message_html_to_text(NULL, NULL, &fmt_len, (const char*) html_message, sess->encoding);

		tmp_msg = malloc(len + 1);

		if (tmp_msg == NULL)
			goto cleanup;

		if (fmt_len != 0) {
			generated_format = malloc(fmt_len + 3);

			if (generated_format == NULL) {
				free(tmp_msg);
				goto cleanup;
			}

			generated_format[0] = '\x02';
			fixed_fmt_len = gg_fix16(fmt_len);
			memcpy(generated_format + 1, &fixed_fmt_len, sizeof(fixed_fmt_len));
			gg_message_html_to_text(tmp_msg, generated_format + 3, NULL, (const char*) html_message, sess->encoding);

			format = generated_format;
			formatlen = fmt_len + 3;
		} else {
			gg_message_html_to_text(tmp_msg, NULL, NULL, (const char*) html_message, sess->encoding);

			format = NULL;
			formatlen = 0;
		}

		if (sess->encoding == GG_ENCODING_UTF8) {
			cp_msg = recoded_msg = gg_encoding_convert(tmp_msg, sess->encoding, GG_ENCODING_CP1250, -1, -1);
			free(tmp_msg);

			if (cp_msg == NULL)
				goto cleanup;
		} else {
			cp_msg = recoded_msg = tmp_msg;
		}
	} else {
		if (sess->encoding == GG_ENCODING_UTF8) {
			cp_msg = recoded_msg = gg_encoding_convert((const char*) message, sess->encoding, GG_ENCODING_CP1250, -1, -1);

			if (cp_msg == NULL)
				goto cleanup;
		} else {
			cp_msg = (const char*) message;
		}
	}

	if (html_message == NULL) {
		size_t len;
		char *tmp;
		const char *utf_msg;
		const unsigned char *format_ = NULL;
		size_t formatlen_ = 0;

		if (sess->encoding == GG_ENCODING_UTF8) {
			utf_msg = (const char*) message;
		} else {
			utf_msg = recoded_msg = gg_encoding_convert((const char*) message, sess->encoding, GG_ENCODING_UTF8, -1, -1);

			if (utf_msg == NULL)
				goto cleanup;
		}

		if (format != NULL && formatlen >= 3) {
			format_ = format + 3;
			formatlen_ = formatlen - 3;
		}

		len = gg_message_text_to_html(NULL, utf_msg, GG_ENCODING_UTF8, format_, formatlen_);

		tmp = malloc(len + 1);

		if (tmp == NULL)
			goto cleanup;

		gg_message_text_to_html(tmp, utf_msg, GG_ENCODING_UTF8, format_, formatlen_);

		utf_html_msg = recoded_html_msg = tmp;
	} else {
		if (sess->encoding == GG_ENCODING_UTF8) {
			utf_html_msg = (const char*) html_message;
		} else {
			utf_html_msg = recoded_html_msg = gg_encoding_convert((const char*) html_message, sess->encoding, GG_ENCODING_UTF8, -1, -1);

			if (utf_html_msg == NULL)
				goto cleanup;
		}
	}

	/* Drobne odchylenie od protokołu. Jeśli wysyłamy kilka
	 * wiadomości w ciągu jednej sekundy, zwiększamy poprzednią
	 * wartość, żeby każda wiadomość miała unikalny numer.
	 */

	seq_no = time(NULL);

	if (seq_no <= sess->seq)
		seq_no = sess->seq + 1;

	sess->seq = seq_no;

	s80.seq = gg_fix32(seq_no);
	s80.msgclass = gg_fix32(msgclass);
	s80.offset_plain = gg_fix32(sizeof(s80) + strlen(utf_html_msg) + 1);
	s80.offset_attr = gg_fix32(sizeof(s80) + strlen(utf_html_msg) + 1 + strlen(cp_msg) + 1);

	if (recipients_count > 1) {
		struct gg_msg_recipients r;
		int i, j, k;
		uin_t *recps;

		r.flag = GG_MSG_OPTION_CONFERENCE;
		r.count = gg_fix32(recipients_count - 1);

		recps = malloc(sizeof(uin_t) * (recipients_count - 1));

		if (!recps) {
			seq_no = -1;
			goto cleanup;
		}

		for (i = 0; i < recipients_count; i++) {
			for (j = 0, k = 0; j < recipients_count; j++) {
				if (j != i) {
					recps[k] = gg_fix32(recipients[j]);
					k++;
				}
			}

			s80.recipient = gg_fix32(recipients[i]);

			if (gg_send_packet(sess, GG_SEND_MSG80, &s80, sizeof(s80), utf_html_msg, strlen(utf_html_msg) + 1, cp_msg, strlen(cp_msg) + 1, &r, sizeof(r), recps, (recipients_count - 1) * sizeof(uin_t), format, formatlen, NULL) == -1)
				seq_no = -1;
		}

		free(recps);
	} else {
		s80.recipient = gg_fix32(recipients[0]);

		if (gg_send_packet(sess, GG_SEND_MSG80, &s80, sizeof(s80), utf_html_msg, strlen(utf_html_msg) + 1, cp_msg, strlen(cp_msg) + 1, format, formatlen, NULL) == -1)
			seq_no = -1;
	}

cleanup:
	free(recoded_msg);
	free(recoded_html_msg);
	free(generated_format);

	return seq_no;
}

#endif /* DOXYGEN */

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
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message(%p, %d, %u, %p)\n", sess, msgclass, recipient, message);

	return gg_send_message_common(sess, msgclass, 1, &recipient, message, (const unsigned char*) "\x02\x06\x00\x00\x00\x08\x00\x00\x00", 9, NULL);
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
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_richtext(%p, %d, %u, %p, %p, %d);\n", sess, msgclass, recipient, message, format, formatlen);

	return gg_send_message_common(sess, msgclass, 1, &recipient, message, format, formatlen, NULL);
}

/**
 * Wysyła formatowaną wiadomość HTML.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipient Numer adresata
 * \param html_message Treść wiadomości HTML
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_html(struct gg_session *sess, int msgclass, uin_t recipient, const unsigned char *html_message)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_html(%p, %d, %u, %p);\n", sess, msgclass, recipient, html_message);

	return gg_send_message_common(sess, msgclass, 1, &recipient, NULL, NULL, 0, html_message);
}

/**
 * Wysyła wiadomość w ramach konferencji.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipients_count Liczba adresatów
 * \param recipients Wskaźnik do tablicy z numerami adresatów
 * \param message Treść wiadomości
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_confer(struct gg_session *sess, int msgclass, int recipients_count, uin_t *recipients, const unsigned char *message)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_confer(%p, %d, %d, %p, %p);\n", sess, msgclass, recipients_count, recipients, message);

	return gg_send_message_common(sess, msgclass, recipients_count, recipients, message, (const unsigned char*) "\x02\x06\x00\x00\x00\x08\x00\x00\x00", 9, NULL);
}

/**
 * Wysyła wiadomość formatowaną w ramach konferencji.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipients_count Liczba adresatów
 * \param recipients Wskaźnik do tablicy z numerami adresatów
 * \param message Treść wiadomości
 * \param format Informacje o formatowaniu
 * \param formatlen Długość informacji o formatowaniu
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_confer_richtext(struct gg_session *sess, int msgclass, int recipients_count, uin_t *recipients, const unsigned char *message, const unsigned char *format, int formatlen)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_confer_richtext(%p, %d, %d, %p, %p, %p, %d);\n", sess, msgclass, recipients_count, recipients, message, format, formatlen);

	return gg_send_message_common(sess, msgclass, recipients_count, recipients, message, format, formatlen, NULL);
}

/**
 * Wysyła formatowaną wiadomość HTML w ramach konferencji.
 *
 * Zwraca losowy numer sekwencyjny, który można zignorować albo wykorzystać
 * do potwierdzenia.
 *
 * \param sess Struktura sesji
 * \param msgclass Klasa wiadomości
 * \param recipients_count Liczba adresatów
 * \param recipients Wskaźnik do tablicy z numerami adresatów
 * \param html_message Treść wiadomości HTML
 *
 * \return Numer sekwencyjny wiadomości lub -1 w przypadku błędu.
 *
 * \ingroup messages
 */
int gg_send_message_confer_html(struct gg_session *sess, int msgclass, int recipients_count, uin_t *recipients, const unsigned char *html_message)
{
	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_send_message_confer_html(%p, %d, %d, %p, %p);\n", sess, msgclass, recipients_count, recipients, html_message);

	return gg_send_message_common(sess, msgclass, recipients_count, recipients, NULL, NULL, 0, html_message);
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

	r.flag = GG_MSG_OPTION_IMAGE_REQUEST;
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
	char buf[1910];
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

	r->flag = GG_MSG_OPTION_IMAGE_REPLY;
	r->size = gg_fix32(size);
	r->crc32 = gg_fix32(gg_crc32(0, (const unsigned char*) image, size));

	while (size > 0) {
		size_t buflen, chunklen;

		/* \0 + struct gg_msg_image_reply */
		buflen = sizeof(struct gg_msg_image_reply) + 1;

		/* w pierwszym kawałku jest nazwa pliku */
		if (r->flag == GG_MSG_OPTION_IMAGE_REPLY) {
			strcpy(buf + buflen, filename);
			buflen += strlen(filename) + 1;
		}

		chunklen = ((size_t) size >= sizeof(buf) - buflen) ? (sizeof(buf) - buflen) : (size_t) size;

		memcpy(buf + buflen, image, chunklen);
		size -= chunklen;
		image += chunklen;

		res = gg_send_packet(sess, GG_SEND_MSG, &s, sizeof(s), buf, buflen + chunklen, NULL);

		if (res == -1)
			break;

		r->flag = GG_MSG_OPTION_IMAGE_REPLY_MORE;
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

		for (u = userlist, t = types, i = 0; i < part_count; u++, t++, i++) {
			n[i].uin = gg_fix32(*u);
			n[i].dunno1 = *t;
		}

		if (gg_send_packet(sess, packet_type, n, sizeof(*n) * part_count, NULL) == -1) {
			free(n);
			res = -1;
			break;
		}

		count -= part_count;
		userlist += part_count;
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
	struct gg_notify *n;
	uin_t *u;
	int i, res = 0;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_notify(%p, %p, %d);\n", sess, userlist, count);

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

		for (u = userlist, i = 0; i < part_count; u++, i++) {
			n[i].uin = gg_fix32(*u);
			n[i].dunno1 = GG_USER_NORMAL;
		}

		if (gg_send_packet(sess, packet_type, n, sizeof(*n) * part_count, NULL) == -1) {
			res = -1;
			free(n);
			break;
		}

		free(n);

		userlist += part_count;
		count -= part_count;
	}

	return res;
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
 * \param sess Struktura sesji
 * \param type Rodzaj zapytania
 * \param request Treść zapytania (może być równe NULL)
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup importexport
 */
int gg_userlist_request(struct gg_session *sess, char type, const char *request)
{
	int len;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	if (!request) {
		sess->userlist_blocks = 1;
		return gg_send_packet(sess, GG_USERLIST_REQUEST, &type, sizeof(type), NULL);
	}

	len = strlen(request);

	sess->userlist_blocks = 0;

	while (len > 2047) {
		sess->userlist_blocks++;

		if (gg_send_packet(sess, GG_USERLIST_REQUEST, &type, sizeof(type), request, 2047, NULL) == -1)
			return -1;

		if (type == GG_USERLIST_PUT)
			type = GG_USERLIST_PUT_MORE;

		request += 2047;
		len -= 2047;
	}

	sess->userlist_blocks++;

	return gg_send_packet(sess, GG_USERLIST_REQUEST, &type, sizeof(type), request, len, NULL);
}

/**
 * Wysyła do serwera zapytanie dotyczące listy kontaktów (10.0).
 *
 * Funkcja służy do importu lub eksportu listy kontaktów do serwera.
 * W odróżnieniu od funkcji \c gg_notify(), ta lista kontaktów jest przez
 * serwer jedynie przechowywana i nie ma wpływu na połączenie. Format
 * listy kontaktów jest jednak weryfikowany przez serwer, który stara się
 * synchronizować listę kontaktów zapisaną w formatach GG 7.0 oraz GG 10.0.
 * Serwer przyjmuje listy kontaktów przysłane w formacie niezgodnym z podanym
 * jako \c format_type, ale nie zachowuje ich, a przesłanie takiej listy jest
 * równoznaczne z usunięciem listy kontaktów.
 *
 * Program nie musi się przejmować kompresją listy kontaktów zgodną
 * z protokołem -- wysyła i odbiera kompletną listę zapisaną czystym tekstem.
 *
 * \param sess Struktura sesji
 * \param type Rodzaj zapytania
 * \param version Numer ostatniej znanej programowi wersji listy kontaktów lub 0
 * \param format_type Typ formatu listy kontaktów
 * \param request Treść zapytania (może być równe NULL)
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup importexport
 */
int gg_userlist100_request(struct gg_session *sess, char type, unsigned int version, char format_type, const char *request)
{
	struct gg_userlist100_request pkt;
	unsigned char *zrequest;
	size_t zrequest_len;
	int ret;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	pkt.type = type;
	pkt.version = gg_fix32(version);
	pkt.format_type = format_type;
	pkt.unknown1 = 0x01;

	if (request == NULL)
		return gg_send_packet(sess, GG_USERLIST100_REQUEST, &pkt, sizeof(pkt), NULL);

	zrequest = gg_deflate(request, &zrequest_len);

	if (zrequest == NULL) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_userlist100_request() gg_deflate() failed\n");
		return -1;
	}

	ret = gg_send_packet(sess, GG_USERLIST100_REQUEST, &pkt, sizeof(pkt), zrequest, zrequest_len, NULL);

	free(zrequest);

	return ret;
}

/**
 * Informuje rozmówcę o pisaniu wiadomości.
 *
 * \param sess Struktura sesji
 * \param recipient Numer adresata
 * \param length Długość wiadomości lub 0 jeśli jest pusta
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup messages
 */
int gg_typing_notification(struct gg_session *sess, uin_t recipient, int length){
	struct gg_typing_notification pkt;
	uin_t uin;

	pkt.length = gg_fix16(length);
	uin = gg_fix32(recipient);
	memcpy(&pkt.uin, &uin, sizeof(uin_t));

	return gg_send_packet(sess, GG_TYPING_NOTIFICATION, &pkt, sizeof(pkt), NULL);
}

/**
 * Rozłącza inną sesję multilogowania.
 *
 * \param gs Struktura sesji
 * \param conn_id Sesja do rozłączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup login
 */
int gg_multilogon_disconnect(struct gg_session *gs, gg_multilogon_id_t conn_id)
{
	struct gg_multilogon_disconnect pkt;

	pkt.conn_id = conn_id;

	return gg_send_packet(gs, GG_MULTILOGON_DISCONNECT, &pkt, sizeof(pkt), NULL);
}

/* @} */

/**
 * Sprawdza czy biblioteka obsługuje daną funkcję.
 *
 * \param feature Identyfikator funkcji.
 *
 * \return Wartość niezerowa jeśli funkcja jest obsłgiwana.
 *
 * \ingroup version
 */
int gg_libgadu_check_feature(gg_libgadu_feature_t feature)
{
	switch (feature)
	{
	case GG_LIBGADU_FEATURE_SSL:
#if defined(GG_CONFIG_HAVE_OPENSSL) || defined(GG_CONFIG_HAVE_GNUTLS)
		return 1;
#else
		return 0;
#endif

	case GG_LIBGADU_FEATURE_PTHREAD:
#ifdef GG_CONFIG_HAVE_PTHREAD
		return 1;
#else
		return 0;
#endif

	case GG_LIBGADU_FEATURE_USERLIST100:
#ifdef GG_CONFIG_HAVE_ZLIB
		return 1;
#else
		return 0;
#endif

	/* Celowo nie ma default, żeby kompilator wyłapał brakujące funkcje */

	}

	return 0;
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
