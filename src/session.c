/* $Id$ */

/*
 *  (C) Copyright 2001-2008 Wojtek Kaniewski <wojtekka@irc.pl>
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
 * \file session.c
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

static int gg_session_callback(struct gg_session *sess);

struct gg_session *gg_session_new(void)
{
	struct gg_session *gs;

	gs = malloc(sizeof(struct gg_session));

	if (gs == NULL)
		return NULL;

	memset(gs, 0, sizeof(struct gg_session));

	gs->type = GG_SESSION_GG;
	gs->callback = gg_session_callback;
	gs->destroy = gg_session_free;
	gs->pid = -1;
	gs->hash_type = GG_LOGIN_HASH_SHA1;

	gg_session_set_protocol_version(gs, GG_DEFAULT_PROTOCOL_VERSION);

	gg_session_set_resolver(gs, GG_RESOLVER_DEFAULT);
	
	return gs;
}

int gg_session_set_uin(struct gg_session *gs, uin_t uin)
{
	if (gs == NULL || uin == 0) {
		errno = EINVAL;
		return -1;
	}

	gs->uin = uin;

	return 0;
}

uin_t gg_session_get_uin(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->uin;
}

int gg_session_set_password(struct gg_session *gs, const char *password)
{
	char *tmp = NULL;

	if (gs == NULL || password == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (password != NULL) {
		tmp = strdup(password);

		if (tmp == NULL)
			return -1;
	}

	free(gs->password);
	gs->password = tmp;

	return 0;
}

const char *gg_session_get_password(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return gs->password;
}

int gg_session_set_async(struct gg_session *gs, int async)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->async = !!async;

	return 0;
}

int gg_session_get_async(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->async;
}

int gg_session_set_hash_type(struct gg_session *gs, gg_login_hash_t hash_type)
{
	if (gs == NULL || hash_type < GG_LOGIN_HASH_DEFAULT || hash_type > GG_LOGIN_HASH_SHA1) {
		errno = EINVAL;
		return -1;
	}

	if (hash_type == GG_LOGIN_HASH_DEFAULT)
		hash_type = GG_LOGIN_HASH_SHA1;	

	gs->hash_type = hash_type;

	return 0;
}

gg_login_hash_t gg_session_get_hash_type(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return GG_LOGIN_HASH_INVALID;
	}

	return gs->hash_type;
}

int gg_session_set_server(struct gg_session *gs, uint32_t address, uint16_t port)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->server_addr = address;
	gs->port = port;

	return 0;
}

int gg_session_get_server(struct gg_session *gs, uint32_t *address, uint16_t *port)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (address != NULL)
		*address = gs->server_addr;

	if (port != NULL)
		*port = gs->port;

	return 0;
}
int gg_session_set_external_address(struct gg_session *gs, uint32_t address, uint16_t port)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->external_addr = address;
	gs->external_port = port;

	return 0;
}

int gg_session_get_external_address(struct gg_session *gs, uint32_t *address, uint16_t *port)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (address != NULL)
		*address = gs->external_addr;

	if (port != NULL)
		*port = gs->external_port;

	return 0;
}

int gg_session_set_protocol_version(struct gg_session *gs, int protocol)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->protocol_version = protocol;

	if (GG_SESSION_PROTOCOL_8_0(gs))
		gs->max_descr_length = GG_STATUS_DESCR_MAXSIZE;
	else
		gs->max_descr_length = GG_STATUS_DESCR_MAXSIZE_PRE_8_0;

	return 0;
}

int gg_session_get_protocol_version(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->protocol_version;
}

int gg_session_set_client_version(struct gg_session *gs, const char *version)
{
	char *tmp = NULL;

	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (version != NULL) {
		tmp = strdup(version);

		if (tmp == NULL)
			return -1;
	}

	free(gs->client_version);
	gs->client_version = tmp;

	return 0;
}

const char *gg_session_get_client_version(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return gs->client_version;
}

int gg_session_set_image_size(struct gg_session *gs, int image_size)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->image_size = image_size;

	return 0;
}

int gg_session_get_image_size(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->image_size;
}

int gg_session_set_last_message(struct gg_session *gs, int last_message)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->last_sysmsg = last_message;

	return 0;
}

int gg_session_get_last_message(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->last_sysmsg;
}

int gg_session_set_encoding(struct gg_session *gs, gg_encoding_t encoding)
{
	if (gs == NULL || encoding < GG_ENCODING_CP1250 || encoding > GG_ENCODING_UTF8) {
		errno = EINVAL;
		return -1;
	}

	gs->encoding = encoding;

	return 0;
}

gg_encoding_t gg_session_get_encoding(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return GG_ENCODING_INVALID;
	}

	return gs->encoding;
}

int gg_session_set_flag(struct gg_session *gs, gg_session_flag_t flag, int value)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch (flag) {
		case GG_SESSION_FLAG_ERA_OMNIX:
			if (value)
				gs->protocol_flags |= GG_ERA_OMNIX_MASK;
			else
				gs->protocol_flags &= ~GG_ERA_OMNIX_MASK;
			break;

		case GG_SESSION_FLAG_AUDIO:
			if (value)
				gs->protocol_flags |= GG_HAS_AUDIO_MASK;
			else
				gs->protocol_flags &= ~GG_HAS_AUDIO_MASK;
			break;

		case GG_SESSION_FLAG_CLEAR_PASSWORD:
			if (value)
				gs->flags |= (1 << flag);
			else
				gs->flags &= ~(1 << flag);
			break;

		default:
			errno = EINVAL;
			return -1;
	}

	return 0;
}

int gg_session_get_flag(struct gg_session *gs, gg_session_flag_t flag)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch (flag) {
		case GG_SESSION_FLAG_ERA_OMNIX:
			return (gs->protocol_flags & GG_ERA_OMNIX_MASK) ? 1 : 0;

		case GG_SESSION_FLAG_AUDIO:
			return (gs->protocol_flags & GG_HAS_AUDIO_MASK) ? 1 : 0;

		case GG_SESSION_FLAG_CLEAR_PASSWORD:
			return (gs->flags & (1 << flag)) ? 1 : 0;

		default:
			errno = EINVAL;
			return -1;
	}
}

int gg_session_set_status(struct gg_session *gs, int status, const char *descr, time_t time)
{
	char *tmp = NULL;
	int res = 0;

	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (descr != NULL) {
		// TODO: konwersja CP1250<->UTF-8

		tmp = strdup(descr);
		
		if (tmp == NULL)
			return -1;

		// TODO: nie ciąć w środku znaku utf-8

		if (strlen(tmp) > gs->max_descr_length)
			tmp[gs->max_descr_length] = 0;
	}

	gs->status_time = time;

	if (gs->state != GG_STATE_CONNECTED) {
		gs->initial_status = status;
		free(gs->initial_descr);
		gs->initial_descr = tmp;
	} else {
		struct gg_new_status p;
		uint32_t new_time;
		int packet_type;
		int append_null = 0;
		int res;

		// dodaj flagę obsługi połączeń głosowych zgodną z GG 7.x

		if (GG_SESSION_PROTOCOL_7_7(gs) && (gs->protocol_flags & GG_HAS_AUDIO_MASK) && !GG_S_I(status))
			status |= GG_STATUS_VOICE_MASK;

		p.status = gg_fix32(status);

		gs->status = status;
		free(gs->status_descr);
		gs->status_descr = tmp;

		if (GG_SESSION_PROTOCOL_8_0(gs)) {
			packet_type = GG_NEW_STATUS80;
			append_null = 1;
		} else {
			packet_type = GG_NEW_STATUS;
			append_null = (time != 0);
		}

		if (time)
			new_time = gg_fix32(time);

		res = gg_send_packet(gs,
				     packet_type,
				     &p,
				     sizeof(p),
				     (tmp) ? tmp : NULL,
				     (tmp) ? strlen(tmp) : 0,	// TODO: unicode
				     (append_null) ? "\0" : NULL,
				     (append_null) ? 1 : 0,
				     (time) ? &new_time : NULL,
				     (time) ? sizeof(new_time) : 0,
				     NULL);
	}

	return res;
}

int gg_session_get_status(struct gg_session *gs, int *status, const char **descr, time_t *time)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (status != NULL)
		*status = (gs->state == GG_STATE_CONNECTED) ? gs->status : gs->initial_status;
	
	if (descr != NULL)
		*descr = (gs->state == GG_STATE_CONNECTED) ? gs->initial_descr : gs->status_descr;
	
	if (time != NULL)
		*time = gs->status_time;

	return 0;
}

int gg_session_get_fd(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->fd;
}

int gg_session_get_check(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->check;
}

int gg_session_get_timeout(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return gs->timeout;
}

int gg_session_is_disconnected(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return (gs->state == GG_STATE_IDLE);
}

int gg_session_is_connecting(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return (gs->state != GG_STATE_IDLE && gs->state != GG_STATE_CONNECTED);
}

int gg_session_is_connected(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	return (gs->state == GG_STATE_CONNECTED);
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

int gg_session_connect(struct gg_session *gs)
{
	char *hostname;
	int port;

	if (gs == NULL || gs->uin == 0 || gs->password == NULL) {
		errno = EINVAL;
		return -1;
	}

	gs->state = GG_STATE_RESOLVING;
	gs->check = GG_CHECK_READ;
	gs->timeout = GG_DEFAULT_TIMEOUT;

	if (gg_proxy_enabled) {
		hostname = gg_proxy_host;
		gs->proxy_port = port = gg_proxy_port;
	} else {
		hostname = GG_APPMSG_HOST;
		port = GG_APPMSG_PORT;
	}

	// XXX przenieść gdzie indziej

	if (gs->port == 0)	
		gs->port = (gg_proxy_enabled) ? GG_HTTPS_PORT : GG_DEFAULT_PORT;

	if (!gs->async) {
		struct in_addr addr;

		if (!gs->server_addr) {
			if ((addr.s_addr = inet_addr(hostname)) == INADDR_NONE) {
				if (gg_gethostbyname(hostname, &addr, 0) == -1) {
					gg_debug(GG_DEBUG_MISC, "// gg_login() host \"%s\" not found\n", hostname);
					return -1;
				}
			}
		} else {
			addr.s_addr = gs->server_addr;
			port = gs->port;
		}

		gs->hub_addr = addr.s_addr;

		if (gg_proxy_enabled)
			gs->proxy_addr = addr.s_addr;

		if ((gs->fd = gg_connect(&addr, port, 0)) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_login() connection failed (errno=%d, %s)\n", errno, strerror(errno));

			/* nie wyszło? próbujemy portu 443. */
			if (gs->server_addr) {
				gs->port = GG_HTTPS_PORT;

				if ((gs->fd = gg_connect(&addr, GG_HTTPS_PORT, 0)) == -1) {
					/* ostatnia deska ratunku zawiodła?
					 * w takim razie zwijamy manatki. */
					gg_debug_session(gs, GG_DEBUG_MISC, "// gg_login() connection failed (errno=%d, %s)\n", errno, strerror(errno));
					goto fail;
				}
			} else {
				goto fail;
			}
		}

		if (gs->server_addr)
			gs->state = GG_STATE_CONNECTING_GG;
		else
			gs->state = GG_STATE_CONNECTING_HUB;

		while (gs->state != GG_STATE_CONNECTED) {
			struct gg_event *e;

			if (!(e = gg_watch_fd(gs))) {
				gg_debug(GG_DEBUG_MISC, "// gg_login() critical error in gg_watch_fd()\n");
				return -1;
			}

			if (e->type == GG_EVENT_CONN_FAILED) {
				errno = EACCES;
				gg_debug(GG_DEBUG_MISC, "// gg_login() could not login\n");
				gg_event_free(e);
				return -1;
			}

			gg_event_free(e);
		}

		return 0;
	}

	if (!gs->server_addr || gg_proxy_enabled) {
		if (gs->resolver_start(&gs->fd, &gs->resolver, hostname) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_login() resolving failed (errno=%d, %s)\n", errno, strerror(errno));
			return -1;
		}
	} else {
		if ((gs->fd = gg_connect(&gs->server_addr, gs->port, gs->async)) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_login() direct connection failed (errno=%d, %s)\n", errno, strerror(errno));
			return -1;
		}
		gs->state = GG_STATE_CONNECTING_GG;
		gs->check = GG_CHECK_WRITE;
		gs->soft_timeout = 1;
	}

	return 0;

fail:
	return -1;
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
 * utracone przy zrywaniu połączenia.
 *
 * \param gs Struktura sesji
 *
 * \ingroup login
 */
int gg_session_disconnect(struct gg_session *gs)
{
	if (gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	gg_debug_session(gs, GG_DEBUG_FUNCTION, "** gg_session_disconnect(%p);\n", gs);

	if (!GG_S_NA(gs->status) && gs->status_descr != NULL)
		gg_session_set_status(gs, GG_STATUS_NOT_AVAIL_DESCR, gs->status_descr, gs->status_time);

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (gs->ssl)
		SSL_shutdown(gs->ssl);
#endif

	gs->resolver_cleanup(&gs->resolver, 1);

	if (gs->fd != -1) {
		shutdown(gs->fd, SHUT_RDWR);
		close(gs->fd);
		gs->fd = -1;
	}

	if (gs->send_buf) {
		free(gs->send_buf);
		gs->send_buf = NULL;
		gs->send_left = 0;
	}

	gs->state = GG_STATE_IDLE;

	return 0;
}

/**
 * \internal Stub funkcji \c gg_session_disconnect() dla zachowania ABI. 
 *
 * \param gs Struktura sesji
 */
void gg_logoff(struct gg_session *gs)
{
	gg_session_disconnect(gs);
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
void gg_session_free(struct gg_session *sess)
{
	struct gg_dcc7 *dcc;

	if (sess == NULL)
		return;

	free(sess->password);
	free(sess->initial_descr);
	free(sess->status_descr);
	free(sess->client_version);
	free(sess->header_buf);

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (sess->ssl != NULL)
		SSL_free(sess->ssl);

	if (sess->ssl_ctx != NULL)
		SSL_CTX_free(sess->ssl_ctx);
#endif
 
	sess->resolver_cleanup(&sess->resolver, 1);

	if (sess->fd != -1)
		close(sess->fd);

	while (sess->images != NULL)
		gg_image_queue_remove(sess, sess->images, 1);

	if (sess->send_buf != NULL)
		free(sess->send_buf);

	for (dcc = sess->dcc7_list; dcc != NULL; dcc = dcc->next)
		dcc->sess = NULL;

	free(sess);
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
	if (sess == NULL) {
		errno = EFAULT;
		return -1;
	}

	sess->event = gg_watch_fd(sess);

	return (sess->event != NULL) ? 0 : -1;
}
