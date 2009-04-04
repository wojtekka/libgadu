/* $Id$ */

/*
 *  (C) Copyright 2001-2009 Wojtek Kaniewski <wojtekka@irc.pl>
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
#include "protocol.h"
#include "encoding.h"
#include "message.h"

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
	gs->encoding = GG_ENCODING_UTF8;
	gs->hash_type = GG_LOGIN_HASH_SHA1;

	gg_session_set_protocol_version(gs, GG_DEFAULT_PROTOCOL_VERSION);

	gg_session_set_resolver(gs, GG_RESOLVER_DEFAULT);
	
	return gs;
}

int gg_session_set_uin(struct gg_session *gs, uin_t uin)
{
	GG_SESSION_CHECK(gs, -1);

	if (uin == 0) {
		errno = EINVAL;
		return -1;
	}

	gs->uin = uin;

	return 0;
}

uin_t gg_session_get_uin(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->uin;
}

int gg_session_set_password(struct gg_session *gs, const char *password)
{
	char *tmp = NULL;

	GG_SESSION_CHECK(gs, -1);

	if (password == NULL) {
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
	GG_SESSION_CHECK(gs, NULL);

	return gs->password;
}

int gg_session_set_async(struct gg_session *gs, int async)
{
	GG_SESSION_CHECK(gs, -1);

	gs->async = !!async;

	return 0;
}

int gg_session_get_async(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->async;
}

int gg_session_set_hash_type(struct gg_session *gs, gg_login_hash_t hash_type)
{
	GG_SESSION_CHECK(gs, -1);

	if (hash_type < GG_LOGIN_HASH_DEFAULT || hash_type > GG_LOGIN_HASH_SHA1) {
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
	GG_SESSION_CHECK(gs, (gg_login_hash_t) -1);

	return gs->hash_type;
}

int gg_session_set_server(struct gg_session *gs, uint32_t address, uint16_t port)
{
	GG_SESSION_CHECK(gs, -1);

	gs->server_addr = address;
	gs->port = port;

	return 0;
}

int gg_session_get_server(struct gg_session *gs, uint32_t *address, uint16_t *port)
{
	GG_SESSION_CHECK(gs, -1);

	if (address != NULL)
		*address = gs->server_addr;

	if (port != NULL)
		*port = gs->port;

	return 0;
}

int gg_session_set_external_address(struct gg_session *gs, uint32_t address, uint16_t port)
{
	GG_SESSION_CHECK(gs, -1);

	gs->external_addr = address;
	gs->external_port = port;

	return 0;
}

int gg_session_get_external_address(struct gg_session *gs, uint32_t *address, uint16_t *port)
{
	GG_SESSION_CHECK(gs, -1);

	if (address != NULL)
		*address = gs->external_addr;

	if (port != NULL)
		*port = gs->external_port;

	return 0;
}

int gg_session_set_bind_address(struct gg_session *gs, uint32_t address)
{
	GG_SESSION_CHECK(gs, -1);

	gs->bind_address = address;

	return 0;
}

uint32_t gg_session_get_bind_address(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, (uint32_t) -1);

	return gs->bind_address;
}

int gg_session_set_protocol_version(struct gg_session *gs, int protocol)
{
	GG_SESSION_CHECK(gs, -1);

	gs->protocol_version = protocol;

	if (GG_SESSION_IS_PROTOCOL_8_0(gs)) {
		gs->max_descr_length = GG_STATUS_DESCR_MAXSIZE;
		gs->ping_period = 256;
	} else {
		gs->max_descr_length = GG_STATUS_DESCR_MAXSIZE_PRE_8_0;
		gs->ping_period = 60;	// XXX sprawdzić
	}

	// XXX poniższe parametry są różne dla protokołu wcześniejszego niż
	// 7.0, więc wypadałoby je poprawić, jeśli mamy wspierać wcześniejsze
	// wersje.

	gs->max_contacts_chunk_length = 2047;	// XXX sprawdzić 8.0

	return 0;
}

int gg_session_get_protocol_version(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->protocol_version;
}

int gg_session_set_client_version(struct gg_session *gs, const char *version)
{
	char *tmp = NULL;

	GG_SESSION_CHECK(gs, -1);

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
	GG_SESSION_CHECK(gs, NULL);

	return gs->client_version;
}

int gg_session_set_image_size(struct gg_session *gs, int image_size)
{
	GG_SESSION_CHECK(gs, -1);

	gs->image_size = image_size;

	return 0;
}

int gg_session_get_image_size(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->image_size;
}

int gg_session_set_last_message(struct gg_session *gs, int last_message)
{
	GG_SESSION_CHECK(gs, -1);

	gs->last_sysmsg = last_message;

	return 0;
}

int gg_session_get_last_message(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->last_sysmsg;
}

int gg_session_set_encoding(struct gg_session *gs, gg_encoding_t encoding)
{
	GG_SESSION_CHECK(gs, -1);

	if (encoding < GG_ENCODING_CP1250 || encoding > GG_ENCODING_UTF8) {
		errno = EINVAL;
		return -1;
	}

	gs->encoding = encoding;

	return 0;
}

gg_encoding_t gg_session_get_encoding(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, (gg_encoding_t) -1);

	return gs->encoding;
}

int gg_session_set_flag(struct gg_session *gs, gg_session_flag_t flag, int value)
{
	GG_SESSION_CHECK(gs, -1);

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
	GG_SESSION_CHECK(gs, -1);

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

	// return jest w switch/default
}

static int gg_session_set_status_8(struct gg_session *gs, int status, const char *descr)
{
	char *tmp;
	int res = 0;

	if (descr != NULL)
		tmp = gg_encoding_convert(descr, gs->encoding, GG_ENCODING_UTF8, -1, gs->max_descr_length);

	if (!GG_SESSION_IS_CONNECTED(gs)) {
		gs->initial_status = status;
		free(gs->initial_descr);
		gs->initial_descr = tmp;
	} else {
		struct gg_new_status80 p;

		p.status = gg_fix32(status);
		p.dunno1 = 0;
		p.descr_len = gg_fix32((tmp != NULL) ? strlen(tmp) : 0);

		gs->status = status;
		free(gs->status_descr);
		gs->status_descr = tmp;

		res = gg_send_packet(gs,
				     GG_NEW_STATUS80,
				     &p,
				     sizeof(p),
				     (tmp != NULL) ? tmp : NULL,
				     (tmp != NULL) ? strlen(tmp) : 0,
				     NULL);
	}

	return res;
}

static int gg_session_set_status_7(struct gg_session *gs, int status, const char *descr, time_t time)
{
	char *tmp;
	int res = 0;

	if (descr != NULL)
		tmp = gg_encoding_convert(descr, gs->encoding, GG_ENCODING_CP1250, -1, gs->max_descr_length);

	gs->status_time = time;

	if (!GG_SESSION_IS_CONNECTED(gs)) {
		gs->initial_status = status;
		free(gs->initial_descr);
		gs->initial_descr = tmp;
	} else {
		struct gg_new_status p;
		uint32_t new_time;

		// dodaj flagę obsługi połączeń głosowych zgodną z GG 7.x

		if (GG_SESSION_IS_PROTOCOL_7_7(gs) && (gs->protocol_flags & GG_HAS_AUDIO_MASK) && !GG_S_I(status))
			status |= GG_STATUS_VOICE_MASK;

		p.status = gg_fix32(status);

		gs->status = status;
		free(gs->status_descr);
		gs->status_descr = tmp;

		new_time = gg_fix32(time);

		res = gg_send_packet(gs,
				     GG_NEW_STATUS,
				     &p,
				     sizeof(p),
				     (tmp) ? tmp : NULL,
				     (tmp) ? strlen(tmp) : 0,
				     (time != 0) ? "\0" : NULL,
				     (time != 0) ? 1 : 0,
				     (time) ? &new_time : NULL,
				     (time) ? sizeof(new_time) : 0,
				     NULL);
	}

	return res;
}

int gg_session_set_status(struct gg_session *gs, int status, const char *descr, time_t time)
{
	GG_SESSION_CHECK(gs, -1);

	if (GG_S(status) == GG_STATUS_AVAIL && descr != NULL)
		status = GG_STATUS_AVAIL_DESCR | (status & GG_STATUS_FRIENDS_MASK);

	if (GG_S(status) == GG_STATUS_BUSY && descr != NULL)
		status = GG_STATUS_BUSY_DESCR | (status & GG_STATUS_FRIENDS_MASK);

	if (GG_S(status) == GG_STATUS_INVISIBLE && descr != NULL)
		status = GG_STATUS_INVISIBLE_DESCR | (status & GG_STATUS_FRIENDS_MASK);

	if (GG_S(status) == GG_STATUS_NOT_AVAIL && descr != NULL)
		status = GG_STATUS_NOT_AVAIL | (status & GG_STATUS_FRIENDS_MASK);

	if (GG_SESSION_IS_PROTOCOL_8_0(gs))
		return gg_session_set_status_8(gs, status, descr);
	else
		return gg_session_set_status_7(gs, status, descr, time);
}

int gg_session_get_status(struct gg_session *gs, int *status, const char **descr, time_t *time)
{
	GG_SESSION_CHECK(gs, -1);

	if (status != NULL)
		*status = GG_SESSION_IS_CONNECTED(gs) ? gs->status : gs->initial_status;
	
	if (descr != NULL)
		*descr = GG_SESSION_IS_CONNECTED(gs) ? gs->initial_descr : gs->status_descr;
	
	if (time != NULL)
		*time = gs->status_time;

	return 0;
}

int gg_session_get_fd(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->fd;
}

int gg_session_get_check(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->check;
}

int gg_session_get_timeout(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->timeout;
}

int gg_session_is_idle(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return GG_SESSION_IS_IDLE(gs);
}

int gg_session_is_connecting(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return GG_SESSION_IS_CONNECTING(gs);
}

int gg_session_is_connected(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return GG_SESSION_IS_CONNECTED(gs);
}

int gg_session_get_ping_period(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->ping_period;
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
int gg_session_ping(struct gg_session *gs)
{
	GG_SESSION_CHECK_CONNECTED(gs, -1);

	return gg_send_packet(gs, GG_PING, NULL);
}

int gg_session_connect(struct gg_session *gs)
{
	char *hostname;
	int port;

	GG_SESSION_CHECK(gs, -1);

	if (!GG_SESSION_IS_IDLE(gs)) {
		errno = EINPROGRESS;
		return -1;
	}

	if (gs->uin == 0 || gs->password == NULL) {
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
					gg_debug(GG_DEBUG_MISC, "// gg_session_connect() host \"%s\" not found\n", hostname);
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
			gg_debug(GG_DEBUG_MISC, "// gg_session_connect() connection failed (errno=%d, %s)\n", errno, strerror(errno));

			/* nie wyszło? próbujemy portu 443. */
			if (gs->server_addr) {
				gs->port = GG_HTTPS_PORT;

				if ((gs->fd = gg_connect(&addr, GG_HTTPS_PORT, 0)) == -1) {
					/* ostatnia deska ratunku zawiodła?
					 * w takim razie zwijamy manatki. */
					gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_connect() connection failed (errno=%d, %s)\n", errno, strerror(errno));
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

		while (!GG_SESSION_IS_CONNECTED(gs)) {
			struct gg_event *e;

			if (!(e = gg_watch_fd(gs))) {
				gg_debug(GG_DEBUG_MISC, "// gg_session_connect() critical error in gg_watch_fd()\n");
				return -1;
			}

			if (e->type == GG_EVENT_CONN_FAILED) {
				errno = EACCES;
				gg_debug(GG_DEBUG_MISC, "// gg_session_connect() could not login\n");
				gg_event_free(e);
				return -1;
			}

			gg_event_free(e);
		}

		return 0;
	}

	if (!gs->server_addr || gg_proxy_enabled) {
		if (gs->resolver_start(&gs->fd, &gs->resolver, hostname) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_session_connect() resolving failed (errno=%d, %s)\n", errno, strerror(errno));
			return -1;
		}
	} else {
		if ((gs->fd = gg_connect(&gs->server_addr, gs->port, gs->async)) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_session_connect() direct connection failed (errno=%d, %s)\n", errno, strerror(errno));
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
 * Funkcja zamyka połączenie bez przeprowadzania przewidzianych przez protokół.
 *
 * \param gs Struktura sesji
 *
 * \return 
 */
int gg_session_shutdown(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

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
 * Kończy połączenie z serwerem.
 *
 * Funkcja nie zwalnia zasobów, więc po jej wywołaniu należy użyć
 * \c gg_free_session(). Jeśli wymagana jest pewność, że opis zostanie
 * ustawiony, należy ustawić flagę \c linger -- w tym wypadku połączenie
 * nie jest zrywane od razu, a dopiero po odebraniu potwierdzenia od
 * serwera. 
 *
 * \note Jeśli w buforze nadawczym połączenia z serwerem znajdują się jeszcze
 * dane (np. z powodu strat pakietów na łączu), prawdopodobnie zostaną one
 * utracone przy zrywaniu połączenia.
 *
 * \param gs Struktura sesji
 * \param linger Flaga opóźnienia rozłączenia aż do otrzymania potwierdzenia
 *
 * \ingroup login
 */
int gg_session_disconnect(struct gg_session *gs, int linger)
{
	int res = 0;

	GG_SESSION_CHECK_CONNECTED(gs, -1);

	gg_debug_session(gs, GG_DEBUG_FUNCTION, "** gg_session_disconnect(%p);\n", gs);

	if (!GG_S_NA(gs->status) && gs->status_descr != NULL) {
		res = gg_session_set_status(gs, GG_STATUS_NOT_AVAIL_DESCR, gs->status_descr, gs->status_time);
	} else if (linger) {
		res = gg_session_set_status(gs, GG_STATUS_NOT_AVAIL, NULL, gs->status_time);
	}

	if (linger) {
		/* Jeśli zmiana stanu się nie powiodła, to połączenie jest
                 * zamykane natychmiast i funkcja zwraca -1. */

		if (res == -1) {
			gg_session_shutdown(gs);
			return -1;
		}

		if (!gs->async) {
			struct gg_header *gh;

			// XXX timeout

			while ((gh = gg_recv_packet(gs)) != NULL) {
				int type;

				type = gh->type;
				free(gh);

				if (type == GG_DISCONNECTING2)
					break;
			}

			if (gh == NULL) {
				gg_session_shutdown(gs);
				return -1;
			}
		}

		gs->state = GG_STATE_DISCONNECTING;
	} else {
		gs->timeout = 5;	// XXX czy 5 sekund wystarczy?
		gg_session_shutdown(gs);
	}

	return 0;
}

static uint32_t gg_session_send_message_7(struct gg_session *gs, gg_message_t *gm)
{
	struct gg_send_msg s;
	unsigned char *attr_header = NULL, attr_buf[3];
	char *text = NULL;

	if (gm->text != NULL) {
		if (gs->encoding != GG_ENCODING_CP1250) {
			text = gg_encoding_convert(gm->text, gs->encoding, GG_ENCODING_CP1250, -1, -1);
			goto failure;
		} else {
			text = gm->text;
		}
	} else if (gm->text == NULL && gm->html != NULL) {
		text = gg_message_html_to_text(gm->html);

		if (text == NULL)
			goto failure;

		if (gs->encoding != GG_ENCODING_CP1250) {
			char *tmp;

			tmp = gg_encoding_convert(text, gs->encoding, GG_ENCODING_CP1250, -1, -1);

			free(text);

			if (tmp == NULL)
				goto failure;

			text = tmp;
		}
	} else {
		errno = EINVAL;
		goto failure;
	}

	if (gm->seq != (uint32_t) -1)
		s.seq = gg_fix32(gm->seq);
	else
		s.seq = gg_fix32(rand());

	s.msgclass = gg_fix32(gm->msgclass);

	if ((gm->attributes != NULL) && (gm->attributes_length > 0)) {
		// XXX zrobić strukturę?
		attr_buf[0] = 0x02;
		attr_buf[1] = gm->attributes_length & 255;
		attr_buf[2] = (gm->attributes_length >> 8) & 255;
		attr_header = attr_buf;
	}

	if (gm->recipient_count > 1) {
		struct gg_msg_recipients r;
		uin_t *recipients;
		int i, j, k;

		r.flag = 0x01;
		r.count = gg_fix32(gm->recipient_count - 1);

		recipients = malloc(sizeof(uin_t) * gm->recipient_count);

		if (recipients == NULL)
			goto failure;

		for (i = 0; i < gm->recipient_count; i++) {

			s.recipient = gg_fix32(gm->recipients[i]);

			for (j = 0, k = 0; j < gm->recipient_count; j++) {
				if (gm->recipients[j] != gm->recipients[i])
					recipients[k++] = gg_fix32(gm->recipients[j]);
			}

			if (gg_send_packet(gs, GG_SEND_MSG, &s, sizeof(s), text, strlen(text), "\0", 1, &r, sizeof(r), recipients, (gm->recipient_count - 1) * sizeof(uin_t), attr_header, 3, gm->attributes, gm->attributes_length, NULL) == -1) {
				free(recipients);
				goto failure;
			}
		}

		free(recipients);
	} else {
		s.recipient = gg_fix32(gm->recipients[0]);

		if (gg_send_packet(gs, GG_SEND_MSG, &s, sizeof(s), text, strlen(text), "\0", 1, attr_header, 3, gm->attributes, gm->attributes_length, NULL) == -1)
			goto failure;
	}

	if (text != gm->text)
		free(text);

	return gg_fix32(s.seq);

failure:
	if (text != gm->text)
		free(text);

	return (uint32_t) -1;
}

static uint32_t gg_session_send_message_8(struct gg_session *gs, gg_message_t *gm)
{
	struct gg_send_msg80 s;
	char attr_header[3];
	const char *attr;
	int attr_len;
	char *text = NULL, *html = NULL;
	time_t now;

	if (gm->html != NULL) {
		if (gs->encoding != GG_ENCODING_UTF8) {
			html = gg_encoding_convert(gm->html, gs->encoding, GG_ENCODING_UTF8, -1, -1);

			if (html == NULL)
				goto failure;
		} else
			html = gm->html;
	} else if (gm->html == NULL && gm->text != NULL) {
		html = gg_message_text_to_html(gm->text, gm->attributes, gm->attributes_length);

		if (html == NULL)
			goto failure;

		if (gs->encoding != GG_ENCODING_UTF8) {
			char *tmp;

			tmp = gg_encoding_convert(html, gs->encoding, GG_ENCODING_UTF8, -1, -1);

			free(html);

			if (tmp == NULL)
				goto failure;

			html = tmp;
		}
	} else {
		errno = EINVAL;
		goto failure;
	}

	if (gm->text != NULL) {
		if (gs->encoding != GG_ENCODING_CP1250) {
			text = gg_encoding_convert(gm->text, gs->encoding, GG_ENCODING_CP1250, -1, -1);
			if (text == NULL)
				goto failure;
		} else {
			text = gm->text;
		}
	} else if (gm->text == NULL && gm->html != NULL) {
		text = gg_message_html_to_text(gm->html);

		if (text == NULL)
			goto failure;

		if (gs->encoding != GG_ENCODING_CP1250) {
			char *tmp;

			tmp = gg_encoding_convert(text, gs->encoding, GG_ENCODING_CP1250, -1, -1);

			free(text);

			if (tmp == NULL)
				goto failure;

			text = tmp;
		}
	}

	// Drobne odchylenie od protokołu. Jeśli wysyłamy kilka wiadomości
	// w ciągu jednej sekundy, zwiększamy poprzednią wartość, żeby każda
	// wiadomość miała unikalny numer.

	now = time(NULL);

	if (now > gm->seq)
		gm->seq = now;
	else
		gm->seq++;

	s.seq = gg_fix32(gm->seq);
	s.msgclass = gg_fix32(gm->msgclass);
	s.offset_plain = sizeof(s) + strlen(html) + 1;
	s.offset_attr = s.offset_plain + strlen(text) + 1;

	if ((gm->attributes != NULL) && (gm->attributes_length > 0)) {
		attr = gm->attributes;
		attr_len = gm->attributes_length;
	} else {
		attr = "\x00\x00\x08\x00\x00\x00";
		attr_len = 6;
	}

	// XXX zrobić strukturę?
	attr_header[0] = 0x02;
	attr_header[1] = attr_len & 255;
	attr_header[2] = (attr_len >> 8) & 255;

	if (gm->recipient_count > 1) {
		struct gg_msg_recipients r;
		uin_t *recipients;
		int i, j, k;

		r.flag = 0x01;
		r.count = gg_fix32(gm->recipient_count - 1);

		recipients = malloc(sizeof(uin_t) * gm->recipient_count);

		if (recipients == NULL)
			goto failure;

		for (i = 0; i < gm->recipient_count; i++) {

			s.recipient = gg_fix32(gm->recipients[i]);

			for (j = 0, k = 0; j < gm->recipient_count; j++) {
				if (gm->recipients[j] != gm->recipients[i])
					recipients[k++] = gg_fix32(gm->recipients[j]);
			}

			if (gg_send_packet(gs, GG_SEND_MSG80, &s, sizeof(s), html, strlen(html), "\0", 1, text, strlen(text), "\0", 1, &r, sizeof(r), recipients, (gm->recipient_count - 1) * sizeof(uin_t), attr_header, 3, attr, attr_len, NULL) == -1) {
				free(recipients);
				goto failure;
			}
		}

		free(recipients);
	} else {
		s.recipient = gg_fix32(gm->recipients[0]);

		if (gg_send_packet(gs, GG_SEND_MSG80, &s, sizeof(s), html, strlen(html), "\0", 1, text, strlen(text), "\0", 1, attr_header, 3, attr, attr_len, NULL) == -1)
			goto failure;
	}

	if (html != gm->html)
		free(html);

	if (text != gm->text)
		free(text);

	return gg_fix32(s.seq);

failure:
	if (html != gm->html)
		free(html);

	if (text != gm->text)
		free(text);

	return (uint32_t) -1;
}

uint32_t gg_session_send_message(struct gg_session *gs, gg_message_t *gm)
{
	GG_SESSION_CHECK_CONNECTED(gs, (uint32_t) -1);

	if (gm->recipient_count < 1) {
		errno = EINVAL;
		return (uint32_t) -1;
	}

	if (GG_SESSION_IS_PROTOCOL_8_0(gs))
		return gg_session_send_message_8(gs, gm);
	else
		return gg_session_send_message_7(gs, gm);
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
int gg_session_contacts_request(struct gg_session *gs, uint8_t type, const char *request)
{
	size_t len;
	int packet_type;

	if (GG_SESSION_IS_PROTOCOL_8_0(gs))
		packet_type = GG_USERLIST_REQUEST80;
	else
		packet_type = GG_USERLIST_REQUEST;

	if (request != NULL)
		len = strlen(request);
	else
		len = 0;

	// Liczymy liczbę bloków, żeby po otrzymaniu takiej samej liczby
	// potwierdzeń poinformować aplikację o udanej operacji.
	//
	gs->userlist_blocks = 0;

	while (request != NULL && len > gs->max_contacts_chunk_length) {
		gs->userlist_blocks++;

		if (gg_send_packet(gs, GG_USERLIST_REQUEST, &type, sizeof(type), request, gs->max_contacts_chunk_length, NULL) == -1)
			return -1;

		if (type == GG_USERLIST_PUT)
			type = GG_USERLIST_PUT_MORE;

		request += gs->max_contacts_chunk_length;
		len -= gs->max_contacts_chunk_length;
	}

	gs->userlist_blocks++;

	return gg_send_packet(gs, GG_USERLIST_REQUEST, &type, sizeof(type), request, len, NULL);
}

int gg_session_export_contacts(struct gg_session *gs, const char *contacts)
{
	GG_SESSION_CHECK_CONNECTED(gs, -1);

	return gg_session_contacts_request(gs, GG_USERLIST_PUT, contacts);
}

int gg_session_import_contacts(struct gg_session *gs)
{
	GG_SESSION_CHECK_CONNECTED(gs, -1);

	return gg_session_contacts_request(gs, GG_USERLIST_GET, NULL);
}

/**
 * Zwalnia zasoby używane przez połączenie z serwerem. Funkcję należy wywołać
 * po zamknięciu połączenia z serwerem, by nie doprowadzić do wycieku zasobów
 * systemowych.
 *
 * \param gs Struktura sesji
 *
 * \ingroup login
 */
void gg_session_free(struct gg_session *gs)
{
	struct gg_dcc7 *dcc;

	if (gs == NULL)
		return;

	free(gs->password);
	free(gs->initial_descr);
	free(gs->status_descr);
	free(gs->client_version);
	free(gs->header_buf);
	free(gs->recv_buf);

#ifdef GG_CONFIG_HAVE_OPENSSL
	if (gs->ssl != NULL)
		SSL_free(gs->ssl);

	if (gs->ssl_ctx != NULL)
		SSL_CTX_free(gs->ssl_ctx);
#endif
 
	gs->resolver_cleanup(&gs->resolver, 1);

	if (gs->fd != -1)
		close(gs->fd);

	while (gs->images != NULL)
		gg_image_queue_remove(gs, gs->images, 1);

	if (gs->send_buf != NULL)
		free(gs->send_buf);

	for (dcc = gs->dcc7_list; dcc != NULL; dcc = dcc->next)
		dcc->sess = NULL;

	free(gs);
}

/**
 * \internal Funkcja zwrotna sesji.
 *
 * Pole \c callback struktury \c gg_session zawiera wskaźnik do tej funkcji.
 * Wywołuje ona \c gg_watch_fd i zachowuje wynik w polu \c event.
 *
 * \note Korzystanie z tej funkcjonalności nie jest już zalecane.
 *
 * \param gs Struktura sesji
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_session_callback(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	gs->event = gg_watch_fd(gs);

	return (gs->event != NULL) ? 0 : -1;
}
