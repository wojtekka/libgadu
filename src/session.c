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
#include "buffer.h"

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
	gs->callback = gg_session_callback;	// XXX do usunięcia
	gs->destroy = gg_session_free;		// XXX do usunięcia
	gs->pid = -1;
	gs->encoding = GG_ENCODING_UTF8;
	gs->hash_type = GG_LOGIN_HASH_SHA1;
	gs->protocol_features = GG_PROTOCOL_FEATURE_MSG80 | GG_PROTOCOL_FEATURE_STATUS80;

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

int gg_session_set_data(struct gg_session *gs, void *data)
{
	GG_SESSION_CHECK(gs, -1);

	gs->data_ptr = data;

	return 0;
}

void *gg_session_get_data(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, NULL);

	return gs->data_ptr;
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
		gs->ping_period = 240;
	} else {
		gs->max_descr_length = GG_STATUS_DESCR_MAXSIZE_PRE_8_0;
		gs->ping_period = 60;	// XXX sprawdzić
	}

	// XXX poniższe parametry są różne dla protokołu wcześniejszego niż
	// 7.0, więc wypadałoby je poprawić, jeśli mamy wspierać wcześniejsze
	// wersje.

	gs->max_contacts_chunk_length = 2047;	// XXX sprawdzić 8.0
	gs->max_image_chunk_length = 1922;
	gs->max_notify_chunk_size = 400;

	return 0;
}

int gg_session_get_protocol_version(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->protocol_version;
}

int gg_session_set_protocol_features(struct gg_session *gs, int features)
{
	GG_SESSION_CHECK(gs, -1);

	gs->protocol_features = features;

	return 0;
}

int gg_session_get_protocol_features(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, -1);

	return gs->protocol_features;
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
	char *tmp = NULL;
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
		p.flags = gg_fix32(0x00800001);;
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
	char *tmp = NULL;
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
				     (tmp != NULL) ? tmp : NULL,
				     (tmp != NULL) ? strlen(tmp) : 0,
				     (time != 0) ? "\0" : NULL,
				     (time != 0) ? 1 : 0,
				     (time != 0) ? &new_time : NULL,
				     (time != 0) ? sizeof(new_time) : 0,
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
	GG_SESSION_CHECK(gs, -1);

	if (!GG_SESSION_IS_IDLE(gs)) {
		errno = EINPROGRESS;
		return -1;
	}

	if (gs->uin == 0 || gs->password == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (gs->server_addr == 0) {
		if (gg_proxy_enabled) {
			gs->resolver_host = gg_proxy_host;
			gs->proxy_port = gg_proxy_port;
			gs->state = (gs->async) ? GG_STATE_RESOLVE_PROXY_HUB_ASYNC : GG_STATE_RESOLVE_PROXY_HUB_SYNC;
		} else {
			gs->resolver_host = GG_APPMSG_HOST;
			gs->proxy_port = 0;
			gs->state = (gs->async) ? GG_STATE_RESOLVE_HUB_ASYNC : GG_STATE_RESOLVE_HUB_SYNC;
		}
	} else {
		gs->connect_addr = gs->server_addr;
		gs->connect_index = 0;

		if (gg_proxy_enabled) {
			gs->resolver_host = gg_proxy_host;
			gs->proxy_port = gg_proxy_port;
			gs->connect_port[0] = GG_HTTPS_PORT;
			gs->connect_port[1] = 0;
			gs->state = (gs->async) ? GG_STATE_RESOLVE_PROXY_GG_ASYNC : GG_STATE_RESOLVE_PROXY_GG_SYNC;
		} else {
			gs->resolver_host = NULL;
			if (gs->port == 0) {
				gs->connect_port[0] = GG_DEFAULT_PORT;
				gs->connect_port[1] = GG_HTTPS_PORT;
			} else {
				gs->connect_port[0] = gs->port;
				gs->connect_port[1] = 0;
			}
			gs->state = GG_STATE_CONNECT_GG;

		}
	}

	// XXX inaczej gg_watch_fd() wyjdzie z timeoutem
	gs->timeout = GG_DEFAULT_TIMEOUT;

	if (!gs->async) {
		while (!GG_SESSION_IS_CONNECTED(gs)) {
			struct gg_event *ge;

			ge = gg_watch_fd(gs);

			if (ge == NULL) {
				gg_debug(GG_DEBUG_MISC, "// gg_session_connect() critical error in gg_watch_fd()\n");
				return -1;
			}

			if (ge->type == GG_EVENT_CONN_FAILED) {
				errno = EACCES;
				gg_debug(GG_DEBUG_MISC, "// gg_session_connect() could not login\n");
				gg_event_free(ge);
				return -1;
			}

			gg_event_free(ge);
		}
	} else {
		struct gg_event *ge;

		ge = gg_watch_fd(gs);

		if (ge == NULL) {
			gg_debug(GG_DEBUG_MISC, "// gg_session_connect() critical error in gg_watch_fd()\n");
			return -1;
		}

		gg_event_free(ge);
	}

	return 0;
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

	free(gs->send_buf);
	gs->send_buf = NULL;
	gs->send_left = 0;

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

	gs->timeout = 5;	// XXX czy 5 sekund wystarczy?

	if (!linger) {
		gg_session_shutdown(gs);
		return 0;
	}

	/* Jeśli zmiana stanu się nie powiodła, to połączenie jest
	 * zamykane natychmiast i funkcja zwraca -1. */

	if (res == -1) {
		gg_session_shutdown(gs);
		return -1;
	}

	gs->state = GG_STATE_DISCONNECTING;

	if (!gs->async) {
		struct gg_event *ge;

		// XXX timeout

		while ((ge = gg_watch_fd(gs)) != NULL) {
			int type;

			type = ge->type;

			gg_event_free(ge);

			if (type == GG_EVENT_DISCONNECT_ACK)
				break;
		}

		gg_session_shutdown(gs);

		if (ge == NULL)
			return -1;
	}

	return 0;
}

static uint32_t gg_session_send_message_7(struct gg_session *gs, gg_message_t *gm)
{
	struct gg_send_msg s;
	unsigned char *attr_header = NULL, attr_buf[3];
	char *text = NULL;
	uint32_t seq;

	if (gm->text != NULL) {
		if (gs->encoding != GG_ENCODING_CP1250) {
			text = gg_encoding_convert(gm->text, gs->encoding, GG_ENCODING_CP1250, -1, -1);
			if (text == NULL)
				goto failure;
		} else {
			text = gm->text;
		}
	} else if (gm->text == NULL && gm->html != NULL) {
		size_t len;

		len = gg_message_html_to_text(NULL, gm->html);

		text = malloc(len + 1);

		if (text == NULL)
			goto failure;

		gg_message_html_to_text(text, gm->html);

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

	seq = gm->seq;

	if (seq == (uint32_t) -1)
		seq = rand();

	s.seq = gg_fix32(seq);
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

		// gm->recipient_count < 65536

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

	return seq;

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
	uint32_t seq;

	if (gm->html != NULL) {
		if (gs->encoding != GG_ENCODING_UTF8) {
			html = gg_encoding_convert(gm->html, gs->encoding, GG_ENCODING_UTF8, -1, -1);

			if (html == NULL)
				goto failure;
		} else
			html = gm->html;
	} else if (gm->html == NULL && gm->text != NULL) {
		size_t len;

		len = gg_message_text_to_html(NULL, gm->text, gm->attributes, gm->attributes_length);

		html = malloc(len + 1);

		if (html == NULL)
			goto failure;

		gg_message_text_to_html(html, gm->text, gm->attributes, gm->attributes_length);

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
		size_t len;

		len = gg_message_html_to_text(NULL, gm->html);

		text = malloc(len + 1);

		if (text == NULL)
			goto failure;

		gg_message_html_to_text(text, gm->html);

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

	seq = gm->seq;

	if (seq == (uint32_t) -1) {
		seq = time(NULL);

		if (seq <= gm->seq)
			seq = gm->seq + 1;

		gs->seq = seq;
	}

	s.seq = gg_fix32(seq);
	s.msgclass = gg_fix32(gm->msgclass);
	s.offset_plain = gg_fix32(sizeof(s) + strlen(html) + 1);
	s.offset_attr = gg_fix32(sizeof(s) + strlen(html) + 1 + strlen(text) + 1);

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

		// gm->recipient_count < 65536

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

	return seq;

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

	if (gm->recipient_count < 1 || gm->recipient_count > 65535) {
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
 * \param length Długość zapytania
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup importexport
 */
int gg_session_contacts_request(struct gg_session *gs, uint8_t type, const char *request, size_t length)
{
	int packet_type;

	if (GG_SESSION_IS_PROTOCOL_8_0(gs))
		packet_type = GG_USERLIST_REQUEST80;
	else
		packet_type = GG_USERLIST_REQUEST;

	// Liczymy liczbę bloków, żeby po otrzymaniu takiej samej liczby
	// potwierdzeń poinformować aplikację o udanej operacji.
	//
	gs->userlist_blocks = 0;

	while (request != NULL && length > gs->max_contacts_chunk_length) {
		gs->userlist_blocks++;

		if (gg_send_packet(gs, GG_USERLIST_REQUEST, &type, sizeof(type), request, gs->max_contacts_chunk_length, NULL) == -1)
			return -1;

		if (type == GG_USERLIST_PUT)
			type = GG_USERLIST_PUT_MORE;

		request += gs->max_contacts_chunk_length;
		length -= gs->max_contacts_chunk_length;
	}

	gs->userlist_blocks++;

	return gg_send_packet(gs, GG_USERLIST_REQUEST, &type, sizeof(type), request, length, NULL);
}

int gg_session_export_contacts(struct gg_session *gs, const char *contacts)
{
	GG_SESSION_CHECK_CONNECTED(gs, -1);

	return gg_session_contacts_request(gs, GG_USERLIST_PUT, contacts, strlen(contacts));
}

int gg_session_import_contacts(struct gg_session *gs)
{
	GG_SESSION_CHECK_CONNECTED(gs, -1);

	return gg_session_contacts_request(gs, GG_USERLIST_GET, NULL, 0);
}

/**
 * Wysyła żądanie obrazka o podanych parametrach.
 *
 * Wiadomości obrazkowe nie zawierają samych obrazków, a tylko ich rozmiary
 * i sumy kontrolne. Odbiorca najpierw szuka obrazków w swojej pamięci
 * podręcznej i dopiero gdy ich nie znajdzie, wysyła żądanie do nadawcy.
 * Wynik zostanie przekazany zdarzeniem \c GG_EVENT_IMAGE_REPLY.
 *
 * \param gs Struktura sesji
 * \param recipient Numer adresata
 * \param size Rozmiar obrazka w bajtach
 * \param crc32 Suma kontrola obrazka
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup messages
 */
int gg_session_image_request(struct gg_session *gs, uin_t recipient, size_t size, uint32_t crc32)
{
	struct gg_send_msg s;
	struct gg_msg_image_request r;
	int res;

	GG_SESSION_CHECK_CONNECTED(gs, -1);

	s.recipient = gg_fix32(recipient);
	s.seq = gg_fix32(0);
	s.msgclass = gg_fix32(GG_CLASS_MSG);

	r.flag = 0x04;
	r.size = gg_fix32(size);
	r.crc32 = gg_fix32(crc32);

	res = gg_send_packet(gs, GG_SEND_MSG, &s, sizeof(s), "\0", 1, &r, sizeof(r), NULL);

	if (res == 0) {
		struct gg_image_queue *q;
		char *buf;

		q = malloc(sizeof(*q));

		if (q == NULL) {
			gg_debug_session(gs, GG_DEBUG_MISC, "// gg_image_request() not enough memory for image queue\n");
			return -1;
		}

		buf = malloc(size);

		if (size != 0 && buf == NULL)
		{
			gg_debug_session(gs, GG_DEBUG_MISC, "// gg_image_request() not enough memory for image\n");
			free(q);
			return -1;
		}

		memset(q, 0, sizeof(*q));

		q->sender = recipient;
		q->size = size;
		q->crc32 = crc32;
		q->image = buf;

		if (gs->images == NULL) {
			gs->images = q;
		} else {
			struct gg_image_queue *qq;

			for (qq = gs->images; qq->next != NULL; qq = qq->next)
				;

			qq->next = q;
		}
	}

	return res;
}

/**
 * Wysyła żądany obrazek.
 *
 * \param gs Struktura sesji
 * \param recipient Numer odbiorcy
 * \param image Bufor z obrazkiem
 * \param size Rozmiar obrazka
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup messages
 */
int gg_session_image_reply(struct gg_session *gs, uin_t recipient, const char *image, size_t size, uint32_t crc32)
{
	struct gg_msg_image_reply r;
	struct gg_send_msg s;
	int res = 0;
	int chunk = 0;

	GG_SESSION_CHECK_CONNECTED(gs, -1);

	if (image == NULL) {
		errno = EFAULT;
		return -1;
	}

	s.recipient = gg_fix32(recipient);
	s.seq = gg_fix32(0);
	s.msgclass = gg_fix32(GG_CLASS_MSG);

	r.size = gg_fix32(size);
	r.crc32 = gg_fix32(crc32);

	while (size > 0) {
		int chunk_len;

		chunk_len = (size >= gs->max_image_chunk_length) ? gs->max_image_chunk_length : size;

		if (chunk == 0) {
			char filename[17];

			r.flag = 0x05;
			snprintf(filename, sizeof(filename), "%08x%08x", crc32, size);
			res = gg_send_packet(gs, GG_SEND_MSG, &s, sizeof(s), "\0", 1, &r, sizeof(r), filename, strlen(filename) + 1, image, chunk_len, NULL);
		} else {
			r.flag = 0x06;
			res = gg_send_packet(gs, GG_SEND_MSG, &s, sizeof(s), "\0", 1, &r, sizeof(r), image, chunk_len, NULL);
		}

		if (res == -1)
			break;

		size -= chunk_len;
		image += chunk_len;

		chunk++;
	}

	return res;
}

/**
 * Wysyła do serwera listę kontaktów.
 *
 * Funkcja informuje serwer o liście kontaktów, których statusy będą
 * obserwowane lub kontaktów, które bedą blokowane.
 *
 * Listę kontaktów należy \b zawsze wysyłać po połączeniu, nawet jeśli
 * jest pusta (\c contacts równe \c NULL lub \c count równe 0).
 *
 * \param gs Struktura sesji
 * \param contacts Wskaźnik do tablicy kontaktów
 * \param count Liczba kontaktów
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_session_send_contacts(struct gg_session *gs, const gg_contact_t *contacts, size_t count)
{
	struct gg_notify *n;
	const gg_contact_t *c;
	int i, res = 0;

	GG_SESSION_CHECK_CONNECTED(gs, -1);

	if (contacts == NULL || count == 0)
		return gg_send_packet(gs, GG_LIST_EMPTY, NULL);

	if (count > gs->max_notify_chunk_size) {
		n = calloc(gs->max_notify_chunk_size, sizeof(struct gg_notify));
	} else {
		n = calloc(count, sizeof(struct gg_notify));
	}

	if (n == NULL) {
		// XXX
		return -1;
	}

	while (count > 0) {
		int chunk_size, packet_type;

		if (count > gs->max_notify_chunk_size) {
			chunk_size = gs->max_notify_chunk_size;
			packet_type = GG_NOTIFY_FIRST;
		} else {
			chunk_size = count;
			packet_type = GG_NOTIFY_LAST;
		}

		for (i = 0, c = contacts; i < chunk_size; i++, c++) {
			n[i].uin = gg_fix32(c->uin);
			n[i].dunno1 = c->type;
		}

		if (gg_send_packet(gs, packet_type, n, sizeof(struct gg_notify) * chunk_size, NULL) == -1) {
			res = -1;
			break;
		}

		contacts += chunk_size;
		count -= chunk_size;
	}

	free(n);

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
 * \param contact Informacje o kontakcie
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_session_add_contact(struct gg_session *gs, const gg_contact_t *contact)
{
	struct gg_add_remove a;

	GG_SESSION_CHECK_CONNECTED(gs, -1);

	if (contact == NULL) {
		errno = EFAULT;
		return -1;
	}

	a.uin = gg_fix32(contact->uin);
	a.dunno1 = contact->type;

	return gg_send_packet(gs, GG_ADD_NOTIFY, &a, sizeof(a), NULL);
}

/**
 * Usuwa kontakt.
 *
 * Usuwa z listy kontaktów dany numer w trakcie połączenia.
 *
 * \param sess Struktura sesji
 * \param contact Informacje o kontakcie
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup contacts
 */
int gg_session_remove_contact(struct gg_session *gs, const gg_contact_t *contact)
{
	struct gg_add_remove a;

	GG_SESSION_CHECK_CONNECTED(gs, -1);

	if (contact == NULL) {
		errno = EFAULT;
		return -1;
	}

	a.uin = gg_fix32(contact->uin);
	a.dunno1 = contact->type;

	return gg_send_packet(gs, GG_ADD_NOTIFY, &a, sizeof(a), NULL);
}

int gg_session_handle_io(struct gg_session *gs, int condition)
{
	struct gg_event *ge;

	GG_SESSION_CHECK(gs, -1);

	ge = gg_watch_fd(gs);

	if (ge == NULL)
		return -1;

	if (gs->event_queue_head == NULL) {
		gs->event_queue_head = ge;
		gs->event_queue_tail = ge;
	} else {
		// XXX gs->event_queue_tail != NULL
		gs->event_queue_tail->next = ge;
		gs->event_queue_tail = ge;
	}

	return 0;
}

int gg_session_handle_timeout(struct gg_session *gs)
{
	struct gg_event *ge;

	GG_SESSION_CHECK(gs, -1);

	gs->timeout = 0;

	ge = gg_watch_fd(gs);

	if (ge == NULL)
		return -1;

	if (gs->event_queue_head == NULL) {
		gs->event_queue_head = ge;
		gs->event_queue_tail = ge;
	} else {
		// XXX gs->event_queue_tail != NULL
		gs->event_queue_tail->next = ge;
		gs->event_queue_tail = ge;
	}

	return 0;
}

struct gg_event *gg_session_get_event(struct gg_session *gs)
{
	struct gg_event *res = NULL;

	GG_SESSION_CHECK(gs, NULL);
	
	if (gs->event_queue_head != NULL) {
		res = gs->event_queue_head;
		if (res == gs->event_queue_tail)
			gs->event_queue_tail = NULL;
		gs->event_queue_head = gs->event_queue_head->next;
		res->next = NULL;
	}

	return res;
}

const struct gg_event *gg_session_peek_event(struct gg_session *gs)
{
	GG_SESSION_CHECK(gs, NULL);

	return gs->event_queue_head;
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
	struct gg_event *ge;

	if (gs == NULL)
		return;

	free(gs->password);
	free(gs->initial_descr);
	free(gs->status_descr);
	free(gs->client_version);
	free(gs->header_buf);
	free(gs->recv_buf);
	free(gs->resolver_result);

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

	free(gs->send_buf);

	for (dcc = gs->dcc7_list; dcc != NULL; dcc = dcc->next)
		dcc->sess = NULL;

	for (ge = gs->event_queue_head; ge != NULL; ) {
		struct gg_event *next = ge->next;
		gg_event_free(ge);
		ge = next;
	}

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

int gg_session_handle_data(struct gg_session *gs, char *read_buf, size_t read_len, struct gg_event *ge)
{
	char *buf_ptr;
	size_t buf_len, pkt_len;

	gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() %d bytes buffered, %d bytes read\n", gs->recv_done, read_len);

	if (gs->recv_buf != NULL) {
		if (read_buf != NULL) {
			char *tmp;

			tmp = realloc(gs->recv_buf, gs->recv_done + read_len);

			if (tmp == NULL) {
				gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() not enough memory for packet chunk\n");
				return -1;
			}

			gs->recv_buf = tmp;

			memcpy(gs->recv_buf + gs->recv_done, read_buf, read_len);
			gs->recv_done += read_len;
		}

		buf_ptr = gs->recv_buf;
		buf_len = gs->recv_done;
	} else {
		if (read_buf == NULL)
			return 0;

		buf_ptr = read_buf;
		buf_len = read_len;
	}

	// Jeśli nie ma gotowego pakietu, olej sprawę.

	if (buf_len >= 8) {
		pkt_len = gg_buffer_get_uint32(buf_ptr + 4);

		gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() %d bytes available, %d bytes packet\n", buf_len, pkt_len);

		if (pkt_len > 65535) {
			gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() packet too long\n");
			errno = EINVAL;
			return -1;
		}

		while (buf_len - 8 >= pkt_len) {
			gg_session_handle_packet(gs, gg_buffer_get_uint32(buf_ptr), buf_ptr + 8, pkt_len, ge);

			if (buf_len == pkt_len + 8) {
				gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() full packet handled\n");

				if (buf_ptr == gs->recv_buf) {
					free(gs->recv_buf);
					gs->recv_buf = NULL;
					gs->recv_done = 0;
				}

				buf_ptr = NULL;
				buf_len = 0;
			} else {
				gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() %d bytes left in buffer, shifting\n", buf_len - pkt_len - 8);

				memmove(buf_ptr, buf_ptr + pkt_len + 8, buf_len - pkt_len - 8);

				buf_len = buf_len - pkt_len - 8;

				if (buf_ptr == gs->recv_buf)
					gs->recv_done = buf_len;
			}

			if (buf_len < 8)
				break;

			pkt_len = gg_buffer_get_uint32(buf_ptr + 4);
		}
	}

	// Jeśli został nam niekompletny pakiet, zapiszmy go sobie

	if (buf_len > 0 || gs->recv_done > 0)
		gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() %d bytes left unparsed\n", buf_len);

	if (buf_len > 0 && buf_ptr != gs->recv_buf) {
		gs->recv_buf = malloc(buf_len);

		if (gs->recv_buf == NULL) {
			gg_debug_session(gs, GG_DEBUG_MISC, "// gg_session_handle_data() not enough memory for packet chunk (%d bytes)\n", buf_len);
			return -1;
		}

		memcpy(gs->recv_buf, buf_ptr, buf_len);
		gs->recv_done = buf_len;
	}

	return 0;
}

