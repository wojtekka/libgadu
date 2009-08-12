/* $Id$ */

/*
 *  (C) Copyright 2001-2009 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Robert J. Woźny <speedy@ziew.org>
 *                          Arkadiusz Miśkiewicz <arekm@pld-linux.org>
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
 * \file events.c
 *
 * \brief Obsługa zdarzeń
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "compat.h"
#include "libgadu.h"
#include "protocol.h"
#include "session.h"
#include "encoding.h"
#include "resolver.h"
#include "debug.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#ifdef GG_CONFIG_HAVE_OPENSSL
#  include <openssl/err.h>
#  include <openssl/x509.h>
#endif

/**
 * Zwalnia pamięć zajmowaną przez informację o zdarzeniu.
 *
 * Funkcję należy wywoływać za każdym razem gdy funkcja biblioteki zwróci
 * strukturę \c gg_event.
 *
 * \param e Struktura zdarzenia
 *
 * \ingroup events
 */
void gg_event_free(struct gg_event *e)
{
	gg_debug(GG_DEBUG_FUNCTION, "** gg_event_free(%p);\n", e);

	if (!e)
		return;

	switch (e->type) {
		case GG_EVENT_MSG:
			free(e->event.msg.message);
			free(e->event.msg.formats);
			free(e->event.msg.recipients);
			free(e->event.msg.xhtml_message);
			break;

		case GG_EVENT_NOTIFY:
			free(e->event.notify);
			break;

		case GG_EVENT_NOTIFY60:
		{
			int i;

			for (i = 0; e->event.notify60[i].uin; i++)
				free(e->event.notify60[i].descr);

			free(e->event.notify60);

			break;
		}

		case GG_EVENT_STATUS60:
			free(e->event.status60.descr);
			break;

		case GG_EVENT_STATUS:
			free(e->event.status.descr);
			break;

		case GG_EVENT_NOTIFY_DESCR:
			free(e->event.notify_descr.notify);
			free(e->event.notify_descr.descr);
			break;

		case GG_EVENT_DCC_VOICE_DATA:
			free(e->event.dcc_voice_data.data);
			break;

		case GG_EVENT_PUBDIR50_SEARCH_REPLY:
		case GG_EVENT_PUBDIR50_READ:
		case GG_EVENT_PUBDIR50_WRITE:
			gg_pubdir50_free(e->event.pubdir50);
			break;

		case GG_EVENT_USERLIST:
			free(e->event.userlist.reply);
			break;

		case GG_EVENT_IMAGE_REPLY:
			free(e->event.image_reply.filename);
			free(e->event.image_reply.image);
			break;

		case GG_EVENT_XML_EVENT:
			free(e->event.xml_event.data);
			break;
	}

	free(e);
}

/** \cond internal */

/**
 * \internal Usuwa obrazek z kolejki do wysłania.
 *
 * \param s Struktura sesji
 * \param q Struktura obrazka
 * \param freeq Flaga zwolnienia elementu kolejki
 *
 * \return 0 jeśli się powiodło, -1 jeśli wystąpił błąd
 */
int gg_image_queue_remove(struct gg_session *s, struct gg_image_queue *q, int freeq)
{
	if (!s || !q) {
		errno = EFAULT;
		return -1;
	}

	if (s->images == q)
		s->images = q->next;
	else {
		struct gg_image_queue *qq;

		for (qq = s->images; qq; qq = qq->next) {
			if (qq->next == q) {
				qq->next = q->next;
				break;
			}
		}
	}

	if (freeq) {
		free(q->image);
		free(q->filename);
		free(q);
	}

	return 0;
}

/** \endcond */

int gg_async_connect_failed(struct gg_session *gs, int *res_ptr)
{
	int res = 0;
	unsigned int res_size = sizeof(res);

	if (!gs->async)
		return 0;

	if (gs->timeout == 0)
		return 1;

	if (getsockopt(gs->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) == -1) {
		*res_ptr = errno;
		return 1;
	}

	if (res != 0) {
		*res_ptr = res;
		return 1;
	}

	*res_ptr = 0;

	return 0;
}

/**
 * Funkcja wywoływana po zaobserwowaniu zmian na deskryptorze sesji.
 *
 * Funkcja zwraca strukturę zdarzenia \c gg_event. Jeśli rodzaj zdarzenia
 * to \c GG_EVENT_NONE, nie wydarzyło się jeszcze nic wartego odnotowania.
 * Strukturę zdarzenia należy zwolnić funkcja \c gg_event_free().
 *
 * \param sess Struktura sesji
 *
 * \return Struktura zdarzenia lub \c NULL jeśli wystąpił błąd
 *
 * \ingroup events
 */
struct gg_event *gg_watch_fd(struct gg_session *sess)
{
	struct gg_event *e;
	int res = 0;
	int port = 0;
	int errno2 = 0;

	gg_debug_session(sess, GG_DEBUG_FUNCTION, "** gg_watch_fd(%p, %s)\n", sess, (sess != NULL) ? gg_debug_state(sess->state) : "GG_STATE_NONE");

	if (!sess) {
		errno = EFAULT;
		return NULL;
	}

	if (sess->timeout == 0 && !sess->soft_timeout) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() timeout\n");
		errno = ETIMEDOUT;
		return NULL;
	}

	if (!(e = (void*) calloc(1, sizeof(*e)))) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() not enough memory for event data\n");
		return NULL;
	}

	e->type = GG_EVENT_NONE;

	if (sess->send_buf && (sess->state == GG_STATE_SENDING_HUB || sess->state == GG_STATE_READING_REPLY || sess->state == GG_STATE_CONNECTED)) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() sending %d bytes of queued data\n", sess->send_left);

		res = write(sess->fd, sess->send_buf, sess->send_left);

		if (res == -1 && errno != EAGAIN) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() write() failed (errno=%d, %s)\n", errno, strerror(errno));

			if (sess->state == GG_STATE_READING_REPLY)
				goto fail_connecting;
			else
				goto done;
		}

		if (res == sess->send_left) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() sent all queued data\n");
			free(sess->send_buf);
			sess->send_buf = NULL;
			sess->send_left = 0;
		} else if (res > 0) {
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() sent %d bytes of queued data, %d bytes left\n", res, sess->send_left - res);

			memmove(sess->send_buf, sess->send_buf + res, sess->send_left - res);
			sess->send_left -= res;
		}
	}

	switch (sess->state) {
		case GG_STATE_RESOLVE_HUB_SYNC:
		case GG_STATE_RESOLVE_PROXY_SYNC:
		{
			struct in_addr addr;

			if ((addr.s_addr = inet_addr(sess->resolver_host)) == INADDR_NONE) {
				struct in_addr *addr_list;

				if (gg_gethostbyname(sess->resolver_host, &addr_list, 0) == -1) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() host %s not found\n", sess->resolver_host);
					goto fail_resolving;
				}

				sess->resolver_result = addr_list;
				sess->resolver_index = 0;
			} else {
				sess->resolver_result = malloc(sizeof(struct in_addr) * 2);
				if (sess->resolver_result == NULL) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() out of memory\n");
					goto fail_resolving;
				}

				sess->resolver_result[0].s_addr = addr.s_addr;
				sess->resolver_result[1].s_addr = INADDR_NONE;
				sess->resolver_index = 0;
			}
			
			goto goto_GG_STATE_CONNECT_HUB;
		}

		case GG_STATE_RESOLVE_HUB_ASYNC:
		case GG_STATE_RESOLVE_PROXY_ASYNC:
		{
			if (sess->resolver_start(&sess->fd, &sess->resolver, sess->resolver_host) == -1) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() resolving failed (errno=%d, %s)\n", errno, strerror(errno));
				goto fail_resolving;
			}

			if (sess->state == GG_STATE_RESOLVE_HUB_ASYNC)
				sess->state = GG_STATE_RESOLVING_HUB;
			else
				sess->state = GG_STATE_RESOLVING_PROXY;
			sess->check = GG_CHECK_READ;
			sess->timeout = GG_DEFAULT_TIMEOUT;

			break;
		}

		case GG_STATE_RESOLVING_HUB:
		case GG_STATE_RESOLVING_PROXY:
		{
			char buf[256];
			int i, count = -1;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_RESOLVING\n");

			res = read(sess->fd, buf, sizeof(buf));

			gg_debug_session(sess, GG_DEBUG_MISC, "read() = %d\n", res);

			if (res == -1) {
				if (errno == EAGAIN || errno == EINTR) {
					res = 0;
					break;
				}

				goto fail_resolving;
			}

			if (res > 0) {
				char *tmp;

				tmp = realloc(sess->recv_buf, sess->recv_done + res);

				if (tmp == NULL)
					goto fail_resolving;

				sess->recv_buf = tmp;
				memcpy(sess->recv_buf + sess->recv_done, buf, res);
				sess->recv_done += res;
			}

			/* Sprawdź, czy mamy listę zakończoną INADDR_NONE */

			for (i = 0; i < sess->recv_done / sizeof(struct in_addr); i++) {
				gg_debug_session(sess, GG_DEBUG_MISC, "addr[%d] = %s\n", i, inet_ntoa(((struct in_addr*) sess->recv_buf)[i]));
				if (((struct in_addr*) sess->recv_buf)[i].s_addr == INADDR_NONE) {
					count = i;
					break;
				}
			}

			gg_debug_session(sess, GG_DEBUG_MISC, "len = %d, count = %d\n", sess->recv_done, count);

			if (res == 0 || count == 0)
				goto fail_resolving;

			if (count == -1)
				break;

			close(sess->fd);
			sess->fd = -1;

			sess->resolver_cleanup(&sess->resolver, 0);

			sess->state = GG_STATE_CONNECT_HUB;
			sess->resolver_result = (struct in_addr*) sess->recv_buf;
			sess->resolver_index = 0;
			sess->recv_buf = NULL;
			sess->recv_done = 0;
			
			/* fall through */
		}

		case GG_STATE_CONNECT_HUB:
		{
			struct in_addr addr;

goto_GG_STATE_CONNECT_HUB:
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECT_HUB\n");

			if (sess->resolver_result[sess->resolver_index].s_addr == INADDR_NONE) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() out of address to connect to\n");
				goto fail_connecting;
			}

			addr = sess->resolver_result[sess->resolver_index++];

			/* jeśli jesteśmy w resolverze i mamy ustawiony port
			 * proxy, znaczy, że resolvowaliśmy proxy. zatem
			 * wpiszmy jego adres. */
			if (sess->proxy_port)
				sess->proxy_addr = sess->resolver_result[sess->resolver_index].s_addr;

			/* zapiszmy sobie adres huba i adres serwera (do
			 * bezpośredniego połączenia, jeśli hub leży)
			 * z resolvera. */
			if (sess->proxy_addr && sess->proxy_port)
				port = sess->proxy_port;
			else {
				sess->server_addr = sess->hub_addr = sess->resolver_result[sess->resolver_index].s_addr;
				port = GG_APPMSG_PORT;
			}

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connecting to %s:%d\n", inet_ntoa(addr), port);

			/* łączymy się albo z hubem, albo z proxy, zależnie
			 * od tego, co resolvowaliśmy. */
			if ((sess->fd = gg_connect(&addr, port, sess->async)) == -1) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", errno, strerror(errno));
				goto goto_GG_STATE_CONNECT_HUB;
			}

			/* jeśli podano serwer i łączmy się przez proxy,
			 * jest to bezpośrednie połączenie, inaczej jest
			 * do huba. */

			if (sess->proxy_addr && sess->proxy_port && sess->server_addr) {
				sess->state = GG_STATE_CONNECTING_GG;
				sess->soft_timeout = 1;
			} else
				sess->state = GG_STATE_CONNECTING_HUB;

			sess->check = GG_CHECK_WRITE;
			sess->timeout = GG_DEFAULT_TIMEOUT;
			sess->soft_timeout = 1;

			break;
		}

		case GG_STATE_CONNECTING_HUB:
		{
			int res;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECTING_HUB\n");

			/* jeśli asynchroniczne, sprawdzamy, czy nie wystąpił
			 * przypadkiem jakiś błąd. */
			if (gg_async_connect_failed(sess, &res)) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", res, strerror(res));
				goto goto_GG_STATE_CONNECT_HUB;
			}

			sess->state = GG_STATE_SEND_HUB;

			/* fall through */
		}

		case GG_STATE_SEND_HUB:
		{
			char buf[1024], *client, *auth;
			const char *host;
			int res;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connected to hub, sending query\n");

			if (!(client = gg_urlencode((sess->client_version) ? sess->client_version : GG_DEFAULT_CLIENT_VERSION))) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() out of memory for client version\n");
				goto fail_connecting;
			}

			if (!gg_proxy_http_only && sess->proxy_addr && sess->proxy_port)
				host = "http://" GG_APPMSG_HOST;
			else
				host = "";

			auth = gg_proxy_auth();

#ifdef GG_CONFIG_HAVE_OPENSSL
			if (sess->ssl) {
				snprintf(buf, sizeof(buf) - 1,
					"GET %s/appsvc/appmsg3.asp?fmnumber=%u&version=%s&lastmsg=%d HTTP/1.0\r\n"
					"Host: " GG_APPMSG_HOST "\r\n"
					"User-Agent: " GG_HTTP_USERAGENT "\r\n"
					"Pragma: no-cache\r\n"
					"%s"
					"\r\n", host, sess->uin, client, sess->last_sysmsg, (auth) ? auth : "");
			} else
#endif
			{
				snprintf(buf, sizeof(buf) - 1,
					"GET %s/appsvc/appmsg_ver8.asp?fmnumber=%u&fmt=2&lastmsg=%d&version=%s HTTP/1.0\r\n"
					"Host: " GG_APPMSG_HOST "\r\n"
					"%s"
					"\r\n", host, sess->uin, sess->last_sysmsg, client, (auth) ? auth : "");
			}

			free(auth);
			free(client);

			gg_debug_session(sess, GG_DEBUG_MISC, "=> -----BEGIN-HTTP-QUERY-----\n%s\n=> -----END-HTTP-QUERY-----\n", buf);

			res = gg_write(sess, buf, strlen(buf));

			if (res == -1) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() sending query failed\n");
				goto fail_writing;
			}

			if (res < strlen(buf)) {
				sess->state = GG_STATE_SENDING_HUB;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
			} else {
				sess->state = GG_STATE_READING_DATA;
				sess->check = GG_CHECK_READ;
				sess->timeout = GG_DEFAULT_TIMEOUT;
			}

			break;
		}

		case GG_STATE_SENDING_HUB:
		{
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_SENDING_HUB\n");

			if (sess->send_left > 0)
				break;

			sess->state = GG_STATE_READING_DATA;
			sess->check = GG_CHECK_READ;
			sess->timeout = GG_DEFAULT_TIMEOUT;

			break;
		}

		case GG_STATE_READING_DATA:
		{
			char buf[1024], *tmp, *host;
			int port = GG_DEFAULT_PORT;
			struct in_addr addr;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_DATA\n");

			/* czytamy linię z gniazda i obcinamy \r\n. */
			gg_read_line(sess->fd, buf, sizeof(buf) - 1);
			gg_chomp(buf);
			gg_debug_session(sess, GG_DEBUG_TRAFFIC, "// gg_watch_fd() received http header (%s)\n", buf);

			/* sprawdzamy, czy wszystko w porządku. */
			if (strncmp(buf, "HTTP/1.", 7) || strncmp(buf + 9, "200", 3)) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() invalid http reply, connection failed\n");
				goto fail_connecting;
			}

			/* ignorujemy resztę nagłówka. */
			while (strcmp(buf, "\r\n") && strcmp(buf, ""))
				gg_read_line(sess->fd, buf, sizeof(buf) - 1);

			/* czytamy pierwszą linię danych. */
			gg_read_line(sess->fd, buf, sizeof(buf) - 1);
			gg_chomp(buf);

			/* jeśli pierwsza liczba w linii nie jest równa zeru,
			 * oznacza to, że mamy wiadomość systemową. */
			if (atoi(buf)) {
				char tmp[1024], *foo, *sysmsg_buf = NULL;
				int len = 0;

				while (gg_read_line(sess->fd, tmp, sizeof(tmp) - 1)) {
					if (!(foo = realloc(sysmsg_buf, len + strlen(tmp) + 2))) {
						gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() out of memory for system message, ignoring\n");
						break;
					}

					sysmsg_buf = foo;

					if (!len)
						strcpy(sysmsg_buf, tmp);
					else
						strcat(sysmsg_buf, tmp);

					len += strlen(tmp);
				}

				e->type = GG_EVENT_MSG;
				e->event.msg.msgclass = atoi(buf);
				e->event.msg.sender = 0;
				e->event.msg.message = (unsigned char*) sysmsg_buf;
			}

			close(sess->fd);

			gg_debug_session(sess, GG_DEBUG_TRAFFIC, "// gg_watch_fd() received http data (%s)\n", buf);

			/* analizujemy otrzymane dane. */
			tmp = buf;

#ifdef GG_CONFIG_HAVE_OPENSSL
			if (!sess->ssl)
#endif
			{
				while (*tmp && *tmp != ' ')
					tmp++;
				while (*tmp && *tmp == ' ')
					tmp++;
			}
			while (*tmp && *tmp != ' ')
				tmp++;
			while (*tmp && *tmp == ' ')
				tmp++;
			host = tmp;
			while (*tmp && *tmp != ' ')
				tmp++;
			*tmp = 0;

			if ((tmp = strchr(host, ':'))) {
				*tmp = 0;
				port = atoi(tmp + 1);
			}

			if (!strcmp(host, "notoperating")) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() service unavailable\n", errno, strerror(errno));
				sess->fd = -1;
				goto fail_unavailable;
			}

			addr.s_addr = inet_addr(host);
			sess->server_addr = addr.s_addr;

			if (!gg_proxy_http_only && sess->proxy_addr && sess->proxy_port) {
				sess->connect_addr = sess->proxy_addr;
				sess->connect_port[0] = sess->proxy_port;
				sess->connect_port[1] = 0;
			} else {
				sess->connect_addr = addr.s_addr;
				sess->connect_port[0] = port;
				sess->connect_port[1] = (port != GG_HTTPS_PORT) ? GG_HTTPS_PORT : 0;
			}

			sess->state = GG_STATE_CONNECT_GG;

			/* fall through */
		}

		case GG_STATE_CONNECT_GG:
		{
			uint16_t port;

goto_GG_STATE_CONNECT_GG:
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECT_GG\n");

			if (sess->connect_index > 1 || sess->connect_port[sess->connect_index] == 0) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() out of connection candidates\n");
				goto fail_connecting;
			}

			port = sess->connect_port[sess->connect_index];
			sess->connect_index++;
			
			sess->fd = gg_connect(&sess->connect_addr, port, sess->async);

			if (sess->fd == -1) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", errno, strerror(errno));
				goto goto_GG_STATE_CONNECT_GG;
			}

			sess->state = GG_STATE_CONNECTING_GG;
			sess->check = GG_CHECK_WRITE;
			sess->timeout = GG_DEFAULT_TIMEOUT;
			sess->soft_timeout = 1;

			sess->port = port;

			break;
		}

		case GG_STATE_CONNECTING_GG:
		{
			int res;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECTING_GG\n");

			sess->soft_timeout = 0;

			/* jeśli wystąpił błąd podczas łączenia się... */
			if (gg_async_connect_failed(sess, &res)) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", res, strerror(res));
				goto goto_GG_STATE_CONNECT_GG;
			}

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() connected\n");

			if (gg_proxy_http_only)
				sess->proxy_port = 0;

			/* jeśli mamy proxy, wyślijmy zapytanie. */
			if (sess->proxy_addr && sess->proxy_port) {
				char buf[100], *auth = gg_proxy_auth();
				struct in_addr addr;

				if (sess->server_addr)
					addr.s_addr = sess->server_addr;
				else
					addr.s_addr = sess->hub_addr;

				snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n", inet_ntoa(addr), sess->port);

				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() proxy request:\n//   %s", buf);

				/* wysyłamy zapytanie. jest ono na tyle krótkie,
				 * że musi się zmieścić w buforze gniazda. jeśli
				 * write() zawiedzie, stało się coś złego. */
				if (write(sess->fd, buf, strlen(buf)) < (signed)strlen(buf)) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() can't send proxy request\n");
					free(auth);
					goto fail_connecting;
				}

				if (auth) {
					gg_debug_session(sess, GG_DEBUG_MISC, "//   %s", auth);
					if (write(sess->fd, auth, strlen(auth)) < (signed)strlen(auth)) {
						gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() can't send proxy request\n");
						free(auth);
						goto fail_connecting;
					}

					free(auth);
				}

				if (write(sess->fd, "\r\n", 2) < 2) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() can't send proxy request\n");
					goto fail_connecting;
				}
			}

#ifdef GG_CONFIG_HAVE_OPENSSL
			if (sess->ssl) {
				SSL_set_fd(sess->ssl, sess->fd);

				sess->state = GG_STATE_TLS_NEGOTIATION;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;

				break;
			}
#endif

			sess->state = GG_STATE_READING_KEY;
			sess->check = GG_CHECK_READ;
			sess->timeout = GG_DEFAULT_TIMEOUT;

			break;
		}

#ifdef GG_CONFIG_HAVE_OPENSSL
		case GG_STATE_TLS_NEGOTIATION:
		{
			int res;
			X509 *peer;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_TLS_NEGOTIATION\n");

			if ((res = SSL_connect(sess->ssl)) <= 0) {
				int err = SSL_get_error(sess->ssl, res);

				if (res == 0) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() disconnected during TLS negotiation\n");

					e->type = GG_EVENT_CONN_FAILED;
					e->event.failure = GG_FAILURE_TLS;
					sess->state = GG_STATE_IDLE;
					close(sess->fd);
					sess->fd = -1;
					break;
				}

				if (err == SSL_ERROR_WANT_READ) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() SSL_connect() wants to read\n");

					sess->state = GG_STATE_TLS_NEGOTIATION;
					sess->check = GG_CHECK_READ;
					sess->timeout = GG_DEFAULT_TIMEOUT;

					break;
				} else if (err == SSL_ERROR_WANT_WRITE) {
					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() SSL_connect() wants to write\n");

					sess->state = GG_STATE_TLS_NEGOTIATION;
					sess->check = GG_CHECK_WRITE;
					sess->timeout = GG_DEFAULT_TIMEOUT;

					break;
				} else {
					char buf[1024];

					ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));

					gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() SSL_connect() bailed out: %s\n", buf);

					e->type = GG_EVENT_CONN_FAILED;
					e->event.failure = GG_FAILURE_TLS;
					sess->state = GG_STATE_IDLE;
					close(sess->fd);
					sess->fd = -1;
					break;
				}
			}

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() TLS negotiation succeded:\n//   cipher: %s\n", SSL_get_cipher_name(sess->ssl));

			peer = SSL_get_peer_certificate(sess->ssl);

			if (!peer)
				gg_debug_session(sess, GG_DEBUG_MISC, "//   WARNING! unable to get peer certificate!\n");
			else {
				char buf[1024];

				X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof(buf));
				gg_debug_session(sess, GG_DEBUG_MISC, "//   cert subject: %s\n", buf);

				X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof(buf));
				gg_debug_session(sess, GG_DEBUG_MISC, "//   cert issuer: %s\n", buf);
			}

			sess->state = GG_STATE_READING_KEY;
			sess->check = GG_CHECK_READ;
			sess->timeout = GG_DEFAULT_TIMEOUT;

			break;
		}
#endif

		case GG_STATE_READING_KEY:
		case GG_STATE_READING_REPLY:
		case GG_STATE_CONNECTED:
		case GG_STATE_DISCONNECTING:
		{
			char buf[1024];

			if (sess->state == GG_STATE_READING_KEY)
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_KEY\n");
			else if (sess->state == GG_STATE_READING_KEY)
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_REPLY\n");
			else if (sess->state == GG_STATE_READING_KEY)
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECTED\n");
			

			res = read(sess->fd, buf, sizeof(buf));


			gg_debug_session(sess, GG_DEBUG_MISC, "read() = %d\n", res);
			{ int i; for (i = 0; i < res; i++) printf("%02x ", (uint8_t) buf[i]); printf("\n"); fflush(stdout); }

			if (res == -1 && (errno == EAGAIN || errno == EINTR)) {
				res = 0;
				break;
			}

			if (res == -1 || res == 0) {
				if (sess->state == GG_STATE_READING_KEY) {
					e->type = GG_EVENT_CONN_FAILED;
					e->event.failure = GG_FAILURE_INVALID;
					sess->state = GG_STATE_IDLE;
					res = 0;
				} else {
					goto fail_completely;
				}

				break;
			}

			if (gg_session_handle_data(sess, buf, res, e) == -1)
				goto fail_completely;

#if 0
			// XXX jeśli pakiet gotowy, dawaj czadu!

			struct gg_header *h;
			struct gg_welcome *w;
			unsigned char *password = (unsigned char*) sess->password;
			int ret;
			uint8_t hash_buf[64];
			uint32_t local_ip;

			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_KEY\n");

			/* XXX bardzo, bardzo, bardzo głupi pomysł na pozbycie
			 * się tekstu wrzucanego przez proxy. */
			if (sess->proxy_addr && sess->proxy_port) {
				char buf[100];

				strcpy(buf, "");
				gg_read_line(sess->fd, buf, sizeof(buf) - 1);
				gg_chomp(buf);
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_watch_fd() proxy response:\n//   %s\n", buf);

				while (strcmp(buf, "")) {
					gg_read_line(sess->fd, buf, sizeof(buf) - 1);
					gg_chomp(buf);
					if (strcmp(buf, ""))
						gg_debug_session(sess, GG_DEBUG_MISC, "//   %s\n", buf);
				}

				/* XXX niech czeka jeszcze raz w tej samej
				 * fazie. głupio, ale działa. */
				sess->proxy_port = 0;

				break;
			}
#endif

			break;
		}
	}

done:
	if (res == -1) {
		free(e);
		e = NULL;
	} else {
		if (sess->send_buf && (sess->state == GG_STATE_READING_REPLY || sess->state == GG_STATE_CONNECTED))
			sess->check |= GG_CHECK_WRITE;
	}

	return e;

fail_completely:
	free(e);
	return NULL;

fail_connecting:
	if (sess->fd != -1) {
		errno2 = errno;
		close(sess->fd);
		errno = errno2;
		sess->fd = -1;
	}
	e->type = GG_EVENT_CONN_FAILED;
	e->event.failure = GG_FAILURE_CONNECTING;
	sess->state = GG_STATE_IDLE;
	goto done;

fail_resolving:
	if (sess->fd != -1) {
		errno2 = errno;
		close(sess->fd);
		errno = errno2;
		sess->fd = -1;
	}

	sess->resolver_cleanup(&sess->resolver, 0);

	e->type = GG_EVENT_CONN_FAILED;
	e->event.failure = GG_FAILURE_RESOLVING;
	sess->state = GG_STATE_IDLE;
	goto done;

fail_writing:
	if (sess->fd != -1) {
		errno2 = errno;
		close(sess->fd);
		errno = errno2;
		sess->fd = -1;
	}

	sess->resolver_cleanup(&sess->resolver, 0);

	e->type = GG_EVENT_CONN_FAILED;
	e->event.failure = GG_FAILURE_WRITING;
	sess->state = GG_STATE_IDLE;
	goto done;

fail_unavailable:
	e->type = GG_EVENT_CONN_FAILED;
	e->event.failure = GG_FAILURE_UNAVAILABLE;
	sess->state = GG_STATE_IDLE;
	goto done;
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
