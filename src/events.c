/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Robert J. Wo¼ny <speedy@ziew.org>
 *                          Arkadiusz Mi¶kiewicz <misiek@pld.org.pl>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#include <time.h>
#include "compat.h"
#include "libgadu.h"
#ifdef __GG_LIBGADU_HAVE_PTHREAD
#  include <pthread.h>
#endif

/*
 * gg_event_free()
 *
 * zwalnia pamiêæ zajmowan± przez informacjê o zdarzeniu.
 *
 *  - e - wska¼nik do informacji o zdarzeniu
 */
void gg_event_free(struct gg_event *e)
{
	gg_debug(GG_DEBUG_FUNCTION, "** gg_event_free(%p);\n", e);
			
	if (!e)
		return;
	
	if (e->type == GG_EVENT_MSG) {
		free(e->event.msg.message);
		free(e->event.msg.formats);
		free(e->event.msg.recipients);
	}
	
	if (e->type == GG_EVENT_NOTIFY)
		free(e->event.notify);
	
	if (e->type == GG_EVENT_STATUS)
		free(e->event.status.descr);

	if (e->type == GG_EVENT_NOTIFY_DESCR) {
		free(e->event.notify_descr.notify);
		free(e->event.notify_descr.descr);
	}

	if (e->type == GG_EVENT_DCC_VOICE_DATA)
		free(e->event.dcc_voice_data.data);
	
	free(e);
}

/*
 * gg_handle_message() // funkcja wewnêtrzna
 *
 * obs³uguje pakiet z przychodz±c± wiadomo¶ci±, rozbijaj±c go na dodatkowe
 * struktury (konferencje, kolorki) w razie potrzeby.
 *
 *  - h - nag³ówek pakietu
 *  - e - opis zdarzenia
 *
 * 0, -1.
 */
static int gg_handle_recv_msg(struct gg_header *h, struct gg_event *e)
{
	struct gg_recv_msg *r = (struct gg_recv_msg*) ((char*) h + sizeof(struct gg_header));
	char *p, *packet_end = (char*) r + h->length;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_handle_recv_msg(%p, %p);\n", h, e);

	if (!r->seq && !r->msgclass) {
		gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() oops, silently ignoring the bait\n");
		e->type = GG_EVENT_NONE;
		return 0;
	}
	//printf("packet=%p\n", h);

	for (p = (char*) r + sizeof(*r); *p; p++) {
		if (*p == 0x02 && p == packet_end - 1) {
			gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() received ctcp packet\n");
			break;
		}
		if (p >= packet_end) {
			gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() malformed packet, message out of bounds\n");
			errno = EINVAL;
			goto fail;
		}
	}
	p++;
	//printf("p=%p\npacket:end=%p\n", p, packet_end);

	/* przeanalizuj dodatkowe opcje */
	while (p < packet_end) {
		
		if (*p == 1) {			/* konferencje */

			struct gg_msg_recipients *m = (void*) p;
			int i, count;
			
			p += sizeof(*m);
			
			if (p > packet_end) {
				gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() packet out of bounds (1)\n");
				errno = EINVAL;
				goto fail;
			}

			count = fix32(m->count);
			
			if (!(e->event.msg.recipients = (void*) malloc(count * sizeof(uin_t)))) {
				gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() not enough memory for recipients data\n");
				errno = EINVAL;
				goto fail;
			}
			
			memcpy(e->event.msg.recipients, p, sizeof(uin_t) * count);

			p += sizeof(uin_t) * count;

			for (i = 0; i < count; i++)
				e->event.msg.recipients[i] = fix32(e->event.msg.recipients[i]);
			
			e->event.msg.recipients_count = count;

		} else if (*p == 2) {		/* richtext */

			unsigned short *len;
			void *tmp;
			
			if (p + 3 > packet_end) {
				gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() packet out of bounds (2)\n");
				errno = EINVAL;
				goto fail;
			}

			len = (unsigned short*) (p + 1);
			*len = fix16(*len);
			gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() p = %p, packetend = %p, len = %d\n", p, packet_end, *len);

			if (!(tmp = malloc(*len))) {
				gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() not enough memory for richtext data\n");
				goto fail;
			}

			p += 3;

			if (p + *len > packet_end) {
				gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() packet out of bounds (3)\n");
				errno = EINVAL;
				goto fail;
			}
				
			memcpy(tmp, p, *len);

			e->event.msg.formats = tmp;
			e->event.msg.formats_length = *len;

			p += *len;

		} else {				/* nieznana opcja */
			gg_debug(GG_DEBUG_MISC, "// gg_handle_recv_msg() unknown payload 0x%.2x\n", *p);
			p = packet_end;
		}
	}

	e->type = GG_EVENT_MSG;
	e->event.msg.msgclass = fix32(r->msgclass);
	e->event.msg.sender = fix32(r->sender);
	e->event.msg.time = fix32(r->time);
	e->event.msg.message = strdup((char*) r + sizeof(*r));

	return 0;
	
fail:
	free(e->event.msg.recipients);
	free(e->event.msg.formats);
	return -1;
}

/*
 * gg_watch_fd_connected() // funkcja wewnêtrzna
 *
 * patrzy na gniazdo, odbiera pakiet i wype³nia strukturê zdarzenia.
 *
 *  - sess - struktura opisuj±ca sesjê
 *  - e - opis zdarzenia
 *
 * 0, -1.
 */
static int gg_watch_fd_connected(struct gg_session *sess, struct gg_event *e)
{
	struct gg_header *h = NULL;
	void *p;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_watch_fd_connected(%p, %p);\n", sess, e);

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (!(h = gg_recv_packet(sess))) {
		gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() gg_recv_packet failed (errno=%d, %s)\n", errno, strerror(errno));
		goto fail;
	}

	p = (char*) h + sizeof(struct gg_header);
	
	switch (h->type) {
		case GG_RECV_MSG:
		{
			if (h->length >= sizeof(struct gg_recv_msg))
				if (gg_handle_recv_msg(h, e))
					goto fail;
			
			break;
		}

		case GG_NOTIFY_REPLY:
		{
			struct gg_notify_reply *n = p;
			int count, i;
			char *tmp;

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() received a notify reply\n");

			if (h->length < sizeof(*n)) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() incomplete packet\n");
				errno = EINVAL;
				goto fail;
			}

			if (fix32(n->status) == GG_STATUS_BUSY_DESCR || fix32(n->status == GG_STATUS_NOT_AVAIL_DESCR) || fix32(n->status) == GG_STATUS_AVAIL_DESCR) {
				e->type = GG_EVENT_NOTIFY_DESCR;
				
				if (!(e->event.notify_descr.notify = (void*) malloc(sizeof(*n) * 2))) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() not enough memory for notify data\n");
					goto fail;
				}
				e->event.notify_descr.notify[1].uin = 0;
				memcpy(e->event.notify_descr.notify, p, sizeof(*n));
				e->event.notify_descr.notify[0].uin = fix32(e->event.notify_descr.notify[0].uin);
				e->event.notify_descr.notify[0].status = fix32(e->event.notify_descr.notify[0].status);
				e->event.notify_descr.notify[0].remote_port = fix16(e->event.notify_descr.notify[0].remote_port);

				count = h->length - sizeof(*n);
				if (!(tmp = malloc(count + 1))) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() not enough memory for notify data\n");
					goto fail;
				}
				memcpy(tmp, (char*) p + sizeof(*n), count);
				tmp[count] = 0;
				e->event.notify_descr.descr = tmp;
				
			} else {
				e->type = GG_EVENT_NOTIFY;
				
				if (!(e->event.notify = (void*) malloc(h->length + 2 * sizeof(*n)))) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() not enough memory for notify data\n");
					goto fail;
				}
				
				memcpy(e->event.notify, p, h->length);
				count = h->length / sizeof(*n);
				e->event.notify[count].uin = 0;
				
				for (i = 0; i < count; i++) {
					e->event.notify[i].uin = fix32(e->event.notify[i].uin);
					e->event.notify[i].status = fix32(e->event.notify[i].status);
					e->event.notify[i].remote_port = fix16(e->event.notify[i].remote_port);		
				}
			}

			break;
		}

		case GG_STATUS:
		{
			struct gg_status *s = p;

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() received a status change\n");

			if (h->length >= sizeof(*s)) {
				e->type = GG_EVENT_STATUS;
				memcpy(&e->event.status, p, sizeof(*s));
				e->event.status.uin = fix32(e->event.status.uin);
				e->event.status.status = fix32(e->event.status.status);
				if (h->length > sizeof(*s)) {
					int len = h->length - sizeof(*s);
					char *buf = malloc(len + 1);
					if (buf) {
						memcpy(buf, (char*) p + sizeof(*s), len);
						buf[len] = 0;
					}
					e->event.status.descr = buf;
				} else
					e->event.status.descr = NULL;
			}

			break;
		}

		case GG_SEND_MSG_ACK:
		{
			struct gg_send_msg_ack *s = p;

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() received a message ack\n");

			if (h->length >= sizeof(*s)) {
				e->type = GG_EVENT_ACK;
				e->event.ack.status = fix32(s->status);
				e->event.ack.recipient = fix32(s->recipient);
				e->event.ack.seq = fix32(s->seq);
			}

			break;
		}

		case GG_PONG: 
		{
			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() received a pong\n");

			e->type = GG_EVENT_PONG;
			sess->last_pong = time(NULL);

			break;
		}

		case GG_DISCONNECTING:
		{
			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() received disconnection warning\n");
			e->type = GG_EVENT_DISCONNECT;
			break;
		}

		default:
			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd_connected() received unknown packet 0x%.2x\n", h->type);
	}
	
	free(h);
	return 0;

fail:
	free(h);
	return -1;
}

/*
 * gg_watch_fd()
 *
 * funkcja, któr± nale¿y wywo³aæ, gdy co¶ siê stanie z obserwowanym
 * deskryptorem. zwraca klientowi informacjê o tym, co siê dzieje.
 *
 *  - sess - identyfikator sesji
 *
 * wska¼nik do struktury gg_event, któr± trzeba zwolniæ pó¼niej
 * za pomoc± gg_event_free(). jesli rodzaj zdarzenia jest równy
 * GG_EVENT_NONE, nale¿y je zignorowaæ. je¶li zwróci³o NULL,
 * sta³o siê co¶ niedobrego -- albo zabrak³o pamiêci albo zerwa³o
 * po³±czenie.
 */
struct gg_event *gg_watch_fd(struct gg_session *sess)
{
	struct gg_event *e;
	int res = 0;
	int port = 0;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_watch_fd(%p);\n", sess);
	
	if (!sess) {
		errno = EFAULT;
		return NULL;
	}

	if (!(e = (void*) calloc(1, sizeof(*e)))) {
		gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() not enough memory for event data\n");
		return NULL;
	}

	e->type = GG_EVENT_NONE;

	switch (sess->state) {
		case GG_STATE_RESOLVING:
		{
			struct in_addr addr;

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_RESOLVING\n");

			if (read(sess->fd, &addr, sizeof(addr)) < sizeof(addr) || addr.s_addr == INADDR_NONE) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() resolving failed\n");

				close(sess->fd);
				sess->fd = -1;

				goto fail_resolving;
			}
			
			close(sess->fd);

#ifndef __GG_LIBGADU_HAVE_PTHREAD
			waitpid(sess->pid, NULL, 0);
#else
			if (sess->resolver) {
				pthread_cancel(*((pthread_t*) sess->resolver));
				free(sess->resolver);
				sess->resolver = NULL;
			}
#endif

			/* je¶li jeste¶my w resolverze i mamy ustawiony port
			 * proxy, znaczy, ¿e resolvowali¶my proxy. zatem
			 * wpiszmy jego adres. */
			if (sess->proxy_port)
				sess->proxy_addr = addr.s_addr;

			/* zapiszmy sobie adres huba i adres serwera (do
			 * bezpo¶redniego po³±czenia, je¶li hub le¿y)
			 * z resolvera. */
			if (sess->proxy_addr && sess->proxy_port)
				port = sess->proxy_port;
			else {
				sess->server_addr = sess->hub_addr = addr.s_addr;
				port = GG_APPMSG_PORT;
			}

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() resolved, connecting to %s:%d\n", inet_ntoa(addr), port);
			
			/* ³±czymy siê albo z hubem, albo z proxy, zale¿nie
			 * od tego, co resolvowali¶my. */
			if ((sess->fd = gg_connect(&addr, port, sess->async)) == -1) {
				/* je¶li w trybie asynchronicznym gg_connect()
				 * zwróci b³±d, nie ma sensu próbowaæ dalej. */
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s), critical\n", errno, strerror(errno));
				goto fail_connecting;
			}

			/* je¶li podano serwer i ³±czmy siê przez proxy,
			 * jest to bezpo¶rednie po³±czenie, inaczej jest
			 * do huba. */
			sess->state = (sess->proxy_addr && sess->proxy_port && sess->server_addr) ? GG_STATE_CONNECTING_GG : GG_STATE_CONNECTING_HUB;
			sess->check = GG_CHECK_WRITE;
			sess->timeout = GG_DEFAULT_TIMEOUT;

			break;
		}

		case GG_STATE_CONNECTING_HUB:
		{
			char buf[1024];
			int res = 0, res_size = sizeof(res);

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECTING_HUB\n");

			/* je¶li asynchroniczne, sprawdzamy, czy nie wyst±pi³
			 * przypadkiem jaki¶ b³±d. */
			if (sess->async && (getsockopt(sess->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res)) {
				/* no tak, nie uda³o siê po³±czyæ z proxy. nawet
				 * nie próbujemy dalej. */
				if (sess->proxy_addr && sess->proxy_port) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection to proxy failed (errno=%d, %s)\n", res, strerror(res));
					goto fail_connecting;
				}
					
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection to hub failed (errno=%d, %s), trying direct connection\n", res, strerror(res));
				close(sess->fd);

				if ((sess->fd = gg_connect(&sess->hub_addr, GG_DEFAULT_PORT, sess->async)) == -1) {
					/* przy asynchronicznych, gg_connect()
					 * zwraca -1 przy b³êdach socket(),
					 * ioctl(), braku routingu itd. dlatego
					 * nawet nie próbujemy dalej. */
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() direct connection failed (errno=%d, %s), critical\n", errno, strerror(errno));
					goto fail_connecting;
				}

				sess->state = GG_STATE_CONNECTING_GG;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
				break;
			}
			
			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connected to hub, sending query\n");

			if (!gg_proxy_http_only && sess->proxy_addr && sess->proxy_port) {
				snprintf(buf, sizeof(buf) - 1,
					"GET http://" GG_APPMSG_HOST "/appsvc/appmsg2.asp?fmnumber=%u&version=%s&lastmsg=%d HTTP/1.0\r\n"
					"Host: " GG_APPMSG_HOST "\r\n"
					"User-Agent: " GG_HTTP_USERAGENT "\r\n"
					"Pragma: no-cache\r\n"
					"\r\n", sess->uin, (sess->client_version) ? sess->client_version : GG_DEFAULT_CLIENT_VERSION, sess->last_sysmsg);
			} else {
				snprintf(buf, sizeof(buf) - 1,
					"GET /appsvc/appmsg2.asp?fmnumber=%u&version=%s&lastmsg=%d HTTP/1.0\r\n"
					"Host: " GG_APPMSG_HOST "\r\n"
					"User-Agent: " GG_HTTP_USERAGENT "\r\n"
					"Pragma: no-cache\r\n"
					"\r\n", sess->uin, (sess->client_version) ? sess->client_version : GG_DEFAULT_CLIENT_VERSION, sess->last_sysmsg);
			};

			/* zwolnij pamiêæ po wersji klienta. */
			if (sess->client_version) {
				free(sess->client_version);
				sess->client_version = NULL;
			}

    			gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-QUERY-----\n%s\n=> -----END-HTTP-QUERY-----\n", buf);
	 
			/* zapytanie jest krótkie, wiêc zawsze zmie¶ci siê
			 * do bufora gniazda. je¶li write() zwróci mniej,
			 * sta³o siê co¶ z³ego. */
			if (write(sess->fd, buf, strlen(buf)) < strlen(buf)) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() sending query failed\n");

				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_WRITING;
				sess->state = GG_STATE_IDLE;
				break;
			}

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

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_DATA\n");

			/* czytamy liniê z gniazda i obcinamy \r\n. */
			gg_read_line(sess->fd, buf, sizeof(buf) - 1);
			gg_chomp(buf);
			gg_debug(GG_DEBUG_TRAFFIC, "// gg_watch_fd() received http header (%s)\n", buf);
	
			/* sprawdzamy, czy wszystko w porz±dku. */
			if (strncmp(buf, "HTTP/1.", 7) || strncmp(buf + 9, "200", 3)) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() that's not what we've expected, trying direct connection\n");

				close(sess->fd);

				/* je¶li otrzymali¶my jakie¶ dziwne informacje,
				 * próbujemy siê ³±czyæ z pominiêciem huba. */
				if (sess->proxy_addr && sess->proxy_port) {
					if ((sess->fd = gg_connect(&sess->proxy_addr, sess->proxy_port, sess->async)) == -1) {
						/* trudno. nie wysz³o. */
						gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection to proxy failed (errno=%d, %s)\n", errno, strerror(errno));
						goto fail_connecting;
					}

					sess->state = GG_STATE_CONNECTING_GG;
					sess->check = GG_CHECK_WRITE;
					sess->timeout = GG_DEFAULT_TIMEOUT;
					break;
				}
				
				sess->port = GG_DEFAULT_PORT;

				/* ³±czymy siê na port 8074 huba. */
				if ((sess->fd = gg_connect(&sess->hub_addr, sess->port, sess->async)) == -1) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s), trying https\n", errno, strerror(errno));

					sess->port = GG_HTTPS_PORT;
					
					/* ³±czymy siê na port 443. */
					if ((sess->fd = gg_connect(&sess->hub_addr, sess->port, sess->async)) == -1) {
						gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", errno, strerror(errno));
						goto fail_connecting;
					}
				}
				
				sess->state = GG_STATE_CONNECTING_GG;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
				break;
			}
	
			/* ignorujemy resztê nag³ówka. */
			while (strcmp(buf, "\r\n") && strcmp(buf, ""))
				gg_read_line(sess->fd, buf, sizeof(buf) - 1);

			/* czytamy pierwsz± liniê danych. */
			gg_read_line(sess->fd, buf, sizeof(buf) - 1);
			gg_chomp(buf);
			
			/* je¶li pierwsza liczba w linii nie jest równa zeru,
			 * oznacza to, ¿e mamy wiadomo¶æ systemow±. */
			if (atoi(buf)) {
				char tmp[1024], *foo, *sysmsg_buf = NULL;
				int len = 0;
				
				while (gg_read_line(sess->fd, tmp, sizeof(tmp) - 1)) {
					if (!(foo = realloc(sysmsg_buf, len + strlen(tmp) + 2))) {
						gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() out of memory for system message, ignoring\n");
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
				e->event.msg.message = sysmsg_buf;
			}
	
			close(sess->fd);
	
			gg_debug(GG_DEBUG_TRAFFIC, "// gg_watch_fd() received http data (%s)\n", buf);

			/* analizujemy otrzymane dane. */
			tmp = buf;
			
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
				port = atoi(tmp+1);
			}

			addr.s_addr = inet_addr(host);
			sess->server_addr = addr.s_addr;

			if (!gg_proxy_http_only && sess->proxy_addr && sess->proxy_port) {
				/* je¶li mamy proxy, ³±czymy siê z nim. */
				if ((sess->fd = gg_connect(&sess->proxy_addr, sess->proxy_port, sess->async)) == -1) {
					/* nie wysz³o? trudno. */
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection to proxy failed (errno=%d, %s)\n", errno, strerror(errno));
					goto fail_connecting;
				}
				
				sess->state = GG_STATE_CONNECTING_GG;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
				break;
			}

			/* ³±czymy siê z w³a¶ciwym serwerem. */
			if ((sess->fd = gg_connect(&addr, port, sess->async)) == -1) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s), trying https\n", errno, strerror(errno));

				sess->port = GG_HTTPS_PORT;

				/* nie wysz³o? próbujemy portu 443. */
				if ((sess->fd = gg_connect(&addr, GG_HTTPS_PORT, sess->async)) == -1) {
					/* ostatnia deska ratunku zawiod³a?
					 * w takim razie zwijamy manatki. */
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", errno, strerror(errno));
					goto fail_connecting;
				}
			}

			sess->state = GG_STATE_CONNECTING_GG;
			sess->check = GG_CHECK_WRITE;
			sess->timeout = GG_DEFAULT_TIMEOUT;
		
			break;
		}

		case GG_STATE_CONNECTING_GG:
		{
			int res, res_size = sizeof(res);

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECTING_GG\n");

			/* je¶li wyst±pi³ b³±d podczas ³±czenia siê... */
			if (sess->async && (getsockopt(sess->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res)) {
				/* je¶li nie uda³o siê po³±czenie z proxy,
				 * nie mamy czego próbowaæ wiêcej. */
				if (sess->proxy_addr && sess->proxy_port) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection to proxy failed (errno=%d, %s)\n", res, strerror(res));
					goto fail_connecting;
				}

				close(sess->fd);

				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s), trying https\n", res, strerror(res));

				sess->port = GG_HTTPS_PORT;

				/* próbujemy na port 443. */
				if ((sess->fd = gg_connect(&sess->server_addr, sess->port, sess->async)) == -1) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connection failed (errno=%d, %s)\n", errno, strerror(errno));
					goto fail_connecting;
				}
			}

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() connected\n");
			
			if (gg_proxy_http_only)
				sess->proxy_port = 0;

			/* je¶li mamy proxy, wy¶lijmy zapytanie. */
			if (sess->proxy_addr && sess->proxy_port) {
				char buf[100], *auth = gg_proxy_auth();

				snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n", inet_ntoa(*((struct in_addr*) &sess->server_addr)), sess->port);

				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() proxy request:\n//   %s", buf);
				
				/* wysy³amy zapytanie. jest ono na tyle krótkie,
				 * ¿e musi siê zmie¶ciæ w buforze gniazda. je¶li
				 * write() zawiedzie, sta³o siê co¶ z³ego. */
				if (write(sess->fd, buf, strlen(buf)) < strlen(buf)) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() can't send proxy request\n");
					goto fail_connecting;
				}

				if (auth) {
					gg_debug(GG_DEBUG_MISC, "//   %s", auth);
					if (write(sess->fd, auth, strlen(auth)) < strlen(auth)) {
						gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() can't send proxy request\n");
						goto fail_connecting;
					}

					free(auth);
				}

				if (write(sess->fd, "\r\n", 2) < 2) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() can't send proxy request\n");
					goto fail_connecting;
				}
			}

			sess->state = GG_STATE_READING_KEY;
			sess->check = GG_CHECK_READ;
			sess->timeout = GG_DEFAULT_TIMEOUT;

			break;
		}

		case GG_STATE_READING_KEY:
		{
			struct gg_header *h;			
			struct gg_welcome *w;
			struct gg_login l;
			struct gg_login_ext lext;
			unsigned int hash;
			unsigned char *password = sess->password;
			int ret;
			
			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_KEY\n");

			/* XXX bardzo, bardzo, bardzo g³upi pomys³ na pozbycie
			 * siê tekstu wrzucanego przez proxy. */
			if (sess->proxy_addr && sess->proxy_port) {
				char buf[100];

				strcpy(buf, "");
				gg_read_line(sess->fd, buf, sizeof(buf) - 1);
				gg_chomp(buf);
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() proxy response:\n//   %s\n", buf);
				
				while (strcmp(buf, "")) {
					gg_read_line(sess->fd, buf, sizeof(buf) - 1);
					gg_chomp(buf);
					if (strcmp(buf, ""))
						gg_debug(GG_DEBUG_MISC, "//   %s\n", buf);
				}

				/* XXX niech czeka jeszcze raz w tej samej
				 * fazie. g³upio, ale dzia³a. */
				sess->proxy_port = 0;
				
				break;
			}

			/* czytaj pierwszy pakiet. */
			if (!(h = gg_recv_packet(sess))) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() didn't receive packet (errno=%d, %s)\n", errno, strerror(errno));

				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_READING;
				sess->state = GG_STATE_IDLE;
				close(sess->fd);
				sess->fd = -1;
				break;
			}
	
			if (h->type != GG_WELCOME) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() invalid packet received\n");

				free(h);
				close(sess->fd);
				sess->fd = -1;
				errno = EINVAL;
				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_INVALID;
				sess->state = GG_STATE_IDLE;
				break;
			}
	
			w = (struct gg_welcome*) ((char*) h + sizeof(struct gg_header));
			w->key = fix32(w->key);

			hash = gg_login_hash(password, w->key);
	
			gg_debug(GG_DEBUG_DUMP, "// gg_watch_fd() challenge %.4x --> hash %.8x\n", w->key, hash);
	
			free(h);

			free(sess->password);
			sess->password = NULL;

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() gg_dcc_ip = %s\n", inet_ntoa(*((struct in_addr*) &gg_dcc_ip)));
			
			if (gg_dcc_ip == (unsigned long) inet_addr("255.255.255.255")) {
				struct sockaddr_in sin;
				int sin_len = sizeof(sin);

				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() detecting address\n");

				if (!getsockname(sess->fd, (struct sockaddr*) &sin, &sin_len)) {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() detected address to %s\n", inet_ntoa(sin.sin_addr));
					l.local_ip = sin.sin_addr.s_addr;
				} else {
					gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() unable to detect address\n");
					l.local_ip = 0;
				}
			} else 
				l.local_ip = gg_dcc_ip;
		
			l.uin = fix32(sess->uin);
			l.hash = fix32(hash);
			l.status = fix32(sess->initial_status ? sess->initial_status : GG_STATUS_AVAIL);
			l.version = fix32(sess->protocol_version);
			l.local_port = fix16(gg_dcc_port);
			
			if (sess->external_addr && sess->external_port > 1023) {
				memcpy(&lext, &l, sizeof(l));
				lext.external_ip = sess->external_addr;
				lext.external_port = sess->external_port;
				gg_debug(GG_DEBUG_TRAFFIC, "// gg_watch_fd() sending GG_LOGIN_EXT packet\n");
				ret = gg_send_packet(sess->fd, GG_LOGIN_EXT, &lext, sizeof(lext), sess->initial_descr, (sess->initial_descr) ? strlen(sess->initial_descr) : 0, NULL);
			} else {
				gg_debug(GG_DEBUG_TRAFFIC, "// gg_watch_fd() sending GG_LOGIN packet\n");
				ret = gg_send_packet(sess->fd, GG_LOGIN, &l, sizeof(l), sess->initial_descr, (sess->initial_descr) ? strlen(sess->initial_descr) : 0, NULL);
			}

			if (ret == -1) {
				gg_debug(GG_DEBUG_TRAFFIC, "// gg_watch_fd() sending packet failed. (errno=%d, %s)\n", errno, strerror(errno));

				close(sess->fd);
				sess->fd = -1;
				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_WRITING;
				sess->state = GG_STATE_IDLE;
				break;
			}
	
			sess->state = GG_STATE_READING_REPLY;

			break;
		}

		case GG_STATE_READING_REPLY:
		{
			struct gg_header *h;

			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_READING_REPLY\n");

			if (!(h = gg_recv_packet(sess))) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() didn't receive packet (errno=%d, %s)\n", errno, strerror(errno));
				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_READING;
				sess->state = GG_STATE_IDLE;
				close(sess->fd);
				sess->fd = -1;
				break;
			}
	
			if (h->type == GG_LOGIN_OK) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() login succeded\n");
				e->type = GG_EVENT_CONN_SUCCESS;
				sess->state = GG_STATE_CONNECTED;
				sess->timeout = -1;
				sess->status = (sess->initial_status) ? sess->initial_status : GG_STATUS_AVAIL;
				free(h);
				break;
			}

			if (h->type == GG_LOGIN_FAILED) {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() login failed\n");
				e->event.failure = GG_FAILURE_PASSWORD;
				errno = EACCES;
			} else {
				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() invalid packet\n");
				e->event.failure = GG_FAILURE_INVALID;
				errno = EINVAL;
			}

			e->type = GG_EVENT_CONN_FAILED;
			sess->state = GG_STATE_IDLE;
			close(sess->fd);
			sess->fd = -1;
			free(h);

			break;
		}

		case GG_STATE_CONNECTED:
		{
			gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() GG_STATE_CONNECTED\n");

			sess->last_event = time(NULL);
			
			if ((res = gg_watch_fd_connected(sess, e)) == -1) {

				gg_debug(GG_DEBUG_MISC, "// gg_watch_fd() watch_fd_connected failed (errno=%d, %s)\n", errno, strerror(errno));

 				if (errno == EAGAIN) {
					e->type = GG_EVENT_NONE;
					res = 0;
				} else
					res = -1;
			}
			break;
		}
	}

done:
	if (res == -1) {
		free(e);
		e = NULL;
	}

	return e;
	
fail_connecting:
	if (sess->fd != -1) {
		close(sess->fd);
		sess->fd = -1;
	}
	e->type = GG_EVENT_CONN_FAILED;
	e->event.failure = GG_FAILURE_CONNECTING;
	sess->state = GG_STATE_IDLE;
	goto done;

fail_resolving:
	e->type = GG_EVENT_CONN_FAILED;
	e->event.failure = GG_FAILURE_RESOLVING;
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
