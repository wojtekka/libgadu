/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>,
 *                          Robert J. Wo¼ny <speedy@ziew.org>,
 *                          Arkadiusz Mi¶kiewicz <misiek@pld.ORG.PL>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#include <time.h>
#include "libgadu.h"
#include "config.h"

/*
 * gg_free_event()
 *
 * zwalnia pamiêæ zajmowan± przez informacjê o zdarzeniu
 *
 *  - event - wska¼nik do informacji o zdarzeniu
 *
 * nie ma czego zwracaæ.
 */
void gg_free_event(struct gg_event *e)
{
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
	
	free(e);
}

/*
 * gg_handle_message() // funkcja wewnêtrzna
 */
static int gg_handle_recv_msg(struct gg_header *h, struct gg_event *e)
{
	struct gg_recv_msg *r = (void*) h + sizeof(struct gg_header);
	char *p, *packet_end = (void*) r + h->length;

	gg_debug(GG_DEBUG_MISC, "-- received a message\n");

	//printf("packet=%p\n", h);

	for (p = (void*) r + sizeof(*r); *p; p++) {
		if (p >= packet_end) {
			gg_debug(GG_DEBUG_MISC, "-- malformed packet, message out of bounds.\n");
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
				gg_debug(GG_DEBUG_MISC, "-- packet out of bounds\n");
				errno = EINVAL;
				goto fail;
			}

			count = fix32(m->count);
			
			if (!(e->event.msg.recipients = (void*) malloc(count * sizeof(uin_t)))) {
				gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
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
				gg_debug(GG_DEBUG_MISC, "-- packet out of bounds\n");
				errno = EINVAL;
				goto fail;
			}

			len = (unsigned short*) (p + 1);
			gg_debug(GG_DEBUG_MISC, "-- p = %p, packetend = %p, len = %d\n", p, packet_end, len);

			if (!(tmp = malloc(*len))) {
				gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
				goto fail;
			}

			p += 3;

			if (p + *len > packet_end) {
				gg_debug(GG_DEBUG_MISC, "-- packet out of bounds\n");
				errno = EINVAL;
				goto fail;
			}
				
			memcpy(tmp, p, *len);

			e->event.msg.formats = tmp;
			e->event.msg.formats_length = *len;

		} else				/* nieznana opcja */
			p = packet_end;
	}

	e->type = GG_EVENT_MSG;
	e->event.msg.msgclass = fix32(r->msgclass);
	e->event.msg.sender = fix32(r->sender);
	e->event.msg.time = fix32(r->time);
	e->event.msg.message = strdup((void*) r + sizeof(*r));

	return 0;
	
fail:
	free(e->event.msg.recipients);
	free(e->event.msg.formats);
	return -1;
}

/*
 * gg_watch_fd_connected() // funkcja wewnêtrzna
 *
 * patrzy na socketa, odbiera pakiet i wype³nia strukturê zdarzenia.
 *
 *  - sock - lalala, trudno zgadn±æ.
 *
 * je¶li b³±d -1, je¶li dobrze 0.
 */
static int gg_watch_fd_connected(struct gg_session *sess, struct gg_event *e)
{
	struct gg_header *h = NULL;
	void *p;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_watch_fd_connected(...);\n");

	if (!(h = gg_recv_packet(sess))) {
		gg_debug(GG_DEBUG_MISC, "-- gg_recv_packet failed. errno = %d (%d)\n", errno, strerror(errno));
		goto fail;
	}

	p = (void*) h + sizeof(struct gg_header);
	
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

			gg_debug(GG_DEBUG_MISC, "-- received a notify reply\n");

			if (h->length < sizeof(*n)) {
				gg_debug(GG_DEBUG_MISC, "-- incomplete packet\n");
				errno = EINVAL;
				goto fail;
			}

			if (fix32(n->status) == GG_STATUS_BUSY_DESCR || fix32(n->status == GG_STATUS_NOT_AVAIL_DESCR)) {
				e->type = GG_EVENT_NOTIFY_DESCR;
				
				if (!(e->event.notify_descr.notify = (void*) malloc(sizeof(*n) * 2))) {
					gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
					goto fail;
				}
				e->event.notify_descr.notify[1].uin = 0;
				memcpy(e->event.notify_descr.notify, p, sizeof(*n));
				e->event.notify_descr.notify[0].uin = fix32(e->event.notify_descr.notify[0].uin);
				e->event.notify_descr.notify[0].status = fix32(e->event.notify_descr.notify[0].status);
				e->event.notify_descr.notify[0].remote_port = fix16(e->event.notify_descr.notify[0].remote_port);

				count = h->length - sizeof(*n);
				if (!(tmp = malloc(count + 1))) {
					gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
					goto fail;
				}
				memcpy(tmp, p + sizeof(*n), count);
				tmp[count] = 0;
				e->event.notify_descr.descr = tmp;
				
			} else {
				e->type = GG_EVENT_NOTIFY;
				
				if (!(e->event.notify = (void*) malloc(h->length + 2 * sizeof(*n)))) {
					gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
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

			gg_debug(GG_DEBUG_MISC, "-- received a status change\n");

			if (h->length >= sizeof(*s)) {
				e->type = GG_EVENT_STATUS;
				memcpy(&e->event.status, p, sizeof(*s));
				e->event.status.uin = fix32(e->event.status.uin);
				e->event.status.status = fix32(e->event.status.status);
				if (h->length > sizeof(*s)) {
					int len = h->length - sizeof(*s);
					char *buf = malloc(len + 1);
					if (buf) {
						memcpy(buf, p + sizeof(*s), len);
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

			gg_debug(GG_DEBUG_MISC, "-- received a message ack\n");

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
			gg_debug(GG_DEBUG_MISC, "-- received a pong\n");

			e->type = GG_EVENT_PONG;
			sess->last_pong = time(NULL);

			break;
		}

		case GG_DISCONNECTING:
		{
			gg_debug(GG_DEBUG_MISC, "-- received disconnection warning\n");
			e->type = GG_EVENT_DISCONNECT;
			break;
		}

		default:
			gg_debug(GG_DEBUG_MISC, "-- received unknown packet 0x%.2x\n", h->type);
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
 * funkcja wywo³ywana, gdy co¶ siê stanie na obserwowanym deskryptorze.
 * zwraca klientowi informacjê o tym, co siê dzieje.
 *
 *  - sess - identyfikator sesji.
 *
 * zwraca wska¼nik do struktury gg_event, któr± trzeba zwolniæ pó¼niej
 * za pomoc± gg_free_event(). jesli rodzaj zdarzenia jest równy
 * GG_EVENT_NONE, nale¿y je olaæ kompletnie. je¶li zwróci³o NULL,
 * sta³o siê co¶ niedobrego -- albo brak³o pamiêci albo zerwa³o
 * po³±czenie albo co¶ takiego.
 */
struct gg_event *gg_watch_fd(struct gg_session *sess)
{
	struct gg_event *e;
	int res = 0;
	int port;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_watch_fd(...);\n");
	
	if (!sess) {
		errno = EFAULT;
		return NULL;
	}

	if (!(e = (void*) calloc(1, sizeof(*e)))) {
		gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
		return NULL;
	}

	e->type = GG_EVENT_NONE;

	switch (sess->state) {
		case GG_STATE_RESOLVING:
		{
			struct in_addr a;

			gg_debug(GG_DEBUG_MISC, "== GG_STATE_RESOLVING\n");

			if (read(sess->fd, &a, sizeof(a)) < sizeof(a) || a.s_addr == INADDR_NONE) {
				gg_debug(GG_DEBUG_MISC, "-- resolving failed\n");				

				errno = ENOENT;
				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_RESOLVING;
				sess->state = GG_STATE_IDLE;

				close(sess->fd);

				break;
			}
			
			sess->server_ip = a.s_addr;

			close(sess->fd);

			waitpid(sess->pid, NULL, 0);

			gg_debug(GG_DEBUG_MISC, "-- resolved, now connecting\n");
			
			if (gg_http_use_proxy) {
				port = gg_http_proxy_port;
			} else {
				port = GG_APPMSG_PORT;
			};

			if ((sess->fd = gg_connect(&a, port, sess->async)) == -1) {
				struct in_addr *addr = (struct in_addr*) &sess->server_ip;
				
				gg_debug(GG_DEBUG_MISC, "-- connection failed, trying direct connection\n");

				if ((sess->fd = gg_connect(addr, GG_DEFAULT_PORT, sess->async)) == -1) {
				    gg_debug(GG_DEBUG_MISC, "-- connection failed, trying https connection\n");
				    if ((sess->fd = gg_connect(&a, GG_HTTPS_PORT, sess->async)) == -1) {		
					gg_debug(GG_DEBUG_MISC, "-- connect() failed. errno = %d (%s)\n", errno, strerror(errno));

					e->type = GG_EVENT_CONN_FAILED;
					e->event.failure = GG_FAILURE_CONNECTING;
					sess->state = GG_STATE_IDLE;
					break;
				    }
				}
				sess->state = GG_STATE_CONNECTING_GG;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
			} else {
				sess->state = GG_STATE_CONNECTING;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
			}
				
			break;
		}

		case GG_STATE_CONNECTING:
		{
			char buf[1024];
			int res, res_size = sizeof(res);

			gg_debug(GG_DEBUG_MISC, "== GG_STATE_CONNECTING\n");

			if (sess->async && (getsockopt(sess->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res)) {
				struct in_addr *addr = (struct in_addr*) &sess->server_ip;
				gg_debug(GG_DEBUG_MISC, "-- http connection failed, errno = %d (%s), trying direct connection\n", res, strerror(res));
				close(sess->fd);

				if ((sess->fd = gg_connect(addr, GG_DEFAULT_PORT, sess->async)) == -1) {
					gg_debug(GG_DEBUG_MISC, "-- connection failed, trying https connection\n");
					if ((sess->fd = gg_connect(addr, GG_HTTPS_PORT, sess->async)) == -1) {
						gg_debug(GG_DEBUG_MISC, "-- connect() failed. errno = %d (%s)\n", errno, strerror(errno));

						e->type = GG_EVENT_CONN_FAILED;
						e->event.failure = GG_FAILURE_CONNECTING;
						sess->state = GG_STATE_IDLE;
						break;
					}
				}

				sess->state = GG_STATE_CONNECTING_GG;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
				break;
			}
			
			gg_debug(GG_DEBUG_MISC, "-- http connection succeded, sending query\n");

			if (gg_http_use_proxy) {
				snprintf(buf, sizeof(buf) - 1,
					"GET http://" GG_APPMSG_HOST "/appsvc/appmsg.asp?fmnumber=%lu HTTP/1.0\r\n"
					"Host: " GG_APPMSG_HOST "\r\n"
					"User-Agent: " GG_HTTP_USERAGENT "\r\n"
					"Pragma: no-cache\r\n"
					"\r\n", sess->uin);
			} else {
				snprintf(buf, sizeof(buf) - 1,
					"GET /appsvc/appmsg.asp?fmnumber=%lu HTTP/1.0\r\n"
					"Host: " GG_APPMSG_HOST "\r\n"
					"User-Agent: " GG_HTTP_USERAGENT "\r\n"
					"Pragma: no-cache\r\n"
					"\r\n", sess->uin);
			};

    			gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-QUERY-----\n%s\n=> -----END-HTTP-QUERY-----\n", buf);
	 
			if (write(sess->fd, buf, strlen(buf)) < strlen(buf)) {
				gg_debug(GG_DEBUG_MISC, "-- sending query failed\n");

				errno = EIO;
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
			int sysmsgidx = 0, sysmsg = 0;
			struct in_addr a;

			gg_debug(GG_DEBUG_MISC, "== GG_STATE_READING_DATA\n");

			gg_read_line(sess->fd, buf, sizeof(buf) - 1);
			gg_chomp(buf);
	
			gg_debug(GG_DEBUG_TRAFFIC, "-- got http response (%s)\n", buf);
			if (strncmp(buf, "HTTP/1.", 7) || strncmp(buf + 9, "200", 3)) {
				gg_debug(GG_DEBUG_MISC, "-- but that's not what we've expected. moving to direct connection\n");
				a.s_addr = sess->server_ip;

				if ((sess->fd = gg_connect(&a, GG_DEFAULT_PORT, sess->async)) == -1) {
					gg_debug(GG_DEBUG_MISC, "-- connection failed, trying https connection\n");
					if ((sess->fd = gg_connect(&a, GG_HTTPS_PORT, sess->async)) == -1) {
						gg_debug(GG_DEBUG_MISC, "-- connection failed, errno = %d (%s)\n", errno, strerror(errno));

						e->type = GG_EVENT_CONN_FAILED;
						e->event.failure = GG_FAILURE_CONNECTING;
						sess->state = GG_STATE_IDLE;
						break;
					}
				}
				sess->state = GG_STATE_CONNECTING_GG;
				sess->check = GG_CHECK_WRITE;
				sess->timeout = GG_DEFAULT_TIMEOUT;
				break;
			}
	
			while (strcmp(buf, "\r\n") && strcmp(buf, ""))
				gg_read_line(sess->fd, buf, sizeof(buf) - 1);

			gg_read_line(sess->fd, buf, sizeof(buf) - 1);
			gg_chomp(buf);
			
			tmp = buf;

			if (*buf) { 
				sysmsgidx = atoi(tmp);	
				while (*tmp && *tmp != ' ')
				    tmp++;
				while (*tmp && *tmp == ' ')
				    tmp++;
				sysmsg = atoi(tmp);
				tmp = 0;
			};

			if (sysmsg && sysmsgidx) {
				char tmp[1024], *foo, *sysmsg_buf = NULL;
				int len = 0;
				
				while (gg_read_line(sess->fd, tmp, sizeof(tmp) - 1)) {
					if (!(foo = realloc(sysmsg_buf, len + strlen(tmp) + 2))) {
						gg_debug(GG_DEBUG_MISC, "-- out of memory for system message. cutting.\n");
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
				e->event.msg.msgclass = sysmsgidx;
				e->event.msg.sender = 0;
				e->event.msg.message = sysmsg_buf;
			}
	
			close(sess->fd);
	
			gg_debug(GG_DEBUG_TRAFFIC, "-- received http data (%s)\n", buf);
						
			tmp = buf;
			
			while (*tmp && *tmp != ' ')
				tmp++;
			while (*tmp && *tmp == ' ')
				tmp++;
			while (*tmp && *tmp != ' ')
				tmp++;
			while (*tmp && *tmp == ' ')
				tmp++;
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
			a.s_addr = inet_addr(host);
			sess->server_ip = a.s_addr;

			if ((sess->fd = gg_connect(&a, port, sess->async)) == -1) {
				gg_debug(GG_DEBUG_MISC, "-- connection failed, trying https connection\n");
				if ((sess->fd = gg_connect(&a, GG_HTTPS_PORT, sess->async)) == -1) {
				    gg_debug(GG_DEBUG_MISC, "-- connection failed, errno = %d (%s)\n", errno, strerror(errno));

				    e->type = GG_EVENT_CONN_FAILED;
				    e->event.failure = GG_FAILURE_CONNECTING;
				    sess->state = GG_STATE_IDLE;
				    break;
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

			gg_debug(GG_DEBUG_MISC, "== GG_STATE_CONNECTING_GG\n");

			if (sess->async && (getsockopt(sess->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res)) {
				struct in_addr *addr = (struct in_addr*) &sess->server_ip;

				gg_debug(GG_DEBUG_MISC, "-- connection failed, trying https connection\n");
				close(sess->fd);

				if ((sess->fd = gg_connect(addr, GG_HTTPS_PORT, sess->async)) == -1) {
					gg_debug(GG_DEBUG_MISC, "-- connection failed, errno = %d (%s)\n", errno, strerror(errno));
				    
					e->type = GG_EVENT_CONN_FAILED;
					e->event.failure = GG_FAILURE_CONNECTING;
					sess->state = GG_STATE_IDLE;
					break;
				}
			}

			gg_debug(GG_DEBUG_MISC, "-- connected\n");
			
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
			unsigned int hash;
			unsigned char *password = sess->password;
			struct sockaddr_in sin;
			int sin_len = sizeof(sin);
			unsigned long sess_ip = 0;

			gg_debug(GG_DEBUG_MISC, "== GG_STATE_READING_KEY\n");

			if (!(h = gg_recv_packet(sess))) {
				gg_debug(GG_DEBUG_MISC, "-- gg_recv_packet() failed. errno = %d (%s)\n", errno, strerror(errno));

				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_READING;
				sess->state = GG_STATE_IDLE;
				close(sess->fd);
				break;
			}
	
			if (h->type != GG_WELCOME) {
				gg_debug(GG_DEBUG_MISC, "-- invalid packet received\n");

				free(h);
				close(sess->fd);
				errno = EINVAL;
				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_INVALID;
				sess->state = GG_STATE_IDLE;
				break;
			}
	
			w = (void*) h + sizeof(struct gg_header);
			w->key = fix32(w->key);

			hash = gg_login_hash(password, w->key);
	
			gg_debug(GG_DEBUG_DUMP, "%%%% klucz serwera %.4x, hash has³a %.8x\n", w->key, hash);
	
			free(h);

			free(sess->password);
			sess->password = NULL;
			
			if(!getsockname(sess->fd, (struct sockaddr*) &sin, &sin_len))
				sess_ip = sin.sin_addr.s_addr;	
		
			if(gg_dcc_ip == INADDR_ANY) {
				sess->client_ip = (sess_ip) ? (sess_ip) : INADDR_NONE;
				sess->client_port = gg_dcc_port;
			} else {
				sess->client_ip = 0;
				sess->client_port = 0;
			};
			
			l.uin = fix32(sess->uin);
			l.hash = fix32(hash);
			l.status = fix32(sess->initial_status ? sess->initial_status : GG_STATUS_AVAIL);
			l.version = fix32(GG_CLIENT_VERSION);
			l.local_ip = sess->client_ip;
			l.local_port = fix16(sess->client_port);
	
			gg_debug(GG_DEBUG_TRAFFIC, "-- sending GG_LOGIN packet\n");

			if (gg_send_packet(sess->fd, GG_LOGIN, &l, sizeof(l), NULL) == -1) {
				gg_debug(GG_DEBUG_TRAFFIC, "-- oops, failed. errno = %d (%s)\n", errno, strerror(errno));

				close(sess->fd);
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

			gg_debug(GG_DEBUG_MISC, "== GG_STATE_READING_REPLY\n");

			if (!(h = gg_recv_packet(sess))) {
				gg_debug(GG_DEBUG_MISC, "-- recv_packet failed\n");
				e->type = GG_EVENT_CONN_FAILED;
				e->event.failure = GG_FAILURE_READING;
				sess->state = GG_STATE_IDLE;
				close(sess->fd);
				break;
			}
	
			if (h->type == GG_LOGIN_OK) {
				gg_debug(GG_DEBUG_MISC, "-- login succeded\n");
				e->type = GG_EVENT_CONN_SUCCESS;
				sess->state = GG_STATE_CONNECTED;
				sess->timeout = -1;
				sess->status = (sess->initial_status) ? sess->initial_status : GG_STATUS_AVAIL;
				free(h);
				break;
			}

			if (h->type == GG_LOGIN_FAILED) {
				gg_debug(GG_DEBUG_MISC, "-- login failed\n");
				e->event.failure = GG_FAILURE_PASSWORD;
				errno = EACCES;
			} else {
				gg_debug(GG_DEBUG_MISC, "-- invalid packet\n");
				e->event.failure = GG_FAILURE_INVALID;
				errno = EINVAL;
			}

			e->type = GG_EVENT_CONN_FAILED;
			sess->state = GG_STATE_IDLE;
			close(sess->fd);
			free(h);

			break;
		}

		case GG_STATE_CONNECTED:
		{
			gg_debug(GG_DEBUG_MISC, "== GG_STATE_CONNECTED\n");

			sess->last_event = time(NULL);
			
			if ((res = gg_watch_fd_connected(sess, e)) == -1) {

				gg_debug(GG_DEBUG_MISC, "-- watch_fd_connected failed. errno = %d (%s)\n", errno, strerror(errno));

 				if (errno == EAGAIN) {
					e->type = GG_EVENT_NONE;
					res = 0;
				} else
					res = -1;
			}
			break;
		}
	}

	if (res == -1) {
		free(e);
		e = NULL;
	}

	return e;
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
