/* $Id$ */

/*
 *  (C) Copyright 2001 Wojtek Kaniewski <wojtekka@irc.pl>,
 *                     Robert J. Wo¼ny <speedy@ziew.org>,
 *                     Arkadiusz Mi¶kiewicz <misiek@pld.ORG.PL>
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
#include <stdarg.h>
#include <pwd.h>
#include <time.h>
#ifdef sun
  #include <sys/filio.h>
#endif
#include "libgadu.h"
#include "config.h"

int gg_debug_level = 0;

int gg_dcc_port = 0;
unsigned long gg_dcc_ip = 0;

/*
 *  zmienne opisuj±ce parametry proxy http.
 */
char *gg_http_proxy_host = NULL;
int gg_http_proxy_port = 0;
int gg_http_use_proxy = 0;

#ifndef lint 
static char rcsid[]
#ifdef __GNUC__
__attribute__ ((unused))
#endif
= "$Id$";
#endif 

/*
 * fix32() // funkcja wewnêtrzna
 *
 * dla maszyn big-endianowych zamienia kolejno¶æ bajtów w ,,long''ach.
 */
unsigned long fix32(unsigned long x)
{
#ifndef WORDS_BIGENDIAN
	return x;
#else
	return (unsigned long)
		(((x & (unsigned long) 0x000000ffU) << 24) |
                 ((x & (unsigned long) 0x0000ff00U) << 8) |
                 ((x & (unsigned long) 0x00ff0000U) >> 8) |
                 ((x & (unsigned long) 0xff000000U) >> 24));
#endif		
}

/*
 * fix16() // funkcja wewnêtrzna
 *
 * dla maszyn big-endianowych zamienia kolejno¶æ bajtów w ,,short''ach.
 */
unsigned short fix16(unsigned short x)
{
#ifndef WORDS_BIGENDIAN
	return x;
#else
	return (unsigned short)
		(((x & (unsigned short) 0x00ffU) << 8) |
                 ((x & (unsigned short) 0xff00U) >> 8));
#endif
}

/*
 * gg_resolve() // funkcja wewnêtrzna
 *
 * tworzy pipe'y, forkuje siê i w drugim procesie zaczyna resolvowaæ 
 * podanego hosta. zapisuje w sesji deskryptor pipe'u. je¶li co¶ tam
 * bêdzie gotowego, znaczy, ¿e mo¿na wczytaæ ,,struct in_addr''. je¶li
 * nie znajdzie, zwraca INADDR_NONE.
 *
 *  - fd - wska¼nik gdzie wrzuciæ deskryptor,
 *  - pid - gdzie wrzuciæ pid dzieciaka,
 *  - hostname - nazwa hosta do zresolvowania.
 *
 * zwraca 0 je¶li uda³o siê odpaliæ proces lub -1 w przypadku b³êdu.
 */
int gg_resolve(int *fd, int *pid, char *hostname)
{
	int pipes[2], res;
	struct in_addr a;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_resolve(..., \"%s\");\n", hostname);
	
	if (!fd | !pid) {
		errno = EFAULT;
		return -1;
	}

	if (pipe(pipes) == -1)
		return -1;

	if ((res = fork()) == -1)
		return -1;

	if (!res) {
		if ((a.s_addr = inet_addr(hostname)) == INADDR_NONE) {
			struct hostent *he;
		
			if (!(he = gethostbyname(hostname)))
				a.s_addr = INADDR_NONE;
			else
				memcpy((char*) &a, he->h_addr, sizeof(a));
		}

		write(pipes[1], &a, sizeof(a));

		exit(0);
	}

	close(pipes[1]);

	*fd = pipes[0];
	*pid = res;

	return 0;
}

/*
 * gg_recv_packet() // funkcja wewnêtrzna
 *
 * odbiera jeden pakiet gg i zwraca wska¼nik do niego. pamiêæ po nim
 * wypada³oby uwolniæ.
 *
 *  - sock - po³±czony socket.
 *
 * je¶li wyst±pi³ b³±d, zwraca NULL. reszta w errno.
 */
static void *gg_recv_packet(struct gg_session *sess)
{
	struct gg_header h;
	char *buf = NULL;
	int ret = 0, offset, size = 0;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_recv_packet(...);\n");
	
	if (!sess) {
		errno = EFAULT;
		return NULL;
	}

	if (sess->recv_left < 1) {
		int tries = 10;
		
		while (ret != sizeof(h)) {
			ret = read(sess->fd, &h, sizeof(h));
			gg_debug(GG_DEBUG_MISC, "-- header recv(..., %d) = %d\n", sizeof(h), ret);
			if (ret < sizeof(h)) {
				if (errno != EINTR || !--tries) {
					gg_debug(GG_DEBUG_MISC, "-- errno = %d (%s)\n", errno, strerror(errno));
					return NULL;
				}
			}
		}

		h.type = fix32(h.type);
		h.length = fix32(h.length);
	} else {
		memcpy(&h, sess->recv_buf, sizeof(h));
	}

	/* jakie¶ sensowne limity na rozmiar pakietu */
	if (h.length < 0 || h.length > 65535) {
		gg_debug(GG_DEBUG_MISC, "-- invalid packet length (%d)\n", h.length);
		errno = ERANGE;
		return NULL;
	}

	if (sess->recv_left > 0) {
		gg_debug(GG_DEBUG_MISC, "-- resuming last gg_recv_packet()\n");
		size = sess->recv_left;
		offset = sess->recv_done;
		buf = sess->recv_buf;
	} else {
		if (!(buf = malloc(sizeof(h) + h.length + 1))) {
			gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
			return NULL;
		}

		memcpy(buf, &h, sizeof(h));

		offset = 0;
		size = h.length;
	}

	while (size > 0) {
		ret = read(sess->fd, buf + sizeof(h) + offset, size);
		gg_debug(GG_DEBUG_MISC, "-- body recv(..., %d) = %d\n", size, ret);
		if (ret > -1 && ret <= size) {
			offset += ret;
			size -= ret;
		} else if (ret == -1) {	
			gg_debug(GG_DEBUG_MISC, "-- errno = %d (%s)\n", errno, strerror(errno));
			if (errno == EAGAIN) {
				gg_debug(GG_DEBUG_MISC, "-- %d bytes received, %d left\n", offset, size);
				sess->recv_buf = buf;
				sess->recv_left = size;
				sess->recv_done = offset;
				return NULL;
			}
			if (errno != EINTR) {
//				errno = EINVAL;
				free(buf);
				return NULL;
			}
		}
	}

	sess->recv_left = 0;

	if ((gg_debug_level & GG_DEBUG_DUMP)) {
		int i;

		gg_debug(GG_DEBUG_DUMP, ">> received packet (type=%.2x):", h.type);
		for (i = 0; i < sizeof(h) + h.length; i++) 
			gg_debug(GG_DEBUG_DUMP, " %.2x", (unsigned char) buf[i]);
		gg_debug(GG_DEBUG_DUMP, "\n");
	}

	return buf;
}

/*
 * gg_send_packet() // funkcja wewnêtrzna
 *
 * konstruuje pakiet i wysy³a go w do serwera.
 *
 *  - sock - po³±czony socket,
 *  - type - typ pakietu,
 *  - payload_1
 *  - payload_length_1
 *  - payload_2
 *  - payload_length_2
 *  - ...
 *  - ...
 *  - NULL - koñcowym parametr (konieczny!)
 *
 * je¶li posz³o dobrze, zwraca 0. w przypadku b³êdu -1. je¶li errno=ENOMEM,
 * zabrak³o pamiêci. inaczej by³ b³±d przy wysy³aniu pakietu. dla errno=0
 * nie wys³ano ca³ego pakietu.
 */
static int gg_send_packet(int sock, int type, ...)
{
	struct gg_header *h;
	char *tmp;
	int tmp_length;
	void *payload;
	int payload_length;
	va_list ap;
	int res;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_send_packet(0x%.2x, ...)\n", type);

	tmp_length = 0;

	if (!(tmp = malloc(sizeof(struct gg_header)))) {
		gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
		return -1;
	}

	h = (struct gg_header*) tmp;
	h->type = fix32(type);
	h->length = fix32(0);

	va_start(ap, type);

	payload = va_arg(ap, void *);

	while (payload) {
		payload_length = va_arg(ap, int);

		if (payload_length < 0)
			gg_debug(GG_DEBUG_MISC, "-- invalid payload length\n");
	
		if (!(tmp = realloc(tmp, sizeof(struct gg_header) + tmp_length + payload_length))) {
                        gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
                        return -1;
                }
		
		memcpy(tmp + sizeof(struct gg_header) + tmp_length, payload, payload_length);
		tmp_length += payload_length;

		payload = va_arg(ap, void *);
	}

	va_end(ap);

	h = (struct gg_header*) tmp;
	h->length = fix32(tmp_length);

	if ((gg_debug_level & GG_DEBUG_DUMP)) {
                int i;
		
                gg_debug(GG_DEBUG_DUMP, "%%%% sending packet (type=%.2x):", fix32(h->type));
                for (i = 0; i < sizeof(struct gg_header) + fix32(h->length); i++)
                        gg_debug(GG_DEBUG_DUMP, " %.2x", (unsigned char) tmp[i]);
                gg_debug(GG_DEBUG_DUMP, "\n");
        }
	
	tmp_length += sizeof(struct gg_header);
	
	if ((res = write(sock, tmp, tmp_length)) < tmp_length) {
		gg_debug(GG_DEBUG_MISC, "-- write() failed. res = %d, errno = %d (%s)\n", res, errno, strerror(errno));
		free(tmp);
		return -1;
	}
	
	free(tmp);	
	return 0;
}


/*
 * gg_login()
 *
 * rozpoczyna procedurê ³±czenia siê z serwerem. resztê obs³guje siê przez
 * gg_watch_event.
 *
 *  - uin - numerek usera,
 *  - password - jego hase³ko,
 *  - async - ma byæ asynchronicznie?
 *
 * UWAGA! program musi obs³u¿yæ SIGCHLD, je¶li ³±czy siê asynchronicznie,
 * ¿eby zrobiæ pogrzeb zmar³emu procesowi resolvera.
 *
 * w przypadku b³êdu zwraca NULL, je¶li idzie dobrze (async) albo posz³o
 * dobrze (sync), zwróci wska¼nik do zaalokowanej struktury `gg_session'.
 */
struct gg_session *gg_login(uin_t uin, char *password, int async)
{
	struct gg_session *sess;
	char *hostname;
	int port;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_login(%u, \"...\", %d);\n", uin, async);

	if (!(sess = malloc(sizeof(*sess))))
		return NULL;
	memset(sess, 0, sizeof(*sess));

	sess->uin = uin;
	if (!(sess->password = strdup(password))) {
		free(sess);
		return NULL;
	}
	sess->state = GG_STATE_RESOLVING;
	sess->check = GG_CHECK_READ;
	sess->timeout = GG_DEFAULT_TIMEOUT;
	sess->async = async;
        sess->type = GG_SESSION_GG;
	
	if (gg_http_use_proxy) {
		hostname = gg_http_proxy_host;
		port = gg_http_proxy_port;
	} else {
		hostname = GG_APPMSG_HOST;
		port = GG_APPMSG_PORT;
	};

	if (async) {
		if (gg_resolve(&sess->fd, &sess->pid, hostname)) {
			gg_debug(GG_DEBUG_MISC, "-- resolving failed\n");
			free(sess);
			return NULL;
		}
	} else {
		struct in_addr a;

		if ((a.s_addr = inet_addr(hostname)) == INADDR_NONE) {
			struct hostent *he;
	
			if (!(he = gethostbyname(hostname))) {
				gg_debug(GG_DEBUG_MISC, "-- host %s not found\n", hostname);
				free(sess);
				return NULL;
			} else
				memcpy((char*) &a, he->h_addr, sizeof(a));
		}

		if (!(sess->fd = gg_connect(&a, port, 0)) == -1) {
			gg_debug(GG_DEBUG_MISC, "-- connection failed\n");
			free(sess);
			return NULL;
		}

		sess->state = GG_STATE_CONNECTING;

		while (sess->state != GG_STATE_CONNECTED) {
			struct gg_event *e;

			if (!(e = gg_watch_fd(sess))) {
				gg_debug(GG_DEBUG_MISC, "-- some nasty error in gg_watch_fd()\n");
				free(sess);
				return NULL;
			}

			if (e->type == GG_EVENT_CONN_FAILED) {
				errno = EACCES;
				gg_debug(GG_DEBUG_MISC, "-- could not login\n");
				gg_free_event(e);
				free(sess);
				return NULL;
			}

			gg_free_event(e);
		}
	}

	return sess;
}

/* 
 * gg_free_session()
 *
 * zwalnia pamiêæ zajmowan± przez opis sesji.
 *
 *  - sess - opis sesji.
 *
 * nie zwraca niczego, bo i po co?
 */
void gg_free_session(struct gg_session *sess)
{
	if (!sess)
		return;

	free(sess->password);
	free(sess);
}

/*
 * gg_change_status()
 *
 * zmienia status u¿ytkownika. przydatne do /away i /busy oraz /quit.
 *
 *  - sess - opis sesji,
 *  - status - nowy status u¿ytkownika.
 *
 * je¶li wys³a³ pakiet zwraca 0, je¶li nie uda³o siê, zwraca -1.
 */
int gg_change_status(struct gg_session *sess, int status)
{
	struct gg_new_status p;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_change_status(..., %d);\n", status);

	p.status = fix32(status);

	return gg_send_packet(sess->fd, GG_NEW_STATUS, &p, sizeof(p), NULL);
}

/*
 * gg_logoff()
 *
 * wylogowuje u¿ytkownika i zamyka po³±czenie.
 *
 *  - sock - deskryptor socketu.
 *
 * nie zwraca b³êdów. skoro siê ¿egnamy, to olewamy wszystko.
 */
void gg_logoff(struct gg_session *sess)
{
	if (!sess)
		return;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_logoff(...);\n");

	if (sess->state == GG_STATE_CONNECTED)
		gg_change_status(sess, GG_STATUS_NOT_AVAIL);
	
	if (sess->fd) {
		shutdown(sess->fd, 2);
		close(sess->fd);
	}
}

/*
 * gg_send_message_ctcp() // TO BE GONE
 *
 * wysy³a wiadomo¶æ do innego u¿ytkownika. zwraca losowy numer
 * sekwencyjny, który mo¿na olaæ albo wykorzystaæ do potwierdzenia.
 *
 *  - sess - opis sesji,
 *  - msgclass - rodzaj wiadomo¶ci,
 *  - recipient - numer adresata,
 *  - message - tre¶æ wiadomo¶ci,
 *  - message_len - d³ugo¶æ.
 *
 * w przypadku b³êdu zwraca -1, inaczej numer sekwencyjny.
 */
int gg_send_message_ctcp(struct gg_session *sess, int msgclass, uin_t recipient, unsigned char *message, int message_len)
{
	struct gg_send_msg s;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}
	
	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_send_message_ctcp(..., %d, %u, \"...\");\n", msgclass, recipient);

	s.recipient = fix32(recipient);
	s.seq = fix32(0);
	s.msgclass = fix32(msgclass);
	
	return gg_send_packet(sess->fd, GG_SEND_MSG, &s, sizeof(s), message, message_len, NULL);
}

/*
 * gg_send_message()
 *
 * wysy³a wiadomo¶æ do innego u¿ytkownika. zwraca losowy numer
 * sekwencyjny, który mo¿na olaæ albo wykorzystaæ do potwierdzenia.
 *
 *  - sess - opis sesji,
 *  - msgclass - rodzaj wiadomo¶ci,
 *  - recipient - numer adresata,
 *  - message - tre¶æ wiadomo¶ci.
 *
 * w przypadku b³êdu zwraca -1, inaczej numer sekwencyjny.
 */
int gg_send_message(struct gg_session *sess, int msgclass, uin_t recipient, unsigned char *message)
{
	struct gg_send_msg s;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}
	
	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_send_message(..., %d, %u, \"...\");\n", msgclass, recipient);

	s.recipient = fix32(recipient);
	if (!sess->seq)
		sess->seq = 0x01740000 | (rand() & 0xffff);
	s.seq = fix32(sess->seq);
	s.msgclass = fix32(msgclass);
	sess->seq += (rand() % 0x300) + 0x300;
	
	if (gg_send_packet(sess->fd, GG_SEND_MSG, &s, sizeof(s), message, strlen(message) + 1, NULL) == -1)
		return -1;

	return fix32(s.seq);
}

/*
 * gg_ping()
 *
 * wysy³a do serwera pakiet typu yeah-i'm-still-alive.
 *
 *  - sess - zgadnij.
 *
 * je¶li nie powiod³o siê wys³anie pakietu, zwraca -1. otherwise 0.
 */
int gg_ping(struct gg_session *sess)
{
	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_ping(...);\n");

	return gg_send_packet(sess->fd, GG_PING, NULL);
}

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
	if (e->type == GG_EVENT_MSG)
		free(e->event.msg.message);
	if (e->type == GG_EVENT_NOTIFY)
		free(e->event.notify);
	free(e);
}

/*
 * gg_notify()
 *
 * wysy³a serwerowi listê ludków, za którymi têsknimy.
 *
 *  - sess - identyfikator sesji,
 *  - userlist - wska¼nik do tablicy numerów,
 *  - count - ilo¶æ numerków.
 *
 * je¶li uda³o siê, zwraca 0. je¶li b³±d, dostajemy -1.
 */
int gg_notify(struct gg_session *sess, uin_t *userlist, int count)
{
	struct gg_notify *n;
	uin_t *u;
	int i, res = 0;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}
	
	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_notify(..., %d);\n", count);
	
	if (!userlist || !count)
		return 0;
	
	if (!(n = (struct gg_notify*) malloc(sizeof(*n) * count)))
		return -1;
	
	for (u = userlist, i = 0; i < count; u++, i++) { 
		n[i].uin = fix32(*u);
		n[i].dunno1 = 3;
	}
	
	if (gg_send_packet(sess->fd, GG_NOTIFY, n, sizeof(*n) * count, NULL) == -1)
		res = -1;

	free(n);

	return res;
}

/*
 * gg_add_notify()
 *
 * dodaje w locie do listy ukochanych dany numerek.
 *
 *  - sess - identyfikator sesji,
 *  - uin - numerek ukochanej.
 *
 * je¶li uda³o siê wys³aæ, daje 0. inaczej -1.
 */
int gg_add_notify(struct gg_session *sess, uin_t uin)
{
	struct gg_add_remove a;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}
	
	gg_debug(GG_DEBUG_FUNCTION, "** gg_add_notify(..., %u);\n", uin);
	
	a.uin = fix32(uin);
	a.dunno1 = 3;
	
	return gg_send_packet(sess->fd, GG_ADD_NOTIFY, &a, sizeof(a), NULL);
}

/*
 * gg_remove_notify()
 *
 * w locie usuwa z listy zainteresowanych.
 *
 *  - sess - id sesji,
 *  - uin - numerek.
 *
 * zwraca -1 je¶li by³ b³±d, 0 je¶li siê uda³o wys³aæ pakiet.
 */
int gg_remove_notify(struct gg_session *sess, uin_t uin)
{
	struct gg_add_remove a;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_remove_notify(..., %u);\n", uin);
	
	a.uin = fix32(uin);
	a.dunno1 = 3;
	
	return gg_send_packet(sess->fd, GG_REMOVE_NOTIFY, &a, sizeof(a), NULL);
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
	struct gg_header *h;
	void *p;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	gg_debug(GG_DEBUG_FUNCTION, "** gg_watch_fd_connected(...);\n");

	if (!(h = gg_recv_packet(sess))) {
		gg_debug(GG_DEBUG_MISC, "-- gg_recv_packet failed. errno = %d (%d)\n", errno, strerror(errno));
		return -1;
	}

	p = (void*) h + sizeof(struct gg_header);
	
	switch (h->type) {
		case GG_RECV_MSG:
		{
			struct gg_recv_msg *r = p;

			gg_debug(GG_DEBUG_MISC, "-- received a message\n");

			if (h->length >= sizeof(*r)) {
				e->type = GG_EVENT_MSG;
				e->event.msg.msgclass = fix32(r->msgclass);
				e->event.msg.sender = fix32(r->sender);
				e->event.msg.message = strdup((char*) r + sizeof(*r));
				e->event.msg.time = fix32(r->time);

				/* pakiet konferencyjny? */
				if (h->length > sizeof(*r) + strlen(e->event.msg.message) + 2) {
					struct gg_msg_recipients *m = (struct gg_msg_recipients *) ((char *)r+ sizeof(*r) + strlen((char *)e->event.msg.message) + 1);
					int i, count = fix32(m->count);

					if (!(e->event.msg.recipients = (void*) malloc(count))) {
						gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
						free(h);
						return -1;
					}

					e->event.msg.recipients_count = count;
					memcpy(e->event.msg.recipients, (char *)m + sizeof(*m),
					       sizeof(uin_t) * count);

					for (i = 0; i < count; i++)
						e->event.msg.recipients[i] = fix32(e->event.msg.recipients[i]);
				} else {
					e->event.msg.recipients_count = 0;
					e->event.msg.recipients = NULL;
				}
			}

			break;
		}

		case GG_NOTIFY_REPLY:
		{
			struct gg_notify_reply *n = p;
			int count, i;

			gg_debug(GG_DEBUG_MISC, "-- received a notify reply\n");
			
			e->type = GG_EVENT_NOTIFY;
			if (!(e->event.notify = (void*) malloc(h->length + 2 * sizeof(*n)))) {
				gg_debug(GG_DEBUG_MISC, "-- not enough memory\n");
				free(h);
				return -1;
			}
			count = h->length / sizeof(*n);
			memcpy(e->event.notify, p, h->length);
			e->event.notify[count].uin = 0;
			for (i = 0; i < count; i++) {
				e->event.notify[i].uin = fix32(e->event.notify[i].uin);
				e->event.notify[i].status = fix32(e->event.notify[i].status);
				e->event.notify[i].remote_port = fix16(e->event.notify[i].remote_port);		
			}

			break;
		}

		case GG_STATUS:
		{
			struct gg_status *s = p;

			gg_debug(GG_DEBUG_MISC, "-- received a status change\n");

			if (h->length >= sizeof(*s)) {
				e->type = GG_EVENT_STATUS;
				memcpy(&e->event.status, p, h->length);
				e->event.status.uin = fix32(e->event.status.uin);
				e->event.status.status = fix32(e->event.status.status);
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

	if (!(e = (void*) malloc(sizeof(*e)))) {
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

			for (hash = 1; *password; password++)
				hash *= (*password) + 1;
			hash *= w->key;
	
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
