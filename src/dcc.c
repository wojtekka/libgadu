/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Tomasz Chiliñski <chilek@chilan.com>
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netdb.h>
#include <fcntl.h>		/* XXX fixy na inne systemy */
#include <sys/ioctl.h>		/* XXX j.w. */
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#ifdef sun
#  include <sys/filio.h>
#endif
#include <stdarg.h>
#include <ctype.h>
#include "config.h"
#include "compat.h"
#include "libgadu.h"

/*
 * gg_dcc_debug_data() // funkcja wewnêtrzna
 *
 * wy¶wietla zrzut pakietu w hexie.
 * 
 *  - prefix - prefiks zrzutu pakietu,
 *  - fd - deskryptor socketa,
 *  - buf - bufor z danymi,
 *  - size - rozmiar danych.
 *
 * brak.
 */
#ifndef GG_DEBUG_DISABLE
static void gg_dcc_debug_data(const char *prefix, int fd, const void *buf, int size)
{
	int i;
	
	gg_debug(GG_DEBUG_MISC, "++ gg_dcc %s (fd=%d,len=%d)", prefix, fd, size);
	
	for (i = 0; i < size; i++)
		gg_debug(GG_DEBUG_MISC, " %.2x", ((unsigned char*) buf)[i]);
	
	gg_debug(GG_DEBUG_MISC, "\n");
}
#else
#define gg_dcc_debug_data(a,b,c,d) { }
#endif

/*
 * gg_dcc_request()
 *
 * wysy³a informacjê o tym, ¿e dany klient powinien siê z nami po³±czyæ.
 * wykorzystywane, kiedy druga strona, której chcemy co¶ wys³aæ jest za
 * maskarad±.
 *
 *  - sess - struktura opisuj±ca sesjê GG,
 *  - uin - numerek odbiorcy.
 *
 * to samo, co gg_send_msg().
 */
int gg_dcc_request(struct gg_session *sess, uin_t uin)
{
	return gg_send_message_ctcp(sess, GG_CLASS_CTCP, uin, "\002", 1);
}

/*
 * gg_dcc_fill_file_info()
 *
 * wype³nia pola gg_dcc niezbêdne do wys³ania pliku.
 *
 *  - d - struktura gg_dcc,
 *  - filename - nazwa pliku.
 *
 * -1 w przypadku b³êdu, 0 je¶li siê powiod³o.
 */
int gg_dcc_fill_file_info(struct gg_dcc *d, const char *filename)
{
	struct stat st;
	const char *p;
	
	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc_fill_file_info(..., \"%s\");\n", filename);
	
	if (!d || d->type != GG_SESSION_DCC_SEND) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_fill_file_info() invalid arguments\n");
		errno = EINVAL;
		return -1;
	}
		
	if (stat(filename, &st) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_fill_file_info() stat() failed (%s)\n", strerror(errno));
		return -1;
	}

	if ((st.st_mode & S_IFDIR)) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_fill_file_info() that's a directory\n");
		errno = EINVAL;
		return -1;
	}

	if ((d->file_fd = open(filename, O_RDONLY)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_fill_file_info() open() failed (%s)\n", strerror(errno));
		return -1;
	}

	memset(&d->file_info, 0, sizeof(d->file_info));

	if (!(st.st_mode & S_IWUSR))
		d->file_info.mode |= fix32(GG_DCC_FILEATTR_READONLY);

	/* XXX czas pliku */
	
	d->file_info.size = fix32(st.st_size);

	for (p = filename + strlen(filename); p > filename && *p != '/'; p--);

	if (*p == '/')
		p++;
	
	gg_debug(GG_DEBUG_MISC, "// gg_dcc_fill_file_info() short name \"%s\"\n", p);
	strncpy(d->file_info.filename, p, sizeof(d->file_info.filename));

	return 0;
}

/*
 * gg_dcc_transfer() // funkcja wewnêtrzna
 * 
 * inicjuje proces wymiany pliku z danym klientem.
 *
 *  - ip - adres ip odbiorcy,
 *  - port - port odbiorcy,
 *  - my_uin - w³asny numer,
 *  - peer_uin - numer obiorcy,
 *  - type - rodzaj wymiany (GG_SESSION_DCC_SEND lub _GET).
 *
 * zaalokowana struktura gg_dcc lub NULL je¶li wyst±pi³ b³±d.
 */
static struct gg_dcc *gg_dcc_transfer(unsigned long ip, unsigned short port, uin_t my_uin, uin_t peer_uin, int type)
{
	struct gg_dcc *d = NULL;
	struct in_addr addr;

	addr.s_addr = ip;
	
	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc_transfer(%s, %d, %ld, %ld, %s);\n", inet_ntoa(addr), port, my_uin, peer_uin, (type == GG_SESSION_DCC_SEND) ? "SEND" : "GET");
	
	if (!ip || ip == INADDR_NONE || !port || !my_uin || !peer_uin) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_transfer() invalid arguments\n");
		errno = EINVAL;
		return NULL;
	}

	if (!(d = (void*) calloc(1, sizeof(*d)))) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_transfer() not enough memory\n");
		return NULL;
	}

	d->check = GG_CHECK_WRITE;
	d->state = GG_STATE_CONNECTING;
	d->type = type;
	d->timeout = GG_DEFAULT_TIMEOUT;
	d->file_fd = -1;
	d->active = 1;
	d->fd = -1;
	d->uin = my_uin;
	d->peer_uin = peer_uin;

	if ((d->fd = gg_connect(&addr, port, 1)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_transfer() connection failed\n");
		free(d);
		return NULL;
	}

	return d;
}

/*
 * gg_dcc_get_file()
 * 
 * inicjuje proces odbierania pliku od danego klienta, gdy ten wys³a³ do
 * nas ¿±danie po³±czenia.
 *
 *  - ip - adres ip odbiorcy,
 *  - port - port odbiorcy,
 *  - my_uin - w³asny numer,
 *  - peer_uin - numer obiorcy.
 *
 * zaalokowana struktura gg_dcc lub NULL je¶li wyst±pi³ b³±d.
 */
struct gg_dcc *gg_dcc_get_file(unsigned long ip, unsigned short port, uin_t my_uin, uin_t peer_uin)
{
	gg_debug(GG_DEBUG_MISC, "// gg_dcc_get_file() handing over to gg_dcc_transfer()\n");

	return gg_dcc_transfer(ip, port, my_uin, peer_uin, GG_SESSION_DCC_GET);
}

/*
 * gg_dcc_send_file()
 * 
 * inicjuje proces wysy³ania pliku do danego klienta.
 *
 *  - ip - adres ip odbiorcy,
 *  - port - port odbiorcy,
 *  - my_uin - w³asny numer,
 *  - peer_uin - numer obiorcy.
 *
 * zaalokowana struktura gg_dcc lub NULL je¶li wyst±pi³ b³±d.
 */
struct gg_dcc *gg_dcc_send_file(unsigned long ip, unsigned short port, uin_t my_uin, uin_t peer_uin)
{
	gg_debug(GG_DEBUG_MISC, "// gg_dcc_send_file() handing over to gg_dcc_transfer()\n");

	return gg_dcc_transfer(ip, port, my_uin, peer_uin, GG_SESSION_DCC_SEND);
}

/*
 * gg_dcc_voice_chat()
 * 
 * próbuje nawi±zaæ po³±czenie g³osowe.
 *
 *  - ip - adres ip odbiorcy,
 *  - port - port odbiorcy,
 *  - my_uin - w³asny numer,
 *  - peer_uin - numer obiorcy.
 *
 * zaalokowana struktura gg_dcc lub NULL je¶li wyst±pi³ b³±d.
 */
struct gg_dcc *gg_dcc_voice_chat(unsigned long ip, unsigned short port, uin_t my_uin, uin_t peer_uin)
{
	gg_debug(GG_DEBUG_MISC, "// gg_dcc_voice_chat() handing over to gg_dcc_transfer()\n");

	return gg_dcc_transfer(ip, port, my_uin, peer_uin, GG_SESSION_DCC_VOICE);
}

/*
 * gg_dcc_set_type()
 *
 * po zdarzeniu GG_EVENT_DCC_CALLBACK nale¿y ustawiæ typ po³±czenia.
 *
 *  - d - struktura opisuj±ca po³±czenie,
 *  - type - tym po³±czenia (GG_SESSION_DCC_SEND lub GG_SESSION_DCC_VOICE).
 *
 * brak
 */
void gg_dcc_set_type(struct gg_dcc *d, int type)
{
	d->type = type;
	d->state = (type == GG_SESSION_DCC_SEND) ? GG_STATE_SENDING_FILE_INFO : GG_STATE_SENDING_VOICE_REQUEST;
}
	
/*
 * gg_dcc_callback() // funkcja wewnêtrzna
 *
 * wywo³ywana z gg_dcc->callback, odpala gg_dcc_watch_fd i ³aduje rezultat
 * do gg_dcc->event.
 */
static int gg_dcc_callback(struct gg_dcc *d)
{
	struct gg_event *e = gg_dcc_watch_fd(d);

	d->event = e;

	return (e != NULL) ? 0 : -1;
}

/*
 * gg_dcc_socket_create()
 *
 * tworzy socketa dla bezpo¶redniej komunikacji miêdzy klientami.
 *
 *  - uin - w³asny numer,
 *  - port - preferowany port, je¶li równy 0 lub -1, próbuje domy¶lnego.
 *
 * zaalokowana struktura `gg_dcc', któr± po¼niej nale¿y
 * zwolniæ funkcj± gg_free_dcc(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_dcc *gg_dcc_socket_create(uin_t uin, unsigned int port)
{
	struct gg_dcc *c;
	struct sockaddr_in sin;
	int sock, bound = 0;
	
        gg_debug(GG_DEBUG_FUNCTION, "** gg_create_dcc_socket(%d, %d);\n", uin, port);
	
	if (!uin) {
		gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() invalid arguments\n");
		errno = EINVAL;
		return NULL;
	}

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() can't create socket (%s)\n", strerror(errno));
		return NULL;
	}

	if (!port)
		port = GG_DEFAULT_DCC_PORT;
	
	while (!bound) {
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(port);
	
		gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() trying port %d\n", port);
		if (!bind(sock, (struct sockaddr*) &sin, sizeof(sin)))
			bound = 1;
		else {
			if (++port == 65535) {
				gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() no free port found\n");
				return NULL;
			}
		}
	}

	if (listen(sock, 10)) {
		gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() unable to listen (%s)\n", strerror(errno));
		return NULL;
	}
	
	gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() bound to port %d\n", port);

	if (!(c = malloc(sizeof(*c)))) {
		gg_debug(GG_DEBUG_MISC, "// gg_create_dcc_socket() not enough memory for struct\n");
		close(sock);
                return NULL;
	}
	memset(c, 0, sizeof(*c));

	c->port = c->id = port;
	c->fd = sock;
        c->type = GG_SESSION_DCC_SOCKET;
	c->uin = uin;
	c->timeout = -1;
	c->state = GG_STATE_LISTENING;
	c->check = GG_CHECK_READ;
	c->callback = gg_dcc_callback;
	c->destroy = gg_dcc_free;
	
	gg_dcc_ip = INADDR_ANY;	
	return c;
}

/*
 * gg_dcc_voice_send()
 *
 * wysy³a ramkê danych dla rozmowy g³osowej.
 *
 *  - d - struktura opisuj±ca po³±czenie dcc,
 *  - buf - bufor z danymi,
 *  - length - rozmiar ramki,
 *
 * je¶li siê powiod³o 0, je¶li nie -1.
 */
int gg_dcc_voice_send(struct gg_dcc *d, char *buf, int length)
{
	struct packet_s {
		uint8_t type;
		uint32_t length;
	} GG_PACKED;
	struct packet_s packet;

	gg_debug(GG_DEBUG_FUNCTION, "++ gg_dcc_voice_send(..., %p, %d);\n", buf, length);
	if (!d || !buf || length < 0 || d->type != GG_SESSION_DCC_VOICE) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_voice_send() invalid argument\n");
		return -1;
	}

	packet.type = 0x03; /* XXX */
	packet.length = fix32(length);

	if (write(d->fd, &packet, sizeof(packet)) < sizeof(packet)) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_voice_send() write() failed\n");
		return -1;
	}
	gg_dcc_debug_data("write", d->fd, &packet, sizeof(packet));

	if (write(d->fd, buf, length) < length) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_voice_send() write() failed\n");
		return -1;
	}
	gg_dcc_debug_data("write", d->fd, buf, length);

	return 0;
}

#define gg_read(fd, buf, size) \
{ \
	int tmp = read(fd, buf, size); \
	if (tmp < size) { \
		if (tmp == -1) { \
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed (%d:%s)\n", errno, strerror(errno)); \
		} else { \
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed (%d bytes, %d needed)\n", tmp, size); \
		} \
		e->type = GG_EVENT_DCC_ERROR; \
		e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE; \
		return e; \
	} \
	gg_dcc_debug_data("read", fd, buf, size); \
} 

#define gg_write(fd, buf, size) \
{ \
	int tmp; \
	gg_dcc_debug_data("write", fd, buf, size); \
	tmp = write(fd, buf, size); \
	if (tmp < size) { \
		if (tmp == -1) { \
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%d:%s)\n", errno, strerror(errno)); \
		} else { \
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%d needed, %d done)\n", size, tmp); \
		} \
		e->type = GG_EVENT_DCC_ERROR; \
		e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE; \
		return e; \
	} \
}

/*
 * gg_dcc_watch_fd()
 *
 * funkcja, któr± nale¿y wywo³aæ, gdy co¶ siê zmieni na gg_dcc->fd.
 *
 *  - c - struktura zwrócona przez gg_create_dcc_socket()
 *
 * zaalokowana struktura gg_event lub NULL, je¶li zabrak³o pamiêci
 * na ni±.
 */
struct gg_event *gg_dcc_watch_fd(struct gg_dcc *h)
{
	struct gg_event *e;
	int foo;

        gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc_watch_fd(...);\n");
	
	if (!h || (h->type != GG_SESSION_DCC && h->type != GG_SESSION_DCC_SOCKET && h->type != GG_SESSION_DCC_SEND && h->type != GG_SESSION_DCC_GET && h->type != GG_SESSION_DCC_VOICE)) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() invalid argument\n");
		errno = EINVAL;
		return NULL;
	}

        if (!(e = (void*) calloc(1, sizeof(*e)))) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() not enough memory\n");
                return NULL;
        }

        e->type = GG_EVENT_NONE;

	if (h->type == GG_SESSION_DCC_SOCKET) {
		struct sockaddr_in sin;
		struct gg_dcc *c;
		int fd, sin_len = sizeof(sin), one = 1;
		
		if ((fd = accept(h->fd, (struct sockaddr*) &sin, &sin_len)) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() can't accept() new connection. ignoring.\n");
			return e;
		}

		gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() new direct connection from %s:%d\n", inet_ntoa(sin.sin_addr), htons(sin.sin_port));

		if (ioctl(fd, FIONBIO, &one) == -1) {
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() can't set nonblocking (%s)\n", strerror(errno));
			close(fd);
			e->type = GG_EVENT_DCC_ERROR;
			e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
			return e;
		}

		if (!(c = (void*) calloc(1, sizeof(*c)))) {
			gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() not enough memory for client data\n");

			free(e);
			close(fd);
			return NULL;
		}

		c->fd = fd;
		c->check = GG_CHECK_READ;
		c->state = GG_STATE_READING_UIN_1;
		c->type = GG_SESSION_DCC;
		c->timeout = GG_DEFAULT_TIMEOUT;
		c->file_fd = -1;
		
		e->type = GG_EVENT_DCC_NEW;
		e->event.dcc_new = c;

		return e;
	} else {
		struct gg_dcc_tiny_packet tiny;
		struct gg_dcc_small_packet small;
		struct gg_dcc_big_packet big;
		int size, tmp, res, res_size;
		char buf[1024], ack[] = "UDAG";

		struct gg_dcc_file_info_packet {
			struct gg_dcc_big_packet big;
			struct gg_file_info file_info;
		} GG_PACKED;
		struct gg_dcc_file_info_packet file_info_packet;

		switch (h->state) {
			case GG_STATE_READING_UIN_1:
			case GG_STATE_READING_UIN_2: {
				uin_t uin;

				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_READING_UIN_%d\n", (h->state == GG_STATE_READING_UIN_1) ? 1 : 2);
				
				gg_read(h->fd, &uin, sizeof(uin));

				if (h->state == GG_STATE_READING_UIN_1) {
					h->state = GG_STATE_READING_UIN_2;
					h->check = GG_CHECK_READ;
					h->timeout = GG_DEFAULT_TIMEOUT;
					h->peer_uin = uin;
				} else {
					h->state = GG_STATE_SENDING_ACK;
					h->check = GG_CHECK_WRITE;
					h->timeout = GG_DEFAULT_TIMEOUT;
					h->uin = uin;
					e->type = GG_EVENT_DCC_CLIENT_ACCEPT;
				}

				return e;
			}

			case GG_STATE_SENDING_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_SENDING_ACK\n");

				gg_write(h->fd, ack, 4);

				h->state = GG_STATE_READING_TYPE;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;

				return e;

			case GG_STATE_READING_TYPE:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_TYPE\n");
				
				gg_read(h->fd, &small, sizeof(small));

				small.type = fix32(small.type);

				switch (small.type) {
					case 0x0003:	/* XXX */
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() callback\n");
						h->type = GG_SESSION_DCC_SEND;
						h->state = GG_STATE_SENDING_FILE_INFO;
						h->check = GG_CHECK_WRITE;
						h->timeout = GG_DEFAULT_TIMEOUT;

						e->type = GG_EVENT_DCC_CALLBACK;
			
						break;

					case 0x0002:	/* XXX */
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() dialin\n");
						h->type = GG_SESSION_DCC_GET;
						h->state = GG_STATE_READING_REQUEST;
						h->check = GG_CHECK_READ;
						h->timeout = GG_DEFAULT_TIMEOUT;
						h->incoming = 1;

						break;

					default:
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() unknown dcc type (%.4x) from %ld\n", small.type, h->peer_uin);
						e->type = GG_EVENT_DCC_ERROR;
						e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
				}

				return e;

			case GG_STATE_READING_REQUEST:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_REQUEST\n");
				
				gg_read(h->fd, &small, sizeof(small));

				small.type = fix32(small.type);

				switch (small.type) {
					case 0x0001:	/* XXX */
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() file transfer request\n");
						h->state = GG_STATE_READING_FILE_INFO;
						h->check = GG_CHECK_READ;
						h->timeout = GG_DEFAULT_TIMEOUT;
						break;
						
					case 0x0003:	/* XXX */
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() voice chat request\n");
						h->state = GG_STATE_SENDING_VOICE_ACK;
						h->check = GG_CHECK_WRITE;
						h->timeout = GG_DCC_TIMEOUT_VOICE_ACK;
						h->type = GG_SESSION_DCC_VOICE;
						e->type = GG_EVENT_DCC_NEED_VOICE_ACK;

						break;
						
					default:
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() unknown dcc request (%.4x) from %ld\n", small.type, h->peer_uin);
						e->type = GG_EVENT_DCC_ERROR;
						e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
				}
		 	
				return e;

			case GG_STATE_READING_FILE_INFO:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_FILE_INFO\n");
				
				gg_read(h->fd, &file_info_packet, sizeof(file_info_packet));

				memcpy(&h->file_info, &file_info_packet.file_info, sizeof(h->file_info));

				h->state = GG_STATE_SENDING_FILE_ACK;
				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DCC_TIMEOUT_FILE_ACK;

				e->type = GG_EVENT_DCC_NEED_FILE_ACK;
				
				return e;

			case GG_STATE_SENDING_FILE_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_FILE_ACK\n");
				
				big.type = fix32(0x0006);	/* XXX */
				big.dunno1 = 0;
				big.dunno2 = 0;

				gg_write(h->fd, &big, sizeof(big));

				h->state = GG_STATE_READING_FILE_HEADER;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;

				h->offset = 0;
				
				return e;
				
			case GG_STATE_SENDING_VOICE_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_VOICE_ACK\n");
				
				tiny.type = 0x01;	/* XXX */

				gg_write(h->fd, &tiny, sizeof(tiny));

				h->state = GG_STATE_READING_VOICE_HEADER;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;

				h->offset = 0;
				
				return e;
				
			case GG_STATE_READING_FILE_HEADER:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_FILE_HEADER\n");
				
				gg_read(h->fd, &big, sizeof(big));

				big.type = fix32(big.type);
				h->chunk_size = fix32(big.dunno1);
				h->chunk_offset = 0;
				
				if (big.type == 0x0005)	{ /* XXX */
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_REFUSED;
					return e;
				}
				

				h->state = GG_STATE_GETTING_FILE;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;
				h->established = 1;
			 	
				return e;

			case GG_STATE_READING_VOICE_HEADER:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_VOICE_HEADER\n");
				
				gg_read(h->fd, &tiny, sizeof(tiny));

				switch (tiny.type) {
					case 0x03:	/* XXX */
						h->state = GG_STATE_READING_VOICE_SIZE;
						h->check = GG_CHECK_READ;
						h->timeout = GG_DEFAULT_TIMEOUT;
						h->established = 1;
						break;
					case 0x04:	/* XXX */
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() peer breaking connection\n");
						/* XXX zwracaæ odpowiedni event */
					default:
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() unknown request (%.2f)\n", tiny.type);
						e->type = GG_EVENT_DCC_ERROR;
						e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
				}
			 	
				return e;

			case GG_STATE_READING_VOICE_SIZE:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_VOICE_SIZE\n");
				
				gg_read(h->fd, &small, sizeof(small));

				small.type = fix32(small.type);

				if (small.type < 16 || small.type > sizeof(buf)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() invalid voice frame size (%d)\n", small.type);
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_NET;
					
					return e;
				}

				h->chunk_size = small.type;
				h->chunk_offset = 0;

				if (!(h->voice_buf = malloc(h->chunk_size))) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() out of memory for voice frame\n");
					return NULL;
				}

				h->state = GG_STATE_READING_VOICE_DATA;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;
			 	
				return e;

			case GG_STATE_READING_VOICE_DATA:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_VOICE_DATA\n");
				
				tmp = read(h->fd, h->voice_buf + h->chunk_offset, h->chunk_size - h->chunk_offset);
				if (tmp < 1) {
					if (tmp == -1) {
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed (%d:%s)\n", errno, strerror(errno));
					} else {
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed, connection broken\n");
					}
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_NET;
					return e;
				}

				gg_dcc_debug_data("read", h->fd, h->voice_buf + h->chunk_offset, tmp);

				h->chunk_offset += tmp;

				if (h->chunk_offset >= h->chunk_size) {
					e->type = GG_EVENT_DCC_VOICE_DATA;
					e->event.dcc_voice_data.data = h->voice_buf;
					e->event.dcc_voice_data.length = h->chunk_size;
					h->state = GG_STATE_READING_VOICE_HEADER;
					h->voice_buf = NULL;
				
				}

				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;
				
				return e;

			case GG_STATE_CONNECTING:
			{
				uin_t uins[2];

				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_CONNECTING\n");
				
				res = 0;
				if ((foo = getsockopt(h->fd, SOL_SOCKET, SO_ERROR, &res, &res_size)) || res) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() connection failed (fd=%d,errno=%d(%s),foo=%d,res=%d(%s))\n", h->fd, errno, strerror(errno), foo, res, strerror(res));
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() connected, sending uins\n");
				
				uins[0] = fix32(h->uin);
				uins[1] = fix32(h->peer_uin);

				gg_write(h->fd, uins, sizeof(uins));
				
				h->state = GG_STATE_READING_ACK;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;
				
				return e;
			}

			case GG_STATE_READING_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_ACK\n");
				
				gg_read(h->fd, buf, 4);

				if (strncmp(buf, ack, 4)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() did't get ack\n");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DEFAULT_TIMEOUT;
				h->state = GG_STATE_SENDING_REQUEST;
				
				return e;

			case GG_STATE_SENDING_VOICE_REQUEST:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_VOICE_REQUEST\n");

				small.type = fix32(0x0003);
				
				gg_write(h->fd, &small, sizeof(small));

				h->state = GG_STATE_READING_VOICE_ACK;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;
				
				return e;
			
			case GG_STATE_SENDING_REQUEST:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_REQUEST\n");

				small.type = (h->type == GG_SESSION_DCC_GET) ? fix32(0x0003) : fix32(0x0002);	/* XXX */
				
				gg_write(h->fd, &small, sizeof(small));
				
				switch (h->type) {
					case GG_SESSION_DCC_GET:
						h->state = GG_STATE_READING_REQUEST;
						h->check = GG_CHECK_READ;
						h->timeout = GG_DEFAULT_TIMEOUT;
						break;

					case GG_SESSION_DCC_SEND:
						h->state = GG_STATE_SENDING_FILE_INFO;
						h->check = GG_CHECK_WRITE;
						h->timeout = GG_DEFAULT_TIMEOUT;

						if (h->file_fd == -1)
							e->type = GG_EVENT_DCC_NEED_FILE_INFO;
						break;
						
					case GG_SESSION_DCC_VOICE:
						h->state = GG_STATE_SENDING_VOICE_REQUEST;
						h->check = GG_CHECK_WRITE;
						h->timeout = GG_DEFAULT_TIMEOUT;
						break;
				}

				return e;
			
			case GG_STATE_SENDING_FILE_INFO:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_FILE_INFO\n");

				if (h->file_fd == -1) {
					e->type = GG_EVENT_DCC_NEED_FILE_INFO;
					return e;
				}

				small.type = fix32(0x0001);	/* XXX */
				
				gg_write(h->fd, &small, sizeof(small));

				file_info_packet.big.type = fix32(0x0003);	/* XXX */
				file_info_packet.big.dunno1 = 0;
				file_info_packet.big.dunno2 = 0;

				memcpy(&file_info_packet.file_info, &h->file_info, sizeof(h->file_info));
				
				gg_write(h->fd, &file_info_packet, sizeof(file_info_packet));

				h->state = GG_STATE_READING_FILE_ACK;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DCC_TIMEOUT_FILE_ACK;

				return e;
				
			case GG_STATE_READING_FILE_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_FILE_ACK\n");
				
				gg_read(h->fd, &big, sizeof(big));

				/* XXX sprawdzaæ wynik */
				
				h->state = GG_STATE_SENDING_FILE_HEADER;
				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DEFAULT_TIMEOUT;

				h->offset = 0;

				return e;

			case GG_STATE_READING_VOICE_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_VOICE_ACK\n");
				
				gg_read(h->fd, &tiny, sizeof(tiny));

				if (tiny.type != 0x01) {
					gg_debug(GG_DEBUG_MISC, "// invalid reply (%.2x), connection refused\n", tiny.type);
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_REFUSED;
					return e;
				}

				h->state = GG_STATE_READING_VOICE_HEADER;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;

				return e;

			case GG_STATE_SENDING_FILE_HEADER:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_FILE_HEADER\n");
				
				if ((h->chunk_size = h->file_info.size - h->offset) > 4096)
					h->chunk_size = 4096;

				h->chunk_offset = 0;
				
				big.type = fix32(0x0003);	/* XXX */
				big.dunno1 = fix32(h->chunk_size);
				big.dunno2 = 0;
				
				gg_write(h->fd, &big, sizeof(big));

				h->state = GG_STATE_SENDING_FILE;
				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DEFAULT_TIMEOUT;
				h->established = 1;

				return e;
				
			case GG_STATE_SENDING_FILE:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_FILE\n");
				
				if ((tmp = h->chunk_size - h->chunk_offset) > sizeof(buf))
					tmp = sizeof(buf);
				
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() offset=%d, size=%d\n", h->offset, h->file_info.size);
				lseek(h->file_fd, h->offset, SEEK_SET);

				size = read(h->file_fd, buf, tmp);

				/* b³±d */
				if (size == -1) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed. (%s)\n", strerror(errno));

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_FILE;

					return e;
				}

				/* koniec pliku? */
				if (size == 0) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() reached eof\n");
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_EOF;

					return e;
				}
				
				/* je¶li wczytali¶my wiêcej, utnijmy. */
				if (h->offset + size > h->file_info.size) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() too much (read=%d, ofs=%d, size=%d)\n", size, h->offset, h->file_info.size);
					size = h->file_info.size - h->offset;

					if (size < 1) {
						gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() reached EOF after cutting\n");
						e->type = GG_EVENT_DCC_DONE;
						return e;
					}
				}

				tmp = write(h->fd, buf, size);

				if (tmp == -1) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%s)\n", strerror(errno));
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_NET;
					return e;
				}

				h->offset += size;
				
				if (h->offset >= h->file_info.size) {
					e->type = GG_EVENT_DCC_DONE;
					return e;
				}
				
				h->chunk_offset += size;
				
				if (h->chunk_offset >= h->chunk_size) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() chunk finished\n");
					h->state = GG_STATE_SENDING_FILE_HEADER;
					h->timeout = GG_DEFAULT_TIMEOUT;
				} else {
					h->state = GG_STATE_SENDING_FILE;
					h->timeout = GG_DCC_TIMEOUT_SEND;
				}
				
				h->check = GG_CHECK_WRITE;

				return e;
				
			case GG_STATE_GETTING_FILE:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_GETTING_FILE\n");
				
				if ((tmp = h->chunk_size - h->chunk_offset) > sizeof(buf))
					tmp = sizeof(buf);
				
				size = read(h->fd, buf, tmp);

				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() ofs=%d, size=%d, read()=%d\n", h->offset, h->file_info.size, size);
				
				/* b³±d */
				if (size == -1) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed. (%s)\n", strerror(errno));

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_NET;

					return e;
				}

				/* koniec? */
				if (size == 0) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() reached eof\n");
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_EOF;

					return e;
				}
				
				tmp = write(h->file_fd, buf, size);
				
				if (tmp == -1 || tmp < size) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%d:fd=%d:res=%d:%s)\n", tmp, h->file_fd, size, strerror(errno));
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_NET;
					return e;
				}

				h->offset += size;
				
				if (h->offset >= h->file_info.size) {
					e->type = GG_EVENT_DCC_DONE;
					return e;
				}

				h->chunk_offset += size;
				
				if (h->chunk_offset >= h->chunk_size) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() chunk finished\n");
					h->state = GG_STATE_READING_FILE_HEADER;
					h->timeout = GG_DEFAULT_TIMEOUT;
				} else {
					h->state = GG_STATE_GETTING_FILE;
					h->timeout = GG_DCC_TIMEOUT_GET;
				}
				
				h->check = GG_CHECK_READ;

				return e;
				
			default:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_???\n");
				e->type = GG_EVENT_DCC_ERROR;
				e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;

				return e;
		}
	}
	
	return e;
}

#undef gg_read
#undef gg_write

/*
 * gg_dcc_free()
 *
 * zwalnia pamiêæ po strukturze po³±czenia dcc.
 *
 *  - c - zwalniana struktura.
 *
 * brak.
 */
void gg_dcc_free(struct gg_dcc *c)
{
        gg_debug(GG_DEBUG_FUNCTION, "** gg_free_dcc(...);\n");
	
	if (!c)
		return;

	if (c->fd != -1)
		close(c->fd);

	free(c);
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
