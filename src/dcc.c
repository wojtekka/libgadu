/* $Id$ */

/*
 *  (C) Copyright 2001 Wojtek Kaniewski <wojtekka@irc.pl>
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
#include <stdarg.h>
#include <ctype.h>
#include "libgg.h"

/*
 * gg_dcc_send_request()
 *
 * wysy³a informacjê o tym, ¿e chcemy wys³aæ plik. je¶li druga strona
 * obs³uguje bezpo¶rednie po³±czenia, po³±czny siê z naszym portem.
 *
 *  - sess - sesja GG,
 *  - uin - numerek odbiorcy.
 *
 * zwraca to samo, co gg_send_msg().
 */
int gg_dcc_send_request(struct gg_session *sess, uin_t uin)
{
	return gg_send_message_ctcp(sess, GG_CLASS_CTCP, uin, "\002", 1);
}

/*
 * gg_dcc_send_file()
 *
 * wype³nia pola gg_dcc niezbêdne do wys³ania pliku.
 *
 *  - d - struktura gg_dcc,
 *  - filename - nazwa pliku.
 *
 * zwraca -1 w przypadku b³êdu, 0 je¶li siê powiod³o.
 */
int gg_dcc_send_file(struct gg_dcc *d, char *filename)
{
	struct stat st;
	char *p;
	
	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc_send_file(..., \"%s\");\n", filename);
	
	if (!d || d->type != GG_SESSION_DCC_SEND) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_send_file() invalid arguments\n");
		errno = EINVAL;
		return -1;
	}
		
	if (stat(filename, &st) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_send_file() stat() failed (%s)\n", strerror(errno));
		return -1;
	}

	if ((d->file_fd = open(filename, O_RDONLY)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_send_file() open() failed (%s)\n", strerror(errno));
		return -1;
	}

	memset(&d->file_info, 0, sizeof(d->file_info));

	if ((st.st_mode & S_IFDIR)) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc_send_file() that's a directory\n");
		errno = EINVAL;
		return -1;
	}
	
	if (!(st.st_mode & S_IWUSR))
		d->file_info.mode |= fix32(GG_DCC_FILEATTR_READONLY);

	/* XXX czas pliku */
	
	d->file_info.size = fix32(st.st_size);

	for (p = filename + strlen(filename); p > filename && *p != '/'; p--);

	if (*p == '/')
		p++;
	
	gg_debug(GG_DEBUG_MISC, "// gg_dcc_send_file() short name \"%s\"\n", p);
	strncpy(d->file_info.filename, p, sizeof(d->file_info.filename));

	return 0;
}
/*
 * gg_create_dcc_socket()
 *
 * tworzy socketa dla bezpo¶redniej komunikacji miêdzy klientami.
 *
 *  - uin - w³asny numerek,
 *  - port - preferowany port, je¶li równy 0 lub -1, próbuje domy¶lnego.
 *
 * zwraca zaalokowan± strukturê `gg_dcc', któr± po¼niej nale¿y
 * zwolniæ funkcj± gg_free_dcc(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_dcc *gg_create_dcc_socket(uin_t uin, unsigned int port)
{
	struct gg_dcc *c;
	struct sockaddr_in sin;
	int sock, bound = 0;
	
        gg_debug(GG_DEBUG_FUNCTION, "** gg_create_dcc_socket(%ld, %d);\n", uin, port);
	
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

	return c;
}

/*
 * gg_dcc_watch_fd()
 *
 * funkcja, któr± nale¿y wywo³aæ, gdy co¶ siê zmieni na gg_dcc->fd.
 *
 *  - c - to co¶, co zwróci³o gg_create_dcc_socket()
 *
 * zwraca zaalogowan± strukturê gg_event lub NULL, je¶li zabrak³o pamiêci
 * na ni±.
 */
struct gg_event *gg_dcc_watch_fd(struct gg_dcc *h)
{
	struct gg_event *e;

        gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc_watch_fd(...);\n");
	
	if (!h || (h->type != GG_SESSION_DCC && h->type != GG_SESSION_DCC_SOCKET && h->type != GG_SESSION_DCC_SEND && h->type != GG_SESSION_DCC_GET)) {
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

		ioctl(fd, FIONBIO, &one);	/* XXX error */

		gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() new direct connection from %s:%d\n", inet_ntoa(sin.sin_addr), htons(sin.sin_port));

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
	}

	if (h->type == GG_SESSION_DCC) {
		struct gg_dcc_small_packet small;
		char ack[] = "UDAG";
		int res;
		uin_t tmp;
		
		switch (h->state) {
			case GG_STATE_READING_UIN_1:
			case GG_STATE_READING_UIN_2:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_READING_UIN_%d\n", (h->state == GG_STATE_READING_UIN_1) ? 1 : 2);
				
				if ((res = read(h->fd, &tmp, sizeof(tmp))) != sizeof(tmp)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed (%s)\n", (res == -1) ? strerror(errno) : "!=sizeof");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				if (h->state == GG_STATE_READING_UIN_1) {
					h->state = GG_STATE_READING_UIN_2;
					h->check = GG_CHECK_READ;
					h->timeout = GG_DEFAULT_TIMEOUT;
					h->peer_uin = tmp;
				} else {
					h->state = GG_STATE_SENDING_ACK;
					h->check = GG_CHECK_WRITE;
					h->timeout = GG_DEFAULT_TIMEOUT;
					h->uin = tmp;
				}

				return e;

			case GG_STATE_SENDING_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_SENDING_ACK\n");

				if ((res = write(h->fd, ack, 4)) != 4) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%s)\n", (res == -1) ? strerror(errno) : "!=sizeof");
					
					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					
					return e;
				}

				h->state = GG_STATE_READING_REQUEST;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;

				return e;

			case GG_STATE_READING_REQUEST:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_REQUEST\n");
				
				if ((tmp = read(h->fd, &small, sizeof(small))) != sizeof(small)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed (%s)\n", (tmp == -1) ? strerror(errno) : "!=sizeof");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				small.type = fix32(small.type);

				if (small.type != GG_DCC_WANT_FILE) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() unknown dcc request (%.4x) from %ld\n", small.type, h->peer_uin);

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}
				
				h->type = GG_SESSION_DCC_SEND;
				h->state = GG_STATE_SENDING_FILE_INFO;
				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DEFAULT_TIMEOUT;
				e->type = GG_EVENT_DCC_NEED_FILE_INFO;

				gg_debug(GG_DEBUG_MISC, "// CHANGED!\n"); /* XXX */

				return e;

			default:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_???\n");

				e->type = GG_EVENT_DCC_ERROR;
				e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;

				return e;
		}
	}

	if (h->type == GG_SESSION_DCC_SEND) {
		struct gg_dcc_small_packet small;
		struct gg_dcc_big_packet big;
		int size, tmp;
		char buf[1024];
		struct {
			struct gg_dcc_big_packet big;
			struct gg_file_info file_info;
		} __attribute__ ((packed)) file_info_packet;

		switch (h->state) {
			case GG_STATE_SENDING_FILE_INFO:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_FILE_INFO\n");

				small.type = fix32(GG_DCC_HAVE_FILE);
				
				if ((tmp = write(h->fd, &small, sizeof(small))) != sizeof(small)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() header1 write() failed (%s)\n", (tmp == -1) ? strerror(errno) : "!=sizeof");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				big.type = fix32(GG_DCC_HAVE_FILEINFO);
				big.dunno1 = 0;
				big.dunno2 = 0;

				memcpy(&file_info_packet.big, &big, sizeof(big));
				memcpy(&file_info_packet.file_info, &h->file_info, sizeof(h->file_info));
				
				if ((tmp = write(h->fd, &file_info_packet, sizeof(file_info_packet))) != sizeof(file_info_packet)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%s)\n", (tmp == -1) ? strerror(errno) : "!=sizeof");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				h->state = GG_STATE_READING_ACK;
				h->check = GG_CHECK_READ;
				h->timeout = 300;	/* XXX sta³a */

				return e;
				
			case GG_STATE_READING_ACK:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_READING_ACK\n");
				
				if ((tmp = read(h->fd, &big, sizeof(big))) != sizeof(big)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() read() failed (%s)\n", (tmp == -1) ? strerror(errno) : "!=sizeof");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				big.type = fix32(big.type);
				
/* XXX zbadaæ dlaczego */
#if 0
				if (small.type != GG_DCC_GIMME_FILE) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() unknown dcc request (%.4x) from %ld\n", small.type, h->peer_uin);

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}
#endif

				h->state = GG_STATE_SENDING_HEADER;
				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DEFAULT_TIMEOUT;

				return e;

			case GG_STATE_SENDING_HEADER:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_HEADER\n");
				
				big.type = fix32(GG_DCC_CATCH_FILE);
				gg_debug(GG_DEBUG_MISC, "// FILESIZE: %d\n", h->file_info.size);
				big.dunno1 = fix32(h->file_info.size);	/* XXX dlaczego? */
				big.dunno2 = 0;
				
				if ((tmp = write(h->fd, &big, sizeof(big))) != sizeof(big)) {
					gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() write() failed (%s)\n", (tmp == -1) ? strerror(errno) : "!=sizeof");

					e->type = GG_EVENT_DCC_ERROR;
					e->event.dcc_error = GG_ERROR_DCC_HANDSHAKE;
					return e;
				}

				h->state = GG_STATE_SENDING_FILE;
				h->check = GG_CHECK_WRITE;
				h->timeout = GG_DEFAULT_TIMEOUT;

				return e;
				
			case GG_STATE_SENDING_FILE:
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() GG_STATE_SENDING_FILE\n");
				
				gg_debug(GG_DEBUG_MISC, "// gg_dcc_watch_fd() offset=%d, size=%d\n", h->offset, h->file_info.size);
				lseek(h->file_fd, h->offset, SEEK_SET);
				size = read(h->file_fd, buf, sizeof(buf));

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
					e->event.dcc_error = GG_ERROR_DCC_SENDING;
					return e;
				}

				h->offset += tmp;
				
				if (h->offset == h->file_info.size)
					e->type = GG_EVENT_DCC_DONE;
				
				h->timeout = 300;	/* XXX sta³a */

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


/*
 * gg_free_dcc()
 *
 * zwalnia pamiêæ po strukturze po³±czenia dcc.
 *
 *  - c - to co¶, co nie jest ju¿ nam potrzebne.
 *
 * nie zwraca niczego. najwy¿ej segfaultnie ;)
 */
void gg_free_dcc(struct gg_dcc *c)
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
