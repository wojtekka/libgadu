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
#include <netdb.h>
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#include <stdarg.h>
#include <ctype.h>
#include "libgg.h"
#include "http.h"

/*
 * zmienne opisuj±ce parametry proxy http.
 */
char *gg_http_proxy_host = NULL;
int gg_http_proxy_port = 0;
int gg_http_use_proxy = 0;

/*
 * gg_http_connect()
 *
 * rozpoczyna po³±czenie po http.
 *
 *  - hostname - adres serwera,
 *  - port - port serwera,
 *  - async - dla asynchronicznego po³±czenia 1,
 *  - method - metoda http (GET/POST/cokolwiek),
 *  - path - ¶cie¿ka do zasobu (musi byæ poprzedzona ,,/''),
 *  - header - nag³ówek zapytania plus ewentualne dane dla POST.
 *
 * zwraca zaalokowan± strukturê `gg_http', któr± po¼niej nale¿y
 * zwolniæ funkcj± gg_free_http(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_http_connect(char *hostname, int port, int async, char *method, char *path, char *header)
{
	struct gg_http *h;

	if (!hostname || !port || !method || !path || !header) {
		errno = EINVAL;
		return NULL;
	}
	
	if (!(h = malloc(sizeof(*h))))
                return NULL;
	memset(h, 0, sizeof(*h));

	if (gg_http_use_proxy) {
		h->query = gg_alloc_sprintf("%s http://%s:%d%s HTTP/1.0\r\n%s",
				method, hostname, port, path, header);
		hostname = gg_http_proxy_host;
		port = gg_http_proxy_port;
	} else {
		h->query = gg_alloc_sprintf("%s %s HTTP/1.0\r\n%s",
				method, path, header);
	}

        gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-QUERY-----\n%s\n=> -----END-HTTP-QUERY-----\n", h->query);

	if (!h->query) {
		free(h);
		return NULL;
	}
	
	h->async = async;
	h->port = port;
	h->fd = -1;
	h->error = 0;
	h->state = GG_STATE_IDLE;
	
	if (async) {
		if (gg_resolve(&h->fd, &h->pid, hostname)) {
			gg_free_http(h);
			return NULL;
		}

		h->state = GG_STATE_RESOLVING;
		h->check = GG_CHECK_READ;
	} else {
		struct hostent *he;
		struct in_addr a;

		if (!(he = gethostbyname(hostname))) {
			gg_free_http(h);
			return NULL;
		} else
			memcpy((char*) &a, he->h_addr, sizeof(a));

		if (!(h->fd = gg_connect(&a, port, 0)) == -1) {
			gg_free_http(h);
			return NULL;
		}

		h->state = GG_STATE_CONNECTING_HTTP;

		while (h->state != GG_STATE_IDLE && h->state != GG_STATE_FINISHED) {
			if (gg_http_watch_fd(h) == -1)
				break;
		}

		if (h->state != GG_STATE_FINISHED) {
			gg_free_http(h);
			return NULL;
		}
	}

	return h;
}

#define GET_LOST(x) \
	close(h->fd); \
	h->state = GG_STATE_IDLE; \
	h->error = x; \
	h->fd = 0; \
	return -1;

/*
 * gg_http_watch_fd()
 *
 * przy asynchronicznej obs³uge http wypada³oby wywo³aæ t± funkcjê przy
 * jaki¶ zmianach na gg_http->fd.
 *
 *  - h - to co¶, co zwróci³o gg_http_connect()
 *
 * je¶li wszystko posz³o dobrze to 0, inaczej -1. po³±czenie bêdzie
 * zakoñczone, je¶li h->state == GG_STATE_FINISHED. je¶li wyst±pi jaki¶
 * b³±d, to bêdzie tam GG_STATE_IDLE i odpowiedni kod b³êdu w h->error.
 */
int gg_http_watch_fd(struct gg_http *h)
{
	if (!h) {
		errno = EINVAL;
		return -1;
	}

	if (h->state == GG_STATE_RESOLVING) {
		struct in_addr a;

		gg_debug(GG_DEBUG_MISC, "=> http, resolving gone\n");

		if (read(h->fd, &a, sizeof(a)) < sizeof(a) || a.s_addr == INADDR_NONE) {
			gg_debug(GG_DEBUG_MISC, "=> http, resolver thread failed\n");
			GET_LOST(GG_FAILURE_RESOLVING);
		}

		close(h->fd);

		waitpid(h->pid, NULL, 0);

		gg_debug(GG_DEBUG_MISC, "=> http, connecting to %s:%d\n", inet_ntoa(a), h->port);

		if ((h->fd = gg_connect(&a, h->port, h->async)) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> http, connection failed\n");
			GET_LOST(GG_FAILURE_CONNECTING);
		}

		h->state = GG_STATE_CONNECTING_HTTP;
		h->check = GG_CHECK_WRITE;

		return 0;
	}

	if (h->state == GG_STATE_CONNECTING_HTTP) {
		int res, res_size = sizeof(res);

		if (h->async && (getsockopt(h->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res)) {
			gg_debug(GG_DEBUG_MISC, "=> http, async connection failed\n");
			GET_LOST(GG_FAILURE_CONNECTING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, connected, sending request\n");

		if ((res = write(h->fd, h->query, strlen(h->query))) < strlen(h->query)) {
			gg_debug(GG_DEBUG_MISC, "=> http, write() failed (len=%d, res=%d, errno=%d)\n", strlen(h->query), res, errno);
			GET_LOST(GG_FAILURE_WRITING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, request sent (len=%d)\n", strlen(h->query));
		free(h->query);
		h->query = NULL;

		h->state = GG_STATE_READING_HEADER;
		h->check = GG_CHECK_READ;

		return 0;	
	}

	if (h->state == GG_STATE_READING_HEADER) {
		char buf[1024], *tmp;
		int res;

		if ((res = read(h->fd, buf, sizeof(buf))) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> http, reading header failed (errno=%d)\n", errno);
			if (h->header) {
				free(h->header);
				h->header = NULL;
			}
			GET_LOST(GG_FAILURE_READING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, read %d bytes\n", res);

#if 0
		if (!h->header_buf) {
			if (!(h->header_buf = malloc(res + 1))) {
				gg_debug(GG_DEBUG_MISC, "=> not enough memory for header\n");
				GET_LOST(GG_FAILURE_READING);
			}
			memcpy(h->header_buf, buf, res);
			h->header_size = res;
		} else {
			if (!(h->header_buf = realloc(h->header_buf, h->header_size + res + 1))) {
				gg_debug(GG_DEBUG_MISC, "=> not enough memory for header\n");
				GET_LOST(GG_FAILURE_READING);
			}
			memcpy(h->header_buf + h->header_size, buf, res);
			h->header_size += res;
		}
#endif

		if (!(h->header = realloc(h->header, h->header_size + res + 1))) {
			gg_debug(GG_DEBUG_MISC, "=> http, not enough memory for header\n");
			GET_LOST(GG_FAILURE_READING);
		}
		memcpy(h->header + h->header_size, buf, res);
		h->header_size += res;

		gg_debug(GG_DEBUG_MISC, "=> http, header_buf=%p, header_size=%d\n", h->header, h->header_size);

		h->header[h->header_size] = 0;

		if ((tmp = strstr(h->header, "\r\n\r\n")) || (tmp = strstr(h->header, "\n\n"))) {
			int sep_len = (*tmp == '\r') ? 4 : 2, left;
			char *line;

			left = h->header_size - ((long)(tmp) - (long)(h->header) + sep_len);

			gg_debug(GG_DEBUG_MISC, "=> http, got all header (%d bytes, %d left)\n", h->header_size - left, left);

			gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-HEADER-----\n%s\n=> -----END-HTTP-HEADER-----\n", h->header);

			/* HTTP/1.1 200 OK */
			if (strlen(h->header) < 16 || strncmp(h->header + 9, "200", 3)) {
				gg_debug(GG_DEBUG_MISC, h->header);
				gg_debug(GG_DEBUG_MISC, "=> http, didn't get 200 OK -- no results\n");
				free(h->header);
				h->header = NULL;
				close(h->fd);
				GET_LOST(GG_FAILURE_404);
			}

			h->data_size = 0;
			line = h->header;
			*tmp = 0;

			while (line) {
				if (!strncasecmp(line, "Content-length: ", 16)) {
					h->data_size = atoi(line + 16);
				}
				line = strchr(line, '\n');
				if (line)
					line++;
			}

			if (!h->data_size) {
				gg_debug(GG_DEBUG_MISC, "=> http, content-length not found\n");
				free(h->header);
				h->header = NULL;
				GET_LOST(GG_FAILURE_READING);
			}

			gg_debug(GG_DEBUG_MISC, "=> http, data_size=%d\n", h->data_size);

			if (!(h->data = malloc(h->data_size + 1))) {
				gg_debug(GG_DEBUG_MISC, "=> http, not enough memory (%d bytes for data_buf)\n", h->data_size + 1);
				free(h->header);
				h->header = NULL;
				GET_LOST(GG_FAILURE_READING);
			}

			if (left) {
				if (left > h->data_size) {
					gg_debug(GG_DEBUG_MISC, "=> http, too much data (%d bytes left, %d needed)\n", left, h->data_size);
					free(h->header);
					free(h->data);
					h->header = NULL;
					h->data = NULL;
					GET_LOST(GG_FAILURE_READING);
				}

				memcpy(h->data, tmp + sep_len, left);
				h->data[left] = 0;
			}

			if (left && left == h->data_size) {
				gg_debug(GG_DEBUG_MISC, "=> http, wow, we got header and data in one shot\n");
				h->state = GG_STATE_FINISHED;
				h->check = 0;
				close(h->fd);
				h->fd = -1;
				return 0;
			} else {
				h->state = GG_STATE_READING_DATA;
				h->check = GG_CHECK_READ;
				return 0;
			}
		} else
			return 0;
	}

	if (h->state == GG_STATE_READING_DATA) {
		char buf[1024];
		int res;

		if ((res = read(h->fd, buf, sizeof(buf))) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> http, reading data failed (errno=%d)\n", errno);
			if (h->data) {
				free(h->data);
				h->data = NULL;
			}
			GET_LOST(GG_FAILURE_READING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, read %d bytes of data\n", res);

		if (strlen(h->data) + res > h->data_size) {
			gg_debug(GG_DEBUG_MISC, "=> http, too much data (%d bytes, %d needed), truncating\n", strlen(h->data) + res, h->data_size);
			res = h->data_size - strlen(h->data);
		}

		h->data[strlen(h->data) + res] = 0;
		memcpy(h->data + strlen(h->data), buf, res);

		gg_debug(GG_DEBUG_MISC, "=> strlen(data)=%d, data_size=%d\n", strlen(h->data), h->data_size);

		if (strlen(h->data) >= h->data_size) {
			gg_debug(GG_DEBUG_MISC, "=> http, we're done, closing socket\n");
			h->state = GG_STATE_FINISHED;
			close(h->fd);
			h->fd = -1;
		}
		return 0;
	}
	
	if (h->fd != -1)
		close(h->fd);

	h->fd = -1;
	h->state = GG_STATE_IDLE;
	h->error = 0;

	return -1;
}

#undef GET_LOST

/*
 * gg_http_stop()
 *
 * je¶li po³±czenie jest w trakcie, przerywa.
 *
 *  - h - to co¶, co zwróci³o gg_http().
 *
 * UWAGA! funkcja potencjalnie niebezpieczna, bo mo¿e pozwalniaæ bufory
 * i pozamykaæ sockety, kiedy co¶ siê dzieje. ale to ju¿ nie mój problem ;)
 */
void gg_http_stop(struct gg_http *h)
{
	if (!h)
		return;

	if (h->state == GG_STATE_IDLE || h->state == GG_STATE_FINISHED)
		return;

	if (h->fd != -1)
		close(h->fd);

}

/*
 * gg_free_http()
 *
 * zwalnia pamiêæ po po³±czeniu.
 *
 *  - h - to co¶, co nie jest ju¿ nam potrzebne.
 *
 * nie zwraca niczego. najwy¿ej segfaultnie ;)
 */
void gg_free_http(struct gg_http *h)
{
	if (!h)
		return;

	free(h->header);
	free(h->data);
	free(h->query);
	free(h);
}

/*
 * Local variables:
 * c-indentation-style: k&r
 * c-basic-offset: 8
 * indent-tabs-mode: notnil
 * End:
 *
 * vim: expandtab shiftwidth=8:
 */
