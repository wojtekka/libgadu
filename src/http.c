/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>
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
#include <netdb.h>
#include <sys/wait.h>
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#include <stdarg.h>
#include <ctype.h>
#include "config.h"
#include "compat.h"
#include "libgadu.h"

/*
 * gg_http_connect() // funkcja pomocnicza
 *
 * rozpoczyna po³±czenie po http.
 *
 *  - hostname - adres serwera
 *  - port - port serwera
 *  - async - asynchroniczne po³±czenie
 *  - method - metoda http (GET, POST, cokolwiek)
 *  - path - ¶cie¿ka do zasobu (musi byæ poprzedzona ,,/'')
 *  - header - nag³ówek zapytania plus ewentualne dane dla POST
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y
 * zwolniæ funkcj± gg_http_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_http_connect(const char *hostname, int port, int async, const char *method, const char *path, const char *header)
{
	struct gg_http *h;

	if (!hostname || !port || !method || !path || !header) {
                gg_debug(GG_DEBUG_MISC, "// gg_http_connect() invalid arguments\n");
		errno = EINVAL;
		return NULL;
	}
	
	if (!(h = malloc(sizeof(*h))))
                return NULL;        
	memset(h, 0, sizeof(*h));

	if (gg_proxy_enabled) {
		h->query = gg_saprintf("%s http://%s:%d%s HTTP/1.0\r\n%s",
				method, hostname, port, path, header);
		hostname = gg_proxy_host;
		port = gg_proxy_port;
	} else {
		h->query = gg_saprintf("%s %s HTTP/1.0\r\n%s",
				method, path, header);
	}

	if (!h->query) {
                gg_debug(GG_DEBUG_MISC, "// gg_http_connect() not enough memory for query\n");
		free(h);
                errno = ENOMEM;
		return NULL;
	}
	
	gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-QUERY-----\n%s\n=> -----END-HTTP-QUERY-----\n", h->query);

	h->async = async;
	h->port = port;
	h->fd = -1;
	h->error = 0;
        h->type = GG_SESSION_HTTP;
	h->id = 0;
	h->user_data = NULL;
	
	if (async) {
		if (gg_resolve(&h->fd, &h->pid, hostname)) {
                        gg_debug(GG_DEBUG_MISC, "// gg_http_connect() resolver failed\n");
			gg_free_http(h);
                        errno = ENOENT;
			return NULL;
		}

		h->state = GG_STATE_RESOLVING;
		h->check = GG_CHECK_READ;
		h->timeout = GG_DEFAULT_TIMEOUT;
	} else {
		struct hostent *he;
		struct in_addr a;

		if (!(he = gg_gethostbyname(hostname))) {
                        gg_debug(GG_DEBUG_MISC, "// gg_http_connect() host not found\n");
			gg_free_http(h);
			return NULL;
		} else {
			memcpy((char*) &a, he->h_addr, sizeof(a));
			free(he);
		}

		if (!(h->fd = gg_connect(&a, port, 0)) == -1) {
                        gg_debug(GG_DEBUG_MISC, "// gg_http_connect() connection failed (errno=%d, %s)\n", errno, strerror(errno));
			gg_free_http(h);
			return NULL;
		}

		h->state = GG_STATE_CONNECTING;

		while (h->state != GG_STATE_ERROR && h->state != GG_STATE_PARSING) {
			if (gg_http_watch_fd(h) == -1)
				break;
		}

		if (h->state != GG_STATE_PARSING) {
                        gg_debug(GG_DEBUG_MISC, "// gg_http_connect() some error\n");
			gg_free_http(h);
			return NULL;
		}
	}

	h->callback = gg_http_watch_fd;
	h->destroy = gg_free_http;
	
	return h;
}

#define gg_http_error(x) \
	close(h->fd); \
	h->fd = -1; \
	h->state = GG_STATE_ERROR; \
	h->error = x; \
	return 0;

/*
 * gg_http_watch_fd()
 *
 * przy asynchronicznej obs³udze HTTP funkcjê t± nale¿y wywo³aæ je¶li
 * zmieni³o siê co¶ na obserwowanym deskryptorze.
 *
 *  - h - struktura opisuj±ca po³±czenie
 *
 * je¶li wszystko posz³o dobrze to 0, inaczej -1. po³±czenie bêdzie
 * zakoñczone, je¶li h->state == GG_STATE_PARSING. je¶li wyst±pi jaki¶
 * b³±d, to bêdzie tam GG_STATE_ERROR i odpowiedni kod b³êdu w h->error.
 */
int gg_http_watch_fd(struct gg_http *h)
{
	if (!h) {
		errno = EINVAL;
		return -1;
	}

	if (h->state == GG_STATE_RESOLVING) {
		struct in_addr a;

		gg_debug(GG_DEBUG_MISC, "=> http, resolving done\n");

		if (read(h->fd, &a, sizeof(a)) < sizeof(a) || a.s_addr == INADDR_NONE) {
			gg_debug(GG_DEBUG_MISC, "=> http, resolver thread failed\n");
			gg_http_error(GG_ERROR_RESOLVING);
		}

		close(h->fd);

		waitpid(h->pid, NULL, 0);

		gg_debug(GG_DEBUG_MISC, "=> http, connecting to %s:%d\n", inet_ntoa(a), h->port);

		if ((h->fd = gg_connect(&a, h->port, h->async)) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> http, connection failed (errno=%d, %s)\n", errno, strerror(errno));
			gg_http_error(GG_ERROR_CONNECTING);
		}

		h->state = GG_STATE_CONNECTING;
		h->check = GG_CHECK_WRITE;
		h->timeout = GG_DEFAULT_TIMEOUT;

		return 0;
	}

	if (h->state == GG_STATE_CONNECTING) {
		int res, res_size = sizeof(res);

		if (h->async && (getsockopt(h->fd, SOL_SOCKET, SO_ERROR, &res, &res_size) || res)) {
			gg_debug(GG_DEBUG_MISC, "=> http, async connection failed (errno=%d, %s)\n", res, strerror(res));
			close(h->fd);
			h->fd = -1;
			h->state = GG_STATE_ERROR;
			h->error = GG_ERROR_CONNECTING;
			errno = res;
			return 0;
		}

		gg_debug(GG_DEBUG_MISC, "=> http, connected, sending request\n");

		if ((res = write(h->fd, h->query, strlen(h->query))) < strlen(h->query)) {
			gg_debug(GG_DEBUG_MISC, "=> http, write() failed (len=%d, res=%d, errno=%d)\n", strlen(h->query), res, errno);
			gg_http_error(GG_ERROR_WRITING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, request sent (len=%d)\n", strlen(h->query));
		free(h->query);
		h->query = NULL;

		h->state = GG_STATE_READING_HEADER;
		h->check = GG_CHECK_READ;
		h->timeout = GG_DEFAULT_TIMEOUT;

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
			gg_http_error(GG_ERROR_READING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, read %d bytes\n", res);

		if (!(h->header = realloc(h->header, h->header_size + res + 1))) {
			gg_debug(GG_DEBUG_MISC, "=> http, not enough memory for header\n");
			gg_http_error(GG_ERROR_READING);
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

			/* HTTP/1.1 200 OK */
			if (strlen(h->header) < 16 || strncmp(h->header + 9, "200", 3)) {
			        gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-HEADER-----\n%s\n=> -----END-HTTP-HEADER-----\n", h->header);

				gg_debug(GG_DEBUG_MISC, h->header);
				gg_debug(GG_DEBUG_MISC, "=> http, didn't get 200 OK -- no results\n");
				free(h->header);
				h->header = NULL;
				gg_http_error(GG_ERROR_CONNECTING);
			}

			h->body_size = 0;
			line = h->header;
			*tmp = 0;
                        
			gg_debug(GG_DEBUG_MISC, "=> -----BEGIN-HTTP-HEADER-----\n%s\n=> -----END-HTTP-HEADER-----\n", h->header);

			while (line) {
				if (!strncasecmp(line, "Content-length: ", 16)) {
					h->body_size = atoi(line + 16);
				}
				line = strchr(line, '\n');
				if (line)
					line++;
			}

			if (!h->body_size) {
				gg_debug(GG_DEBUG_MISC, "=> http, content-length not found\n");
				free(h->header);
				h->header = NULL;
				gg_http_error(GG_ERROR_READING);
			}

			gg_debug(GG_DEBUG_MISC, "=> http, body_size=%d\n", h->body_size);

			if (!(h->body = malloc(h->body_size + 1))) {
				gg_debug(GG_DEBUG_MISC, "=> http, not enough memory (%d bytes for body_buf)\n", h->body_size + 1);
				free(h->header);
				h->header = NULL;
				gg_http_error(GG_ERROR_READING);
			}

			if (left) {
				if (left > h->body_size) {
					gg_debug(GG_DEBUG_MISC, "=> http, too much body (%d bytes left, %d needed)\n", left, h->body_size);
					free(h->header);
					free(h->body);
					h->header = NULL;
					h->body = NULL;
					gg_http_error(GG_FAILURE_READING);
				}

				memcpy(h->body, tmp + sep_len, left);
			}
			h->body[left] = 0;

			if (left && left == h->body_size) {
				gg_debug(GG_DEBUG_MISC, "=> http, wow, we got header and body in one shot\n");
				h->state = GG_STATE_PARSING;
				h->check = 0;
				h->timeout = GG_DEFAULT_TIMEOUT;
				close(h->fd);
				h->fd = -1;
				return 0;
			} else {
				h->state = GG_STATE_READING_DATA;
				h->check = GG_CHECK_READ;
				h->timeout = GG_DEFAULT_TIMEOUT;
				return 0;
			}
		} else
			return 0;
	}

	if (h->state == GG_STATE_READING_DATA) {
		char buf[1024];
		int res;

		if ((res = read(h->fd, buf, sizeof(buf))) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> http, reading body failed (errno=%d)\n", errno);
			if (h->body) {
				free(h->body);
				h->body = NULL;
			}
			gg_http_error(GG_ERROR_READING);
		}

		gg_debug(GG_DEBUG_MISC, "=> http, read %d bytes of body\n", res);

		if (strlen(h->body) + res > h->body_size) {
			gg_debug(GG_DEBUG_MISC, "=> http, too much body (%d bytes, %d needed), truncating\n", strlen(h->body) + res, h->body_size);
			res = h->body_size - strlen(h->body);
		}

		h->body[strlen(h->body) + res] = 0;
		memcpy(h->body + strlen(h->body), buf, res);

		gg_debug(GG_DEBUG_MISC, "=> strlen(body)=%d, body_size=%d\n", strlen(h->body), h->body_size);

		if (strlen(h->body) >= h->body_size) {
			gg_debug(GG_DEBUG_MISC, "=> http, we're done, closing socket\n");
			h->state = GG_STATE_PARSING;
			close(h->fd);
			h->fd = -1;
		}
		return 0;
	}
	
	if (h->fd != -1)
		close(h->fd);

	h->fd = -1;
	h->state = GG_STATE_ERROR;
	h->error = 0;

	return -1;
}

#undef gg_http_error

/*
 * gg_http_stop()
 *
 * je¶li po³±czenie jest w trakcie, przerywa je.
 * 
 * UWAGA! funkcja potencjalnie niebezpieczna, poniewa¿ mo¿e pozwalniaæ
 * bufory i pozamykaæ gniazda, kiedy co¶ wa¿nego siê dzieje. 
 *
 *  - h - struktura opisuj±ca po³±czenie
 */
void gg_http_stop(struct gg_http *h)
{
	if (!h)
		return;

	if (h->state == GG_STATE_ERROR || h->state == GG_STATE_DONE)
		return;

	if (h->fd != -1)
		close(h->fd);
        h->fd = -1;
}

/*
 * gg_http_free()
 *
 * próbuje zamkn±æ po³±czenie i zwalnia pamiêæ po nim.
 *
 *  - h - struktura, któr± nale¿y zlikwidowaæ
 */
void gg_http_free(struct gg_http *h)
{
	if (!h)
		return;

	gg_http_stop(h);

	free(h->header);
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
 * vim: shiftwidth=8:
 */
