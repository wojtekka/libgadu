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
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#include <stdarg.h>
#include <ctype.h>
#include "libgg.h"

/*
 * gg_register()
 *
 * próbuje zarejestrowaæ u¿ytkownika.
 *
 *  - email, password - informacja rejestracyjne,
 *  - async - ma byæ asynchronicznie?
 *
 * zwraca zaalokowan± strukturê `gg_http', któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_free_register(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_register(char *email, char *password, int async)
{
        struct gg_http *h;
	char *__pwd, *__email, *form, *query;

	if (!email | !password) {
		errno = EINVAL;
		return NULL;
	}

	__pwd = gg_urlencode(password);
	__email = gg_urlencode(email);

	if (!__pwd || !__email) {
		gg_debug(GG_DEBUG_MISC, "=> register, not enough memory for form fields\n");
		free(__pwd);
		free(__email);
                errno = ENOMEM;
		return NULL;
	}

	form = gg_alloc_sprintf("pwd=%s&email=%s&code=%u", __pwd, __email,
			gg_http_hash(email, password));

	free(__pwd);
	free(__email);

	if (!form) {
		gg_debug(GG_DEBUG_MISC, "=> register, not enough memory for form query\n");
                errno = ENOMEM;
		return NULL;
	}

	gg_debug(GG_DEBUG_MISC, "=> register, %s\n", form);

	query = gg_alloc_sprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"User-Agent: " GG_HTTP_USERAGENT "\r\n"
		"Content-Length: %d\r\n"
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s",
		strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> register, gg_http_connect() failed mysteriously\n");
		free(query);
                return NULL;
	}

	h->type = GG_SESSION_REGISTER;

	free(query);

	if (!async)
		gg_pubdir_watch_fd(h);
	
	return h;
}

/*
 * gg_pubdir_watch_fd()
 *
 * przy asynchronicznym zak³adaniu wypada³oby wywo³aæ t± funkcjê przy
 * jaki¶ zmianach na gg_http->fd.
 *
 *  - h - to co¶, co zwróci³a funkcja obs³ugi katalogu publicznego.
 *
 * je¶li wszystko posz³o dobrze to 0, inaczej -1. operacja bêdzie
 * zakoñczona, je¶li h->state == GG_STATE_DONE. je¶li wyst±pi jaki¶
 * b³±d, to bêdzie tam GG_STATE_ERROR i odpowiedni kod b³êdu w h->error.
 */
int gg_pubdir_watch_fd(struct gg_http *h)
{
	struct gg_pubdir *p;

	if (!h) {
		errno = EINVAL;
		return -1;
	}

        if (h->state == GG_STATE_ERROR) {
                gg_debug(GG_DEBUG_MISC, "=> pubdir, watch_fd issued on failed session\n");
                errno = EINVAL;
                return -1;
        }
	
	if (h->state != GG_STATE_PARSING) {
		if (gg_http_watch_fd(h) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> pubdir, http failure\n");
                        errno = EINVAL;
			return -1;
		}
	}

	if (h->state != GG_STATE_PARSING)
                return 0;
	
        h->state = GG_STATE_DONE;
	
	if (!(h->data = p = malloc(sizeof(struct gg_pubdir)))) {
		gg_debug(GG_DEBUG_MISC, "=> pubdir, not enough memory for results\n");
		return -1;
	}
	p->success = 0;
	p->uin = 0;
	
	gg_debug(GG_DEBUG_MISC, "=> pubdir, let's parse \"%s\"\n", h->body);

	if (strncasecmp(h->body, "reg_success:", 12))
		gg_debug(GG_DEBUG_MISC, "=> pubdir, error.\n");
	else {
		p->uin = strtol(h->body + 12, NULL, 0);
		p->success = 1;
		gg_debug(GG_DEBUG_MISC, "=> pubdir, success (uin=%ld)\n", p->uin);
	}

	return 0;
}

/*
 * gg_free_register()
 *
 * zwalnia pamiêæ po efektach rejestracji.
 *
 *  - h - to co¶, co nie jest ju¿ nam potrzebne.
 *
 * nie zwraca niczego. najwy¿ej segfaultnie.
 */
void gg_free_register(struct gg_http *h)
{
	if (!h)
		return;
	
	free(h->data);
	gg_free_http(h);
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
