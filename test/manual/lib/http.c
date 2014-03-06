/*
 *  (C) Copyright 2008 Wojtek Kaniewski <wojtekka@irc.pl>
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

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "http.h"

static size_t handle_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	char *new_text, **text_ptr;
	size_t bytes, text_len;

	text_ptr = (char**) stream;

	bytes = size * nmemb;

#if 0
	printf("Read %d\n", bytes);
#endif

	if (*text_ptr == NULL) {
		text_len = 0;
		new_text = malloc(bytes + 1);
	} else {
		text_len = strlen(*text_ptr);
		new_text = realloc(*text_ptr, text_len + bytes + 1);
	}

	if (new_text == NULL) {
		free(*text_ptr);
		*text_ptr = NULL;
		return 0;
	}

	memcpy(new_text + text_len, ptr, bytes);
	new_text[text_len + bytes] = 0;
	*text_ptr = new_text;

	return bytes;
}

char *gg_http_fetch(const char *method, const char *url, const char *auth_header, char *post_data)
{
	CURL *c;
	struct curl_slist *hdr = NULL;
	char *text = NULL;
	char **write_data_to = &text;

	c = curl_easy_init();

	if (c == NULL)
		return NULL;

	if (auth_header)
		hdr = curl_slist_append(hdr, auth_header);

	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, handle_data);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, write_data_to);
	curl_easy_setopt(c, CURLOPT_USERAGENT, "Gadu-Gadu Client, build 8,0,0,4881");
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
	if (strcmp(method, "POST") == 0) {
		curl_easy_setopt(c, CURLOPT_HTTPPOST, NULL);
		if (post_data)
			curl_easy_setopt(c, CURLOPT_POSTFIELDS, post_data);
	}
/* from gadu-gadu, under LGPL 3.0 :> */
	curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0);	/* bylo 1 */
/*	curl_easy_setopt(c, CURLOPT_RETURNTRANSFER, 1); */
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(c, CURLOPT_MAXREDIRS, 3);

#if 0
	curl_easy_setopt(c, CURLOPT_VERBOSE, 1);
#endif

	curl_easy_perform(c);

	if (hdr)
		curl_slist_free_all(hdr);

	curl_easy_cleanup(c);

	return text;
}

void http_init(void)
{
	curl_global_init(CURL_GLOBAL_SSL);
}
