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

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "oauth.h"
#include "http.h"
#include "xml.h"
#include "config.h"
#include "urlencode.h"

char *token, *token_secret;

#define HTTP_METHOD1 "POST"
#define HTTP_URL1 "http://api.gadu-gadu.pl/request_token"
int oauth_request() {
	char *auth, *reply;

	printf("\033[1m/request_token\033[0m\n\n");

	if (!(auth = gg_oauth_generate_header(HTTP_METHOD1, HTTP_URL1, CONSUMER_KEY, CONSUMER_SECRET, NULL, NULL)))
		return 0;

	printf("header = '%s'\n", auth);

	reply = gg_http_fetch(HTTP_METHOD1, HTTP_URL1, auth, NULL);

	free(auth);

	if (reply == NULL)
		return 0;

	printf("reply = '%s'\n", reply);

	if (gg_parse_token_reply(reply, &token, &token_secret) == -1) {
		free(reply);
		return 0;
	}

	free(reply);

	printf("token = '%s'\ntoken_secret = '%s'\n", token, token_secret);
	return 1;
}

#define HTTP_AUTH_METHOD "POST"
#define HTTP_AUTH_URL	"https://login.gadu-gadu.pl/authorize"
int oauth_authorize() {
	char *tmp, *reply;

	printf("\n\033[1m/authorize\033[0m\n\n");
	
	tmp = gg_urlencode_printf("callback_url=http://www.mojageneracja.pl&request_token=%s&uin=%s&password=%s",
			token, CONSUMER_KEY, CONSUMER_SECRET);

	reply = gg_http_fetch(HTTP_AUTH_METHOD, HTTP_AUTH_URL, NULL, tmp);

	free(reply);
	free(tmp);
	return 1;
}

#define HTTP_METHOD2 "POST"
#define HTTP_URL2 "http://api.gadu-gadu.pl/access_token"
int oauth_access() {
	char *auth, *reply;
	printf("\n\033[1m/access_token\033[0m\n\n");

	if (!(auth = gg_oauth_generate_header(HTTP_METHOD2, HTTP_URL2, CONSUMER_KEY, CONSUMER_SECRET, token, token_secret)))
		return 0;

	printf("header = '%s'\n", auth);

	reply = gg_http_fetch(HTTP_METHOD2, HTTP_URL2, auth, NULL);

	free(auth);

	if (reply == NULL)
		return 0;

	free(token);		token = NULL;
	free(token_secret);	token_secret = NULL;

	if (gg_parse_token_reply(reply, &token, &token_secret) == -1) {
		free(reply);
		return 0;
	}

	printf("reply = '%s'\n", reply);

	free(reply);
	return 1;
}

int oauth_init() {
	if (!oauth_request())
		return 0;
	if (!oauth_authorize())
		return 0;
	if (!oauth_access())
		return 0;
	return 1;
}

#define HTTP_METHOD3 "GET"
#define HTTP_URL3_BASE "http://api.gadu-gadu.pl/users/"

void oauth_ask(const char *uid)
{
	char *auth;
	char *reply;
	char *tmp;

	tmp = gg_urlencode_printf(HTTP_URL3_BASE "%s.xml", uid);

	printf("\n\033[1m%s\033[0m\n\n", tmp);

	auth = gg_oauth_generate_header(HTTP_METHOD3, tmp, CONSUMER_KEY, CONSUMER_SECRET, token, token_secret);

	if (auth == NULL) {
		free(tmp);
		return;
	}

	printf("header = '%s'\n", auth);

	reply = gg_http_fetch(HTTP_METHOD3, tmp, auth, NULL);

	if (reply == NULL)
		return;

	printf("reply = '%s'\n", reply);

	free(reply);
	free(auth);
	free(tmp);
}

int main(int argc, char **argv)
{
	int i;

	srand(time(NULL));
	http_init();

	if (argc < 2) {
		printf("usage: %s <uid1> [uid2] [uid3] [uid4] ....\n", argv[0]);
		return 1;
	}

	if (!oauth_init()) {
		free(token);
		free(token_secret);
		return 1;
	}

	for (i = 1; i < argc; i++)	/* mozeby wypadalo sprawdzac przez strtol() czy to faktycznie jest int? */
		oauth_ask(argv[i]);

	free(token);
	free(token_secret);
	return 0;
}

