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
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>

#include "lib/oauth.h"
#include "lib/http.h"
#include "lib/xml.h"
#include "lib/urlencode.h"

#include "network.h"

char *token, *token_secret;

char *config_uin = NULL;
char *config_password = NULL;

static int config_read(void)
{
	char buf[256];
	FILE *f;

	if (!(f = fopen("config", "r"))) {
		if (!(f = fopen("../config", "r")))
			return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		while (strlen(buf) > 0 && isspace(buf[strlen(buf) - 1]))
			buf[strlen(buf) - 1] = 0;

		if (!strncmp(buf, "uin ", 4)) {
			free(config_uin);
			config_uin = strdup(buf + 4);
		}

		if (!strncmp(buf, "password ", 9)) {
			free(config_password);
			config_password = strdup(buf + 9);
		}
	}

	fclose(f);

	if (!config_uin || !config_password)
		return -1;

	return 0;
}

static void config_free(void)
{
	free(config_uin);
	free(config_password);
}

#define HTTP_METHOD1 "POST"
#define HTTP_URL1 "http://api.gadu-gadu.pl/request_token"
static int oauth_request(void)
{
	char *auth, *reply;

	printf("\033[1m/request_token\033[0m\n\n");

	if (!(auth = gg_oauth_generate_header(HTTP_METHOD1, HTTP_URL1, config_uin, config_password, NULL, NULL)))
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
static int oauth_authorize(void)
{
	char *tmp, *reply;

	printf("\n\033[1m/authorize\033[0m\n\n");

	tmp = gg_urlencode_printf("callback_url=http://www.mojageneracja.pl&request_token=%s&uin=%s&password=%s",
			token, config_uin, config_password);

	reply = gg_http_fetch(HTTP_AUTH_METHOD, HTTP_AUTH_URL, NULL, tmp);

	free(reply);
	free(tmp);
	return 1;
}

#define HTTP_METHOD2 "POST"
#define HTTP_URL2 "http://api.gadu-gadu.pl/access_token"
static int oauth_access(void)
{
	char *auth, *reply;
	printf("\n\033[1m/access_token\033[0m\n\n");

	if (!(auth = gg_oauth_generate_header(HTTP_METHOD2, HTTP_URL2,
		config_uin, config_password, token, token_secret)))
	{
		return 0;
	}

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

static int oauth_init(void)
{
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

static void oauth_ask(const char *uid)
{
	char *auth;
	char *reply;
	char *tmp;

	tmp = gg_urlencode_printf(HTTP_URL3_BASE "%s.xml", uid);

	printf("\n\033[1m%s\033[0m\n\n", tmp);

	auth = gg_oauth_generate_header(HTTP_METHOD3, tmp, config_uin, config_password, token, token_secret);

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

#ifdef _WIN32
	gg_win32_init_network();
#endif

	http_init();

	if (argc < 2) {
		printf("usage: %s <uid1> [uid2] [uid3] [uid4] ....\n", argv[0]);
		return 1;
	}

	if (config_read() == -1) {
		perror("config");
		exit(1);
	}

	if (!oauth_init()) {
		free(token);
		free(token_secret);
		config_free();
		return 1;
	}

	for (i = 1; i < argc; i++)	/* mozeby wypadalo sprawdzac przez strtol() czy to faktycznie jest int? */
		oauth_ask(argv[i]);

	config_free();
	free(token);
	free(token_secret);
	return 0;
}
