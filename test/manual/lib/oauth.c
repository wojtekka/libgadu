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
#include <time.h>

#include "hmac.h"
#include "urlencode.h"
#include "base64.h"
#include "oauth_parameter.h"

char *gg_oauth_static_nonce;		/* dla unit testów */
char *gg_oauth_static_timestamp;	/* dla unit testów */

static void gg_oauth_generate_nonce(char *buf, int len)
{
	const char charset[] = "0123456789";

	if (buf == NULL || len < 1)
		return;

	while (len > 1) {
		*buf++ = charset[(unsigned) (((float) sizeof(charset) - 1.0) * rand() / (RAND_MAX + 1.0))];
		len--;
	}

	*buf = 0;
}

static char *gg_oauth_generate_signature(const char *method, const char *url, const char *request, const char *consumer_secret, const char *token_secret)
{
	char *text, *key, *res;
	unsigned char digest[20];

	if (!(text = gg_urlencode_printf("%s&%s&%s", method, url, request)))
		return NULL;

	if (!(key = gg_urlencode_printf("%s&%s", consumer_secret, token_secret))) {
		free(text);
		return NULL;
	}

	printf("text = '%s'\n", text);
	printf("key = '%s'\n", key);

	gg_hmac_sha1((unsigned char*) text, strlen(text), (unsigned char*) key, strlen(key), digest);

	free(key);
	free(text);

	res = gg_base64_encode((const char*) digest, 20);

	printf("signature = '%s'\n", res);

	return res;
}

char *gg_oauth_generate_header(const char *method, const char *url, const const char *consumer_key, const char *consumer_secret, const char *token, const char *token_secret)
{
	char *request, *signature, *res;
	char nonce[80], timestamp[16];
	gg_oauth_parameter_t *params = NULL;

	if (gg_oauth_static_nonce == NULL)
		gg_oauth_generate_nonce(nonce, sizeof(nonce));
	else {
		strncpy(nonce, gg_oauth_static_nonce, sizeof(nonce) - 1);
		nonce[sizeof(nonce) - 1] = 0;
	}

	if (gg_oauth_static_timestamp == NULL)
		snprintf(timestamp, sizeof(timestamp), "%ld", time(NULL));
	else {
		strncpy(timestamp, gg_oauth_static_timestamp, sizeof(timestamp) - 1);
		timestamp[sizeof(timestamp) - 1] = 0;
	}

	gg_oauth_parameter_set(&params, "oauth_consumer_key", consumer_key);
	gg_oauth_parameter_set(&params, "oauth_nonce", nonce);
	gg_oauth_parameter_set(&params, "oauth_signature_method", "HMAC-SHA1");
	gg_oauth_parameter_set(&params, "oauth_timestamp", timestamp);
	gg_oauth_parameter_set(&params, "oauth_token", token);
	gg_oauth_parameter_set(&params, "oauth_version", "1.0");

	request = gg_oauth_parameter_join(params, 0);

	signature = gg_oauth_generate_signature(method, url, request, consumer_secret, token_secret);

	free(request);

	gg_oauth_parameter_free(params);
	params = NULL;

	if (signature == NULL)
		return NULL;

	gg_oauth_parameter_set(&params, "oauth_version", "1.0");
	gg_oauth_parameter_set(&params, "oauth_nonce", nonce);
	gg_oauth_parameter_set(&params, "oauth_timestamp", timestamp);
	gg_oauth_parameter_set(&params, "oauth_consumer_key", consumer_key);
	gg_oauth_parameter_set(&params, "oauth_token", token);
	gg_oauth_parameter_set(&params, "oauth_signature_method", "HMAC-SHA1");
	gg_oauth_parameter_set(&params, "oauth_signature", signature);

	free(signature);

	res = gg_oauth_parameter_join(params, 1);

	gg_oauth_parameter_free(params);

	return res;
}

