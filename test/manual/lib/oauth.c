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

#include "oauth.h"

#include "hmac.h"
#include "urlencode.h"
#include "base64.h"
#include "oauth_parameter.h"
#include "fileio.h"
#include "internal.h"

#ifdef _WIN32
#include <windows.h>
#endif

char *gg_oauth_static_nonce;		/* dla unit testów */
char *gg_oauth_static_timestamp;	/* dla unit testów */

/* copy-paste from common.c */
#define gg_debug(...)
static int gg_rand(void *buff, size_t len)
{
#ifdef _WIN32
	HCRYPTPROV hProvider = 0;
	int res = 0;

	if (!CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		gg_debug(GG_DEBUG_MISC | GG_DEBUG_ERROR, "// gg_rand() "
			"couldn't acquire crypto context\n");
		return -1;
	}

	if (!CryptGenRandom(hProvider, len, buff)) {
		gg_debug(GG_DEBUG_MISC | GG_DEBUG_ERROR, "// gg_rand() "
			"couldn't fill random buffer\n");
		res = -1;
	}

	CryptReleaseContext(hProvider, 0);

	return res;
#else
	uint8_t *buff_b = buff;

	int fd = open("/dev/random", O_RDONLY);
	if (fd < 0)
		fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		gg_debug(GG_DEBUG_MISC | GG_DEBUG_ERROR, "// gg_rand() "
			"couldn't open random device\n");
		return -1;
	}

	while (len > 0) {
		/* TODO: handle EINTR */
		ssize_t got_data = read(fd, buff_b, len);
		if (got_data < 0) {
			gg_debug(GG_DEBUG_MISC | GG_DEBUG_ERROR, "// gg_rand() "
				"couldn't read from random device\n");
			close(fd);
			return -1;
		}

		buff_b += got_data;
		len -= got_data;
	}

	close(fd);

	return 0;
#endif
}
#undef gg_debug

static int uniform_rand_10(void)
{
	uint8_t rval;

	do {
		if (gg_rand(&rval, sizeof(rval)) != 0)
			exit(-1);
	} while (rval >= 250);

	return (rval % 10);
}

static void gg_oauth_generate_nonce(char *buf, int len)
{
	const char charset[] = "0123456789";

	if (buf == NULL || len < 1)
		return;

	while (len > 1) {
		GG_STATIC_ASSERT(sizeof(charset) - 1 == 10,
			uniform_rand_10_can_only_randomize_10_element_array);
		*buf++ = charset[uniform_rand_10()];
		len--;
	}

	*buf = 0;
}

static char *gg_oauth_generate_signature(const char *method, const char *url,
	const char *request, const char *consumer_secret,
	const char *token_secret)
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

	res = gg_base64_encode2((const char*) digest, 20);

	printf("signature = '%s'\n", res);

	return res;
}

char *gg_oauth_generate_header(const char *method, const char *url,
	const char *consumer_key, const char *consumer_secret,
	const char *token, const char *token_secret)
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
