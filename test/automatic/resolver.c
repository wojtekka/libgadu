/*
 *  (C) Copyright 2001-2006 Wojtek Kaniewski <wojtekka@irc.pl>
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

#include <arpa/inet.h>
#include <errno.h>
#include "libgadu.h"
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOCALHOST "127.0.0.1"

int delay_flag;
int connect_flag;

struct hostent *gethostbyname(const char *name)
{
	static struct hostent he;
	static struct in_addr addr;
	static char *addr_list[2];
	static char sname[128];

#if 0
	printf("gethostbyname(\"%s\")\n", name);
#endif

	addr_list[0] = (char*) &addr;
	addr_list[1] = NULL;
	addr.s_addr = inet_addr(LOCALHOST);

	strncpy(sname, name, sizeof(sname) - 1);
	sname[sizeof(sname) - 1] = 0;

	memset(&he, 0, sizeof(he));
	he.h_name = sname;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(struct in_addr);
	he.h_addr_list = addr_list;

	if (delay_flag)
		sleep(2);

	return &he;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf,
	size_t buflen, struct hostent **result, int *h_errnop)
{
	struct hostent *tmp;

	if (buflen < sizeof(struct hostent)) {
		errno = ERANGE;
		*result = NULL;
		return -1;
	}

	tmp = gethostbyname(name);

	if (tmp != NULL) {
		*h_errnop = 0;
		memcpy(ret, tmp, sizeof(struct hostent));
		*result = ret;
	} else {
		*h_errnop = h_errno;
		*result = NULL;
	}

	return (*result != NULL) ? 0 : -1;
}

int connect(int fd, const struct sockaddr *sa, socklen_t sa_len)
{
	connect_flag = 1;
	return 0;
}

static int test(int resolver, int delay)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	int loops = 0;

	delay_flag = delay;
	connect_flag = 0;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "";
	glp.resolver = resolver;
	glp.async = 1;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (!delay_flag) {
		for (loops = 0; loops < 5; loops++) {
			struct gg_event *ge;
			struct timeval tv;
			fd_set fds;

			FD_ZERO(&fds);
			FD_SET(gs->fd, &fds);

			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if (select(gs->fd + 1, &fds, NULL, NULL, &tv) == -1) {
				if (errno == EAGAIN)
					continue;

				gg_free_session(gs);

				return 0;
			}

			ge = gg_watch_fd(gs);

			if (ge == NULL) {
				gg_free_session(gs);
				return 0;
			} else {
				if (ge->type == GG_EVENT_CONN_FAILED) {
					gg_event_free(ge);
					gg_free_session(gs);
					return 0;
				}

				gg_event_free(ge);
			}

			if (connect_flag == 1)
				break;
		}
	} else {
		sleep(1);
	}

	gg_free_session(gs);

	if (loops == 5)
		return 0;

	return 1;
}

static int dummy_start(int *fd, void **private_data, const char *hostname)
{
	fprintf(stderr, "** custom resolver started\n");
	return 0;
}

static void dummy_cleanup(void **private_data, int force)
{
	fprintf(stderr, "** custom resolver cleaning up\n");
}

static int test_set_get(void)
{
	struct gg_session *gs;
	struct gg_http *gh;
	struct gg_login_params glp;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "";
	glp.resolver = 0;
	glp.async = 1;

	/* Test globalnych ustawień */

	if (gg_global_get_resolver() != GG_RESOLVER_DEFAULT) {
		printf("Expected global default resolver #1\n");
		return 0;
	}

	printf("Setting global fork resolver\n");
	gg_global_set_resolver(GG_RESOLVER_FORK);

	if (gg_global_get_resolver() != GG_RESOLVER_FORK) {
		printf("Expected global fork resolver\n");
		return 0;
	}

	printf("Setting global pthread resolver\n");
	gg_global_set_resolver(GG_RESOLVER_PTHREAD);

	if (gg_global_get_resolver() != GG_RESOLVER_PTHREAD) {
		printf("Expected global thread resolver\n");
		return 0;
	}

	printf("Setting global custom resolver\n");
	gg_global_set_custom_resolver(dummy_start, dummy_cleanup);

	if (gg_global_get_resolver() != GG_RESOLVER_CUSTOM) {
		printf("Expected global custom resolver\n");
		return 0;
	}

	printf("Setting global default resolver\n");
	gg_global_set_resolver(GG_RESOLVER_DEFAULT);

	if (gg_global_get_resolver() != GG_RESOLVER_DEFAULT) {
		printf("Expected global default resolver #2\n");
		return 0;
	}

	/* Test lokalnych ustawień -- domyślny */

	printf("Testing local default resolver\n");

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_FORK && gg_session_get_resolver(gs) != GG_RESOLVER_PTHREAD) {
		printf("Expected local fork or pthread resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Testy globalnego default + lokalne */

	printf("Testing global default fork\n");

	gg_global_set_resolver(GG_RESOLVER_DEFAULT);

	/* Test lokalnych ustawień -- fork */

	printf("Testing local fork resolver\n");

	glp.resolver = GG_RESOLVER_FORK;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_FORK) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test lokalnych ustawień -- pthread */

	printf("Testing local pthread resolver\n");

	glp.resolver = GG_RESOLVER_PTHREAD;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_PTHREAD) {
		printf("Expected local pthread resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Testy globalnego fork + lokalne */

	printf("Setting global fork resolver\n");
	gg_global_set_resolver(GG_RESOLVER_FORK);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local default resolver\n");

	glp.resolver = GG_RESOLVER_DEFAULT;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_FORK) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local fork resolver\n");

	glp.resolver = GG_RESOLVER_FORK;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_FORK) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local pthread resolver\n");

	glp.resolver = GG_RESOLVER_PTHREAD;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_PTHREAD) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Testy globalnego pthread + lokalne */

	printf("Setting global pthread resolver\n");
	gg_global_set_resolver(GG_RESOLVER_PTHREAD);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local default resolver\n");

	glp.resolver = GG_RESOLVER_DEFAULT;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_PTHREAD) {
		printf("Expected local pthread resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local fork resolver\n");

	glp.resolver = GG_RESOLVER_FORK;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_FORK) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local pthread resolver\n");

	glp.resolver = GG_RESOLVER_PTHREAD;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_PTHREAD) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Testy globalnego custom + lokalne */

	printf("Setting global custom resolver\n");
	gg_global_set_custom_resolver(dummy_start, dummy_cleanup);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local default resolver\n");

	glp.resolver = GG_RESOLVER_DEFAULT;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_CUSTOM) {
		printf("Expected local custom resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local fork resolver\n");

	glp.resolver = GG_RESOLVER_FORK;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_FORK) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test globalnych ustawień + lokalne */

	printf("Testing local pthread resolver\n");

	glp.resolver = GG_RESOLVER_PTHREAD;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (gg_session_get_resolver(gs) != GG_RESOLVER_PTHREAD) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_free_session(gs);

	/* Test HTTP */

	printf("Testing global default resolver in HTTP\n");
	gg_global_set_resolver(GG_RESOLVER_DEFAULT);

	gh = gg_http_connect("test", 80, 1, "GET", "/test", "");

	if (gh == NULL)
		return 0;

	if (gg_http_get_resolver(gh) != GG_RESOLVER_FORK && gg_http_get_resolver(gh) != GG_RESOLVER_PTHREAD) {
		printf("Expected local fork or pthread resolver\n");
		return 0;
	}

	gg_http_free(gh);

	/* Test HTTP */

	printf("Testing global fork resolver in HTTP\n");
	gg_global_set_resolver(GG_RESOLVER_FORK);

	gh = gg_http_connect("test", 80, 1, "GET", "/test", "");

	if (gh == NULL)
		return 0;

	if (gg_http_get_resolver(gh) != GG_RESOLVER_FORK) {
		printf("Expected local fork resolver\n");
		return 0;
	}

	gg_http_free(gh);

	/* Test HTTP */

	printf("Testing global pthread resolver in HTTP\n");
	gg_global_set_resolver(GG_RESOLVER_PTHREAD);

	gh = gg_http_connect("test", 80, 1, "GET", "/test", "");

	if (gh == NULL)
		return 0;

	if (gg_http_get_resolver(gh) != GG_RESOLVER_PTHREAD) {
		printf("Expected local pthread resolver\n");
		return 0;
	}

	gg_http_free(gh);

	/* Test HTTP */

	printf("Testing global custom resolver in HTTP\n");
	gg_global_set_custom_resolver(dummy_start, dummy_cleanup);

	gh = gg_http_connect("test", 80, 1, "GET", "/test", "");

	if (gh == NULL)
		return 0;

	if (gg_http_get_resolver(gh) != GG_RESOLVER_CUSTOM) {
		printf("Expected local custom resolver\n");
		return 0;
	}

	gg_http_free(gh);

	/* Czyścimy po sobie */

	gg_global_set_resolver(GG_RESOLVER_DEFAULT);

	return 1;
}

int main(int argc, char **argv)
{
	int i, j, k = 1;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	gg_debug_level = 255;

	printf("*** TEST %d ***\n\n", k++);
	if (!test_set_get()) {
		printf("*** TEST FAILED ***\n");
		exit(1);
	}
	printf("\n");

	for (i = GG_RESOLVER_DEFAULT; i <= GG_RESOLVER_PTHREAD; i++) {
		for (j = 0; j < 2; j++) {
			printf("*** TEST %d ***\n\n", k++);

			if (!test(i, j)) {
				printf("*** TEST FAILED ***\n");
				exit(1);
			}

			printf("\n");
		}
	}

	return 0;
}
