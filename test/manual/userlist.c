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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>

#include "libgadu.h"
#include "network.h"
#include "userconfig.h"

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [OPTIONS]\n"
	"\n"
	"Options:\n"
	"  -c            Check userlist version\n"
	"  -p            Put userlist content from stdin to server\n"
	"  -g            Get userlist content from server to stdout\n"
	"  -r            Remove userlist content from server\n"
	"  -v VERSION    Set userlist version for -p, -r or -g\n"
	"  -f FORMAT     Set userlist format (7.0, 10.0 or numeric value)\n"
	"  -d            Print debug messages\n"
	"\n"
	"Note: Put and remove operations require correct userlist version.\n"
	"\n", argv0);
}

int main(int argc, char **argv)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	int opt;
	int format = GG_USERLIST100_FORMAT_TYPE_GG100;
	int version = 0;
	enum { MODE_NONE, MODE_VERSION, MODE_GET, MODE_PUT, MODE_REMOVE } mode = MODE_NONE;
	int type = GG_USERLIST100_GET;
	char *content = NULL;
	int debug = 0;
	int res = 0;

#ifdef _WIN32
	gg_win32_init_network();
#endif

	while ((opt = getopt(argc, argv, "cv:gpf:hdr")) != -1) {
		switch (opt) {
			case 'v':
				version = atoi(optarg);
				break;

			case 'c':
				mode = MODE_VERSION;
				type = GG_USERLIST100_GET;
				break;

			case 'g':
				mode = MODE_GET;
				type = GG_USERLIST100_GET;
				break;

			case 'p':
				mode = MODE_PUT;
				type = GG_USERLIST100_PUT;
				break;

			case 'r':
				mode = MODE_REMOVE;
				type = GG_USERLIST100_PUT;
				free(content);
				content = strdup(" ");
				break;

			case 'f':
				if (strcmp(optarg, "7.0") == 0)
					format = GG_USERLIST100_FORMAT_TYPE_GG70;
				else if (strcmp(optarg, "10.0") == 0)
					format = GG_USERLIST100_FORMAT_TYPE_GG100;
				else
					format = atoi(optarg);
				break;

			case 'd':
				debug = 1;
				break;

			case 'h':
				usage(argv[0]);
				exit(0);
		}
	}

	if (mode == MODE_NONE) {
		usage(argv[0]);
		exit(1);
	}

	if (config_read() == -1) {
		perror("config");
		exit(1);
	}

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	if (debug) {
		gg_debug_file = stderr;
		gg_debug_level = ~0;
	}

	memset(&glp, 0, sizeof(glp));
	glp.uin = config_uin;
	glp.password = config_password;

	gs = gg_login(&glp);

	if (gs == NULL) {
		perror("gg_login");
		exit(1);
	}

	if (mode == MODE_PUT) {
		char buf[1024];

		while (fgets(buf, sizeof(buf), stdin)) {
			char *tmp;
			size_t len;

			len = (content == NULL) ? 0 : strlen(content);

			tmp = realloc(content, len + strlen(buf) + 1);

			if (tmp == NULL) {
				perror("realloc");
				free(content);
				gg_free_session(gs);
				exit(1);
			}

			content = tmp;
			strcpy(content + len, buf);
		}
	}

	gg_notify(gs, NULL, 0);

	if (gg_userlist100_request(gs, type, version, format, content) == -1) {
		perror("gg_userlist100_request");
		gg_free_session(gs);
		free(content);
		exit(1);
	}

	for (;;) {
		struct gg_event *ge;

		ge = gg_watch_fd(gs);

		if (ge == NULL) {
			perror("gg_watch_fd");
			free(content);
			gg_free_session(gs);
			exit(1);
		}

		if (ge->type == GG_EVENT_USERLIST100_REPLY) {
			switch (ge->event.userlist100_reply.type) {
				case GG_USERLIST100_REPLY_REJECT:
					fprintf(stderr, "Rejected\n");
					res = 1;
					break;
				case GG_USERLIST100_REPLY_LIST:
					if (mode == MODE_VERSION)
						printf("%d\n", ge->event.userlist100_reply.version);
					else
						printf("%s", ge->event.userlist100_reply.reply);
					break;
				case GG_USERLIST100_REPLY_UPTODATE:
				case GG_USERLIST100_REPLY_ACK:
					res = 0;
					break;
			}

			gg_event_free(ge);

			break;
		}

		gg_event_free(ge);
	}

	gg_logoff(gs);
	free(content);
	gg_free_session(gs);
	config_free();

	return res;
}
