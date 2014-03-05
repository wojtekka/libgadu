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
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

#include "libgadu.h"
#include "network.h"
#include "internal.h"
#include "userconfig.h"

int test_mode;
int connected;

enum {
	TEST_MODE_SEND = 0,
	TEST_MODE_SEND_NAT,
	TEST_MODE_RECEIVE,
	TEST_MODE_RECEIVE_NAT,
	TEST_MODE_RECEIVE_RESUME,
	TEST_MODE_LAST
};

static void debug(const char *msg, ...) GG_GNUC_PRINTF(1, 2);
static void debug(const char *msg, ...)
{
	va_list ap;

	fprintf(stderr, "\033[1m");

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, "\033[0m");
	fflush(stderr);
}

#undef connect
#ifdef _WIN32
static gg_win32_hook_data_t connect_hook;

static int my_connect(SOCKET socket, const struct sockaddr *address, int address_len)
#else
extern int __connect(int socket, const struct sockaddr *address, socklen_t address_len);

int connect(int socket, const struct sockaddr *address, socklen_t address_len)
#endif
{
	struct sockaddr_in sin;
#ifdef _WIN32
	int ret;
#endif

	if (connected && test_mode == TEST_MODE_SEND_NAT) {
		memcpy(&sin, address, address_len);
		sin.sin_addr.s_addr = INADDR_NONE;
		address = (struct sockaddr*) &sin;
	}

#ifdef _WIN32
	gg_win32_hook_set_enabled(&connect_hook, 0);
	ret = connect(socket, address, address_len);
	gg_win32_hook_set_enabled(&connect_hook, 1);

	return ret;
#else
	return __connect(socket, address, address_len);
#endif
}

int main(int argc, char **argv)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	struct gg_dcc7 *gd = NULL;
	time_t ping = 0, last = 0;
	int fds[2] = { -1, -1 };

	if (argc != 2 || atoi(argv[1]) >= TEST_MODE_LAST) {
		fprintf(stderr, "usage: %s <mode>\n"
				"\n"
				"mode: 0 - send file\n"
				"      1 - send file, simulate NAT\n"
				"      2 - receive file\n"
				"      3 - receive file, simulate NAT\n"
				"      4 - receive file, resume at the end\n"
				"\n", argv[0]);
		exit(1);
	}

	test_mode = atoi(argv[1]);

	if (config_read() == -1 || config_peer == 0) {
		perror("config");
		exit(1);
	}

#ifdef _WIN32
	gg_win32_init_network();
	gg_win32_hook(connect, my_connect, &connect_hook);
#else
	signal(SIGPIPE, SIG_IGN);
#endif
	gg_debug_file = stdout;
	gg_debug_level = ~0;

	if (!config_file && socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) == -1) {
		perror("pipe");
		exit(1);
	}

	memset(&glp, 0, sizeof(glp));
	glp.uin = config_uin;
	glp.password = config_password;
	glp.async = 1;
	glp.client_addr = config_ip;
	glp.client_port = config_port;
	glp.protocol_version = GG_PROTOCOL_VERSION_100;

	if (config_dir && (test_mode == TEST_MODE_RECEIVE ||
		test_mode == TEST_MODE_RECEIVE_NAT ||
		test_mode == TEST_MODE_RECEIVE_RESUME))
	{
		if (chdir(config_dir) == -1) {
			perror("chdir");
			exit(1);
		}
	}

	debug("Connecting...\n");

	if (!(gs = gg_login(&glp))) {
		perror("gg_login");
		exit(1);
	}

	for (;;) {
		fd_set rds, wds;
		struct timeval tv;
		time_t now;
		int res, maxfd = -1;

		FD_ZERO(&rds);
		FD_ZERO(&wds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		maxfd = gs->fd;

		if ((gs->check & GG_CHECK_READ))
			FD_SET(gs->fd, &rds);

		if ((gs->check & GG_CHECK_WRITE))
			FD_SET(gs->fd, &wds);

		if (gd && gd->fd != -1) {
			if (gd->fd > maxfd)
				maxfd = gd->fd;

			if ((gd->check & GG_CHECK_READ))
				FD_SET(gd->fd, &rds);

			if ((gd->check & GG_CHECK_WRITE))
				FD_SET(gd->fd, &wds);
		}

		if (fds[1] != -1) {
			if (fds[1] > maxfd)
				maxfd = fds[1];

			FD_SET(fds[1], &wds);
		}

		if ((res = select(maxfd + 1, &rds, &wds, NULL, &tv)) == -1) {
			if (errno == EINTR)
				continue;

			perror("select");
			exit(1);
		}

		now = time(NULL);

		if (last != now) {
			if (gs->timeout != -1 && gs->timeout-- == 0 && !gs->soft_timeout) {
				debug("Timeout\n");
				exit(1);
			}

			if (gd && gd->timeout != -1 && gd->timeout-- == 0 && !gd->soft_timeout) {
				debug("Timeout\n");
				exit(1);
			}

			last = now;
		}

		if (gs->state == GG_STATE_CONNECTED && ping && now - ping > 60) {
			ping = now;
			gg_ping(gs);
		}

		if (FD_ISSET(gs->fd, &rds) || FD_ISSET(gs->fd, &wds) || (gs->timeout == 0 && gs->soft_timeout)) {
			struct gg_event *ge;
			uin_t uin;
			int status;

			if (!(ge = gg_watch_fd(gs))) {
				debug("Connection broken\n");
				exit(1);
			}

			switch (ge->type) {
				case GG_EVENT_CONN_SUCCESS:
					debug("Connected\n");
					connected = 1;
					gg_notify(gs, &config_peer, 1);

					if (test_mode == TEST_MODE_RECEIVE_NAT)
						gs->client_addr = INADDR_NONE;

					ping = time(NULL);

					break;

				case GG_EVENT_CONN_FAILED:
					debug("Connection failed\n");
					exit(1);

				case GG_EVENT_MSG:
					debug("Message from %d: %s\n", ge->event.msg.sender, ge->event.msg.message);
					break;

				case GG_EVENT_DISCONNECT:
					debug("Forced to disconnect\n");
					exit(1);

				case GG_EVENT_USER_DATA:
					debug("User data\n");
					break;

				case GG_EVENT_NOTIFY60:
					uin = ge->event.notify60[0].uin;
					status = ge->event.notify60[0].status;
					/* fall-through */

				case GG_EVENT_STATUS60:
					if (ge->type == GG_EVENT_STATUS60) {
						uin = ge->event.status60.uin;
						status = ge->event.status60.status;
					}

					if (uin == config_peer &&
						(GG_S_A(status) || GG_S_B(status)) &&
						(test_mode == TEST_MODE_SEND || test_mode == TEST_MODE_SEND_NAT))
					{
						debug("Sending file...\n");

						if (config_file) {
							gd = gg_dcc7_send_file(gs, config_peer,
								config_file, NULL, NULL);
						} else {
							gd = gg_dcc7_send_file_fd(gs, config_peer, fds[0],
								config_size, "test.bin", "DummySHA1HashOfAAAAA");
						}

						if (!gd) {
							perror("gg_dcc7_send_file");
							exit(1);
						}
					}

					break;

				case GG_EVENT_DCC7_NEW:
					debug("Incoming direct connection\n");

					if (test_mode == TEST_MODE_RECEIVE ||
						test_mode == TEST_MODE_RECEIVE_NAT ||
						test_mode == TEST_MODE_RECEIVE_RESUME)
					{
						gd = ge->event.dcc7_new;
						if (config_dir) {
							gd->file_fd = open((char*) gd->filename,
								O_WRONLY | O_CREAT, 0600);
#if 0
							lseek(gd->file_fd, gd->size, SEEK_SET);
#endif
						} else
							gd->file_fd = open("/dev/null", O_WRONLY);
						if (gd->file_fd == -1) {
							perror("open");
							exit(1);
						}
						if (test_mode != TEST_MODE_RECEIVE_RESUME)
							gg_dcc7_accept(gd, 0);
						else
							gg_dcc7_accept(gd, gd->size);
					}

					break;

				case GG_EVENT_DCC7_ERROR:
					debug("Direct connection error\n");
					exit(1);

				case GG_EVENT_DCC7_ACCEPT:
					debug("Accepted\n");
					break;

				case GG_EVENT_DCC7_REJECT:
					debug("Rejected\n");
					exit(1);

				case GG_EVENT_DCC7_PENDING:
					debug("Pending\n");
					break;

				case GG_EVENT_NONE:
					break;

				default:
					debug("Unsupported event %d\n", ge->type);
					break;
			}

			gg_event_free(ge);
		}

		if (gd && gd->fd != -1 && (FD_ISSET(gd->fd, &rds) ||
			FD_ISSET(gd->fd, &wds) || (gd->timeout == 0 && gd->soft_timeout)))
		{
			struct gg_event *ge;

			if (!(ge = gg_dcc7_watch_fd(gd))) {
				debug("Direct connection broken\n");
				exit(1);
			}

			switch (ge->type) {
				case GG_EVENT_DCC7_ERROR:
					debug("Direct connection error\n");
					exit(1);

				case GG_EVENT_DCC7_CONNECTED:
					debug("Direct connection established\n");
					break;

				case GG_EVENT_DCC7_DONE:
					debug("Finished");
					gg_event_free(ge);
					gg_dcc7_free(gd);
					gg_free_session(gs);
					config_free();
					exit(1);

				case GG_EVENT_NONE:
					break;

				default:
					debug("Unsupported event %d\n", ge->type);
					break;
			}

			gg_event_free(ge);
		}

		if (fds[1] != -1 && FD_ISSET(fds[1], &wds)) {
			char buf[4096];

			memset(buf, 'A', sizeof(buf));

			if (write(fds[1], buf, sizeof(buf)) < 1) {
				perror("write");
				exit(1);
			}
		}
	}

	return 0;
}
