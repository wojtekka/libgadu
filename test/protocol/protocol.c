#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libgadu.h>

#include "script.h"

#define LOCALHOST "127.0.67.67"
#define LOCALPORT 17219

#define debug(msg...) \
	do { \
		fprintf(stderr, "\033[1m"); \
		fprintf(stderr, msg); \
		fprintf(stderr, "\033[0m"); \
		fflush(stderr); \
	} while(0)

static char outbuf[4096];
static int outbuflen = 0;
static int fd = -1;	/* connected socket */

int buffered_write(char *data, int len)
{

	return 0;
}

int main(int argc, char **argv)
{
	struct gg_login_params glp;
	struct gg_session *gs = NULL;
	int lfd;	/* listening socket */
	int value = 1;
	struct sockaddr_in sin;
	char inbuf[4096];
	int inbuflen = 0;
	int state = 0;
	time_t last = 0;

	signal(SIGPIPE, SIG_IGN);
	gg_debug_file = stdout;
	gg_debug_level = ~0;

	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(LOCALPORT);
	sin.sin_addr.s_addr = inet_addr(LOCALHOST);

	if (bind(lfd, (struct sockaddr*) &sin, sizeof(sin))) {
		perror("bind");
		exit(1);
	}

	if (listen(lfd, 5)) {
		perror("listen");
		exit(1);
	}

	state = 0;
	last = time(NULL);

	for (;;) {
		fd_set rds, wds;
		struct timeval tv;
		int res, maxfd = -1;

		if (script[state].type == ACTION_END) {
			debug("state %d: ending\n", state);
			exit(0);
		}

		if (script[state].type == ACTION_LOGIN) {
			debug("state %d: connecting\n", state);

			if (gs)
				gg_free_session(gs);

			memcpy(&glp, script[state].glp, sizeof(glp));
			glp.server_addr = inet_addr(LOCALHOST);
			glp.server_port = LOCALPORT;
			glp.async = 1;

			if (!(gs = gg_login(&glp))) {
				perror("gg_login");
				exit(1);
			}

			state++;
			last = time(NULL);

			continue;
		}

		if (script[state].type == ACTION_LOGOFF) {
			debug("state %d: disconnecting\n", state);
			gg_free_session(gs);
			gs = NULL;

			state++;
			last = time(NULL);

			continue;
		}

		if (script[state].type == ACTION_SEND) {
			debug("state %d: sending data\n", state);

			if (outbuflen > 0) {
				if (outbuflen + script[state].data_len > sizeof(outbuf)) {
					errno = ENOMEM;
					perror("write");
					exit(1);
				}

				memcpy(outbuf + outbuflen, script[state].data, script[state].data_len);
				outbuflen += script[state].data_len;
			} else {
				int res;

				res = write(fd, script[state].data, script[state].data_len);

				if (res < 0) {
					perror("write");
					exit(1);
				}

				if (outbuflen + script[state].data_len - res > sizeof(outbuf)) {
					errno = ENOMEM;
					perror("write");
					exit(1);
				}

				if (res != script[state].data_len) {
					memcpy(outbuf + outbuflen, script[state].data + res, script[state].data_len - res);
					outbuflen += script[state].data_len - res;
				}
			}

			state++;
			last = time(NULL);

			continue;
		}

		if (script[state].type == ACTION_CALL) {
			debug("state %d: calling function\n", state);

			(script[state].call)(gs);
			state++;
			last = time(NULL);

			continue;
		}

		if (script[state].type == EXPECT_DATA && inbuflen >= 8) {
			int len;

			len = (((unsigned char) inbuf[4]) | ((unsigned char) inbuf[5]) << 8 | ((unsigned char) inbuf[6]) << 16 | ((unsigned char) inbuf[7]) << 24) + 8;

			if (inbuflen >= len) {
				int i;

				if (script[state].data_len != len) {
					debug("state %d: invalid data length %d vs %d\n", state, len, script[state].data_len);
					exit(1);
				}

				for (i = 0; i < script[state].data_len; i++) {
					if (((unsigned char) inbuf[i] & script[state].data_mask[i]) != script[state].data[i]) {
						debug("state %d: received invalid data at %d %d %d\n", state, i, script[state].data[i], inbuf[i]);
						exit(1);
					}
				}

				if (len == inbuflen) {
					inbuflen = 0;
				} else {
					memmove(inbuf, inbuf + len, inbuflen - len);
					inbuflen -= len;
				}

				debug("state %d: received data\n", state);

				state++;
				last = time(NULL);

				continue;
			}
		}

		if (time(NULL) - last >= 5) {
			debug("state %d: timeout\n", state);
			exit(1);
		}

		FD_ZERO(&rds);
		FD_ZERO(&wds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		maxfd = -1;

		FD_SET(lfd, &rds);
		maxfd = lfd;

		if (gs) {
			if (gs->fd > maxfd)
				maxfd = gs->fd;

			if ((gs->check & GG_CHECK_READ))
				FD_SET(gs->fd, &rds);

			if ((gs->check & GG_CHECK_WRITE))
				FD_SET(gs->fd, &wds);
		}

		if (fd != -1) {
			if (fd > maxfd)
				maxfd = fd;
			FD_SET(fd, &rds);
			if (outbuflen > 0)
				FD_SET(fd, &wds);
		}

		if ((res = select(maxfd + 1, &rds, &wds, NULL, &tv)) == -1) {
			if (errno == EINTR)
				continue;

			perror("select");
			exit(1);
		}

		if (FD_ISSET(lfd, &rds)) {
			socklen_t sinlen = sizeof(sin);

			res = accept(lfd, (struct sockaddr*) &sin, &sinlen);

			if (res == -1) {
				perror("accept");
				exit(1);
			}

			if (fd != -1) {
				perror("accept");
				exit(1);
			}

			fd = res;

			if (script[state].type != EXPECT_CONNECT) {
				debug("state %d: unexpected connect\n", state);
				exit(1);
			}

			debug("state %d: connected\n", state);
			state++;
			last = time(NULL);

			continue;
		}

		if (fd != -1 && FD_ISSET(fd, &rds)) {
			res = read(fd, inbuf + inbuflen, sizeof(inbuf) - inbuflen);

			if (res < 1) {
				if (script[state].type != EXPECT_DISCONNECT) {
					debug("state %d: unexpected disconnect\n", state);
					exit(1);
				}

				debug("state %d: disconnected\n", state);
				state++;
				last = time(NULL);
			} else {
				inbuflen += res;
			}

			continue;
		}

		if (fd != -1 && FD_ISSET(fd, &wds)) {
			res = write(fd, outbuf, outbuflen);

			if (res == -1) {
				perror("write");
				exit(1);
			} else if (res == outbuflen) {
				outbuflen = 0;
			} else if (res > 0) {
				memmove(outbuf, outbuf + outbuflen, outbuflen - res);
				outbuflen -= res;
			}
		}

		if (gs && (FD_ISSET(gs->fd, &rds) || FD_ISSET(gs->fd, &wds))) {
			struct gg_event *ge;

			if (res == 0)
				gs->timeout = 0;

			ge = gg_watch_fd(gs);

			if (!ge) {
				perror("gg_watch_fd");
				exit(1);
			}

			if (ge->type != GG_EVENT_NONE || (script[state].type == EXPECT_EVENT && script[state].event == GG_EVENT_NONE)) {
				if (script[state].type != EXPECT_EVENT) {
					debug("state %d: unexpected event %d\n", state, ge->type);
					exit(1);
				}

				if ((script[state].event != 0 && ge->type != script[state].event) || (script[state].check_event && !(script[state].check_event)(ge->type, &ge->event))) {
					debug("state %d: invalid event %d\n", state, ge->type);
					exit(1);
				}

				debug("state %d: received event %d\n", state, ge->type);
				state++;
				last = time(NULL);
				continue;
			}

			gg_event_free(ge);
		}
	}

	return 0;
}
