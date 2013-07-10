/* $Id: remind.c 299 2002-02-06 21:40:00Z wojtekka $ */

#include <stdio.h>
#include <stdlib.h>
#include "libgadu.h"

#ifdef ASYNC

#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <sys/select.h>
#  include <sys/wait.h>
#endif
#include <signal.h>
#include <errno.h>

#ifndef _WIN32
static void sigchld(int sig)
{
	wait(NULL);
	signal(SIGCHLD, sigchld);
}
#endif

#endif

int main(int argc, char **argv)
{
	struct gg_http *h;
	struct gg_pubdir *p;
	uin_t uin;
	const char *email;
	const char *tokenid;
	const char *tokenval;

	if (argc < 5) {
		printf("Użycie: %s <uin> <e-mail> <id-tokenu> <wartość-tokenu>\n", argv[0]);
		return 1;
	}

	uin = atoi(argv[1]);
	email = argv[2];
	tokenid = argv[3];
	tokenval = argv[4];

	gg_debug_level = 255;

#ifndef ASYNC
	if (!(h = gg_remind_passwd3(uin, email, tokenid, tokenval, 0))) {
		printf("Błąd przypominania hasła.\n");
		return 1;
	}
#else

#ifndef _WIN32
	signal(SIGCHLD, sigchld);
#endif

	if (!(h = gg_remind_passwd3(uin, email, tokenid, tokenval, 1)))
		return 1;

        while (1) {
                fd_set rd, wr, ex;

                FD_ZERO(&rd);
                FD_ZERO(&wr);
                FD_ZERO(&ex);

                if ((h->check & GG_CHECK_READ))
                        FD_SET(h->fd, &rd);
                if ((h->check & GG_CHECK_WRITE))
                        FD_SET(h->fd, &wr);
                FD_SET(h->fd, &ex);

                if (select(h->fd + 1, &rd, &wr, &ex, NULL) == -1 || FD_ISSET(h->fd, &ex)) {
			if (errno == EINTR)
				continue;
			gg_free_remind_passwd(h);
			perror("select");
			return 1;
		}

                if (FD_ISSET(h->fd, &rd) || FD_ISSET(h->fd, &wr)) {
			if (gg_remind_passwd_watch_fd(h) == -1) {
				gg_free_remind_passwd(h);
				fprintf(stderr, "Błąd połączenia.\n");
				return 1;
			}
			if (h->state == GG_STATE_ERROR) {
				gg_free_remind_passwd(h);
				fprintf(stderr, "Błąd przypominania hasła.\n");
				return 1;
			}
			if (h->state == GG_STATE_DONE)
				break;
		}
        }
#endif

	p = h->data;
	printf("success=%d\n", p->success);
	gg_free_remind_passwd(h);

	return 0;
}

