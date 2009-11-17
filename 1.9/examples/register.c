/* $Id: register.c 299 2002-02-06 21:40:00Z wojtekka $ */

#include <stdio.h>
#include <string.h>
#include "libgadu.h"

#ifdef ASYNC

#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

void sigchld(int sig)
{
	wait(NULL);
	signal(SIGCHLD, sigchld);
}

#endif

int main(int argc, char **argv)
{
	struct gg_http *h;
	struct gg_pubdir *p;
	const char *email;
	const char *password;
	const char *tokenid;
	const char *tokenval;

	if (argc < 5) {
		printf("Użycie: %s <e-mail> <hasło> <id-tokenu> <wartość-tokenu>\n", argv[0]);
		return 1;
	}

	email = argv[1];
	password = argv[2];
	tokenid = argv[3];
	tokenval = argv[4];

	gg_debug_level = 255;
	
#ifndef ASYNC
	if (!(h = gg_register3(email, password, tokenid, tokenval, 0))) {
		printf("Błąd rejestracji.\n");
		return 1;
	}

#else

	signal(SIGCHLD, sigchld);

	if (!(h = gg_register3(email, password, tokenid, tokenval, 1)))
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
			gg_free_register(h);
			perror("select");
			return 1;
		}

                if (FD_ISSET(h->fd, &rd) || FD_ISSET(h->fd, &wr)) {
			if (gg_register_watch_fd(h) == -1) {
				gg_free_register(h);
				fprintf(stderr, "Błąd połączenia.\n");
				return 1;
			}
			if (h->state == GG_STATE_ERROR) {
				gg_free_register(h);
				fprintf(stderr, "Błąd rejestracji.\n");
				return 1;
			}
			if (h->state == GG_STATE_DONE)
				break;
		}
        }
#endif

	p = h->data;
	printf("success=%d\nuin=%d\n", p->success, p->uin);
	gg_free_register(h);

	return 0;
}

