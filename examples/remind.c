/* $Id: remind.c 299 2002-02-06 21:40:00Z wojtekka $ */

#include <stdio.h>
#include "libgadu.h"

#ifdef ASYNC

#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

void sigchld()
{
	wait(NULL);
	signal(SIGCHLD, sigchld);
}

#endif

int main()
{
	struct gg_http *h;
	struct gg_pubdir *p;
	uin_t uin;

	gg_debug_level = 255;
	
	printf("uin: ");
	scanf("%d", &uin);

#ifndef ASYNC

	if (!(h = gg_remind_passwd(uin, 0))) {
		printf("błąd\n");
		return 1;
	}
	p = h->data;
	printf("success=%d\n", p->success);
	gg_free_remind_passwd(h);

#else

	signal(SIGCHLD, sigchld);

	if (!(h = gg_remind_passwd(uin, 1)))
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
				fprintf(stderr, "no błąd jak błąd\n");
				return 1;
			}
			if (h->state == GG_STATE_ERROR) {
				gg_free_remind_passwd(h);
				fprintf(stderr, "jakiśtam błąd\n");
				return 1;
			}
			if (h->state == GG_STATE_DONE) {
				p = h->data;
				printf("success=%d\n", p->success);
				gg_free_remind_passwd(h);
				break;
			}
		}
        }

#endif

	return 0;
}

