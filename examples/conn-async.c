/*
 * Przykładowy program demonstrujący asynchroniczne połączenie z serwerem.
 * Poza połączeniem nie robi nic. Nie przejmuje się błędami.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#ifdef WIN32
#  include <winsock2.h>
#else
#  include <sys/wait.h>
#  include <sys/time.h>
#  include <sys/socket.h>
#endif
#include <time.h>
#include "libgadu.h"

int main(void)
{
	struct gg_login_params p;
	struct gg_session *sess;
	struct timeval tv;
	struct gg_event *e;
	fd_set rd, wd;
	time_t last = 0, now;
	int ret;

	gg_debug_level = ~0;
	
	memset(&p, 0, sizeof(p));
	p.uin = 123456;
	p.password = "qwerty";
	p.async = 1;
	
	sess = gg_login(&p);

	for (;;) {
		FD_ZERO(&rd);
		FD_ZERO(&wd);

		if ((sess->check & GG_CHECK_READ))
			FD_SET(sess->fd, &rd);
		if ((sess->check & GG_CHECK_WRITE))
			FD_SET(sess->fd, &wd);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		
		ret = select(sess->fd + 1, &rd, &wd, NULL, &tv);

		if (ret == -1) {
			perror("select");
			return 1;
		}

		now = time(NULL);

		if (now != last) {
			if (sess->timeout != -1 && sess->timeout-- == 0 && !sess->soft_timeout) {
				printf("Przekroczenie czasu operacji.\n");
				gg_free_session(sess);
				return 1;
			}
		}
	
		if (sess && (FD_ISSET(sess->fd, &rd) || FD_ISSET(sess->fd, &wd) || (sess->timeout == 0 && sess->soft_timeout))) {
			if (!(e = gg_watch_fd(sess))) {
				printf("Połączenie zerwane.\n");
				gg_free_session(sess);
				return 1;
			}

			if (e->type == GG_EVENT_CONN_SUCCESS) {
				printf("Połączono z serwerem.\n");
				gg_free_event(e);
				gg_logoff(sess);
				gg_free_session(sess);
				return 0;
			}

			if (e->type == GG_EVENT_CONN_FAILED) {
				printf("Błąd połączenia.\n");
				gg_free_event(e);
				gg_logoff(sess);
				gg_free_session(sess);
				return 1;
			}

			gg_free_event(e);
		}
	}
	
	return 1;
}

