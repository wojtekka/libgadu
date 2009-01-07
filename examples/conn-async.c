/*
 * Przykładowy program demonstrujący asynchroniczne połączenie z serwerem.
 * Poza połączeniem nie robi nic. Nie przejmuje się błędami.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include "libgadu.h"

int main(int argc, char **argv)
{
	struct gg_session *gs;
	time_t last = 0;

	if (argc < 3) {
		printf("użycie: %s <uin> <hasło>\n", argv[0]);
		return 1;
	}

	gg_debug_level = 255;
	
	gs = gg_session_new();

	if (gs == NULL) {
		perror("gg_session_new");
		return 1;
	}

	gg_session_set_uin(gs, atoi(argv[1]));
	gg_session_set_password(gs, argv[2]);
	gg_session_set_async(gs, 1);

	if (gg_session_connect(gs) == -1) {
		perror("gg_session_connect");
		gg_session_free(gs);
		return 1;
	}

	for (;;) {
		struct timeval tv;
		fd_set rd, wd;
		int ret, fd, check;
		time_t now;

		FD_ZERO(&rd);
		FD_ZERO(&wd);

		fd = gg_session_get_fd(gs);
		check = gg_session_get_check(gs);

		if ((check & GG_CHECK_READ))
			FD_SET(fd, &rd);
		if ((check & GG_CHECK_WRITE))
			FD_SET(fd, &wd);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		
		ret = select(fd + 1, &rd, &wd, NULL, &tv);

		if (ret == -1) {
			perror("select");
			return 1;
		}

		now = time(NULL);

		if (now != last) {
			if (gs->timeout != -1 && gs->timeout-- == 0 && !gs->soft_timeout) {
				printf("Przekroczenie czasu operacji.\n");
				gg_session_free(gs);
				return 1;
			}
		}
	
		if (gs != NULL && (FD_ISSET(fd, &rd) || FD_ISSET(fd, &wd) || (gs->timeout == 0 && gs->soft_timeout))) {
			struct gg_event *ge;

			ge = gg_watch_fd(gs);

			if (ge == NULL) {
				printf("Połączenie zerwane.\n");
				gg_session_free(gs);
				return 1;
			}

			if (ge->type == GG_EVENT_CONN_SUCCESS) {
				printf("Połączono z serwerem.\n");
				gg_event_free(ge);
				break;
			}

			if (ge->type == GG_EVENT_CONN_FAILED) {
				printf("Błąd połączenia.\n");
				gg_event_free(ge);
				gg_session_free(gs);
				return 1;
			}

			gg_event_free(ge);
		}
	}
	
	gg_session_disconnect(gs);
	gg_session_free(gs);

	return 0;
}

