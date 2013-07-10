#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

int main(void)
{
	struct gg_http *h;
	struct gg_token *t;
	char path[] = "token.XXXXXX";
	FILE *f;

	gg_debug_level = 255;
	
#ifndef ASYNC

	if (!(h = gg_token(0))) {
		printf("Błąd pobierania tokenu.\n");
		return 1;
	}

#else

#ifndef _WIN32
	signal(SIGCHLD, sigchld);
#endif

	if (!(h = gg_token(1)))
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
			gg_token_free(h);
			perror("select");
			return 1;
		}

                if (FD_ISSET(h->fd, &rd) || FD_ISSET(h->fd, &wr)) {
			if (gg_token_watch_fd(h) == -1) {
				gg_token_free(h);
				fprintf(stderr, "Błąd połączenia.\n");
				return 1;
			}
			if (h->state == GG_STATE_ERROR) {
				gg_token_free(h);
				fprintf(stderr, "Błąd pobierania tokenu.\n");
				return 1;
			}
			if (h->state == GG_STATE_DONE)
				break;

		}
        }

#endif

	t = h->data;

#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || _XOPEN_SOURCE >= 500
	if (mkstemp(path) == -1) {
#else
	if (strcmp(mktemp(path), "") == 0) {
#endif
		printf("Błąd tworzenia pliku tymczasowego.\n");
		gg_token_free(h);
		return 1;
	}

	f = fopen(path, "w");

	if (f == NULL) {
		printf("Błąd otwierania pliku tymczasowego %s.\n", path);
		gg_token_free(h);
		return 1;
	}

	if (fwrite(h->body, h->body_size, 1, f) != 1) {
		printf("Błąd zapisu do pliku tymczasowego %s.\n", path);
		gg_token_free(h);
		fclose(f);
		unlink(path);
		return 1;
	}

	fclose(f);

	printf("id=%s\nwidth=%d\nheight=%d\nlength=%d\npath=%s\n", t->tokenid, t->width, t->height, t->length, path);

	gg_token_free(h);

	return 0;
}

