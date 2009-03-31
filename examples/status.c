/*
 * przykład prostego programu łączącego się z serwerem i zmieniającego opis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libgadu.h"

int main(int argc, char **argv)
{
	struct gg_session *gs;

	if (argc < 4) {
		fprintf(stderr, "użycie: %s <mójnumerek> <mojehasło> <opis>\n", argv[0]);
		return 1;
	}

	gg_debug_level = 255;

	gs = gg_session_new();

	if (gs == NULL) {
		perror("gg_session_new");
		gg_session_free(gs);
		return 1;
	}

	gg_session_set_uin(gs, atoi(argv[1]));
	gg_session_set_password(gs, argv[2]);
	gg_session_set_status(gs, GG_STATUS_INVISIBLE_DESCR, argv[3], 0);
	
	if (gg_session_connect(gs) == -1) {
		perror("gg_session_connect");
		gg_session_free(gs);
		return 1;
	}

	gg_notify(gs, NULL, 0);

	printf("Połączono. Naciśnij Enter...\n");

	getchar();

	gg_session_disconnect(gs, 1);

	gg_session_free(gs);

	return 0;
}
