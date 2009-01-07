/* Przykład pamiętania ustawień między połączeniami. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libgadu.h"

int main(int argc, char **argv)
{
	struct gg_session *gs;

	if (argc < 3) {
		fprintf(stderr, "użycie: %s <mójnumerek> <mojehasło>\n", argv[0]);
		return 1;
	}

	gg_debug_level = 255;

	/* Pierwsze połączenie */
	
	gs = gg_session_new();

	if (gs == NULL) {
		perror("gg_session_new");
		gg_session_free(gs);
		return 1;
	}

	gg_session_set_uin(gs, atoi(argv[1]));
	gg_session_set_password(gs, argv[2]);
	gg_session_set_status(gs, GG_STATUS_AVAIL_DESCR, "Jeden", 0);

	printf("\nPróba #1\n--------\n");

	if (gg_session_connect(gs) == -1) {
		perror("gg_session_connect #1");
		gg_session_free(gs);
		return 1;
	}

	gg_notify(gs, NULL, 0);

	printf("Zzzz...\n");
	sleep(3);

	gg_session_disconnect(gs);

	/* Drugie połączenie */

	gg_session_set_status(gs, GG_STATUS_BUSY_DESCR, "Dwa", 0);

	printf("\nPróba #2\n--------\n");

	if (gg_session_connect(gs) == -1) {
		perror("gg_session_connect #2");
		gg_session_free(gs);
		return 1;
	}

	gg_notify(gs, NULL, 0);

	printf("Zzzz...\n");
	sleep(3);

	gg_session_disconnect(gs);

	/* Trzecie połączenie */

	gg_session_set_status(gs, 0, NULL, 0);

	printf("\nPróba #3\n--------\n");

	if (gg_session_connect(gs) == -1) {
		perror("gs_session_connect #3");
		gg_session_free(gs);
		return 1;
	}

	gg_notify(gs, NULL, 0);

	gg_session_set_status(gs, GG_STATUS_AVAIL_DESCR, "Trzy", 0);

	printf("Zzzz...\n");
	sleep(3);

	gg_session_disconnect(gs);

	gg_session_free(gs);

	return 0;
}
