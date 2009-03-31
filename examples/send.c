/*
 * przykład prostego programu łączącego się z serwerem i wysyłającego
 * jedną wiadomość.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libgadu.h"

int main(int argc, char **argv)
{
	struct gg_session *gs;

	if (argc < 5) {
		fprintf(stderr, "użycie: %s <mójnumerek> <mojehasło> <numerek> <wiadomość>\n", argv[0]);
		return 1;
	}

	gg_debug_level = 255;

	gs = gg_session_new();

	if (gs == NULL) {
		perror("gg_session_new");
		gg_session_free(gs);
		return 1;
	}

	gg_session_set_uin(gs, atoi(argv[2]));
	gg_session_set_password(gs, argv[1]);
	
	if (gg_session_connect(gs) == -1) {
		perror("gg_session_connect");
		gg_session_free(gs);
		return 1;
	}

	if (gg_notify(gs, NULL, 0) == -1) {
		perror("gg_notify");
		gg_session_free(gs);
		return 1;
	}

	if (gg_send_message(gs, GG_CLASS_MSG, atoi(argv[3]), (unsigned char*) argv[4]) == -1) {
		perror("gg_send_message");
		gg_session_free(gs);
		return 1;
	}

	/* poniższą część można olać, ale poczekajmy na potwierdzenie */

	while (0) {
		struct gg_event *ge;

		ge = gg_watch_fd(gs);

		if (ge == NULL) {
			perror("gg_watch_fd");
			gg_session_free(gs);
			return 1;
		}

		if (ge->type == GG_EVENT_ACK) {
			printf("Wysłano.\n");
			gg_event_free(ge);
			break;
		}

		gg_event_free(ge);
	}

	gg_session_disconnect(gs, 0);

	gg_session_free(gs);

	return 0;
}
