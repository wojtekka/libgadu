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
	struct gg_session *sess;
	struct gg_event *e;
	struct gg_login_params p;

	if (argc < 5) {
		fprintf(stderr, "użycie: %s <mójnumerek> <mojehasło> <numerek> <wiadomość>\n", argv[0]);
		return 1;
	}

	gg_debug_level = 255;

	memset(&p, 0, sizeof(p));
	p.uin = atoi(argv[2]);
	p.password = argv[1];
	
	if (!(sess = gg_login(&p))) {
		printf("Nie udało się połączyć: %s\n", strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	printf("Połączono.\n");

	if (gg_notify(sess, NULL, 0) == -1) {	/* serwery gg nie pozwalaja wysylac wiadomosci bez powiadomienia o userliscie (przetestowane p.protocol_version [0x15; def] */
		printf("Połączenie przerwane: %s\n", strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	if (gg_send_message(sess, GG_CLASS_MSG, atoi(argv[3]), (unsigned char*) argv[4]) == -1) {
		printf("Połączenie przerwane: %s\n", strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	/* poniższą część można olać, ale poczekajmy na potwierdzenie */

	while (0) {
		if (!(e = gg_watch_fd(sess))) {
			printf("Połączenie przerwane: %s\n", strerror(errno));
			gg_logoff(sess);
			gg_free_session(sess);
			return 1;
		}

		if (e->type == GG_EVENT_ACK) {
			printf("Wysłano.\n");
			gg_free_event(e);
			break;
		}

		gg_free_event(e);
	}

	gg_logoff(sess);
	gg_free_session(sess);

	return 0;
}
