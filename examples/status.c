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
	struct gg_login_params glp;

	if (argc < 4) {
		fprintf(stderr, "użycie: %s <mójnumerek> <mojehasło> <opis>\n", argv[0]);
		return 1;
	}

	gg_debug_level = 255;

	memset(&glp, 0, sizeof(glp));
	glp.uin = atoi(argv[1]);
	glp.password = argv[2];
//	glp.encoding = GG_ENCODING_UTF8;
//	glp.protocol_version = 0x2d;
	glp.status = GG_STATUS_INVISIBLE_DESCR;
	glp.status_descr = argv[3];
	
	if (!(gs = gg_login(&glp))) {
		printf("Nie udało się połączyć: %s\n", strerror(errno));
		gg_free_session(gs);
		return 1;
	}

	gg_notify(gs, NULL, 0);

	printf("Połączono.\n");

	if (gg_change_status_descr(gs, GG_STATUS_NOT_AVAIL_DESCR, argv[3]) == -1) {
		printf("Połączenie przerwane: %s\n", strerror(errno));
		gg_free_session(gs);
		return 1;
	}

	gg_logoff(gs);
	gg_free_session(gs);

	return 0;
}
