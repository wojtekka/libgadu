/*
 *  (C) Copyright 2001-2006 Wojtek Kaniewski <wojtekka@irc.pl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License Version
 *  2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

/*
 * przykład prostego programu łączącego się z serwerem i zmieniającego opis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libgadu.h"
#include "network.h"

int main(int argc, char **argv)
{
	struct gg_session *gs;
	struct gg_login_params glp;

	if (argc < 4) {
		fprintf(stderr, "użycie: %s <mójnumerek> <mojehasło> <opis>\n", argv[0]);
		return 1;
	}

#ifdef _WIN32
	gg_win32_init_network();
#endif

	gg_debug_level = 255;

	memset(&glp, 0, sizeof(glp));
	glp.uin = atoi(argv[1]);
	glp.password = argv[2];
#if 0
	glp.encoding = GG_ENCODING_UTF8;
	glp.protocol_version = GG_PROTOCOL_VERSION_110;
#endif
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
