/*
 *  (C) Copyright 2011 Wojtek Kaniewski <wojtekka@irc.pl>
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

#include "network.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

/* Code losely based on sockerpair implementation by Nathan C. Meyrs.
 * The original copyright notice follows: */

/* socketpair.c
 * Copyright 2007, 2010 by Nathan C. Myers <ncm@cantrip.org>
 * This code is Free Software. It may be copied freely, in original or
 * modified form, subject only to the restrictions that (1) the author is
 * relieved from all responsibilities for any use for any purpose, and (2)
 * this copyright notice must be retained, unchanged, in its entirety. If
 * for any reason the author might be held responsible for any consequences
 * of copying or use, license is withheld.
 */

int gg_win32_socketpair(int sv[2])
{
	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(sin);
	int server = -1;
	int tmp = 1;

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sv[0] = -1;
	sv[1] = -1;

	if (server == -1)
		goto fail;
	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;

	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp)) == -1)
		goto fail;

	if (bind(server, (struct sockaddr*) &sin, sin_len) == -1)
		goto fail;

	if (listen(server, 1) == -1)
		goto fail;

	if (getsockname(server, (struct sockaddr*) &sin, &sin_len) == -1)
		goto fail;
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sv[0] = socket(AF_INET, SOCK_STREAM, 0);

	if (sv[0] == -1)
		goto fail;
	
	if (connect(sv[0], (struct sockaddr*) &sin, sin_len) == -1)
		goto fail;

	sv[1] = accept(server, NULL, NULL);

	if (sv[1] == -1)
		goto fail;

	close(server);

	return 0;

fail:
	close(server);
	close(sv[0]);
	close(sv[1]);

	return -1;
}

#endif /* _WIN32 */
