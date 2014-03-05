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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "libgadu.h"
#include "network.h"
#include "userconfig.h"

unsigned int config_uin;
char *config_password;
unsigned int config_peer;
char *config_file;
char *config_dir;
unsigned int config_size = 1048576;
unsigned long config_ip = 0xffffffff;
unsigned int config_port;
char *config_server;
char *config_proxy;

int config_read(void)
{
	char buf[256];
	FILE *f;

	if (!(f = fopen("config", "r"))) {
		if (!(f = fopen("../config", "r")))
			return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		while (strlen(buf) > 0 && isspace(buf[strlen(buf) - 1]))
			buf[strlen(buf) - 1] = 0;

		if (strncmp(buf, "uin ", 4) == 0)
			config_uin = atoi(buf + 4);

		if (strncmp(buf, "password ", 9) == 0) {
			free(config_password);
			config_password = strdup(buf + 9);
		}

		if (strncmp(buf, "peer ", 5) == 0)
			config_peer = atoi(buf + 5);

		if (strncmp(buf, "file ", 5) == 0) {
			free(config_file);
			config_file = strdup(buf + 5);
		}

		if (strncmp(buf, "dir ", 4) == 0) {
			free(config_dir);
			config_dir = strdup(buf + 4);
		}

		if (strncmp(buf, "size ", 5) == 0)
			config_size = atoi(buf + 5);

		if (strncmp(buf, "ip ", 3) == 0)
			config_ip = inet_addr(buf + 3);

		if (strncmp(buf, "port ", 5) == 0)
			config_port = atoi(buf + 5);

		if (strncmp(buf, "server ", 7) == 0) {
			free(config_server);
			config_server = strdup(buf + 7);
		}

		if (strncmp(buf, "proxy ", 6) == 0) {
			free(config_proxy);
			config_proxy = strdup(buf + 6);
		}
	}

	fclose(f);

	if (config_uin == 0 || config_password == NULL)
		return -1;

	return 0;
}

void config_free(void)
{
	free(config_password);
	free(config_dir);
	free(config_file);
	free(config_server);
	free(config_proxy);
}
