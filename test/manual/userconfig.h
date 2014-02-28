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

#ifndef USERCONFIG_H
#define USERCONFIG_H

unsigned int config_uin;
char *config_password;
unsigned int config_peer;
char *config_file;
char *config_dir;
unsigned int config_size;
unsigned long config_ip;
unsigned int config_port;
char *config_server;
char *config_proxy;

int config_read(void);
void config_free(void);

#endif /* USERCONFIG_H */
