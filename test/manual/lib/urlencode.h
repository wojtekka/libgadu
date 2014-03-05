/*
 *  (C) Copyright 2008 Wojtek Kaniewski <wojtekka@irc.pl>
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

#ifndef URLENCODE_H
#define URLENCODE_H

#include <sys/types.h>
#include <libgadu.h>

size_t gg_urlencode_strlen(const char *s);
char *gg_urlencode_strcpy(char *dest, const char *src);
char *gg_urlencode(const char *s);
char *gg_urlencode_printf(char *format, ...) GG_GNUC_PRINTF(1, 2);

#endif /* URLENCODE_H */
