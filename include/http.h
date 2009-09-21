/*
 *  (C) Copyright 2009 Wojtek Kaniewski <wojtekka@irc.pl>
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

#ifndef LIBGADU_HTTP_H
#define LIBGADU_HTTP_H

const char *gg_http_find_header(const char *buf, size_t len, const char *name);
int gg_http_get_header_int(const char *buf, size_t len, const char *name);
char *gg_http_get_header_string(const char *buf, size_t len, const char *name);
const char *gg_http_find_body(const char *buf, size_t len);
int gg_http_is_complete(const char *buf, size_t len);

#endif /* LIBGADU_HTTP_H */
