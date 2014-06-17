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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "urlencode.h"

#define gg_urlencode_isvalid(c) \
( \
	(((c) >= 'a') && ((c) <= 'z')) || \
	(((c) >= 'A') && ((c) <= 'Z')) || \
	(((c) >= '0') && ((c) <= '9')) || \
	((c) == '.') || \
	((c) == '-') || \
	((c) == '_') || \
	((c) == '~') \
)

static const char gg_urlencode_hex_table[] = "0123456789ABCDEF";

size_t gg_urlencode_strlen(const char *p)
{
	int len = 0;

	if (p == NULL)
		return 0;

	for (; *p; p++, len++) {
		if (!gg_urlencode_isvalid(*p))
			len += 2;
	}

	return len;
}

char *gg_urlencode_strcpy(char *buf, const char *str)
{
	char *q;
	const char *p;

	if (str == NULL) {
		*buf = 0;
		return buf;
	}

	for (p = str, q = buf; *p; p++, q++) {
		if (gg_urlencode_isvalid(*p))
			*q = *p;
		else {
			if (*p == ' ')
				*q = '+';
			else {
				*q++ = '%';
				*q++ = gg_urlencode_hex_table[(*p >> 4) & 15];
				*q = gg_urlencode_hex_table[*p & 15];
			}
		}
	}

	*q = 0;

	return q;
}

char *gg_urlencode(const char *s)
{
	char *res;

	res = malloc(gg_urlencode_strlen(s) + 1);

	if (res == NULL)
		return NULL;

	gg_urlencode_strcpy(res, s);

	return res;
}


char *gg_urlencode_printf(char *format, ...)
{
	char *buf, *tmp;
	size_t size = 0;
	char **args;
	int argc = 0;
	va_list ap;
	int i, j;

	for (i = 0; format[i]; i++) {
		if (format[i] == '%') {
			i++;
			if (format[i] == '%')		/* %% */
				size++;
			else if (format[i] == 's')	/* %s */
				argc++;
		} else
			size++;
	}

	if (argc <= 0)
		return NULL;
	args = calloc(argc, sizeof(char *));
	if (!args)
		return NULL;

	va_start(ap, format);

	for (j = 0; j < argc; j++) {
		char *tmp = va_arg(ap, char *);

		size += gg_urlencode_strlen(tmp);
		args[j] = tmp;
	}

	va_end(ap);

	tmp = buf = malloc(size + 1);

	if (!buf) {
		free(args);
		return NULL;
	}

	*buf = '\0';

	for (i = 0, j = 0; format[i]; i++) {
		if (format[i] == '%') {
			i++;
			if (format[i] == '%')		/* %% */
				*tmp++ = '%';
			else if (format[i] == 's') {	/* %s */
				tmp = gg_urlencode_strcpy(tmp, args[j++]);
			}
		} else
			*tmp++ = format[i];
	}
	*tmp = '\0';

	free(args);
	return buf;
}
