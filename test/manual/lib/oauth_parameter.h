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

#ifndef OAUTH_PARAMETER_H
#define OAUTH_PARAMETER_H

typedef struct gg_oauth_parameter gg_oauth_parameter_t;

int gg_oauth_parameter_set(gg_oauth_parameter_t **list, const char *key, const char *value);
char *gg_oauth_parameter_join(gg_oauth_parameter_t *list, int header);
void gg_oauth_parameter_free(gg_oauth_parameter_t *list);

#endif /* OAUTH_PARAMETER_H */
