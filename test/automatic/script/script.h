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

#ifndef SCRIPT_H
#define SCRIPT_H

#include "libgadu.h"

typedef enum {
	ACTION_LOGIN = 1,
	ACTION_SEND,
	ACTION_END,
	ACTION_CALL,
	ACTION_LOGOFF,
	EXPECT_DATA,
	EXPECT_EVENT,
	EXPECT_CONNECT,
	EXPECT_DISCONNECT,
} state_type_t;

typedef int (*state_check_event_func_t)(int type, union gg_event_union *);
typedef void (*state_api_call_func_t)(struct gg_session *);

typedef struct {
	const char *filename;
	int line;
	int test;
	state_type_t type;
	struct gg_login_params *glp;
	int event;
	state_check_event_func_t check_event;
	state_api_call_func_t call;
	unsigned char *data;
	unsigned char *data_mask;
	int data_len;
} state_t;

extern state_t script[];

extern const char *tests[];

#ifdef _WIN32
#define logon_time_t uint32_t
#else
#define logon_time_t time_t
#endif

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE 1

#ifdef GG_CONFIG_BIGENDIAN
#define ip(a, b, c, d) ((a)<<24|(b)<<16|(c)<<8|(d))
#else
#define ip(a, b, c, d) ((a)|(b)<<8|(c)<<16|(d)<<24)
#endif

#endif /* SCRIPT_H */
