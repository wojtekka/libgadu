/* $Id$ */

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

#ifndef LIBGADU_SESSION_H
#define LIBGADU_SESSION_H

#define GG_SESSION_CHECK(gs, result) \
	if ((gs) == NULL) { \
		errno = EINVAL; \
		return (result); \
	}

#define GG_SESSION_PROTOCOL_7_7(gs) ((gs)->protocol_version >= 0x2a)
#define GG_SESSION_PROTOCOL_8_0(gs) ((gs)->protocol_version >= 0x2d)

#define GG_SESSION_IS_IDLE(gs) ((gs)->state == GG_STATE_IDLE)
#define GG_SESSION_IS_CONNECTING(gs) ((gs)->state != GG_STATE_IDLE && (gs)->state != GG_STATE_CONNECTED)
#define GG_SESSION_IS_CONNECTED(gs) ((gs)->state == GG_STATE_CONNECTED)

#endif /* LIBGADU_SESSION_H */
