/* $Id$ */

/*
 *  (C) Copyright 2009 Jakub Zawadzki <darkjames@darkjames.ath.cx>
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

#ifndef LIBGADU_INTERNAL_H
#define LIBGADU_INTERNAL_H

#include "libgadu.h"

#ifdef GG_CONFIG_HAVE_GNUTLS

#include <gnutls/gnutls.h>

typedef struct {
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;
} gg_session_gnutls_t;

#define GG_SESSION_GNUTLS(sess) ((gg_session_gnutls_t*) (sess)->ssl)->session

#endif /* GG_CONFIG_HAVE_GNUTLS */

typedef struct {
	uint32_t addr;
	uint16_t port;
	uint8_t family;
} gg_dcc7_relay_t;

#define GG_DCC7_RELAY_LIST(dcc) ((gg_dcc7_relay_t*) (dcc)->relay_list)

char *gg_cp_to_utf8(const char *b);
char *gg_utf8_to_cp(const char *b);
int gg_pubdir50_handle_reply_sess(struct gg_session *sess, struct gg_event *e, const char *packet, int length);
void gg_debug_dump_session(struct gg_session *sess, const void *buf, unsigned int buf_length, const char *format, ...);

#endif /* LIBGADU_INTERNAL_H */
