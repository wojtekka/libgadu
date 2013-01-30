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

#define GG_PROTOCOL_110 0x40

struct gg_dcc7_relay {
	uint32_t addr;
	uint16_t port;
	uint8_t family;
};

struct gg_chat_list {
	uint64_t id;
	uint32_t version;
	uint32_t participants_count;
	uin_t *participants;

	struct gg_chat_list *next;
};

typedef struct gg_dcc7_relay gg_dcc7_relay_t;

int gg_pubdir50_handle_reply_sess(struct gg_session *sess, struct gg_event *e, const char *packet, int length);

int gg_resolve(int *fd, int *pid, const char *hostname);
int gg_resolve_pthread(int *fd, void **resolver, const char *hostname);
void gg_resolve_pthread_cleanup(void *resolver, int kill);

int gg_login_hash_sha1_2(const char *password, uint32_t seed, uint8_t *result);

int gg_chat_update(struct gg_session *sess, uint64_t id, uint32_t version, const uin_t *participants, unsigned int participants_count);
struct gg_chat_list *gg_chat_find(struct gg_session *sess, uint64_t id);

uin_t gg_str_to_uin(const char *str, int len);
const char * gg_uin_to_str(uin_t uin);

uint64_t gg_fix64(uint64_t x);

#endif /* LIBGADU_INTERNAL_H */
