/* $Id$ */

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

#ifndef LIBGADU_PROTOCOL_H
#define LIBGADU_PROTOCOL_H

#include "libgadu.h"

#define GG_LOGIN80 0x0031

struct gg_login80 {
	uint32_t uin;			/* mój numerek */
	char language[2];		/* język */
	uint8_t hash_type;		/* rodzaj hashowania hasła */
	uint8_t hash[64];		/* hash hasła dopełniony zerami */
	uint32_t status;		/* status na dzień dobry */
	uint32_t dunno1;		/* 0x00000000 */
	uint32_t dunno2;		/* 0x00000007 */
	uint32_t local_ip;		/* mój adres ip */
	uint16_t local_port;		/* port, na którym słucham */
	uint32_t external_ip;		/* zewnętrzny adres ip (???) */
	uint16_t external_port;		/* zewnętrzny port (???) */
	uint8_t image_size;		/* maksymalny rozmiar grafiki w KiB */
	uint8_t dunno3;			/* 0x64 */
	/* uint32_t version_length; */	/* długość wersji */
	/* char version[]; */		/* wersja */
	/* uint32_t descr_length; */	/* długość opisu */
	/* char descr[]; */		/* opis */
} GG_PACKED;

#define GG_LOGIN_OK80 0x0035

struct gg_login_ok80
{
	uint32_t dunno1;		/* 0x00000001 */
} GG_PACKED;

#define GG_NEW_STATUS80 0x0038

struct gg_new_status80
{
	uint32_t status;		/* status */
	uint32_t dunno1;		/* 0x00000000 */
	uint32_t descr_len;		/* długość opisu */
} GG_PACKED;

#define GG_STATUS80 0x0036
#define GG_NOTIFY_REPLY80 0x0037

struct gg_notify_reply80
{
	uint32_t uin;		/* numerek plus flagi w najstarszym bajcie */
	uint32_t status;	/* status danej osoby */
	uint32_t unknown1;	/* 0x00000000 */
	uint32_t remote_ip;	/* adres IP bezpośrednich połączeń */
	uint16_t remote_port;	/* port bezpośrednich połączeń */
	uint8_t image_size;	/* maksymalny rozmiar obrazków w KB */
	uint8_t unknown2;	/* 0x00 */
	uint32_t unknown3;	/* 0x00000000 */
	uint32_t descr_len;	/* rozmiar opisu */
} GG_PACKED;

#define GG_SEND_MSG80 0x002d

struct gg_send_msg80 {
	uint32_t recipient;
	uint32_t seq;
	uint32_t msgclass;
	uint32_t offset_plain;
	uint32_t offset_attr;
} GG_PACKED;

#define GG_RECV_MSG80 0x002e

struct gg_recv_msg80 {
	uint32_t sender;
	uint32_t seq;
	uint32_t time;
	uint32_t msgclass;
	uint32_t offset_plain;
	uint32_t offset_attr;
} GG_PACKED;

#define GG_USERLIST_REQUEST80 0x002f

#define GG_USERLIST_REPLY80 0x0030

#define GG_DISCONNECTING2 0x000d

#endif /* LIBGADU_PROTOCOL_H */
