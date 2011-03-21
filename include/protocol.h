/*
 *  (C) Copyright 2009-2010 Jakub Zawadzki <darkjames@darkjames.ath.cx>
 *                          Wojtek Kaniewski <wojtekka@irc.pl>
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

#ifdef _WIN32
#pragma pack(push, 1)
#endif

#define GG_LOGIN80BETA 0x0029

#define GG_LOGIN80 0x0031

#define GG_PROTOCOL_FEATURE_STATUS80BETA	0x01
#define GG_PROTOCOL_FEATURE_MSG80		0x02
#define GG_PROTOCOL_FEATURE_STATUS80 		0x05

#define GG8_LANG        "pl"
#define GG8_VERSION     "Gadu-Gadu Client Build "

struct gg_login80 {
	uint32_t uin;			/* mój numerek */
	char language[2];		/* język: GG8_LANG */
	uint8_t hash_type;		/* rodzaj hashowania hasła */
	uint8_t hash[64];		/* hash hasła dopełniony zerami */
	uint32_t status;		/* status na dzień dobry */
	uint32_t flags;			/* flagi (przeznaczenie nieznane) */
	uint32_t features;		/* opcje protokołu (GG_FEATURES8) */
	uint32_t local_ip;		/* mój adres ip */
	uint16_t local_port;		/* port, na którym słucham */
	uint32_t external_ip;		/* zewnętrzny adres ip (???) */
	uint16_t external_port;		/* zewnętrzny port (???) */
	uint8_t image_size;		/* maksymalny rozmiar grafiki w KiB */
	uint8_t dunno2;			/* 0x64 */
	/* uint32_t version_length; */	/* długość wersji */
	/* char version[]; */		/* wersja */
	/* uint32_t descr_length; */	/* długość opisu */
	/* char descr[]; */		/* opis */
} GG_PACKED;

#define GG_LOGIN_HASH_TYPE_INVALID 0x0016

#define GG_LOGIN80_OK 0x0035

/**
 * Logowanie powiodło się (pakiet \c GG_LOGIN80_OK)
 */
struct gg_login80_ok
{
	uint32_t unknown1;		/* 0x00000001 */
} GG_PACKED;

/**
 * Logowanie nie powiodło się (pakiet \c GG_LOGIN80_FAILED)
 */
#define GG_LOGIN80_FAILED 0x0043

struct gg_login80_failed {
	uint32_t unknown1;		/* 0x00000001 */
} GG_PACKED;

#define GG_NEW_STATUS80BETA 0x0028

#define GG_NEW_STATUS80 0x0038

/**
 * Zmiana stanu (pakiet \c GG_NEW_STATUS80)
 */
struct gg_new_status80
{
	uint32_t status;		/**< Nowy status */
	uint32_t flags;			/**< Flagi (przeznaczenie nieznane) */
	uint32_t descr_len;		/**< Rozmiar opisu */
} GG_PACKED;

#define GG_STATUS80BETA 0x002a
#define GG_NOTIFY_REPLY80BETA 0x002b

#define GG_STATUS80 0x0036
#define GG_NOTIFY_REPLY80 0x0037

struct gg_notify_reply80
{
	uint32_t uin;		/* numerek plus flagi w najstarszym bajcie */
	uint32_t status;	/* status danej osoby */
	uint32_t features;	/* opcje protokołu */
	uint32_t remote_ip;	/* adres IP bezpośrednich połączeń */
	uint16_t remote_port;	/* port bezpośrednich połączeń */
	uint8_t image_size;	/* maksymalny rozmiar obrazków w KB */
	uint8_t unknown1;	/* 0x00 */
	uint32_t flags;		/* flagi połączenia */
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

#define GG_DISCONNECT_ACK 0x000d

#define GG_RECV_MSG_ACK 0x0046

struct gg_recv_msg_ack {
	uint32_t count;
} GG_PACKED;

#define GG_USER_DATA 0x0044

struct gg_user_data {
	uint32_t type;
	uint32_t users;
} GG_PACKED;

struct gg_user_data_user {
	uint32_t uin;
	uint32_t fields;
} GG_PACKED;

#define GG_TYPING_NOTIFICATION 0x0059

struct gg_typing_notification {
	uint16_t length;
	uint32_t uin;
} GG_PACKED;

#define GG_USERLIST_REQUEST80 0x002f

#define GG_USERLIST_REPLY80 0x0030

#define GG_MSG_CALLBACK 0x02	/**< Żądanie zwrotnego połączenia bezpośredniego */

#define GG_MSG_OPTION_CONFERENCE 0x01
#define GG_MSG_OPTION_ATTRIBUTES 0x02
#define GG_MSG_OPTION_IMAGE_REQUEST 0x04
#define GG_MSG_OPTION_IMAGE_REPLY 0x05
#define GG_MSG_OPTION_IMAGE_REPLY_MORE 0x06

#define GG_DCC7_VOICE_RETRIES 0x11	/* 17 powtorzen */

#define GG_DCC7_RESERVED1		0xdeadc0de
#define GG_DCC7_RESERVED2		0xdeadbeaf

struct gg_dcc7_voice_auth {
	uint8_t type;			/* 0x00 -> wysylanie ID
					   0x01 -> potwierdzenie ID
					*/
	gg_dcc7_id_t id;		/* identyfikator połączenia */
	uint32_t reserved1;		/* GG_DCC7_RESERVED1 */
	uint32_t reserved2;		/* GG_DCC7_RESERVED2 */
} GG_PACKED;

struct gg_dcc7_voice_nodata {	/* wyciszony mikrofon, ten pakiet jest wysylany co 1s (jesli chcemy podtrzymac polaczenie) */
	uint8_t type;			/* 0x02 */
	gg_dcc7_id_t id;		/* identyfikator połączenia */
	uint32_t reserved1;		/* GG_DCC7_RESERVED1 */
	uint32_t reserved2;		/* GG_DCC7_RESERVED2 */
} GG_PACKED;

struct gg_dcc7_voice_data {
	uint8_t type;			/* 0x03 */
	uint32_t did;			/* XXX: co ile zwieksza sie u nas id pakietu [uzywac 0x28] */
	uint32_t len;			/* rozmiar strukturki - 1 (sizeof(type)) */
	uint32_t packet_id;		/* numerek pakietu */
	uint32_t datalen;		/* rozmiar danych */
	/* char data[]; */		/* ramki: albo gsm, albo speex, albo melp, albo inne. */
} GG_PACKED;

struct gg_dcc7_voice_init {
	uint8_t type;			/* 0x04 */
	uint32_t id;			/* nr kroku [0x1 - 0x5] */
	uint32_t protocol;		/* XXX: wersja protokolu (0x29, 0x2a, 0x2b) */
	uint32_t len;			/* rozmiar sizeof(protocol)+sizeof(len)+sizeof(data) = 0x08 + sizeof(data) */
	/* char data[]; */		/* reszta danych */
} GG_PACKED;

struct gg_dcc7_voice_init_confirm {
	uint8_t type;			/* 0x05 */
	uint32_t id;			/* id tego co potwierdzamy [0x1 - 0x5] */
} GG_PACKED;

#define GG_TIMEOUT_DISCONNECT 5	/**< Maksymalny czas oczekiwania na rozłączenie */

#ifdef _WIN32
#pragma pack(pop)
#endif

#endif /* LIBGADU_PROTOCOL_H */
