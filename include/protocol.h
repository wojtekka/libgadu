/* $Id$ */

/*
 *  (C) Copyright 2009-2010 Jakub Zawadzki <darkjames@darkjames.ath.cx>
 *                          Bartłomiej Zimoń <uzi18@o2.pl>
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

#define GG_LOGIN105 0x0083

#undef GG_FEATURE_STATUS80BETA
#undef GG_FEATURE_MSG80
#undef GG_FEATURE_STATUS80
#define GG_FEATURE_STATUS80BETA		0x01
#define GG_FEATURE_MSG80		0x02
#define GG_FEATURE_STATUS80 		0x05

#define GG8_LANG	"pl"
#define GG8_VERSION	"Gadu-Gadu Client Build "

#define GG11_VERSION	"GG-Phoenix/"
#define GG11_TARGET	" (BUILD;WINNT_x86-msvc;rv:11.0,pl;release;standard) (OS;Windows;Windows NT 6.1)"

struct gg_login80 {
	uint32_t uin;			/* mój numerek */
	uint8_t language[2];		/* język: GG8_LANG */
	uint8_t hash_type;		/* rodzaj hashowania hasła */
	uint8_t hash[64];		/* hash hasła dopełniony zerami */
	uint32_t status;		/* status na dzień dobry */
	uint32_t flags;			/* flagi (przeznaczenie nieznane) */
	uint32_t features;		/* opcje protokołu (GG8_FEATURES) */
	uint32_t local_ip;		/* mój adres ip */
	uint16_t local_port;		/* port, na którym słucham */
	uint32_t external_ip;		/* zewnętrzny adres ip (???) */
	uint16_t external_port;		/* zewnętrzny port (???) */
	uint8_t image_size;		/* maksymalny rozmiar grafiki w KiB */
	uint8_t dunno2;			/* 0x64 */
} GG_PACKED;

#define GG_LOGIN_HASH_TYPE_INVALID 0x0016

#define GG_LOGIN80_OK 0x0035

#define GG_LOGIN110_OK 0x009d

/**
 * Logowanie powiodło się (pakiet \c GG_LOGIN80_OK)
 */
struct gg_login80_ok {
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
struct gg_new_status80 {
	uint32_t status;			/**< Nowy status */
	uint32_t flags;				/**< flagi (nieznane przeznaczenie) */
	uint32_t description_size;		/**< rozmiar opisu */
} GG_PACKED;

#define GG_NEW_STATUS105 0x0063

#define GG_STATUS80BETA 0x002a
#define GG_NOTIFY_REPLY80BETA 0x002b

#define GG_STATUS80 0x0036
#define GG_NOTIFY_REPLY80 0x0037

struct gg_notify_reply80 {
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
	uint32_t seq;
} GG_PACKED;

#define GG_USER_DATA 0x0044

struct gg_user_data {
	uint32_t type;
	uint32_t user_count;
} GG_PACKED;

struct gg_user_data_user {
	uint32_t uin;
	uint32_t attr_count;
} GG_PACKED;

#define GG_TYPING_NOTIFICATION 0x0059

struct gg_typing_notification {
	uint16_t length;
	uint32_t uin;
} GG_PACKED;

#define GG_XML_ACTION 0x002c

#define GG_RECV_OWN_MSG 0x005a

#define GG_MULTILOGON_INFO 0x005b

struct gg_multilogon_info {
	uint32_t count;
} GG_PACKED;

struct gg_multilogon_info_item {
	uint32_t addr;
	uint32_t flags;
	uint32_t features;
	uint32_t logon_time;
	gg_multilogon_id_t conn_id;
	uint32_t unknown1;
	uint32_t name_size;
} GG_PACKED;

#define GG_MULTILOGON_DISCONNECT 0x0062

struct gg_multilogon_disconnect {
	gg_multilogon_id_t conn_id;
} GG_PACKED;

#define GG_MSG_CALLBACK 0x02	/**< Żądanie zwrotnego połączenia bezpośredniego */

#define GG_MSG_OPTION_CONFERENCE 0x01
#define GG_MSG_OPTION_ATTRIBUTES 0x02
#define GG_MSG_OPTION_IMAGE_REQUEST 0x04
#define GG_MSG_OPTION_IMAGE_REPLY 0x05
#define GG_MSG_OPTION_IMAGE_REPLY_MORE 0x06

#define GG_DCC7_ABORT 0x0025

struct gg_dcc7_abort {
	gg_dcc7_id_t id;		/* identyfikator połączenia */
	uint32_t uin_from;		/* numer nadawcy */
	uint32_t uin_to;		/* numer odbiorcy */
} GG_PACKED;

#define GG_DCC7_ABORTED 0x0025

struct gg_dcc7_aborted {
	gg_dcc7_id_t id;		/* identyfikator połączenia */
} GG_PACKED;

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

#define GG_DCC7_RELAY_TYPE_SERVER 0x01	/* adres serwera, na który spytać o proxy */
#define GG_DCC7_RELAY_TYPE_PROXY 0x08	/* adresy proxy, na które sie łączyć */

#define GG_DCC7_RELAY_DUNNO1 0x02

#define GG_DCC7_RELAY_REQUEST 0x0a

struct gg_dcc7_relay_req {
	uint32_t magic;			/* 0x0a */
	uint32_t len;			/* długość całego pakietu */
	gg_dcc7_id_t id;   		/* identyfikator połączenia */
	uint16_t type;   		/* typ zapytania */
	uint16_t dunno1;		/* 0x02 */
} GG_PACKED;

#define GG_DCC7_RELAY_REPLY_RCOUNT 0x02

#define GG_DCC7_RELAY_REPLY 0x0b

struct gg_dcc7_relay_reply {
	uint32_t magic;			/* 0x0b */
	uint32_t len;			/* długość całego pakietu */
	uint32_t rcount;		/* ilość serwerów */
} GG_PACKED;

struct gg_dcc7_relay_reply_server {
	uint32_t addr;		/* adres ip serwera */
	uint16_t port;		/* port serwera */
	uint8_t family;		/* rodzina adresów (na końcu?!) AF_INET=2 */
} GG_PACKED;

#define GG_DCC7_WELCOME_SERVER 0xc0debabe

struct gg_dcc7_welcome_server {
	uint32_t magic;			/* 0xc0debabe */
	gg_dcc7_id_t id;		/* identyfikator połączenia */
} GG_PACKED;

struct gg_dcc7_welcome_p2p {
	gg_dcc7_id_t id;		/* identyfikator połączenia */
} GG_PACKED;

#define GG_TIMEOUT_DISCONNECT 5	/**< Maksymalny czas oczekiwania na rozłączenie */

#define GG_USERLIST100_VERSION 0x5c

struct gg_userlist100_version {
	uint32_t version;		/* numer wersji listy kontaktów */
} GG_PACKED;

#define GG_USERLIST100_REQUEST 0x0040

struct gg_userlist100_request {
	uint8_t type;			/* rodzaj żądania */
	uint32_t version;		/* numer ostatniej znanej wersji listy kontaktów bądź 0 */
	uint8_t format_type;		/* rodzaj żądanego typu formatu listy kontaktów */
	uint8_t unknown1;		/* 0x01 */
	/* char request[]; */
} GG_PACKED;

#define GG_USERLIST100_REPLY 0x41

struct gg_userlist100_reply {
	uint8_t type;			/* rodzaj odpowiedzi */
	uint32_t version;		/* numer wersji listy kontaktów aktualnie przechowywanej przez serwer */
	uint8_t format_type;		/* rodzaj przesyłanego typu formatu listy kontaktów */
	uint8_t unknown1;		/* 0x01 */
	/* char reply[]; */
} GG_PACKED;

struct gg_pong110 {
	uint8_t dummy;
	uint32_t time;
} GG_PACKED;

struct gg_chat_create {
	uint32_t seq;
	uint32_t dummy;
} GG_PACKED;

struct gg_chat_invite {
	uint64_t id;
	uint32_t seq;
	uint32_t participants_count;
	/* struct {
		uint32_t uin;
		uint32_t dummy; (0x1e)
	} participants[]; */
} GG_PACKED;

struct gg_chat_leave {
	uint64_t id;
	uint32_t seq;
} GG_PACKED;

struct gg_chat_created {
	uint64_t id;
	uint32_t seq;
} GG_PACKED;

struct gg_chat_invite_ack {
	uint64_t id;
	uint32_t seq;
	uint32_t unknown1; /* 0x00 */
	uint32_t unknown2; /* 0x10 */
} GG_PACKED;

struct gg_chat_left {
	uint64_t id;
	uint32_t uin;
} GG_PACKED;

#define GG_ADD_NOTIFY105 0x007b
#define GG_REMOVE_NOTIFY105 0x007c
#define GG_EVENT110 0x0084
#define GG_IMTOKEN 0x008c
#define GG_ACCESS_INFO 0x008f
#define GG_NOTIFY105_FIRST 0x0077
#define GG_NOTIFY105_LAST 0x0078
#define GG_NOTIFY105_LIST_EMPTY 0x0079
#define GG_PONG110 0x00a1
#define GG_OPTIONS 0x009b

#define GG_SEND_MSG110 0x007d
#define GG_RECV_MSG110 0x007e
#define GG_RECV_OWN_MSG110 0x0082
#define GG_ACK110 0x0086
#define GG_SEND_MSG_ACK110 0x0087

#define GG_CHAT_INFO 0x0093
#define GG_CHAT_INFO_UPDATE 0x009e
#define GG_CHAT_CREATED 0x0045
#define GG_CHAT_INVITE_ACK 0x0047
#define GG_CHAT_RECV_MSG 0x0088
#define GG_CHAT_RECV_OWN_MSG 0x008e
#define GG_CHAT_CREATE 0x0047
#define GG_CHAT_INVITE 0x0090
#define GG_CHAT_LEAVE 0x0052
#define GG_CHAT_LEFT 0x0066
#define GG_CHAT_SEND_MSG 0x008d

#define GG_UIN_INFO 0x007a
#define GG_TRANSFER_INFO 0x00a0

#ifdef _WIN32
#pragma pack(pop)
#endif

#endif /* LIBGADU_PROTOCOL_H */
