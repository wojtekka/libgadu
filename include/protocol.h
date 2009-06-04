#ifndef __GG_PROTOCOL_H
#define __GG_PROTOCOL_H

#include "libgadu.h"

#ifdef _WIN32
#pragma pack(push, 1)
#endif

#define GG_LOGIN80 0x0031

#define GG8_LANG	"pl"
#define GG8_VERSION	"Gadu-Gadu Client Build 8.0.0.8731"

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

#define GG_LOGIN80_OK 0x0035

#define GG_NEW_STATUS80 0x0038

/**
 * Zmiana stanu (pakiet \c GG_NEW_STATUS80)
 */
struct gg_new_status80 {
	uint32_t status;			/**< Nowy status */
	uint32_t flags;				/**< flagi (nieznane przeznaczenie) */
	uint32_t description_size;		/**< rozmiar opisu */
} GG_PACKED;

#define GG_STATUS80 0x0036
#define GG_NOTIFY_REPLY80 0x0037

struct gg_notify_reply80 {
	uint32_t uin;		/* numerek plus flagi w najstarszym bajcie */
	uint32_t status;	/* status danej osoby */
	uint32_t flags;		/* flagi (przeznaczenie nieznane) */
	uint32_t remote_ip;	/* adres IP bezpośrednich połączeń */
	uint16_t remote_port;	/* port bezpośrednich połączeń */
	uint8_t image_size;	/* maksymalny rozmiar obrazków w KB */
	uint8_t unknown2;	/* 0x00 */
	uint32_t unknown3;	/* 0x00000000 */
	uint32_t descr_len;	/* rozmiar opisu */
} GG_PACKED;


#ifdef _WIN32
#pragma pack(pop)
#endif

#endif /* __GG_PROTOCOL_H */
