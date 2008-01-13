/* $Id$ */

/*
 *  (C) Copyright 2001-2007 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Tomasz Chiliński <chilek@chilan.com>
 *                          Adam Wysocki <gophi@ekg.chmurka.net>
 *  
 *  Thanks to Jakub Zawadzki <darkjames@darkjames.ath.cx>
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110,
 *  USA.
 */

/**
 * \file dcc7.c
 *
 * \brief Obsługa połączeń bezpośrednich od wersji Gadu-Gadu 7.x
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef sun
#  include <sys/filio.h>
#endif
#include <time.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "compat.h"
#include "libgadu.h"

/**
 * \internal Dodaje połączenie bezpośrednie do sesji.
 *
 * \param sess Struktura sesji
 * \param dcc Struktura połączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_session_add(struct gg_session *sess, struct gg_dcc7 *dcc)
{
	if (!sess || !dcc || dcc->next) {
		errno = EINVAL;
		return -1;
	}

	dcc->next = sess->dcc7_list;
	sess->dcc7_list = dcc;

	return 0;
}

/**
 * \internal Usuwa połączenie bezpośrednie z sesji.
 *
 * \param sess Struktura sesji
 * \param dcc Struktura połączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_session_remove(struct gg_session *sess, struct gg_dcc7 *dcc)
{
	struct gg_dcc7 *tmp;

	if (!sess || !dcc) {
		errno = EINVAL;
		return -1;
	}

	if (sess->dcc7_list == dcc) {
		sess->dcc7_list = dcc->next;
		dcc->next = NULL;
		return 0;
	}

	for (tmp = sess->dcc7_list; tmp; tmp = tmp->next) {
		if (tmp->next == dcc) {
			tmp = dcc->next;
			dcc->next = NULL;
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

/**
 * \internal Zwraca strukturę połączenia o danym identyfikatorze.
 *
 * \param sess Struktura sesji
 * \param id Identyfikator połączenia
 * \param uin Numer nadawcy lub odbiorcy
 *
 * \return Struktura połączenia lub \c NULL jeśli nie znaleziono
 */
static struct gg_dcc7 *gg_dcc7_session_find(struct gg_session *sess, gg_dcc7_id_t id, uin_t uin)
{
	struct gg_dcc7 *tmp;
	int empty;

	empty = !memcmp(&id, "\0\0\0\0\0\0\0\0", 8);

	for (tmp = sess->dcc7_list; tmp; tmp = tmp->next) {
		if (empty) {
			if (tmp->peer_uin == uin && !tmp->state == GG_STATE_WAITING_FOR_ACCEPT)
				return tmp;
		} else {
			if (!memcmp(&tmp->cid, &id, sizeof(id)))
				return tmp;
		}
	}

	return NULL;
}

/**
 * \internal Nawiązuje połączenie bezpośrednie
 *
 * \param sess Struktura sesji
 * \param dcc Struktura połączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_connect(struct gg_session *sess, struct gg_dcc7 *dcc)
{
	if (!sess || !dcc) {
		errno = EINVAL;
		return -1;
	}

	if ((dcc->fd = gg_connect(&dcc->remote_addr, dcc->remote_port, 1)) == -1) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// gg_dcc7_connect() connection failed\n");
		return -1;
	}

	dcc->state = GG_STATE_CONNECTING;
	dcc->check = GG_CHECK_WRITE;
	dcc->timeout = GG_DCC7_TIMEOUT_CONNECT;
	dcc->soft_timeout = 1;

	return 0;
}

/**
 * \internal Tworzy gniazdo nasłuchujące dla połączenia bezpośredniego
 *
 * \param dcc Struktura połączenia
 * \param port Preferowany port (jeśli równy 0 lub -1, próbuje się domyślnego)
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_listen(struct gg_dcc7 *dcc, uint16_t port)
{
	struct sockaddr_in sin;
	int fd, bound = 0;

	if (!dcc) {
		errno = EINVAL;
		return -1;
	}

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_listen() can't create socket (%s)\n", strerror(errno));
		return -1;
	}

	// XXX losować porty?
	
	if (!port)
		port = GG_DEFAULT_DCC_PORT;

	while (!bound) {
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(port);

		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_listen() trying port %d\n", port);
		if (!bind(fd, (struct sockaddr*) &sin, sizeof(sin)))
			bound = 1;
		else {
			if (++port == 65535) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_listen() no free port found\n");
				close(fd);
				errno = ENOENT;
				return -1;
			}
		}
	}

	if (listen(fd, 1)) {
		int errsv = errno;
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_listen() unable to listen (%s)\n", strerror(errno));
		close(fd);
		errno = errsv;
		return -1;
	}

	dcc->fd = fd;
	dcc->local_port = port;
	
	dcc->state = GG_STATE_LISTENING;
	dcc->check = GG_CHECK_READ;
	dcc->timeout = GG_DCC7_TIMEOUT_FILE_ACK;

	return 0;
}

/**
 * \internal Tworzy gniazdo nasłuchujące i wysyła jego parametry
 *
 * \param dcc Struktura połączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_listen_and_send_info(struct gg_dcc7 *dcc)
{
	struct gg_dcc7_info pkt;

	// XXX dać możliwość konfiguracji?
	
	dcc->local_addr = dcc->sess->client_addr;

	if (gg_dcc7_listen(dcc, 0) == -1)
		return -1;

	memset(&pkt, 0, sizeof(pkt));
	pkt.uin = gg_fix32(dcc->peer_uin);
	pkt.type = GG_DCC7_TYPE_P2P;
	pkt.id = dcc->cid;
	snprintf((char*) pkt.info, sizeof(pkt.info), "%s %d", inet_ntoa(*((struct in_addr*) &dcc->local_addr)), dcc->local_port);

	return gg_send_packet(dcc->sess, GG_DCC7_INFO, &pkt, sizeof(pkt), NULL);
}

/**
 * \internal Odwraca połączenie po nieudanym connect()
 *
 * \param dcc Struktura połączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_reverse_connect(struct gg_dcc7 *dcc)
{
	if (dcc->reverse)
		return -1;

	gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() connection timeout, trying reverse connection\n");
	close(dcc->fd);
	dcc->fd = -1;
	dcc->reverse = 1;

	return gg_dcc7_listen_and_send_info(dcc);
}

/**
 * \internal Wysyła do serwera żądanie nadania identyfikatora sesji
 *
 * \param sess Struktura sesji
 * \param type Rodzaj połączenia (\c GG_DCC7_TYPE_FILE lub \c GG_DCC7_TYPE_VOICE)
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
static int gg_dcc7_request_id(struct gg_session *sess, uint32_t type)
{
	struct gg_dcc7_id_request pkt;

	if (!sess) {
		errno = EFAULT;
		return -1;
	}

	if (sess->state != GG_STATE_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	if (type != GG_DCC7_TYPE_VOICE && type != GG_DCC7_TYPE_FILE) {
		errno = EINVAL;
		return -1;
	}
	
	memset(&pkt, 0, sizeof(pkt));
	pkt.type = gg_fix32(type);

	return gg_send_packet(sess, GG_DCC7_ID_REQUEST, &pkt, sizeof(pkt), NULL);
}

/**
 * \internal Rozpoczyna wysyłanie pliku.
 *
 * Funkcja jest wykorzystywana przez \c gg_dcc7_send_file() oraz
 * \c gg_dcc_send_file_fd().
 *
 * \param sess Struktura sesji
 * \param rcpt Numer odbiorcy
 * \param fd Deskryptor pliku
 * \param size Rozmiar pliku
 * \param filename1250 Nazwa pliku w kodowaniu CP-1250
 * \param hash Skrót SHA-1 pliku
 * \param seek Flaga mówiąca, czy można używać lseek()
 *
 * \return Struktura \c gg_dcc7 lub \c NULL w przypadku błędu
 *
 * \ingroup dcc7
 */
static struct gg_dcc7 *gg_dcc7_send_file_common(struct gg_session *sess, uin_t rcpt, int fd, size_t size, const char *filename1250, const char *hash, int seek)
{
	struct gg_dcc7 *dcc = NULL;

	if (!sess || !rcpt || !filename1250 || !hash || fd == -1) {
		errno = EINVAL;
		goto fail;
	}

	if (!(dcc = malloc(sizeof(struct gg_dcc7)))) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_send_file() not enough memory\n");
		goto fail;
	}

	if (gg_dcc7_request_id(sess, GG_DCC7_TYPE_FILE) == -1)
		goto fail;

	memset(dcc, 0, sizeof(struct gg_dcc7));
	dcc->type = GG_SESSION_DCC7_SEND;
	dcc->dcc_type = GG_DCC7_TYPE_FILE;
	dcc->state = GG_STATE_REQUESTING_ID;
	dcc->timeout = GG_DEFAULT_TIMEOUT;
	dcc->sess = sess;
	dcc->fd = -1;
	dcc->uin = sess->uin;
	dcc->peer_uin = rcpt;
	dcc->file_fd = fd;
	dcc->size = size;
	dcc->seek = seek;

	strncpy((char*) dcc->filename, filename1250, GG_DCC7_FILENAME_LEN - 1);
	dcc->filename[GG_DCC7_FILENAME_LEN] = 0;

	memcpy(dcc->hash, hash, GG_DCC7_HASH_LEN);

	if (gg_dcc7_session_add(sess, dcc) == -1)
		goto fail;

	return dcc;

fail:
	if (dcc)
		free(dcc);

	return NULL;
}

/**
 * Rozpoczyna wysyłanie pliku o danej nazwie.
 *
 * \param sess Struktura sesji
 * \param rcpt Numer odbiorcy
 * \param filename Nazwa pliku w lokalnym systemie plików
 * \param filename1250 Nazwa pliku w kodowaniu CP-1250
 * \param hash Skrót SHA-1 pliku (lub \c NULL jeśli ma być wyznaczony)
 *
 * \return Struktura \c gg_dcc7 lub \c NULL w przypadku błędu
 *
 * \ingroup dcc7
 */
struct gg_dcc7 *gg_dcc7_send_file(struct gg_session *sess, uin_t rcpt, const char *filename, const char *filename1250, const char *hash)
{
	struct gg_dcc7 *dcc = NULL;
	const char *tmp;
	char hash_buf[GG_DCC7_HASH_LEN];
	struct stat st;
	int fd = -1;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc7_send_file(%p, %d, \"%s\", %p);\n", sess, rcpt, filename, hash);

	if (!sess || !rcpt || !filename) {
		errno = EINVAL;
		goto fail;
	}

	if (!filename1250)
		filename1250 = filename;

	if (stat(filename, &st) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_send_file() stat() failed (%s)\n", strerror(errno));
		goto fail;
	}

	if ((st.st_mode & S_IFDIR)) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_send_file() that's a directory\n");
		errno = EINVAL;
		goto fail;
	}

	if ((fd = open(filename, O_RDONLY)) == -1) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_send_file() open() failed (%s)\n", strerror(errno));
		goto fail;
	}

	if (hash) {
		memcpy(dcc->hash, hash, GG_DCC7_HASH_LEN);
	} else {
		if (gg_file_hash_sha1(fd, (uint8_t*) hash_buf) == -1)
			goto fail;

		hash = hash_buf;
	}

	if ((tmp = strrchr(filename1250, '/')))
		filename1250 = tmp + 1;

	if (!(dcc = gg_dcc7_send_file_common(sess, rcpt, fd, st.st_size, filename1250, hash, 1)))
		goto fail;

	return dcc;

fail:
	if (fd != -1) {
		int errsv = errno;
		close(fd);
		errno = errsv;
	}

	if (dcc)
		free(dcc);

	return NULL;
}

/**
 * Rozpoczyna wysyłanie pliku o danym deskryptorze.
 *
 * \param sess Struktura sesji
 * \param rcpt Numer odbiorcy
 * \param fd Deskryptor pliku
 * \param size Rozmiar pliku
 * \param filename1250 Nazwa pliku w kodowaniu CP-1250
 * \param hash Skrót SHA-1 pliku
 *
 * \return Struktura \c gg_dcc7 lub \c NULL w przypadku błędu
 *
 * \ingroup dcc7
 */
struct gg_dcc7 *gg_dcc7_send_file_fd(struct gg_session *sess, uin_t rcpt, int fd, size_t size, const char *filename1250, const char *hash)
{
	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc7_send_file_fd(%p, %d, %d, %u, \"%s\", %p);\n", sess, rcpt, fd, size, filename1250, hash);

	return gg_dcc7_send_file_common(sess, rcpt, fd, size, filename1250, hash, 0);
}


/**
 * Potwierdza chęć odebrania pliku.
 *
 * \param dcc Struktura połączenia
 * \param offset Początkowy offset przy wznawianiu przesyłania pliku
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup dcc7
 */
int gg_dcc7_accept(struct gg_dcc7 *dcc, unsigned int offset)
{
	struct gg_dcc7_accept pkt;

	if (!dcc->sess) {
		errno = EFAULT;
		return -1;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.uin = gg_fix32(dcc->peer_uin);
	pkt.id = dcc->cid;
	pkt.offset = gg_fix32(offset);

	if (gg_send_packet(dcc->sess, GG_DCC7_ACCEPT, &pkt, sizeof(pkt), NULL) == -1)
		return -1;

	return gg_dcc7_listen_and_send_info(dcc);
}

/**
 * Odrzuca próbę przesłania pliku.
 *
 * \param dcc Struktura połączenia
 * \param reason Powód odrzucenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 *
 * \ingroup dcc7
 */
int gg_dcc7_reject(struct gg_dcc7 *dcc, int reason)
{
	struct gg_dcc7_reject pkt;

	if (!dcc->sess) {
		errno = EFAULT;
		return -1;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.uin = gg_fix32(dcc->peer_uin);
	pkt.id = dcc->cid;
	pkt.reason = gg_fix32(reason);

	return gg_send_packet(dcc->sess, GG_DCC7_REJECT, &pkt, sizeof(pkt), NULL);
}

/**
 * \internal Obsługuje pakiet identyfikatora połączenia bezpośredniego.
 *
 * \param sess Struktura sesji
 * \param e Struktura zdarzenia
 * \param payload Treść pakietu
 * \param len Długość pakietu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
int gg_dcc7_handle_id(struct gg_session *sess, struct gg_event *e, void *payload, int len)
{
	struct gg_dcc7_id_reply *p = payload;
	struct gg_dcc7 *tmp;

	gg_debug_session(sess, GG_DEBUG_MISC, "// sess %p dcc_list %p\n", sess, sess->dcc7_list);

	for (tmp = sess->dcc7_list; tmp; tmp = tmp->next) {
		gg_debug_session(sess, GG_DEBUG_MISC, "// checking dcc %p, state %d, type %d\n", tmp, tmp->state, tmp->dcc_type);

		if (tmp->state != GG_STATE_REQUESTING_ID || tmp->dcc_type != gg_fix32(p->type))
			continue;
		
		tmp->cid = p->id;

		switch (tmp->dcc_type) {
			case GG_DCC7_TYPE_FILE:
			{
				struct gg_dcc7_new s;

				memset(&s, 0, sizeof(s));
				s.id = tmp->cid;
				s.type = gg_fix32(GG_DCC7_TYPE_FILE);
				s.uin_from = gg_fix32(tmp->uin);
				s.uin_to = gg_fix32(tmp->peer_uin);
				s.size = gg_fix32(tmp->size);

				strncpy((char*) s.filename, (char*) tmp->filename, GG_DCC7_FILENAME_LEN);

				tmp->state = GG_STATE_WAITING_FOR_ACCEPT;
				tmp->timeout = GG_DCC7_TIMEOUT_FILE_ACK;

				return gg_send_packet(sess, GG_DCC7_NEW, &s, sizeof(s), NULL);
			}
		}
	}

	return 0;
}

/**
 * \internal Obsługuje pakiet akceptacji połączenia bezpośredniego.
 *
 * \param sess Struktura sesji
 * \param e Struktura zdarzenia
 * \param payload Treść pakietu
 * \param len Długość pakietu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
int gg_dcc7_handle_accept(struct gg_session *sess, struct gg_event *e, void *payload, int len)
{
	struct gg_dcc7_accept *p = payload;
	struct gg_dcc7 *dcc;

	if (!(dcc = gg_dcc7_session_find(sess, p->id, gg_fix32(p->uin)))) {
		// XXX wysłać reject?
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}

	if (dcc->state != GG_STATE_WAITING_FOR_ACCEPT) {
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}
	
	// XXX czy dla odwrotnego połączenia powinniśmy wywołać już zdarzenie GG_DCC7_ACCEPT?
	
	dcc->offset = gg_fix32(p->offset);
	dcc->state = GG_STATE_WAITING_FOR_INFO;

	return 0;
}

/**
 * \internal Obsługuje pakiet informacji o połączeniu bezpośrednim.
 *
 * \param sess Struktura sesji
 * \param e Struktura zdarzenia
 * \param payload Treść pakietu
 * \param len Długość pakietu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
int gg_dcc7_handle_info(struct gg_session *sess, struct gg_event *e, void *payload, int len)
{
	struct gg_dcc7_info *p = payload;
	struct gg_dcc7 *dcc;
	char *tmp;

	if (!(dcc = gg_dcc7_session_find(sess, p->id, gg_fix32(p->uin))))
		return 0;
	
	if (p->type != GG_DCC7_TYPE_P2P) {
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}

	if ((dcc->remote_addr = inet_addr(p->info)) == INADDR_NONE) {
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}

	if (!(tmp = strchr(p->info, ' ')) || !(dcc->remote_port = atoi(tmp + 1))) {
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}

	// jeśli nadal czekamy na połączenie przychodzące, a druga strona nie
	// daje rady i oferuje namiary na siebie, bierzemy co dają.

	if (dcc->state != GG_STATE_WAITING_FOR_INFO && (dcc->state != GG_STATE_LISTENING || dcc->reverse)) {
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}

	if (dcc->state == GG_STATE_LISTENING) {
		close(dcc->fd);
		dcc->fd = -1;
		dcc->reverse = 1;
	}
	
	if (dcc->type == GG_SESSION_DCC7_SEND) {
		e->type = GG_EVENT_DCC7_ACCEPT;
		e->event.dcc7_accept.dcc7 = dcc;
		e->event.dcc7_accept.type = gg_fix32(p->type);
		e->event.dcc7_accept.remote_ip = dcc->remote_addr;
		e->event.dcc7_accept.remote_port = dcc->remote_port;
	}

	if (gg_dcc7_connect(sess, dcc) == -1) {
		if (gg_dcc7_reverse_connect(dcc) == -1) {
			e->type = GG_EVENT_DCC7_ERROR;
			e->event.dcc7_error = GG_ERROR_DCC7_NET;
			return 0;
		}
	}

	return 0;
}

/**
 * \internal Obsługuje pakiet odrzucenia połączenia bezpośredniego.
 *
 * \param sess Struktura sesji
 * \param e Struktura zdarzenia
 * \param payload Treść pakietu
 * \param len Długość pakietu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
int gg_dcc7_handle_reject(struct gg_session *sess, struct gg_event *e, void *payload, int len)
{
	struct gg_dcc7_reject *p = payload;
	struct gg_dcc7 *dcc;

	if (!(dcc = gg_dcc7_session_find(sess, p->id, gg_fix32(p->uin))))
		return 0;
	
	if (dcc->state != GG_STATE_WAITING_FOR_ACCEPT) {
		e->type = GG_EVENT_DCC7_ERROR;
		e->event.dcc7_error = GG_ERROR_DCC7_HANDSHAKE;
		return 0;
	}

	e->type = GG_EVENT_DCC7_REJECT;
	e->event.dcc7_reject.dcc7 = dcc;
	e->event.dcc7_reject.reason = gg_fix32(p->reason);

	// XXX ustawić state na rejected?

	return 0;
}

/**
 * \internal Obsługuje pakiet nowego połączenia bezpośredniego.
 *
 * \param sess Struktura sesji
 * \param e Struktura zdarzenia
 * \param payload Treść pakietu
 * \param len Długość pakietu
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu
 */
int gg_dcc7_handle_new(struct gg_session *sess, struct gg_event *e, void *payload, int len)
{
	struct gg_dcc7_new *p = payload;
	struct gg_dcc7 *dcc;

	switch (gg_fix32(p->type)) {
		case GG_DCC7_TYPE_FILE:
			if (!(dcc = malloc(sizeof(struct gg_dcc7)))) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_dcc7_handle_new() not enough memory\n");
				return -1;
			}
			
			memset(dcc, 0, sizeof(struct gg_dcc7));
			dcc->type = GG_SESSION_DCC7_GET;
			dcc->dcc_type = GG_DCC7_TYPE_FILE;
			dcc->fd = -1;
			dcc->file_fd = -1;
			dcc->uin = sess->uin;
			dcc->peer_uin = gg_fix32(p->uin_from);
			dcc->cid = p->id;
			dcc->sess = sess;

			if (gg_dcc7_session_add(sess, dcc) == -1) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_dcc7_handle_new() unable to add to session\n");
				gg_dcc7_free(dcc);
				return -1;
			}

			dcc->size = gg_fix32(p->size);
			strncpy((char*) dcc->filename, (char*) p->filename, GG_DCC7_FILENAME_LEN - 1);
			dcc->filename[GG_DCC7_FILENAME_LEN] = 0;
			memcpy(dcc->hash, p->hash, GG_DCC7_HASH_LEN);

			e->type = GG_EVENT_DCC7_NEW;
			e->event.dcc7_new = dcc;

			break;

		case GG_DCC7_TYPE_VOICE:
			if (!(dcc = malloc(sizeof(struct gg_dcc7)))) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_handle_packet() not enough memory\n");
				return -1;
			}
			
			memset(dcc, 0, sizeof(struct gg_dcc7));

			dcc->type = GG_SESSION_DCC7_VOICE;
			dcc->dcc_type = GG_DCC7_TYPE_VOICE;
			dcc->fd = -1;
			dcc->file_fd = -1;
			dcc->uin = sess->uin;
			dcc->peer_uin = gg_fix32(p->uin_from);
			dcc->cid = p->id;
			dcc->sess = sess;

			if (gg_dcc7_session_add(sess, dcc) == -1) {
				gg_debug_session(sess, GG_DEBUG_MISC, "// gg_dcc7_handle_new() unable to add to session\n");
				gg_dcc7_free(dcc);
				return -1;
			}

			e->type = GG_EVENT_DCC7_NEW;
			e->event.dcc7_new = dcc;

			break;

		default:
			gg_debug_session(sess, GG_DEBUG_MISC, "// gg_dcc7_handle_new() unknown dcc type (%04x) from %ld\n", gg_fix32(p->type), gg_fix32(p->uin_from));

			break;
	}

	return 0;
}

/**
 * \internal Ustawia odpowiednie stany wewnętrzne w zależności od rodzaju
 * połączenia.
 * 
 * \param dcc Struktura połączenia
 *
 * \return 0 jeśli się powiodło, -1 w przypadku błędu.
 */
static int gg_dcc7_postauth_fixup(struct gg_dcc7 *dcc)
{
	if (!dcc) {
		errno = EINVAL;
		return -1;
	}

	switch (dcc->type) {
		case GG_SESSION_DCC7_GET:
			dcc->state = GG_STATE_GETTING_FILE;
			dcc->check = GG_CHECK_READ;
			return 0;

		case GG_SESSION_DCC7_SEND:
			dcc->state = GG_STATE_SENDING_FILE;
			dcc->check = GG_CHECK_WRITE;
			return 0;

		case GG_SESSION_DCC7_VOICE:
			dcc->state = GG_STATE_READING_VOICE_DATA;
			dcc->check = GG_CHECK_READ;
			return 0;
	}

	errno = EINVAL;

	return -1;
}

/**
 * Funkcja wywoływana po zaobserwowaniu zmian na deskryptorze połączenia.
 *
 * Funkcja zwraca strukturę zdarzenia \c gg_event. Jeśli rodzaj zdarzenia
 * to \c GG_EVENT_NONE, nie wydarzyło się jeszcze nic wartego odnotowania.
 * Strukturę zdarzenia należy zwolnić funkcja \c gg_event_free().
 *
 * \param dcc Struktura połączenia
 *
 * \return Struktura zdarzenia lub \c NULL jeśli wystąpił błąd
 *
 * \ingroup dcc7
 */
struct gg_event *gg_dcc7_watch_fd(struct gg_dcc7 *dcc)
{
	struct gg_event *e;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc7_watch_fd(%p);\n", dcc);

	if (!dcc || (dcc->type != GG_SESSION_DCC7_SEND && dcc->type != GG_SESSION_DCC7_GET && dcc->type != GG_SESSION_DCC7_VOICE)) {
		static int shown = 0;

		if (!shown)
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() invalid argument\n");
		shown = 1;
		errno = EINVAL;
		return NULL;
	}

	if (!(e = malloc(sizeof(struct gg_event)))) {
		gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() not enough memory\n");
		return NULL;
	}

	memset(e, 0, sizeof(struct gg_event));
	e->type = GG_EVENT_NONE;

	switch (dcc->state) {
		case GG_STATE_LISTENING:
		{
			struct sockaddr_in sin;
			int fd, one = 1;
			unsigned int sin_len = sizeof(sin);

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_STATE_LISTENING\n");

			if ((fd = accept(dcc->fd, (struct sockaddr*) &sin, &sin_len)) == -1) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() accept() failed (%s)\n", strerror(errno));
				return e;
			}

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() connection from %s:%d\n", inet_ntoa(sin.sin_addr), htons(sin.sin_port));

#ifdef FIONBIO
			if (ioctl(fd, FIONBIO, &one) == -1) {
#else
			if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
#endif
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() can't set nonblocking (%s)\n", strerror(errno));
				close(fd);
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_HANDSHAKE;
				return e;
			}

			close(dcc->fd);
			dcc->fd = fd;

			dcc->state = GG_STATE_READING_ID;
			dcc->check = GG_CHECK_READ;
			dcc->timeout = GG_DEFAULT_TIMEOUT;
			dcc->incoming = 1;

			dcc->remote_port = ntohs(sin.sin_port);
			dcc->remote_addr = sin.sin_addr.s_addr;

			e->type = GG_EVENT_DCC7_CONNECTED;
			e->event.dcc7_connected.dcc7 = dcc;

			return e;
		}

		case GG_STATE_CONNECTING:
		{
			int res = 0, error = 0;
			unsigned int error_size = sizeof(error);

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_STATE_CONNECTING\n");

			dcc->soft_timeout = 0;

			if (dcc->timeout == 0)
				error = ETIMEDOUT;

			if (error || (res = getsockopt(dcc->fd, SOL_SOCKET, SO_ERROR, &error, &error_size)) == -1 || error != 0) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() connection failed (%s)\n", (res == -1) ? strerror(errno) : strerror(error));

				if (gg_dcc7_reverse_connect(dcc) != -1)
					break;
				
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_NET;
				return e;
			}

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() connected, sending id\n");

			dcc->state = GG_STATE_SENDING_ID;
			dcc->check = GG_CHECK_WRITE;
			dcc->timeout = GG_DEFAULT_TIMEOUT;
			dcc->incoming = 0;

			return e;
		}

		case GG_STATE_READING_ID:
		{
			gg_dcc7_id_t id;
			int res;

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_STATE_READING_ID\n");

			if ((res = read(dcc->fd, &id, sizeof(id))) != sizeof(id)) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() read() failed (%d, %s)\n", res, strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_HANDSHAKE;
				return e;
			}

			if (memcmp(&id, &dcc->cid, sizeof(id))) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() invalid id\n");
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_HANDSHAKE;
				return e;
			}

			if (dcc->incoming) {
				dcc->state = GG_STATE_SENDING_ID;
				dcc->check = GG_CHECK_WRITE;
				dcc->timeout = GG_DEFAULT_TIMEOUT;
			} else {
				gg_dcc7_postauth_fixup(dcc);
				dcc->timeout = GG_DEFAULT_TIMEOUT;
			}

			return e;
		}

		case GG_STATE_SENDING_ID:
		{
			int res;

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_SENDING_ID\n");

			if ((res = write(dcc->fd, &dcc->cid, sizeof(dcc->cid))) != sizeof(dcc->cid)) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() write() failed (%d, %s)", res, strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_HANDSHAKE;
				return e;
			}

			if (dcc->incoming) {
				gg_dcc7_postauth_fixup(dcc);
				dcc->timeout = GG_DEFAULT_TIMEOUT;
			} else {
				dcc->state = GG_STATE_READING_ID;
				dcc->check = GG_CHECK_READ;
				dcc->timeout = GG_DEFAULT_TIMEOUT;
			}

			return e;
		}

		case GG_STATE_SENDING_FILE:
		{
			char buf[1024];
			int chunk, res;

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_STATE_SENDING_FILE (offset=%d, size=%d)\n", dcc->offset, dcc->size);

			if (dcc->seek && lseek(dcc->file_fd, dcc->offset, SEEK_SET) == (off_t) -1) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() lseek() failed (%s)\n", strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_FILE;
				return e;
			}

			if ((chunk = dcc->size - dcc->offset) > sizeof(buf))
				chunk = sizeof(buf);

			if ((res = read(dcc->file_fd, buf, chunk)) < 1) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() read() failed (res=%d, %s)\n", res, strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = (res == -1) ? GG_ERROR_DCC7_FILE : GG_ERROR_DCC7_EOF;
				return e;
			}

			if ((res = write(dcc->fd, buf, res)) == -1) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() write() failed (%s)\n", strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_NET;
				return e;
			}

			dcc->offset += res;

			if (dcc->offset >= dcc->size) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() finished\n");
				e->type = GG_EVENT_DCC7_DONE;
				return e;
			}

			dcc->state = GG_STATE_SENDING_FILE;
			dcc->check = GG_CHECK_WRITE;
			dcc->timeout = GG_DCC7_TIMEOUT_SEND;

			return e;
		}

		case GG_STATE_GETTING_FILE:
		{
			char buf[1024];
			int res, wres;

			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_STATE_GETTING_FILE (offset=%d, size=%d)\n", dcc->offset, dcc->size);

			if ((res = read(dcc->fd, buf, sizeof(buf))) < 1) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() read() failed (fd=%d, res=%d, %s)\n", dcc->fd, res, strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = (res == -1) ? GG_ERROR_DCC7_NET : GG_ERROR_DCC7_EOF;
				return e;
			}

			// XXX zapisywać do skutku?

			if ((wres = write(dcc->file_fd, buf, res)) < res) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() write() failed (fd=%d, res=%d, %s)\n", dcc->file_fd, wres, strerror(errno));
				e->type = GG_EVENT_DCC7_ERROR;
				e->event.dcc_error = GG_ERROR_DCC7_FILE;
				return e;
			}

			dcc->offset += res;

			if (dcc->offset >= dcc->size) {
				gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() finished\n");
				e->type = GG_EVENT_DCC7_DONE;
				return e;
			}

			dcc->state = GG_STATE_GETTING_FILE;
			dcc->check = GG_CHECK_READ;
			dcc->timeout = GG_DCC7_TIMEOUT_GET;

			return e;
		}

		default:
		{
			gg_debug(GG_DEBUG_MISC, "// gg_dcc7_watch_fd() GG_STATE_???\n");
			e->type = GG_EVENT_DCC7_ERROR;
			e->event.dcc_error = GG_ERROR_DCC7_HANDSHAKE;

			return e;
		}
	}

	return e;
}

/**
 * Zwalnia zasoby używane przez połączenie bezpośrednie.
 *
 * \param dcc Struktura połączenia
 *
 * \ingroup dcc7
 */
void gg_dcc7_free(struct gg_dcc7 *dcc)
{
	gg_debug(GG_DEBUG_FUNCTION, "** gg_dcc7_free(%p);\n", dcc);

	if (!dcc)
		return;

	if (dcc->fd != -1)
		close(dcc->fd);

	if (dcc->file_fd != -1)
		close(dcc->file_fd);

	if (dcc->sess)
		gg_dcc7_session_remove(dcc->sess, dcc);

	free(dcc);
}
