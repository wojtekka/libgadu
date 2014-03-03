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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "libgadu.h"
#include "network.h"
#include "internal.h"

enum {
	EXPECT_NOTHING = 0,
	EXPECT_PACKET,
	EXPECT_ERROR,
	EXPECT_EAGAIN,
};

int state;
int offset;
int expected_packet;
static int recv_called = 0;
static int send_called = 0;

struct {
	const char *data;
	int result;

	int expect;
	uint32_t type;
	uint32_t length;
	const char *expected_data;
} input[] = {
	{ "\x01\x00\x00\x00\x00\x00\x00\x00", 8, EXPECT_PACKET, 1, 0, "" },

	{ "\x02\x00\x00\x00\x08\x00\x00\x00""ABCDEFGH", 16, EXPECT_PACKET, 2, 8, "ABCDEFGH" },

	{ "\x03\x00\x00\x00\x04\x00\x00\x00", 8, EXPECT_NOTHING, 0, 0, NULL },
	{ "IJKL", 4, EXPECT_PACKET, 3, 4, "IJKL" },

	{ "", -EINTR, EXPECT_NOTHING, 0, 0, NULL },

	{ "\x04\x00\x00\x00", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "", -EINTR, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x02\x00\x00\x00", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "MN", 2, EXPECT_PACKET, 4, 2, "MN" },

	{ "\x05\x00", 2, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00\x00", 2, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x06\x00\x00", 3, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "OPQR", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "ST", 2, EXPECT_PACKET, 5, 6, "OPQRST" },

	{ "\x06", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x01", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00", 1, EXPECT_NOTHING, 0, 0, NULL },
	{ "U", 1, EXPECT_PACKET, 6, 1, "U" },

	{ "\x07\x00\x00\x00", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "", -EINTR, EXPECT_NOTHING, 0, 0, NULL },
	{ "\x00\x00\x00\x00", 4, EXPECT_PACKET, 7, 0, "" },

	{ "\x08\x00\x00\x00", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "", -EAGAIN, EXPECT_EAGAIN, 0, 0, NULL },
	{ "\x04\x00\x00\x00", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "", -EINTR, EXPECT_NOTHING, 0, 0, NULL },
	{ "", -EAGAIN, EXPECT_EAGAIN, 0, 0, NULL },
	{ "1234", 4, EXPECT_PACKET, 8, 4, "1234" },

	{ "\x09\x00\x00\x00\x00\x00\x00\x01", 8, EXPECT_ERROR, 0, 0, NULL },

	{ "\x0a\x00\x00\x00", 4, EXPECT_NOTHING, 0, 0, NULL },
	{ "", -ENOTCONN, EXPECT_ERROR, 0, 0, NULL },

	{ "\x0b\x00\x00\x00\xff\x00\x00\x00", 8, EXPECT_NOTHING, 0, 0, NULL },
	{ "VW", 2, EXPECT_NOTHING, 0, 0, NULL },
	{ "", 0, EXPECT_ERROR, 0, 0, NULL },

	{ "", 0, EXPECT_ERROR, 0, 0, NULL },

	{ "", -ENOTSOCK, EXPECT_ERROR, 0, 0, NULL },
};

#undef recv
#ifdef _WIN32
static int my_recv(SOCKET fd, char *buf, int len, int flags)
#else
ssize_t recv(int fd, void *buf, size_t len, int flags)
#endif
{
	ssize_t result;

	recv_called = 1;

	if (fd != 123) {
		fprintf(stderr, "recv: Invalid descriptor\n");
		errno = EINVAL;
		return -1;
	}

	if (input[state].expect == EXPECT_PACKET)
		expected_packet = 1;

	result = input[state].result;

	if (result > -1 && result - offset >= 0) {
		if ((size_t)(result - offset) > (size_t)len) {
			memcpy(buf, input[state].data + offset, len);
			offset += len;
			result = len;
		} else {
			memcpy(buf, input[state].data + offset, result - offset);
			result -= offset;

			state++;
			offset = 0;
		}
	} else {
		errno = -input[state].result;
		result = -1;
		state++;
	}

	return result;
}

static void resolver_cleanup(void **priv_data, int force)
{

}

static void gs_init(struct gg_session *gs, struct gg_session_private *gsp, int async)
{
	memset(gsp, 0, sizeof(struct gg_session_private));
	memset(gs, 0, sizeof(struct gg_session));
	gs->private_data = gsp;
	gs->fd = 123;
	gs->state = GG_STATE_CONNECTED;
	gs->timeout = -1;
	gs->resolver_cleanup = resolver_cleanup;
	gs->async = async;
}

/* TODO: napisać test na r1324 */
static void test_recv_packet(void)
{
	struct gg_session gs;
	struct gg_session_private gsp;

	gg_debug_level = ~0;

	gs_init(&gs, &gsp, 0);

	for (state = 0; (size_t)state < sizeof(input) / sizeof(input[0]); ) {
		struct gg_header *gh;

		expected_packet = 0;

		gh = gg_recv_packet(&gs);

		if (!recv_called) {
			fprintf(stderr, "recv hook not called\n");
			exit(1);
		}

		if (gh == NULL) {
			if (expected_packet) {
				fprintf(stderr, "Returned nothing, expected packet\n");
				exit(1);
			}

			if (errno == EAGAIN) {
				if (input[state-1].expect != EXPECT_EAGAIN) {
					fprintf(stderr, "Returned no event, expected something\n");
					exit(1);
				}
			} else {
				if (input[state-1].expect != EXPECT_ERROR) {
					fprintf(stderr, "Returned error (%s) "
						"when expected something\n",
						strerror(errno));
					exit(1);
				}

				/* Posprzątaj, bo jedziemy dalej */
				gs_init(&gs, &gsp, 0);
			}

		} else {
			if (input[state-1].expect != EXPECT_PACKET) {
				fprintf(stderr, "Returned packet, expected \n");
				exit(1);
			}

			if (gh->type != input[state-1].type) {
				fprintf(stderr, "Expected type %d, received %d\n", input[state-1].type, gh->type);
				exit(1);
			}

			if (gh->length != input[state-1].length) {
				fprintf(stderr, "Expected length %d, received %d\n", input[state-1].length, gh->length);
				exit(1);
			}

			if (memcmp(((char*) gh) + sizeof(*gh),
				input[state-1].expected_data,
				input[state-1].length) != 0)
			{
				fprintf(stderr, "Invalid packet payload\n");
				exit(1);
			}
		}

		free(gh);
	}

	fprintf(stderr, "Test succeeded.\n");
}

static unsigned int send_state = 0;

struct {
	const char *expect_buf;
	size_t expect_len;
	ssize_t result_value;
	int result_errno;
} send_list[] = {
	{ "\x34\x12\x00\x00\x06\x00\x00\x00""ABCDEF", 14, 14, 0 },
	{ "\x45\x23\x00\x00\x03\x00\x00\x00""GHI", 11, -1, ETIMEDOUT },
	{ "\x56\x34\x00\x00\x06\x00\x00\x00""JKLMNO", 14, -1, EINTR },
	{ "\x56\x34\x00\x00\x06\x00\x00\x00""JKLMNO", 14, 8, 0 },
	{ "\x67\x45\x00\x00\x06\x00\x00\x00""PQRSTU", 14, -1, EAGAIN },
};

#undef send
#ifdef _WIN32
static int my_send(SOCKET fd, const char *buf, int len, int flags)
#else
ssize_t send(int fd, const void *buf, size_t len, int flags)
#endif
{
	ssize_t res;

	send_called = 1;

	if (send_state >= sizeof(send_list) / sizeof(send_list[0])) {
		fprintf(stderr, "Unexpected send\n");
		exit(1);
	}

	if ((size_t)len != send_list[send_state].expect_len) {
		fprintf(stderr, "Expected %d bytes instead of %d\n", (int) send_list[send_state].expect_len, (int) len);
		exit(1);
	}

	if (memcmp(buf, send_list[send_state].expect_buf, len) != 0) {
		fprintf(stderr, "Invalid data\n");
		exit(1);
	}

	errno = send_list[send_state].result_errno;
	res = send_list[send_state].result_value;
	send_state++;

	printf("send(%d, %p, %d, %d) = %d\n", (int)fd, buf, (int) len, flags, (int) res);

	return res;
}

static void test_send_packet(void)
{
	struct gg_session gs;
	struct gg_session_private gsp;

	gs_init(&gs, &gsp, 1);

	/* Poprawne wysyłanie */

	if (gg_send_packet(&gs, 0x1234, "ABC", 3, "DEF", 3, NULL) != 0) {
		if (!send_called)
			fprintf(stderr, "send hook not called\n");
		else
			fprintf(stderr, "Expected success\n");
		exit(1);
	}

	if (gs.send_buf != NULL || gs.send_left != 0) {
		fprintf(stderr, "Unexpected queue\n");
		exit(1);
	}

	/* Błąd wysyłania */

	if (gg_send_packet(&gs, 0x2345, "GHI", 3, NULL) != -1) {
		fprintf(stderr, "Expected failure\n");
		exit(1);
	}

	if (gs.send_buf != NULL || gs.send_left != 0) {
		fprintf(stderr, "Unexpected queue\n");
		exit(1);
	}

	/* EINTR na początek, niech wznowi i potem niekompletna transmisja */

	if (gg_send_packet(&gs, 0x3456, "JKLMNO", 6, NULL) != 0) {
		fprintf(stderr, "Expected success\n");
		exit(1);
	}

	if (gs.send_buf == NULL || gs.send_left != 6 || memcmp(gs.send_buf, "JKLMNO", 6) != 0) {
		fprintf(stderr, "Not queued properly\n");
		exit(1);
	}

	free(gs.send_buf);

	/* EAGAIN na początek */

	gs_init(&gs, &gsp, 1);

	if (gg_send_packet(&gs, 0x4567, "PQRSTU", 6, NULL) != 0) {
		fprintf(stderr, "Expected success\n");
		exit(1);
	}

	if (gs.send_buf == NULL || gs.send_left != 14 || memcmp(gs.send_buf,
		"\x67\x45\x00\x00\x06\x00\x00\x00""PQRSTU", 14) != 0)
	{
		fprintf(stderr, "Not queued properly\n");
		exit(1);
	}

	/* Wyślij jeszcze trochę, żeby dodało do kolejki */

	if (gg_send_packet(&gs, 0x5678, "VWX", 3, NULL) != 0) {
		fprintf(stderr, "Expected success\n");
		exit(1);
	}

	if (gs.send_buf == NULL || gs.send_left != 25 || memcmp(gs.send_buf,
		"\x67\x45\x00\x00\x06\x00\x00\x00""PQRSTU""\x78\x56\x00\x00\x03"
		"\x00\x00\x00""VWX", 25) != 0)
	{
		fprintf(stderr, "Not queued properly\n");
		exit(1);
	}

	free(gs.send_buf);

	/* Sprawdź, czy wszystko już sprawdzone */

	if (send_state != sizeof(send_list) / sizeof(send_list[0])) {
		fprintf(stderr, "More sends expected\n");
		exit(1);
	}

	fprintf(stderr, "Test succeeded.\n");
}

#ifdef _WIN32

static int my_get_last_error(void)
{
	return errno;
}

#endif

int main(void)
{
#ifdef _WIN32
	gg_win32_hook(WSAGetLastError, my_get_last_error, NULL);
	gg_win32_hook(recv, my_recv, NULL);
	gg_win32_hook(send, my_send, NULL);
#endif

	test_recv_packet();
	test_send_packet();

	return 0;
}
