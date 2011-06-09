#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "libgadu.h"

enum {
	EXPECT_NOTHING = 0,
	EXPECT_PACKET,
	EXPECT_ERROR
};

int state;
int offset;

struct {
	const char *data;
	int result;

	int expect;
	int type;
	int length;
	const char *expected_data;
} input[] = {
	{ "\x01\x00\x00\x00\x00\x00\x00\x00", 8, EXPECT_PACKET, 1, 0, "" },

	{ "\x02\x00\x00\x00\x08\x00\x00\x00""ABCDEFGH", 16, EXPECT_PACKET, 2, 8, "ABCDEFGH" },

	{ "\x03\x00\x00\x00\x04\x00\x00\x00", 8 },
	{ "IJKL", 4, EXPECT_PACKET, 3, 4, "IJKL" },

	{ "", -EINTR },

	{ "\x04\x00\x00\x00", 4 },
	{ "", -EINTR },
	{ "\x02\x00\x00\x00", 4 },
	{ "MN", 2, EXPECT_PACKET, 4, 2, "MN" },

	{ "\x05\x00", 2 },
	{ "\x00\x00", 2 },
	{ "\x06\x00\x00", 3 },
	{ "\x00", 1 },
	{ "OPQR", 4 },
	{ "ST", 2, EXPECT_PACKET, 5, 6, "OPQRST" },

	{ "\x06", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "\x01", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "U", 1, EXPECT_PACKET, 6, 1, "U" },

	{ "\x07\x00\x00\x00", 4 },
	{ "", -EINTR },
	{ "\x00\x00\x00\x00", 4, EXPECT_PACKET, 7, 0, "" },

	{ "\x08\x00\x00\x00", 4 },
	{ "", -EAGAIN },
	{ "\x04\x00\x00\x00", 4 },
	{ "", -EINTR },
	{ "", -EAGAIN },
	{ "1234", 4, EXPECT_PACKET, 8, 4, "1234" },

	{ "\x09\x00\x00\x00\x00\x00\x00\x01", 8, EXPECT_ERROR },

	{ "\x0a\x00\x00\x00", 4 },
	{ "", -ENOTCONN, EXPECT_ERROR },

	{ "\x0b\x00\x00\x00\xff\x00\x00\x00", 8 },
	{ "VW", 2 },
	{ "", 0, EXPECT_ERROR },

	{ "", 0, EXPECT_ERROR },

	{ "", -ENOTSOCK, EXPECT_ERROR },
};

ssize_t read(int fd, char *buf, size_t len)
{
	ssize_t result;

	if (fd != 123) {
		fprintf(stderr, "read: Invalid descriptor\n");
		errno = EINVAL;
		return -1;
	}

	result = input[state].result;

	if (result > -1) {
		if (result - offset > len) {
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

static void gs_init(struct gg_session *gs)
{
	memset(gs, 0, sizeof(struct gg_session));
	gs->fd = 123;
	gs->state = GG_STATE_CONNECTED;
	gs->timeout = -1;
	gs->resolver_cleanup = resolver_cleanup;
}

int main(void)
{
	struct gg_session gs;

	gg_debug_level = ~0;

	gs_init(&gs);

	for (state = 0; state < sizeof(input) / sizeof(input[0]); ) {
		struct gg_header *gh;

		gh = gg_recv_packet(&gs);

		if (gh == NULL) {
			if (errno == EAGAIN) {
				if (input[state-1].expect != EXPECT_NOTHING) {
					fprintf(stderr, "Returned no event, expected something\n");
					return 1;
				}
			} else {
				if (input[state-1].expect != EXPECT_ERROR) {
					fprintf(stderr, "Returned error (%s) when expected something\n", strerror(errno));
					return 1;
				}

				/* Posprzątaj, bo jedziemy dalej */
				gs_init(&gs);
			}

		} else {
			if (input[state-1].expect != EXPECT_PACKET) {
				fprintf(stderr, "Returned packet, expected \n");
				return 1;
			}

			if (gh->type != input[state-1].type) {
				fprintf(stderr, "Expected type %d, received %d\n", input[state-1].type, gh->type);
				return 1;
			}

			if (gh->length != input[state-1].length) {
				fprintf(stderr, "Expected length %d, received %d\n", input[state-1].length, gh->length);
				return 1;
			}

			if (memcmp(((char*) gh) + sizeof(*gh), input[state-1].expected_data, input[state-1].length) != 0) {
				fprintf(stderr, "Invalid packet payload\n");
				return 1;
			}
		}

		free(gh);
	}

	fprintf(stderr, "Test succeeded.\n");

	return 0;
}
