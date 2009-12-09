#include <stdio.h>
#include <errno.h>
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

	if (state > sizeof(input) / sizeof(input[0])) {
		fprintf(stderr, "read: Exceeded input rules\n");
		errno = EFAULT;
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

int main(void)
{
	struct gg_session gs;
	int i;

	gg_debug_level = ~0;

	memset(&gs, 0, sizeof(gs));
	gs.fd = 123;
	gs.state = GG_STATE_CONNECTED;
	gs.flags = (1 << GG_SESSION_FLAG_RAW_PACKET);
	gs.timeout = -1;
	gs.resolver_cleanup = resolver_cleanup;

	for (i = 0; i < sizeof(input) / sizeof(input[0]); ) {
		struct gg_event *ge;

		ge = gg_watch_fd(&gs);

		if (ge == NULL) {
			if (input[state-1].expect != EXPECT_ERROR) {
				fprintf(stderr, "Returned error (%s) when expected something\n", strerror(errno));
				return 1;
			}

			/* Posprzątaj, bo jedziemy dalej */
			free(gs.recv_buf);
			gs.recv_buf = NULL;
			gs.recv_done = 0;
			gs.fd = 123;
			gs.state = GG_STATE_CONNECTED;
		} else if (ge->type == GG_EVENT_NONE) {
			if (input[state-1].expect != EXPECT_NOTHING) {
				fprintf(stderr, "Returned no event, expected something\n");
				return 1;
			}

			gg_event_free(ge);
		} else if (ge->type == GG_EVENT_RAW_PACKET) {
			if (input[state-1].expect != EXPECT_PACKET) {
				fprintf(stderr, "Returned packet, expected \n");
				return 1;
			}

			if (ge->event.raw_packet.type != input[state-1].type) {
				fprintf(stderr, "Expected type %d, received %d\n", input[state-1].type, ge->event.raw_packet.type);
				return 1;
			}

			if (ge->event.raw_packet.length != input[state-1].length) {
				fprintf(stderr, "Expected length %d, received %d\n", input[state-1].length, ge->event.raw_packet.length);
				return 1;
			}

			if (memcmp(ge->event.raw_packet.data, input[state-1].expected_data, input[state-1].length) != 0) {
				fprintf(stderr, "Invalid packet payload\n");
				return 1;
			}

			gg_event_free(ge);
		} else {
			fprintf(stderr, "Returned invalid event (%d)\n", ge->type);
			return 1;
		}

		i++;
	}

	fprintf(stderr, "Test succeeded.\n");

	return 0;
}
