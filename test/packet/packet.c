#include <stdio.h>
#include <errno.h>
#include "libgadu.h"

int state;
int offset;

struct {
	const char *data;
	int result;
	int errno_;
} input[] = {
	{ "\x01\x00\x00\x00\x00\x00\x00\x00", 8 },

	{ "\x02\x00\x00\x00\x08\x00\x00\x00""ABCDEFGH", 16 },

	{ "\x03\x00\x00\x00\x04\x00\x00\x00", 8 },
	{ "IJKL", 4 },

	{ "", -1, EINTR },

	{ "\x04\x00\x00\x00", 4 },
	{ "", -1, EINTR },
	{ "\x02\x00\x00\x00", 4 },
	{ "MN", 2 },

	{ "\x05\x00", 2 },
	{ "\x00\x00", 2 },
	{ "\x06\x00\x00", 3 },
	{ "\x00", 1 },
	{ "OPQR", 4 },
	{ "ST", 2 },

	{ "\x06", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "\x01", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "\x00", 1 },
	{ "U", 1 },

	{ "\x07\x00\x00\x00", 4 },
	{ "", -1, EINTR },
	{ "\x00\x00\x00\x00", 4 },

	{ "\x08\x00\x00\x00\x00\x00\x00\x01", 8 },

	{ "\x09\x00\x00\x00", 4 },
	{ "", -1, ENOTCONN },

	{ "\x0a\x00\x00\x00\xff\x00\x00\x00", 8 },
	{ "VW", 2 },
	{ "", 0, 0 },

	{ "", 0, 0 },

	{ "", -1, ENOTSOCK },
};

struct {
	int type;
	int length;
	const char *data;
} output[] = {
	{ 1, 0, "" },
	{ 2, 8, "ABCDEFGH" },
	{ 3, 4, "IJKL" },
	{ 4, 2, "MN" },
	{ 5, 6, "OPQRST" },
	{ 6, 1, "U" },
	{ 7, 0, "" },
	{ -1, },
	{ -1, },
	{ -1, },
	{ -1, },
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

	if (result != -1) {
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
		errno = input[state].errno_;
		state++;
	}

	return result;
}

int main(void)
{
	struct gg_session gs;
	int i;

	gg_debug_level = ~0;

	memset(&gs, 0, sizeof(gs));
	gs.fd = 123;

	for (i = 0; i < sizeof(output) / sizeof(output[0]); i++) {
		struct gg_header *gh;

		gh = gg_recv_packet(&gs);

		if (gh == NULL) {
			if (output[i].type != -1) {
				fprintf(stderr, "gg_recv_packet: Returned error (%s), expected success\n", strerror(errno));
				return 1;
			}

			free(gs.recv_buf);
			gs.recv_buf = NULL;
			gs.recv_done = 0;
		} else {
			if (output[i].type == -1) {
				fprintf(stderr, "gg_recv_packet: Returned success, expected error\n");
				return 1;
			}

			if (gh->type != output[i].type) {
				fprintf(stderr, "gg_recv_packet: Expected type %d, received %d\n", output[i].type, gh->type);
				return 1;
			}

			if (gh->length != output[i].length) {
				fprintf(stderr, "gg_recv_packet: Expected length %d, received %d\n", output[i].length, gh->length);
				return 1;
			}

			if (memcmp(((char*) gh) + sizeof(struct gg_header), output[i].data, output[i].length) != 0) {
				fprintf(stderr, "gg_recv_packet: Invalid packet payload\n");
				return 1;
			}

			free(gh);
		}
	}

	fprintf(stderr, "Test succeeded.\n");

	return 0;
}
