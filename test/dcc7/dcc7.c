#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libgadu.h>
#include "../../include/compat.h"

#define debug(msg...) \
	do { \
		fprintf(stderr, "\033[1m"); \
		fprintf(stderr, msg); \
		fprintf(stderr, "\033[0m"); \
		fflush(stderr); \
	} while(0)

unsigned int config_uin;
char *config_password;
unsigned int config_peer;
char *config_file;
char *config_dir;
unsigned int config_size = 1048576;
unsigned long config_ip = 0xffffffff;
unsigned int config_port = 0;
unsigned int config_localport = 0;

int test_mode;
int connected;

enum {
	TEST_MODE_SEND = 0,
	TEST_MODE_SEND_NAT,
	TEST_MODE_RECEIVE,
	TEST_MODE_RECEIVE_NAT,
	TEST_MODE_RECEIVE_RESUME,
	TEST_MODE_LAST
};

extern int __connect(int socket, const struct sockaddr *address, socklen_t address_len);

int connect(int socket, const struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in sin;

	if (connected && test_mode == TEST_MODE_SEND_NAT) {
		memcpy(&sin, address, address_len);
		sin.sin_addr.s_addr = INADDR_NONE;
		address = (struct sockaddr*) &sin;
	}

	return __connect(socket, address, address_len);
}

int config_read(void)
{
	char buf[256];
	FILE *f;

	if (!(f = fopen("config", "r"))) {
		if (!(f = fopen("../config", "r")))
			return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		while (strlen(buf) > 0 && isspace(buf[strlen(buf) - 1]))
			buf[strlen(buf) - 1] = 0;

		if (!strncmp(buf, "uin ", 4))
			config_uin = atoi(buf + 4);

		if (!strncmp(buf, "password ", 9))
			config_password = strdup(buf + 9);

		if (!strncmp(buf, "peer ", 5))
			config_peer = atoi(buf + 5);

		if (!strncmp(buf, "file ", 5))
			config_file = strdup(buf + 5);

		if (!strncmp(buf, "dir ", 4))
			config_dir = strdup(buf + 4);

		if (!strncmp(buf, "size ", 5))
			config_size = atoi(buf + 5);

		if (!strncmp(buf, "ip ", 3))
			config_ip = inet_addr(buf + 3);

		if (!strncmp(buf, "port ", 5))
			config_port = atoi(buf + 5);

		if (!strncmp(buf, "localport ", 10))
			config_localport = atoi(buf + 10);
	}

	fclose(f);

	if (!config_uin || !config_password || !config_peer)
		return -1;

	return 0;
}

void config_free(void)
{
	free(config_password);
	free(config_file);
}

int main(int argc, char **argv)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	struct gg_dcc7 *gd = NULL;
	time_t ping = 0, last = 0;
	int fds[2] = { -1, -1 };

	if (argc != 2 || atoi(argv[1]) >= TEST_MODE_LAST) {
		fprintf(stderr, "usage: %s <mode>\n"
				"\n"
				"mode: 0 - send file\n"
				"      1 - send file, simulate NAT\n"
				"      2 - receive file\n"
				"      3 - receive file, simulate NAT\n"
				"      4 - receive file, resume at the end\n"
				"\n", argv[0]);
		exit(1);
	}

	test_mode = atoi(argv[1]);

	if (config_read() == -1) {
		perror("config");
		exit(1);
	}

	signal(SIGPIPE, SIG_IGN);
	gg_debug_file = stdout;
	gg_debug_level = ~0;

	if (!config_file && pipe(fds) == -1) {
		perror("pipe");
		exit(1);
	}

	memset(&glp, 0, sizeof(glp));
	glp.uin = config_uin;
	glp.password = config_password;
	glp.async = 1;
	glp.external_addr = config_ip;
	glp.external_port = config_port;
	glp.client_port = config_localport;
	glp.protocol_version = 0x2e;

	gg_dcc_ip = config_ip;

	if (config_dir && (test_mode == TEST_MODE_RECEIVE || test_mode == TEST_MODE_RECEIVE_NAT || test_mode == TEST_MODE_RECEIVE_RESUME)) {
		if (chdir(config_dir) == -1) {
			perror("chdir");
			exit(1);
		}
	}

	debug("Connecting...\n");

	if (!(gs = gg_login(&glp))) {
		perror("gg_login");
		exit(1);
	}

	for (;;) {
		fd_set rds, wds;
		struct timeval tv;
		time_t now;
		int res, maxfd = -1;

		FD_ZERO(&rds);
		FD_ZERO(&wds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		maxfd = gs->fd;

		if ((gs->check & GG_CHECK_READ))
			FD_SET(gs->fd, &rds);

		if ((gs->check & GG_CHECK_WRITE))
			FD_SET(gs->fd, &wds);

		if (gd && gd->fd != -1) {
			if (gd->fd > maxfd)
				maxfd = gd->fd;

			if ((gd->check & GG_CHECK_READ))
				FD_SET(gd->fd, &rds);

			if ((gd->check & GG_CHECK_WRITE))
				FD_SET(gd->fd, &wds);
		}

		if (fds[1] != -1) {
			if (fds[1] > maxfd)
				maxfd = fds[1];

			FD_SET(fds[1], &wds);
		}

		if ((res = select(maxfd + 1, &rds, &wds, NULL, &tv)) == -1) {
			if (errno == EINTR)
				continue;

			perror("select");
			exit(1);
		}

		now = time(NULL);

		if (last != now) {
			if (gs->timeout != -1 && gs->timeout-- == 0 && !gs->soft_timeout) {
				debug("Timeout\n");
				exit(1);
			}

			if (gd && gd->timeout != -1 && gd->timeout-- == 0 && !gd->soft_timeout) {
				debug("Timeout\n");
				exit(1);
			}

			last = now;
		}

		if (gs->state == GG_STATE_CONNECTED && ping && now - ping > 60) {
			ping = now;
			gg_ping(gs);
		}

		if (FD_ISSET(gs->fd, &rds) || FD_ISSET(gs->fd, &wds) || (gs->timeout == 0 && gs->soft_timeout)) {
			struct gg_event *ge;
			uin_t uin;
			int status;

			if (!(ge = gg_watch_fd(gs))) {
				debug("Connection broken\n");
				exit(1);
			}

			switch (ge->type) {
				case GG_EVENT_CONN_SUCCESS:
					debug("Connected\n");
					connected = 1;
					gg_notify(gs, &config_peer, 1);

					if (test_mode == TEST_MODE_RECEIVE_NAT)
						gs->client_addr = INADDR_NONE;

					ping = time(NULL);

					break;

				case GG_EVENT_CONN_FAILED:
					debug("Connection failed\n");
					exit(1);

				case GG_EVENT_NONE:
					break;

				case GG_EVENT_MSG:
					debug("Message from %d: %s\n", ge->event.msg.sender, ge->event.msg.message);
					break;

				case GG_EVENT_DISCONNECT:
					debug("Forced to disconnect\n");
					exit(1);

				case GG_EVENT_NOTIFY60:
					uin = ge->event.notify60[0].uin;
					status = ge->event.notify60[0].status;
					/* fall-through */

				case GG_EVENT_STATUS60:
					if (ge->type == GG_EVENT_STATUS60) {
						uin = ge->event.status60.uin;
						status = ge->event.status60.status;
					}

					if (uin == config_peer && (GG_S_A(status) || GG_S_B(status)) && (test_mode == TEST_MODE_SEND || test_mode == TEST_MODE_SEND_NAT)) {
						debug("Sending file...\n");
					
						if (config_file)
							gd = gg_dcc7_send_file(gs, config_peer, config_file, NULL, NULL);
						else
							gd = gg_dcc7_send_file_fd(gs, config_peer, fds[0], config_size, "test.bin", "DummySHA1HashOfAAAAA");

						if (!gd) {
							perror("gg_dcc7_send_file");
							exit(1);
						}
					}

					break;

				case GG_EVENT_DCC7_NEW:
					debug("Incoming direct connection\n");

					if (test_mode == TEST_MODE_RECEIVE || test_mode == TEST_MODE_RECEIVE_NAT || test_mode == TEST_MODE_RECEIVE_RESUME) {
						gd = ge->event.dcc7_new;
						if (config_dir) {
							gd->file_fd = open((char*) gd->filename, O_WRONLY | O_CREAT, 0600);
//							lseek(gd->file_fd, gd->size, SEEK_SET);
						} else 
							gd->file_fd = open("/dev/null", O_WRONLY);
						if (gd->file_fd == -1) {
							perror("open");
							exit(1);
						}
						if (test_mode != TEST_MODE_RECEIVE_RESUME)
							gg_dcc7_accept(gd, 0);
						else
							gg_dcc7_accept(gd, gd->size);
					}

					break;
				
				case GG_EVENT_DCC7_ERROR:
					debug("Direct connection error\n");
					exit(1);

				case GG_EVENT_DCC7_ACCEPT:
					debug("Accepted\n");
					break;

				case GG_EVENT_DCC7_CONNECTED:
					debug("Connected\n");
					break;

				case GG_EVENT_DCC7_PENDING:
					debug("Pending ...\n");
					break;

				case GG_EVENT_DCC7_REJECT:
					debug("Rejected\n");
					exit(1);

				default:
					debug("Unsupported event %d\n", ge->type);
					break;
			}

			gg_event_free(ge);
		}

		if (gd && gd->fd != -1 && (FD_ISSET(gd->fd, &rds) || FD_ISSET(gd->fd, &wds) || (gd->timeout == 0 && gd->soft_timeout))) {
			struct gg_event *ge;

			if (!(ge = gg_dcc7_watch_fd(gd))) {
				debug("Direct connection broken\n");
				exit(1);
			}

			switch (ge->type) {
				case GG_EVENT_DCC7_ERROR:
					debug("Direct connection error\n");
					exit(1);

				case GG_EVENT_DCC7_CONNECTED:
					debug("Direct connection established\n");
					break;

				case GG_EVENT_DCC7_DONE:
					debug("Finished");
					gg_event_free(ge);
					gg_dcc7_free(gd);
					gg_free_session(gs);
					config_free();
					exit(1);

				case GG_EVENT_NONE:
					break;

				default:
					debug("Unsupported event %d\n", ge->type);
					break;
			}

			gg_event_free(ge);
		}

		if (fds[1] != -1 && FD_ISSET(fds[1], &wds)) {
			char buf[4096];

			memset(buf, 'A', sizeof(buf));

			if (write(fds[1], buf, sizeof(buf)) < 1) {
				perror("write");
				exit(1);
			}
		}
	}

	return 0;
}

