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
#include <sys/signal.h>
#include <netinet/in.h>
#include <netdb.h>

#include <libgadu.h>

#define LOCALHOST "127.0.67.67"
#define LOCALPORT 17219

#define TEST_MAX 100

enum {
	FLAG_SERVER = 1
};

/** Port plugged flags */
int plugs[3];

/** Resolver enabled flag */
int resolve;

/** Server pid, duh */
int server_pid;

int test_errors;
int test_failed[TEST_MAX];

static inline void set32(char *ptr, unsigned int value)
{
	unsigned char *tmp = (unsigned char*) ptr;

	tmp[0] = value & 255;
	tmp[1] = (value >> 8) & 255;
	tmp[2] = (value >> 16) & 255;
	tmp[3] = (value >> 24) & 255;
}

static inline unsigned int get32(char *ptr)
{
	unsigned char *tmp = (unsigned char*) ptr;

	return tmp[0] | (tmp[1] << 8) | (tmp[2] << 16) | (tmp[3] << 24);
}

void failure(void) __attribute__ ((noreturn));

void failure(void)
{
	if (getpid() == server_pid) {
		kill(getppid(), SIGTERM);
	} else {
		kill(server_pid, SIGTERM);
	}
	
	exit(0);
}

void debug(const char *fmt, ...)
{
	char buf[4096];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fprintf(stderr, "\033[1m%s\033[0m", buf);
	fflush(stderr);
}

extern int __connect(int socket, const struct sockaddr *address, socklen_t address_len);
extern struct hostent *__gethostbyname(const char *name);
int __gethostbyname_r(const char *name,  struct hostent *ret, char *buf,
size_t buflen,  struct hostent **result, int *h_errnop);

int port_to_index(int port)
{
	switch (port) {
		case 80:
			return 0;
		case 443:
			return 1;
		case 8074:
			return 2;
		default:
			debug("Invalid port %d, terminating\n", port);
			failure();
	}
}

void port_plug(int port)
{
	plugs[port_to_index(port)] = 1;
}

void port_unplug(int port)
{
	plugs[port_to_index(port)] = 0;
}

struct hostent *gethostbyname(const char *name)
{
	static struct hostent he;
	static struct in_addr addr;
	static char *addr_list[2];
	static char sname[128];

	if (!resolve) {
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}

	if (strcmp(name, GG_APPMSG_HOST)) {
		debug("Invalid argument for gethostbyname(): \"%s\"\n", name);
		errno = EINVAL;
		return NULL;
	}

	addr_list[0] = (char*) &addr;
	addr_list[1] = NULL;
	addr.s_addr = inet_addr(LOCALHOST);

	strncpy(sname, name, sizeof(sname) - 1);
	sname[sizeof(sname) - 1] = 0;

	memset(&he, 0, sizeof(he));
	he.h_name = sname;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(struct in_addr);
	he.h_addr_list = addr_list;
	
	return &he;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	if (buflen < sizeof(struct hostent)) {
		errno = ERANGE;
		*result = NULL;
		return -1;
	}

	*result = gethostbyname(name);
	*h_errnop = h_errno;

	return (*result) ? 0 : -1;
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in sin;

	if (address_len < sizeof(sin)) {
		debug("Invalid argument for connect(): sa_len < %d\n", sizeof(sin));
		errno = EINVAL;
		return -1;
	}

	memcpy(&sin, address, address_len);

	printf("connect(%s, %d)\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

	if (sin.sin_family != AF_INET) {
		debug("Invalid argument for connect(): sa_family = %d\n", sin.sin_family);
		errno = EINVAL;
		return -1;
	}

	if (sin.sin_addr.s_addr != inet_addr(LOCALHOST)) {
		debug("Invalid argument for connect(): sin_addr = %s\n", inet_ntoa(sin.sin_addr));
		errno = EINVAL;
		return -1;
	}

	switch (ntohs(sin.sin_port)) {
		case 80:
		case 443:
		case 8074:
		{
			int idx = port_to_index(ntohs(sin.sin_port));

			if (plugs[idx])
				idx = 3;

			sin.sin_port = htons(LOCALPORT + idx);

			break;
		}

		default:
			debug("Invalid argument for connect(): sin_port = %d\n", ntohs(sin.sin_port));
			errno = EINVAL;
			return -1;
	}

	return __connect(socket, (struct sockaddr*) &sin, address_len);
}

int try_connect(int async, int flags)
{
	struct gg_session *gs;
	struct gg_login_params glp;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "dupa.8";
	glp.async = async;

	if ((flags & FLAG_SERVER)) {
		glp.server_addr = inet_addr(LOCALHOST);
	}

	gs = gg_login(&glp);

	if (!async) {
		if (!gs)
			return 0;

		gg_free_session(gs);
		return 1;
	} else {
		if (!gs)
			return 0;

		for (;;) {
			struct timeval tv;
			fd_set rd, wr;
			int res;

			FD_ZERO(&rd);
			FD_ZERO(&wr);

			if ((gs->check & GG_CHECK_READ))
				FD_SET(gs->fd, &rd);

			if ((gs->check & GG_CHECK_WRITE))
				FD_SET(gs->fd, &wr);

			if ((gs->timeout)) {
				tv.tv_sec = gs->timeout;
				tv.tv_usec = 0;
			}

			res = select(gs->fd + 1, &rd, &wr, NULL, (gs->timeout) ? &tv : NULL);
			
			if (!res) {
				debug("Timeout\n");
				gg_free_session(gs);
				return 0;
			}

			if (res == -1 && errno != EINTR) {
				debug("select() failed: %s\n", strerror(errno));
				gg_free_session(gs);
				return 0;
			}

			if (FD_ISSET(gs->fd, &rd) || FD_ISSET(gs->fd, &wr)) {
				struct gg_event *ge;
				
				ge = gg_watch_fd(gs);

				if (!ge) {
					debug("gg_watch_fd failure\n");
					gg_free_session(gs);
					return 0;
				}

				switch (ge->type) {
					case GG_EVENT_CONN_SUCCESS:
						gg_event_free(ge);
						gg_free_session(gs);
						return 1;

					case GG_EVENT_CONN_FAILED:
						gg_event_free(ge);
						gg_free_session(gs);
						return 0;

					case GG_EVENT_NONE:
						break;

					default:
						debug("Unknown event %d\n", ge->type);
						gg_event_free(ge);
						gg_free_session(gs);
						return 0;
				}

				gg_event_free(ge);
			}
		}
	}
}

void test_run(int num, int result, int flags, const char *desc)
{
	if (num > TEST_MAX) {
		debug("%d > TEST_MAX\n", num);
		failure();
	}

	printf("\n------------------------------------------------------------------------------\n");
	printf(" Test %d\n", num);
	if (desc)
		printf(" Description: %s\n", desc);
	printf(" Expected result: %s\n", (result) ? "success" : "failure");
	printf("------------------------------------------------------------------------------\n");

	if (!!try_connect(0, flags) != !!result) {
		test_errors++;
		test_failed[num - 1] = 1;
		debug("Test %d failed in synchronous mode\n", num);
	}

	if (!!try_connect(1, flags) != !!result) {
		test_errors++;
		test_failed[num - 1] = 1;
		debug("Test %d failed in asynchronous mode\n", num);
	}
}

void test_reset(void)
{
	memset(plugs, 0, sizeof(plugs));
	resolve = 1;
}

void serve(void)
{
	int sfds[4];
	int cfds[2] = { -1, -1 };
	time_t started[3];
	int i;
	char buf[4096];
	int len;

	for (i = 0; i < 4; i++) {
		struct sockaddr_in sin;
		int value = 1;

		if ((sfds[i] = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			failure();
		}

		setsockopt(sfds[i], SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(LOCALPORT + i);
		sin.sin_addr.s_addr = inet_addr(LOCALHOST);

		if (bind(sfds[i], (struct sockaddr*) &sin, sizeof(sin))) {
			perror("bind");
			failure();
		}

		if (i != 3 && listen(sfds[i], 1)) {
			perror("listen");
			failure();
		}
	}

	for (;;) {
		struct timeval tv;
		fd_set rd, wr;
		int max = -1;
		int res;

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&rd);
		FD_ZERO(&wr);

		for (i = 0; i < 3; i++) {
			FD_SET(sfds[i], &rd);

			if (sfds[i] > max)
				max = sfds[i];

			if (cfds[i] != -1) {
				FD_SET(cfds[i], &rd);
				
				if (cfds[i] > max)
					max = cfds[i];
			}
		}

		res = select(max + 1, &rd, &wr, NULL, &tv);

		if (res == -1 && errno != EINTR) {
			debug("select() failed: %s\n", strerror(errno));
			kill(getppid(), SIGTERM);
			return;
		}

		for (i = 0; i < 2; i++) {
			if (cfds[i] == -1)
				continue;
			
			if (time(NULL) - started[i] > 5) {
				debug("Timeout!\n");
				close(cfds[i]);
				cfds[i] = -1;
			}
		}

		for (i = 0; i < 3; i++) {
			if (FD_ISSET(sfds[i], &rd)) {
				struct sockaddr_in sin;
				socklen_t sin_len;
				int j;
					
				j = (i == 2) ? 1 : i;
				
				if (cfds[j] != -1)
					close(cfds[j]);

				cfds[j] = accept(sfds[i], (struct sockaddr*) &sin, &sin_len);
				memset(buf, 0, sizeof(buf));
				len = 0;
				started[j] = time(NULL);

				if (j == 1) {
					char seed[12];

					set32(seed, GG_WELCOME);
					set32(seed + 4, 4);
					set32(seed + 8, 0x12345678);

					write(cfds[j], seed, sizeof(seed));
				}
			}
		}

		if (cfds[0] != -1 && FD_ISSET(cfds[0], &rd)) {
			int res;

			res = read(cfds[0], buf + len, sizeof(buf) - len - 1);

			if (res > 0) {
				buf[len + res] = 0;
				len += res;

				if (strstr(buf, "\r\n\r\n")) {
					snprintf(buf, sizeof(buf), "HTTP/1.0 200 OK\r\n\r\n0 %s:%d %s\r\n", LOCALHOST, 8074, LOCALHOST);
					write(cfds[0], buf, strlen(buf));
					close(cfds[0]);
					cfds[0] = -1;
				}
			} else {
				close(cfds[0]);
				cfds[0] = -1;
			}
		}

		if (cfds[1] != -1 && FD_ISSET(cfds[1], &rd)) {
			int res;

			res = read(cfds[1], buf + len, sizeof(buf) - len);

			if (res > 0) {
				len += res;

				if (len > 8 && len >= get32(buf + 4)) {
					char ok[8];

					set32(ok, GG_LOGIN_OK);
					set32(ok + 4, 0);

					write(cfds[1], ok, sizeof(ok));
				}
			} else {
				close(cfds[0]);
				cfds[0] = -1;
			}
		}
	}
}

void cleanup(int sig)
{
	kill(server_pid, SIGTERM);
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	gg_debug_file = stdout;
	gg_debug_level = ~0;

	if ((server_pid = fork()) == -1) {
		perror("fork");
		failure();
	}

	if (!server_pid) {
		serve();
		exit(0);
	}

	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGQUIT, cleanup);

	/* Test 1 */

	test_reset();
	resolve = 0;
	test_run(1, 0, 0, "Resolver failure");

	/* Test 2 */

	test_reset();
	port_plug(80);
	port_plug(443);
	port_plug(8074);
	test_run(2, 0, 0, "All ports closed");

	/* Test 3 */

	test_reset();
	test_run(3, 1, 0, "Regular connection");

	/* Test 4 */

	test_reset();
	port_plug(8074);
	test_run(4, 1, 0, "Fallback to port 443");

	/* Test 5 */

	test_reset();
	port_plug(80);
	test_run(5, 1, 0, "Fallback to hub address if it's down");

	printf("\n------------------------------------------------------------------------------\n");
	printf(" Error count: %d\n", test_errors);
	if (test_errors > 0) {
		int i, first = 1;

		printf(" Failed tests: ");

		for (i = 0; i < TEST_MAX; i++) {
			if (!test_failed[i])
				continue;

			if (!first)
				printf(", ");
			first = 0;
			printf("%d", i + 1);
		}

		printf("\n");
	}
	printf("------------------------------------------------------------------------------\n");

	return 0;
}

