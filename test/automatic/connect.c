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
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>

#include <libgadu.h>

#define LOCALHOST "127.0.67.67"
#define LOCALPORT 17219
#define UNREACHABLE "192.0.2.1"	/* documentation and example class, RFC 3330 */

#define TEST_MAX (3*3*3*3*2)

enum {
	FLAG_SERVER = 1,
};

enum {
	PLUG_NONE = 0,
	PLUG_RESET = 1,
	PLUG_TIMEOUT = 2
};

/** Port and resolver plug flags */
int plug_80, plug_443, plug_8074, plug_resolver;

/** Flags telling which actions libgadu */
int tried_80, tried_443, tried_8074, tried_resolver;

/** Asynchronous mode flag */
int async_mode;

/** Server process id, duh! */
int server_pid = -1;

/** Report file */
FILE *log_file;

/** Log buffer */
char *log_buffer;

static void debug_handler(int level, const char *format, va_list ap)
{
	char buf[4096], *tmp;
	int len = (log_buffer) ? strlen(log_buffer) : 0;

	if (vsnprintf(buf, sizeof(buf), format, ap) >= sizeof(buf) - 1) {
		fprintf(stderr, "Increase temporary log buffer size!\n");
		return;
	}

	if (!(tmp = realloc(log_buffer, len + strlen(buf) + 1))) {
		fprintf(stderr, "Out of memory for log buffer!\n");
		return;
	}

	if (log_buffer) {
		log_buffer = tmp;
		strcat(log_buffer, buf);
	} else {
		log_buffer = tmp;
		strcpy(log_buffer, buf);
	}
}

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
	if (server_pid == 0) {
		kill(getppid(), SIGTERM);
	} else if (server_pid != -1) {
		kill(server_pid, SIGTERM);
		printf("\n");
	}
	
	exit(0);
}

void debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	debug_handler(0, "\001", ap);
	debug_handler(0, fmt, ap);
	debug_handler(0, "\002", ap);
	va_end(ap);
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
		case 8074:
			return 1;
		case 443:
			return 2;
		default:
			debug("Invalid port %d, terminating\n", port);
			failure();
	}
}

struct hostent *gethostbyname(const char *name)
{
	static struct hostent he;
	static struct in_addr addr;
	static char *addr_list[2];
	static char sname[128];

	tried_resolver = 1;

	if (plug_resolver != PLUG_NONE) {
		if (plug_resolver == PLUG_TIMEOUT) {
			if (async_mode)
				sleep(30);
			h_errno = TRY_AGAIN;
		} else {
			h_errno = HOST_NOT_FOUND;
		}
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
	int result, plug, port;

	if (address_len < sizeof(sin)) {
		debug("Invalid argument for connect(): sa_len < %d\n", sizeof(sin));
		errno = EINVAL;
		return -1;
	}

	memcpy(&sin, address, address_len);

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
			plug = plug_80;
			port = LOCALPORT;
			tried_80 = 1;
			break;
		case 443:
			plug = plug_443;
			port = LOCALPORT + 1;
			tried_443 = 1;
			break;
		case 8074:
			plug = plug_8074;
			port = LOCALPORT + 2;
			tried_8074 = 1;
			break;
		default:
			debug("Invalid argument for connect(): sin_port = %d\n", ntohs(sin.sin_port));
			errno = EINVAL;
			return -1;
	}

	switch (plug) {
		case PLUG_NONE:
			sin.sin_port = htons(port);
			break;
		case PLUG_RESET:
			sin.sin_port = htons(LOCALPORT + 3);
			break;
		case PLUG_TIMEOUT:
			if (!async_mode) {
				errno = ETIMEDOUT;
				return -1;
			}

			sin.sin_addr.s_addr = inet_addr(UNREACHABLE);
			break;
	}

	result =  __connect(socket, (struct sockaddr*) &sin, address_len);

	return result;
}

int test_connect(int server)
{
	struct gg_session *gs;
	struct gg_login_params glp;

	tried_80 = 0;
	tried_443 = 0;
	tried_8074 = 0;
	tried_resolver = 0;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "dupa.8";
	glp.async = async_mode;

	if (server) {
		glp.server_addr = inet_addr(LOCALHOST);
//		glp.server_port = 8074;
	}

	gs = gg_login(&glp);

	if (!async_mode) {
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
				tv.tv_sec = 1;
				tv.tv_usec = 0;
			}

			res = select(gs->fd + 1, &rd, &wr, NULL, (gs->timeout) ? &tv : NULL);
			
			if (res == 0 && !gs->soft_timeout) {
				debug("Hard timeout\n");
				gg_free_session(gs);
				return 0;
			}

			if (res == -1 && errno != EINTR) {
				debug("select() failed: %s\n", strerror(errno));
				gg_free_session(gs);
				return 0;
			}

			if (FD_ISSET(gs->fd, &rd) || FD_ISSET(gs->fd, &wr) || (res == 0 && gs->soft_timeout)) {
				struct gg_event *ge;
				
				if (res == 0) {
					debug("Soft timeout\n");
					gs->timeout = 0;
				}
		
				ge = gg_watch_fd(gs);

				if (!ge) {
					debug("gg_watch_fd() failed\n");
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

void test_stats(void)
{
/*
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
*/
	printf("------------------------------------------------------------------------------\n");
}

void serve(void)
{
	int sfds[4];
	int cfds[2] = { -1, -1 };
	time_t started[3];
	int i;
	char buf[4096];
	int len = 0;

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

			if (i < 2 && cfds[i] != -1) {
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

					send(cfds[j], seed, sizeof(seed), 0);
				}
			}
		}

		if (cfds[0] != -1 && FD_ISSET(cfds[0], &rd)) {
			int res;

			res = recv(cfds[0], buf + len, sizeof(buf) - len - 1, 0);

			if (res > 0) {
				buf[len + res] = 0;
				len += res;

				if (strstr(buf, "\r\n\r\n")) {
					snprintf(buf, sizeof(buf), "HTTP/1.0 200 OK\r\n\r\n0 0 %s:%d %s\r\n", LOCALHOST, 8074, LOCALHOST);
					send(cfds[0], buf, strlen(buf), 0);
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

			res = recv(cfds[1], buf + len, sizeof(buf) - len, 0);

			if (res > 0) {
				len += res;

				if (len > 8 && len >= get32(buf + 4)) {
					char ok[8];

					set32(ok, GG_LOGIN_OK);
					set32(ok + 4, 0);

					send(cfds[1], ok, sizeof(ok), 0);
				}
			} else {
				close(cfds[1]);
				cfds[1] = -1;
			}
		}
	}
}

char *htmlize(const char *in)
{
	char *out;
	int i, j, size = 0;

	for (i = 0; in[i]; i++) {
		switch (in[i]) {
			case '<':
			case '>':
				size += 4;
				break;
			case '&':
				size += 5;
				break;
			case '\n':
				size += 7;
				break;
			case 1:
				size += 3;
				break;
			case 2:
				size += 4;
				break;
			default:
				size++;
		}
	}

	if (!(out = malloc(size + 1)))
		return NULL;

	for (i = 0, j = 0; in[i]; i++) {
		switch (in[i]) {
			case '<':
				strcpy(out + j, "&lt;");
				j += 4;
				break;
			case '>':
				strcpy(out + j, "&gt;");
				j += 4;
				break;
			case '&':
				strcpy(out + j, "&amp;");
				j += 5;
				break;
			case '\n':
				strcpy(out + j, "<br />\n");
				j += 7;
				break;
			case 1:
				strcpy(out + j, "<b>");
				j += 3;
				break;
			case 2:
				strcpy(out + j, "</b>");
				j += 4;
				break;
			default:
				out[j] = in[i];
				j++;
		}
	}
		
	out[size] = 0;

	return out;
}

void cleanup(int sig)
{
	failure();
}

void sigalrm(int sig)
{

}

int main(int argc, char **argv)
{
	int i, test_from = 0, test_to = 0, result[TEST_MAX][2] = { { 0, } };
	int exit_code = 0;

	if (argc == 3) {
		test_from = atoi(argv[1]);
		test_to = atoi(argv[2]);
	}

	if (argc != 3 || test_from < 1 || test_from > TEST_MAX || test_from > test_to || test_to < 1 || test_to > TEST_MAX) {
		test_from = 1;
		test_to = TEST_MAX;
	}

	if (!(log_file = fopen("report.html", "w"))) {
		perror("fopen");
		failure();
	}

	signal(SIGPIPE, SIG_IGN);
	gg_debug_handler = debug_handler;
	gg_debug_level = ~0;

	if ((server_pid = fork()) == -1) {
		perror("fork");
		failure();
	}

	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGQUIT, cleanup);
	signal(SIGALRM, sigalrm);

	if (!server_pid) {
		serve();
		exit(0);
	}

	fprintf(log_file, 
"<html>\n"
"<head>\n"
"<title>libgadu connection test report</title>\n"
"<style type=\"text/css\">\n"
".io { text-align: center; }\n"
".testno { font-size: 16pt; }\n"
".yes { background: #c0ffc0; }\n"
".no { background: #ffc0c0; }\n"
"tt { margin: 4px 3px; display: block; }\n"
"#header { margin-bottom: 0.5em; text-align: right; }\n"
"</style>\n"
"<script>\n"
"function toggle(id)\n"
"{\n"
"	if (document.getElementById(id).style.display == 'none')\n"
"		document.getElementById(id).style.display = 'block';\n"
"	else\n"
"		document.getElementById(id).style.display = 'none';\n"
"}\n"
"function showall()\n"
"{\n"
"	for (i = %d; i <= %d; i++) {\n"
"		document.getElementById('log'+i+'a').style.display = 'block';\n"
"		document.getElementById('log'+i+'b').style.display = 'block';\n"
"	}\n"
"}\n"
"</script>\n"
"</head>\n"
"<body>\n"
"<div id=\"header\">\n"
"<a href=\"javascript:showall();\">Show all</a>\n"
"</div>\n"
"<table border=\"1\" width=\"100%%\">\n"
"<tr><td rowspan=\"2\">No.</td><td colspan=\"5\" class=\"io\">Input</td><td colspan=\"3\" class=\"io\">Output</td></tr>\n"
"<tr><th>Resolver</th><th>Hub</th><th>Port 8074</th><th>Port 443</th><th>Server</th><th>Expect</th><th>Sync</th><th>Async</th></tr>\n", test_from, test_to);

	fflush(log_file);

	for (i = test_from - 1; i < test_to; i++) {
		int j = i, server, expect = 0;
		char *log[2];
		const char *display;

		printf("\r\033[KTest %d of %d...", i + 1, TEST_MAX);
		fflush(stdout);

		plug_80 = j % 3;
		j /= 3;
		plug_8074 = j % 3;
		j /= 3;
		plug_443 = j % 3;
		j /= 3;
		plug_resolver = j % 3;
		j /= 3;
		server = j % 2;
		j /= 2;

		for (j = 0; j < 2; j++) {
			async_mode = j;
			result[i][j] = test_connect(server);

			/* check for invalid behaviour */
			if (server && (tried_resolver || tried_80)) {
				result[i][j] = 0;
				debug("Used resolver or hub when server provided\n");
			}

			if (tried_443 && !tried_8074) {
				result[i][j] = 0;
				debug("Didn't try 8074 although tried 443\n");
			}

			if (!server && plug_resolver == PLUG_NONE && !tried_80) {
				result[i][j] = 0;
				debug("Didn't use hub\n");
			}

			if (server && !tried_8074 && !tried_443) {
				result[i][j] = 0;
				debug("Didn't try connecting directly\n");
			}

			if ((server || (plug_resolver == PLUG_NONE && plug_80 == PLUG_NONE)) && plug_8074 != PLUG_NONE && !tried_443) {
				result[i][j] = 0;
				debug("Didn't try 443\n");
			}

			log[j] = log_buffer;
			log_buffer = NULL;
		}

		if ((plug_resolver == PLUG_NONE && plug_80 == PLUG_NONE) || server) {
			if (plug_8074 == PLUG_NONE || plug_443 == PLUG_NONE)
				expect = 1;
		}

		if (result[i][0] == result[i][1] && result[i][0] == expect) {
			display = " style=\"display: none;\"";
		} else {
			display = "";
			exit_code = 1;
		}

		fprintf(log_file, "<tr class=\"params\"><td><b>%d</b></td>", i + 1);
		fprintf(log_file, (plug_resolver == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((plug_resolver == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (plug_80 == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((plug_80 == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (plug_8074 == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((plug_8074 == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (plug_443 == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((plug_443 == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (server) ? "<td>Yes</td>" : "<td>No</td>");
		fprintf(log_file, (expect) ? "<td class=\"yes\">Success</td>" : "<td class=\"no\">Failure</td>");

		for (j = 0; j < 2; j++) {
			fprintf(log_file, "<td class=\"%s\"><a href=\"javascript:toggle('log%d%c');\">%s</a></td>", (result[i][j]) ? "yes" : "no", i + 1, 'a' + j, (result[i][j]) ? "Success" : "Failure");
		}

		fprintf(log_file, "</tr>\n");

		for (j = 0; j < 2; j++) {
			const char *class = (result[i][j]) ? "yes" : "no";
			char *tmp = htmlize(log[j]);

			fprintf(log_file, "<tr>\n<td colspan=\"9\" class=\"%s\">\n<tt id=\"log%d%c\"%s>\n%s\n</tt>\n</td>\n</tr>\n", class, i + 1, 'a' + j, display, tmp);
			free(tmp);
		}

		fflush(log_file);

		free(log[0]);
		free(log[1]);

		while (waitpid(-1, NULL, WNOHANG) != 0);
	}

	fprintf(log_file, "</body>\n</html>\n");

	printf("\n");

	cleanup(0);

	return exit_code;
}

