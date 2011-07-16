#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
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
#include <pthread.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <libgadu.h>

#define HOST_LOCAL "127.0.0.1"
#define HOST_PROXY "proxy.example.org"
#define HOST_UNREACHABLE "192.0.2.1"	/* documentation and example class, RFC 3330 */

#define TEST_MAX (3*3*3*3*2*2*2)

typedef enum {
	PLUG_NONE = 0,
	PLUG_RESET = 1,
	PLUG_TIMEOUT = 2
} test_plug_t;

typedef enum {
	PORT_80,
	PORT_443,
	PORT_8074,
	PORT_8080,
	PORT_CLOSED,
	PORT_COUNT
} test_port_t;

typedef struct {
	test_plug_t plug_80;
	test_plug_t plug_443;
	test_plug_t plug_8074;
	test_plug_t plug_8080;
	test_plug_t plug_resolver;
	bool server;
	bool async_mode;
	bool proxy_mode;
	bool ssl_mode;

	bool tried_80;
	bool tried_443;
	bool tried_8074;
	bool tried_8080;
	bool tried_non_8080;
	bool tried_resolver;
} test_param_t;

/** Port and resolver plug flags */
//static int plug_80, plug_443, plug_8074, plug_8080, plug_resolver;

/** Flags telling which actions libgadu */
//static int tried_80, tried_443, tried_8074, tried_8080, tried_resolver, tried_non_8080;

/** Asynchronous mode flag */
//static int async_mode;

/** Proxy mode flag */
//static int proxy_mode;

/** Report file */
static FILE *log_file;

/** Log buffer */
static char *log_buffer;

/** Local ports */
static int ports[PORT_COUNT];

static gnutls_certificate_credentials_t x509_cred;
static gnutls_dh_params_t dh_params;
#define DH_BITS 1024
#define CERT_FILE "connect.pem"
#define KEY_FILE "connect.pem"

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static test_param_t *get_test_param(void)
{
	static test_param_t test;

	return &test;
}

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

	log_buffer = tmp;
	strcpy(log_buffer + len, buf);
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

static void failure(void) __attribute__ ((noreturn));

static void failure(void)
{
	exit(0);
}

static void debug(const char *fmt, ...)
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

typedef struct {
	struct in_addr addr;
	char *addr_list[2];
	char name[1];
} resolver_storage_t;

struct hostent *gethostbyname(const char *name)
{
	static char buf[256];
	static struct hostent he;
	struct hostent *he_ptr;

	if (gethostbyname_r(name, &he, buf, sizeof(buf), &he_ptr, &h_errno) == -1)
		return NULL;
	
	return he_ptr;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	resolver_storage_t *storage;
	int h_errno;
	test_param_t *test;

	test = get_test_param();

	if (buflen < sizeof(*storage) + strlen(name)) {
		errno = ERANGE;
		*result = NULL;
		return -1;
	}

	test->tried_resolver = 1;

	storage = (void*) buf;

	if (test->plug_resolver != PLUG_NONE) {
		if (test->plug_resolver == PLUG_TIMEOUT) {
			if (test->async_mode)
				sleep(30);
			*h_errnop = TRY_AGAIN;
		} else {
			*h_errnop = HOST_NOT_FOUND;
		}
		*result = NULL;
		return -1;
	}

	if ((!test->proxy_mode && strcmp(name, GG_APPMSG_HOST) != 0) || (test->proxy_mode && strcmp(name, HOST_PROXY) != 0)) {
		debug("Invalid argument for gethostbyname(): \"%s\"\n", name);
		*h_errnop = HOST_NOT_FOUND;
		*result = NULL;
		return -1;
	}

	storage->addr_list[0] = (char*) &storage->addr;
	storage->addr_list[1] = NULL;
	storage->addr.s_addr = inet_addr(HOST_LOCAL);

	strcpy(storage->name, name);

	memset(ret, 0, sizeof(*ret));
	ret->h_name = storage->name;
	ret->h_addrtype = AF_INET;
	ret->h_length = sizeof(struct in_addr);
	ret->h_addr_list = storage->addr_list;
	
	*result = ret;
	*h_errnop = h_errno;

	return 0;
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in sin;
	int result, plug, port;
	test_param_t *test;

	test = get_test_param();

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

	if (sin.sin_addr.s_addr != inet_addr(HOST_LOCAL)) {
		debug("Invalid argument for connect(): sin_addr = %s\n", inet_ntoa(sin.sin_addr));
		errno = EINVAL;
		return -1;
	}

	if (ntohs(sin.sin_port) != 8080)
		test->tried_non_8080 = 1;

	switch (ntohs(sin.sin_port)) {
		case 80:
			plug = test->plug_80;
			port = ports[PORT_80];
			test->tried_80 = 1;
			break;
		case 443:
			plug = test->plug_443;
			port = ports[PORT_443];
			test->tried_443 = 1;
			break;
		case 8074:
			plug = test->plug_8074;
			port = ports[PORT_8074];
			test->tried_8074 = 1;
			break;
		case 8080:
			plug = test->plug_8080;
			port = ports[PORT_8080];
			test->tried_8080 = 1;
			break;
		default:
			debug("Invalid argument for connect(): sin_port = %d\n", ntohs(sin.sin_port));
			errno = EINVAL;
			return -1;
	}

	if (test->proxy_mode && ntohs(sin.sin_port) != 8080)
		plug = PLUG_RESET;

	switch (plug) {
		case PLUG_NONE:
			sin.sin_port = htons(port);
			break;
		case PLUG_RESET:
			sin.sin_port = htons(ports[PORT_CLOSED]);
			break;
		case PLUG_TIMEOUT:
			if (!test->async_mode) {
				errno = ETIMEDOUT;
				return -1;
			}

			sin.sin_addr.s_addr = inet_addr(HOST_UNREACHABLE);
			break;
	}

	result =  __connect(socket, (struct sockaddr*) &sin, address_len);

	return result;
}

static bool client(test_param_t *test)
{
	struct gg_session *gs;
	struct gg_login_params glp;

	gg_proxy_host = HOST_PROXY;
	gg_proxy_port = 8080;
	gg_proxy_enabled = test->proxy_mode;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "dupa.8";
	glp.async = test->async_mode;
	glp.resolver = GG_RESOLVER_PTHREAD;

	if (test->server)
		glp.server_addr = inet_addr(HOST_LOCAL);

	if (test->ssl_mode)
		glp.tls = GG_SSL_REQUIRED;

	gs = gg_login(&glp);

	if (gs == NULL)
		return false;

	if (!test->async_mode) {
		gg_free_session(gs);
		return true;
	} else {
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
				return false;
			}

			if (res == -1 && errno != EINTR) {
				debug("select() failed: %s\n", strerror(errno));
				gg_free_session(gs);
				return false;
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
					return false;
				}

				switch (ge->type) {
					case GG_EVENT_CONN_SUCCESS:
						gg_event_free(ge);
						gg_free_session(gs);
						return true;

					case GG_EVENT_CONN_FAILED:
						gg_event_free(ge);
						gg_free_session(gs);
						return false;

					case GG_EVENT_NONE:
						break;

					default:
						debug("Unknown event %d\n", ge->type);
						gg_event_free(ge);
						gg_free_session(gs);
						return false;
				}

				gg_event_free(ge);
			}
		}
	}
}

static bool server_ssl_init(gnutls_session_t *session, int cfd)
{
	if (*session != NULL) {
		gnutls_deinit(*session);
		*session = NULL;
	}
	
	if (gnutls_init(session, GNUTLS_SERVER) != GNUTLS_E_SUCCESS)
		goto fail;
	
	if (gnutls_set_default_priority(*session) != GNUTLS_E_SUCCESS)
		goto fail;

	if (gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred) != GNUTLS_E_SUCCESS)
		goto fail;

	gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t) cfd);

	if (gnutls_handshake(*session) != GNUTLS_E_SUCCESS)
		goto fail;

	return true;

fail:
	gnutls_deinit(*session);
	*session = NULL;
	return false;
}

static void server_ssl_deinit(gnutls_session_t *session)
{
	gnutls_deinit(*session);
	*session = NULL;
}

//static void server(int port_pipe)
static void* server(void* arg)
{
	int port_pipe = (int) arg;
	int sfds[PORT_COUNT];
	int cfd = -1;
	enum { CLIENT_HUB, CLIENT_GG, CLIENT_GG_SSL, CLIENT_PROXY } ctype;
	time_t started;
	int i;
	char buf[4096];
	int len = 0;
	const char welcome_packet[] = { 1, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4 };
	const char login_ok_packet[] = { 3, 0, 0, 0, 0, 0, 0, 0 };
	const char hub_reply[] = "HTTP/1.0 200 OK\r\n\r\n0 0 " HOST_LOCAL ":8074 " HOST_LOCAL "\r\n";
	const char hub_ssl_reply[] = "HTTP/1.0 200 OK\r\n\r\n0 0 " HOST_LOCAL ":443 " HOST_LOCAL "\r\n";
	const char proxy_reply[] = "HTTP/1.0 200 OK\r\n\r\n";
	const char proxy_error[] = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found\r\n";
	gnutls_session_t session = NULL;

	for (i = 0; i < PORT_COUNT; i++) {
		struct sockaddr_in sin;
		socklen_t sin_len = sizeof(sin);
		int value = 1;

		sfds[i] = socket(AF_INET, SOCK_STREAM, 0);

		if (sfds[i] == -1) {
			perror("socket");
			failure();
		}

		setsockopt(sfds[i], SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(HOST_LOCAL);

		if (bind(sfds[i], (struct sockaddr*) &sin, sizeof(sin)) == -1) {
			perror("bind");
			failure();
		}

		if (getsockname(sfds[i], (struct sockaddr*) &sin, &sin_len) == -1) {
			perror("getsockname");
			failure();
		}

		ports[i] = ntohs(sin.sin_port);

		if (i != PORT_CLOSED) {
			if (listen(sfds[i], 1) == -1) {
				perror("listen");
				failure();
			}
		}
	}

	if (write(port_pipe, ports, sizeof(ports)) != sizeof(ports)) {
		perror("write->pipe");
		failure();
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

		for (i = 0; i < PORT_COUNT; i++) {
			if (i == PORT_CLOSED)
				continue;

			FD_SET(sfds[i], &rd);

			if (sfds[i] > max)
				max = sfds[i];
		}

		if (cfd != -1) {
			FD_SET(cfd, &rd);
				
			if (cfd > max)
				max = cfd;
		}

		res = select(max + 1, &rd, &wr, NULL, &tv);

		if (res == -1 && errno != EINTR) {
			debug("select() failed: %s\n", strerror(errno));
//XXX			kill(getppid(), SIGTERM);
			break;
		}

		if (cfd != -1) {
			if (time(NULL) - started > 5) {
				debug("Timeout!\n");
				server_ssl_deinit(&session);
				close(cfd);
				cfd = -1;
				continue;
			}
		}

		if (cfd != -1 && FD_ISSET(cfd, &rd)) {
			int res;
			test_param_t *test;

			test = get_test_param();

			if (ctype == CLIENT_GG_SSL)
				res = gnutls_record_recv(session, buf + len, sizeof(buf) - len - 1);
			else
				res = recv(cfd, buf + len, sizeof(buf) - len - 1, 0);

			if (res < 1) {
				server_ssl_deinit(&session);
				close(cfd);
				cfd = -1;
				continue;
			}

			buf[len + res] = 0;
			len += res;

			switch (ctype) {
				case CLIENT_HUB:
					if (strstr(buf, "\r\n\r\n") != NULL) {
						if (!test->ssl_mode)
							send(cfd, hub_reply, strlen(hub_reply), 0);
						else
							send(cfd, hub_ssl_reply, strlen(hub_ssl_reply), 0);
						close(cfd);
						cfd = -1;
					}
					break;

				case CLIENT_GG:
					if (len > 8 && len >= get32(buf + 4))
						send(cfd, login_ok_packet, sizeof(login_ok_packet), 0);
					break;

				case CLIENT_GG_SSL:
					if (len > 8 && len >= get32(buf + 4))
						gnutls_record_send(session, login_ok_packet, sizeof(login_ok_packet));
					break;

				case CLIENT_PROXY:
					if (strstr(buf, "\r\n\r\n") != NULL) {
						test_param_t *test;

						test = get_test_param();

						if (strncmp(buf, "GET http://" GG_APPMSG_HOST, 11 + strlen(GG_APPMSG_HOST)) == 0) {
							test->tried_80 = 1;
							if (test->plug_80 == PLUG_NONE) {
								if (!test->ssl_mode)
									send(cfd, hub_reply, strlen(hub_reply), 0);
								else
									send(cfd, hub_ssl_reply, strlen(hub_ssl_reply), 0);
							} else
								send(cfd, proxy_error, strlen(proxy_error), 0);
							close(cfd);
							cfd = -1;
						} else if (strncmp(buf, "CONNECT " HOST_LOCAL ":443 ", 13 + strlen(HOST_LOCAL)) == 0) {
							test->tried_443 = 1;

							if (test->plug_443 == PLUG_NONE) {
								send(cfd, proxy_reply, strlen(proxy_reply), 0);

								if (test->ssl_mode) {
									if (!server_ssl_init(&session, cfd)) {
										debug("Handshake failed");
										close(cfd);
										cfd = -1;
										continue;
									}

									gnutls_record_send(session, welcome_packet, sizeof(welcome_packet));

									ctype = CLIENT_GG_SSL;
								} else {
									send(cfd, welcome_packet, sizeof(welcome_packet), 0);
									ctype = CLIENT_GG;
								}
							} else {
								send(cfd, proxy_error, strlen(proxy_error), 0);
							}
							len = 0;
						} else {
							debug("Invalid proxy request");
							send(cfd, proxy_error, strlen(proxy_error), 0);
							close(cfd);
							cfd = -1;
						}
					}
					break;
			}
		}

		for (i = 0; i < PORT_COUNT; i++) {
			if (i == PORT_CLOSED)
				continue;

			if (FD_ISSET(sfds[i], &rd)) {
				struct sockaddr_in sin;
				socklen_t sin_len;
				int fd;
				test_param_t *test;

				test = get_test_param();

				fd = accept(sfds[i], (struct sockaddr*) &sin, &sin_len);

				if (cfd != -1) {
					debug("Overlapping connections\n");
					close(fd);
					close(cfd);
					cfd = -1;
					continue;
				}

				cfd = fd;
				memset(buf, 0, sizeof(buf));
				len = 0;
				started = time(NULL);

				if (i == PORT_80)
					ctype = CLIENT_HUB;
				else if (i == PORT_443 && test->ssl_mode) {
					ctype = CLIENT_GG_SSL;

					if (!server_ssl_init(&session, cfd)) {
						debug("Handshake failed");
						close(cfd);
						cfd = -1;
						continue;
					}
						
					gnutls_record_send(session, welcome_packet, sizeof(welcome_packet));
				} else if (i == PORT_443 || i == PORT_8074) {
					ctype = CLIENT_GG;
					send(cfd, welcome_packet, sizeof(welcome_packet), 0);
				} else if (i == PORT_8080)
					ctype = CLIENT_PROXY;
			}
		}
	}

	return NULL;
}

static char *htmlize(const char *in)
{
	char *out;
	int i, j, size = 0;

	for (i = 0; in != NULL && in[i] != 0; i++) {
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

	out = malloc(size + 1);

	if (out == NULL)
		return NULL;

	for (i = 0, j = 0; in != NULL && in[i] != 0; i++) {
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

static void cleanup(int sig)
{
	failure();
}

int main(int argc, char **argv)
{
	int i, test_from = 0, test_to = 0;
	bool result[TEST_MAX][2] = { { false, } };
	int exit_code = 0;
	int port_pipe[2];
	pthread_t t;

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_key_file(x509_cred, CERT_FILE, KEY_FILE, GNUTLS_X509_FMT_PEM);

	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_BITS);
	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	if (argc == 3) {
		test_from = atoi(argv[1]);
		test_to = atoi(argv[2]);
	}

	if (argc != 3 || test_from < 1 || test_from > TEST_MAX || test_from > test_to || test_to < 1 || test_to > TEST_MAX) {
		test_from = 1;
		test_to = TEST_MAX;
	}

	signal(SIGPIPE, SIG_IGN);
	gg_debug_handler = debug_handler;
	gg_debug_level = ~0;

	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGQUIT, cleanup);
	signal(SIGSEGV, cleanup);
	signal(SIGABRT, cleanup);

	if (pipe(port_pipe) == -1) {
		perror("pipe");
		failure();
	}

	pthread_create(&t, NULL, server, (void*) port_pipe[1]);

	if (read(port_pipe[0], ports, sizeof(ports)) != sizeof(ports)) {
		perror("read<-pipe");
		failure();
	}

	log_file = fopen("report.html", "w");

	if (log_file == NULL) {
		perror("fopen");
		failure();
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
"<tr><td rowspan=\"2\">No.</td><td colspan=\"6\" class=\"io\">Input</td><td colspan=\"3\" class=\"io\">Output</td></tr>\n"
"<tr><th>Proxy</th><th>Resolver</th><th>Hub</th><th>Port 8074</th><th>Port 443</th><th>Server</th><th>Expect</th><th>Sync</th><th>Async</th></tr>\n", test_from, test_to);

	fflush(log_file);

	for (i = test_from - 1; i < test_to; i++) {
		int j = i;
		bool expect = false;
		char *log[2];
		const char *display;
		test_param_t *test;

		printf("\r\033[KTest %d of %d...", i + 1, TEST_MAX);
		fflush(stdout);

		test = get_test_param();

		for (j = 0; j < 2; j++) {
			memset(test, 0, sizeof(test_param_t));
			test->plug_80 = i % 3;
			test->plug_8074 = i / 3 % 3;
			test->plug_443 = i / 3 / 3 % 3;
			test->plug_resolver = i / 3 / 3 / 3 % 3;
			test->server =  i / 3 / 3 / 3 / 3 % 2;
			test->proxy_mode = i / 3 / 3 / 3 / 3 / 2 % 2;
			test->ssl_mode = i / 3 / 3 / 3 / 3 / 2 / 2 % 2;

			test->async_mode = j;
			result[i][j] = client(test);

			/* check for invalid behaviour */
			if (test->proxy_mode && test->tried_non_8080) {
				result[i][j] = false;
				debug("Connected directly when proxy enabled\n");
			}

			if (!test->proxy_mode && test->tried_8080) {
				result[i][j] = false;
				debug("Connected to proxy when proxy disabled\n");
			}

			if (test->server && !test->proxy_mode && (test->tried_resolver || test->tried_80)) {
				result[i][j] = false;
				debug("Used resolver or hub when server provided\n");
			}

			if (!test->proxy_mode && !test->ssl_mode && test->tried_443 && !test->tried_8074) {
				result[i][j] = false;
				debug("Didn't try 8074 although tried 443\n");
			}

			if (!test->server && test->plug_resolver == PLUG_NONE && !test->tried_80) {
				result[i][j] = false;
				debug("Didn't use hub\n");
			}

			if (test->server && (!test->proxy_mode || test->plug_resolver == PLUG_NONE) && !test->tried_8074 && !test->tried_443) {
				result[i][j] = false;
				debug("Didn't try connecting directly\n");
			}

			if ((test->server || (test->plug_resolver == PLUG_NONE && test->plug_80 == PLUG_NONE)) && test->plug_8074 != PLUG_NONE && !test->tried_443) {
				result[i][j] = false;
				debug("Didn't try 443\n");
			}

			if ((test->proxy_mode || test->ssl_mode) && test->tried_8074) {
				result[i][j] = false;
				debug("Tried 8074 in proxy or SSL mode\n");
			}

			log[j] = log_buffer;
			log_buffer = NULL;
		}

		if (!test->proxy_mode) {
			if ((test->plug_resolver == PLUG_NONE && test->plug_80 == PLUG_NONE) || test->server)
				if ((!test->ssl_mode && test->plug_8074 == PLUG_NONE) || test->plug_443 == PLUG_NONE)
					expect = true;
		} else {
			if (test->plug_resolver == PLUG_NONE && test->plug_8080 == PLUG_NONE && (test->plug_80 == PLUG_NONE || test->server) && test->plug_443 == PLUG_NONE)
				expect = true;
		}

		if (result[i][0] == result[i][1] && result[i][0] == expect) {
			display = " style=\"display: none;\"";
		} else {
			display = "";
			exit_code = 1;
		}

		fprintf(log_file, "<tr class=\"params\"><td><b>%d</b></td>", i + 1);
		fprintf(log_file, (test->proxy_mode) ? "<td>Yes</td>" : "<td>No</td>");
		fprintf(log_file, (test->plug_resolver == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((test->plug_resolver == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (test->plug_80 == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((test->plug_80 == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (test->plug_8074 == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((test->plug_8074 == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (test->plug_443 == PLUG_NONE) ? "<td class=\"yes\">Running</td>" : ((test->plug_443 == PLUG_RESET) ? "<td class=\"no\">Closed</td>" : "<td class=\"no\">Timeout</td>"));
		fprintf(log_file, (test->server) ? "<td>Yes</td>" : "<td>No</td>");
		fprintf(log_file, (expect) ? "<td class=\"yes\">Success</td>" : "<td class=\"no\">Failure</td>");

		for (j = 0; j < 2; j++) {
			fprintf(log_file, "<td class=\"%s\"><a href=\"javascript:toggle('log%d%c');\">%s</a></td>", (result[i][j]) ? "yes" : "no", i + 1, 'a' + j, (result[i][j]) ? "Success" : "Failure");
		}

		fprintf(log_file, "</tr>\n");

		for (j = 0; j < 2; j++) {
			const char *class = (result[i][j]) ? "yes" : "no";
			char *tmp = htmlize(log[j]);

			fprintf(log_file, "<tr>\n<td colspan=\"10\" class=\"%s\">\n<tt id=\"log%d%c\"%s>\n%s\n</tt>\n</td>\n</tr>\n", class, i + 1, 'a' + j, display, tmp);
			free(tmp);
		}

		fflush(log_file);

		free(log[0]);
		free(log[1]);
	}

	fprintf(log_file, "</body>\n</html>\n");
	fclose(log_file);

	printf("\n");

	pthread_cancel(t);
	pthread_join(t, NULL);

	gnutls_certificate_free_credentials(x509_cred);
	gnutls_dh_params_deinit(dh_params);
	gnutls_global_deinit();

	return exit_code;
}
