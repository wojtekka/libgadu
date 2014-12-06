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
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "config.h"

#if defined(GG_CONFIG_HAVE_PTHREAD)
#  include <pthread.h>
#elif defined(_WIN32)
#  define GG_SIMULATE_WIN32_PTHREAD
#endif

#include "libgadu.h"
#include "network.h"
#include "internal.h"

#ifdef GG_CONFIG_HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

#ifndef _WIN32
/* should not be different from 127.0.0.1, because this is the only address
 * from 127.0.0.0/8 pool that is guaranted to be configured as a loopback */
#  define HOST_LOCAL "127.0.0.1"
#else
/* must be different from INADDR_LOOPBACK=127.0.0.1, because this one is used
 * for win32-related hacks */
#  define HOST_LOCAL "127.0.0.2"
#endif
#define HOST_PROXY "proxy.example.org"

#if 0
#define SERVER_TIMEOUT 60
#define CLIENT_TIMEOUT 60
#endif

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

#ifdef GG_SIMULATE_WIN32_PTHREAD

typedef CRITICAL_SECTION pthread_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER { 0 }

typedef struct
{
	HANDLE handle;

	void *(*func)(void *);
	void *arg;
} pthread_t;

#endif

/** Log buffer */
static char *log_buffer;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Server data */
static int server_ports[PORT_COUNT];
static pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifndef GG_SIMULATE_WIN32_PTHREAD
static pthread_cond_t server_cond = PTHREAD_COND_INITIALIZER;
#endif
static bool server_init = false;
static int server_pipe[2];

/** gethostbyname/connect timeout notification pipe */
static int timeout_pipe[2];

/** Verbosity flag */
static bool verbose;

#ifdef GG_CONFIG_HAVE_GNUTLS
static bool gnutls_initialized;
static gnutls_certificate_credentials_t x509_cred;
static gnutls_dh_params_t dh_params;
#define DH_BITS 1024
#define CERT_FILE "connect.pem"
#define KEY_FILE "connect.pem"
#endif

#ifdef _WIN32
static bool errno_is_set = 0;
#endif

static void failure(void) GG_NORETURN;

static void failure(void)
{
	exit(1);
}

#ifdef GG_SIMULATE_WIN32_PTHREAD

static inline int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	EnterCriticalSection(mutex);
	return 0;
}

static inline int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	LeaveCriticalSection(mutex);
	return 0;
}

static inline void GG_CDECL _pthread_create_body(void *args)
{
	pthread_t *th = args;

	th->func(th->arg);
}

static inline int pthread_create(pthread_t *th, void *attr,
	void *(*func)(void *), void *arg)
{
	if (th == NULL || func == NULL)
		return -1;
	if (attr != NULL || arg != NULL)
		return -1;

	th->func = func;
	th->arg = arg;
	th->handle = (HANDLE)_beginthread(_pthread_create_body, 0, th);
	if (!th->handle)
		return -1;

	return 0;
}

static inline int pthread_join(pthread_t th, void **res)
{
	if (res != NULL)
		return -1;

	if (!th.handle)
		return 0;

	WaitForSingleObject(th.handle, INFINITE);

	return 0;
}

#endif /* GG_SIMULATE_WIN32_PTHREAD */

static test_param_t *get_test_param(void)
{
	static test_param_t test;

	return &test;
}

static void debug_handler(int level, const char *format, va_list ap)
{
	if (verbose) {
		vprintf(format, ap);
	} else {
		char buf[4096], *tmp;
		int len, ret;

		ret = vsnprintf(buf, sizeof(buf), format, ap);

		if (ret < 0) {
			fprintf(stderr, "vsnprintf error!\n");
			return;
		}

		if ((size_t)ret >= sizeof(buf)) {
			fprintf(stderr, "Increase temporary log buffer size!\n");
			return;
		}

		if (pthread_mutex_lock(&log_mutex) != 0) {
			fprintf(stderr, "pthread_mutex_lock failed!\n");
			return;
		}

		len = (log_buffer != NULL) ? strlen(log_buffer) : 0;

		tmp = realloc(log_buffer, len + strlen(buf) + 1);

		if (tmp != NULL) {
			log_buffer = tmp;
			strcpy(log_buffer + len, buf);
		} else {
			fprintf(stderr, "Out of memory for log buffer!\n");
		}

		if (pthread_mutex_unlock(&log_mutex) != 0) {
			fprintf(stderr, "pthread_mutex_unlock failed!\n");
			failure();
		}
	}
}

#if 0
static inline void set32(char *ptr, unsigned int value)
{
	unsigned char *tmp = (unsigned char*) ptr;

	tmp[0] = value & 255;
	tmp[1] = (value >> 8) & 255;
	tmp[2] = (value >> 16) & 255;
	tmp[3] = (value >> 24) & 255;
}
#endif

static inline unsigned int get32(char *ptr)
{
	unsigned char *tmp = (unsigned char*) ptr;

	return tmp[0] | (tmp[1] << 8) | (tmp[2] << 16) | (tmp[3] << 24);
}

static void debug(const char *fmt, ...) GG_GNUC_PRINTF(1, 2);
static void debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	debug_handler(0, fmt, ap);
	va_end(ap);
}

#ifndef _WIN32
extern int __connect(int socket, const struct sockaddr *address, socklen_t address_len);
#endif

typedef struct {
	struct in_addr addr;
	char *addr_list[2];
	char name[1];
} resolver_storage_t;

int gethostbyname_r(const char *name, struct hostent *ret, char *buf,
	size_t buflen, struct hostent **result, int *h_errnop);

#undef h_errno
static int h_errno;

#undef gethostbyname
#ifdef _WIN32
static struct hostent *my_gethostbyname(const char *name)
#else
struct hostent *gethostbyname(const char *name)
#endif
{
	static char buf[256];
	static struct hostent he;
	struct hostent *he_ptr;

	if (gethostbyname_r(name, &he, buf, sizeof(buf), &he_ptr, &h_errno) != 0)
		return NULL;

	return he_ptr;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf,
	size_t buflen, struct hostent **result, int *h_errnop)
{
	resolver_storage_t *storage = (void*) buf;
	test_param_t *test;

	test = get_test_param();

	*result = NULL;

	if (buflen < sizeof(*storage) + strlen(name))
		return ERANGE;

	test->tried_resolver = 1;

	if (test->plug_resolver != PLUG_NONE) {
		if (test->plug_resolver == PLUG_TIMEOUT) {
			if (test->async_mode) {
				int res;
				if ((res = send(timeout_pipe[1], "", 1, 0)) != 1) {
					if (res == -1)
						perror("send");
					else
						fprintf(stderr, "send returned %d\n", res);
					failure();
				}
			}
			*h_errnop = TRY_AGAIN;
		} else {
			*h_errnop = HOST_NOT_FOUND;
		}
		return -1;
	}

	if ((!test->proxy_mode && strcmp(name, GG_APPMSG_HOST) != 0) ||
		(test->proxy_mode && strcmp(name, HOST_PROXY) != 0))
	{
		debug("Invalid argument for gethostbyname(): \"%s\"\n", name);
		*h_errnop = HOST_NOT_FOUND;
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

	return 0;
}

#undef connect
#ifdef _WIN32
static gg_win32_hook_data_t connect_hook;

static int my_connect(SOCKET socket, const struct sockaddr *address, int address_len)
#else
int connect(int socket, const struct sockaddr *address, socklen_t address_len)
#endif
{
	struct sockaddr_in sin;
	int result, plug, port;
	test_param_t *test;

	test = get_test_param();

#ifdef GG_CONFIG_HAVE_GNUTLS
	/* GnuTLS may want to connect */
	if (!gnutls_initialized) {
#ifdef _WIN32
		int ret;

		gg_win32_hook_set_enabled(&connect_hook, 0);
		ret = connect(socket, address, address_len);
		gg_win32_hook_set_enabled(&connect_hook, 1);

		errno_is_set = 0;
		return ret;
#else
		return __connect(socket, address, address_len);
#endif
	}
#endif

#ifdef _WIN32
	errno_is_set = 1;
#endif

	if ((size_t)address_len < sizeof(sin)) {
		debug("Invalid argument for connect(): sa_len < %"
			GG_SIZE_FMT "\n", sizeof(sin));
		errno = EINVAL;
		return -1;
	}

	memcpy(&sin, address, address_len);

	if (sin.sin_family != AF_INET) {
		debug("Invalid argument for connect(): sa_family = %d\n", sin.sin_family);
		errno = EINVAL;
		return -1;
	}

#ifdef _WIN32
	if (sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
		int ret;

		gg_win32_hook_set_enabled(&connect_hook, 0);
		ret = connect(socket, address, address_len);
		gg_win32_hook_set_enabled(&connect_hook, 1);

		errno_is_set = 0;
		return ret;
	}
#endif

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
			port = server_ports[PORT_80];
			test->tried_80 = 1;
			break;
		case 443:
			plug = test->plug_443;
			port = server_ports[PORT_443];
			test->tried_443 = 1;
			break;
		case 8074:
			plug = test->plug_8074;
			port = server_ports[PORT_8074];
			test->tried_8074 = 1;
			break;
		case 8080:
			plug = test->plug_8080;
			port = server_ports[PORT_8080];
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
#ifdef _WIN32
			/* TODO: it doesn't seems to fit win32 sockets behavior.
			 * In real case, win32 may hang here - just remove this
			 * block and see what's happens.
			 *
			 * For blocking sockets, connect() should return
			 * ECONNREFUSED. For async it should:
			 * - return EINPROGRESS;
			 * - next call to select() returns >= 1;
			 * - getsockopt(..., SO_ERROR, ...) returns ECONNREFUSED.
			 *
			 * Instead, on win32 select() returns 0 and getsockopt
			 * always returns 0.
			 *
			 * Function send(fd, "", 0, 0) called just after
			 * connect, returns ECONNRESET both for "RESET" and
			 * "TIMEOUT" sockets.
			 */
			if (test->async_mode) {
				errno = ECONNREFUSED;
				return -1;
			}
#endif
			sin.sin_port = htons(server_ports[PORT_CLOSED]);
			break;
		case PLUG_TIMEOUT:
			if (!test->async_mode) {
				errno = ETIMEDOUT;
			} else {
				int res;
				if ((res = send(timeout_pipe[1], "", 1, 0)) != 1) {
					debug("send() returned %d\n", res);
					errno = EBADF;
					return -1;
				}
				errno = EINPROGRESS;
			}
			return -1;
	}

#ifdef _WIN32
	gg_win32_hook_set_enabled(&connect_hook, 0);
	result = connect(socket, (struct sockaddr*) &sin, address_len);
	gg_win32_hook_set_enabled(&connect_hook, 1);

	errno_is_set = 0;
#else
	result = __connect(socket, (struct sockaddr*) &sin, address_len);
#endif

	return result;
}

#ifdef _WIN32
static gg_win32_hook_data_t get_last_error_hook;

static int my_get_last_error(void)
{
	int result;

	if (errno_is_set) {
		errno_is_set = 0;
		return errno;
	}

	gg_win32_hook_set_enabled(&get_last_error_hook, 0);
	result = WSAGetLastError();
	gg_win32_hook_set_enabled(&get_last_error_hook, 1);

	return result;
}

#endif

/** @return 1 on success, 0 on failure, -1 on error */
static int client_func(const test_param_t *test)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	char tmp;

	gg_proxy_host = HOST_PROXY;
	gg_proxy_port = 8080;
	gg_proxy_enabled = test->proxy_mode;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "dupa.8";
	glp.async = test->async_mode;

	if (test->server)
		glp.server_addr = inet_addr(HOST_LOCAL);

	if (test->ssl_mode)
		glp.tls = GG_SSL_ENABLED;

	while (recv(timeout_pipe[0], &tmp, 1, 0) != -1);

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (!test->async_mode) {
		gg_free_session(gs);
		return 1;
	} else {
		for (;;) {
			fd_set rd, wr;
			int res;
			int max_fd;
			struct timeval *tv_ptr = NULL;

#ifdef CLIENT_TIMEOUT
			struct timeval tv;

			tv.tv_sec = CLIENT_TIMEOUT;
			tv.tv_usec = 0;
			tv_ptr = &tv;
#endif

			FD_ZERO(&rd);
			FD_ZERO(&wr);

			max_fd = timeout_pipe[0];

			if (gs->fd > max_fd)
				max_fd = gs->fd;

			FD_SET(timeout_pipe[0], &rd);

			if ((gs->check & GG_CHECK_READ))
				FD_SET(gs->fd, &rd);

			if ((gs->check & GG_CHECK_WRITE))
				FD_SET(gs->fd, &wr);

			res = select(max_fd + 1, &rd, &wr, NULL, tv_ptr);

			if (res == 0) {
				debug("Test timeout\n");
				gg_free_session(gs);
				return 0;
			}

			if (res == -1 && errno != EINTR) {
				debug("select() failed: %s (errno=%d)\n", strerror(errno), errno);
				gg_free_session(gs);
				return -1;
			}
			if (res == -1)
				continue;

			if (FD_ISSET(timeout_pipe[0], &rd)) {
				if (recv(timeout_pipe[0], &tmp, 1, 0) != 1) {
					debug("Test error\n");
					gg_free_session(gs);
					return -1;
				}

				if (!gs->soft_timeout) {
					debug("Hard timeout\n");
					gg_free_session(gs);
					return 0;
				}
			}

			if (FD_ISSET(gs->fd, &rd) || FD_ISSET(gs->fd, &wr) ||
				(FD_ISSET(timeout_pipe[0], &rd) && gs->soft_timeout))
			{
				struct gg_event *ge;

				if (FD_ISSET(timeout_pipe[0], &rd)) {
					debug("Soft timeout\n");
					gs->timeout = 0;
				}

				ge = gg_watch_fd(gs);

				if (!ge) {
					debug("gg_watch_fd() failed\n");
					gg_free_session(gs);
					return -1;
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
						return -1;
				}

				gg_event_free(ge);
			}
		}
	}
}

#ifdef GG_CONFIG_HAVE_GNUTLS
static int server_ssl_init(gnutls_session_t *session, int client_fd)
{
	int res;

	if (*session != NULL) {
		gnutls_deinit(*session);
		*session = NULL;
	}

	if ((res = gnutls_init(session, GNUTLS_SERVER)) != GNUTLS_E_SUCCESS)
		goto fail;

	if ((res = gnutls_set_default_priority(*session)) != GNUTLS_E_SUCCESS)
		goto fail;

	if ((res = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred)) != GNUTLS_E_SUCCESS)
		goto fail;

	gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t) (ptrdiff_t) client_fd);

	if ((res = gnutls_handshake(*session)) !=  GNUTLS_E_SUCCESS)
		goto fail;

	return GNUTLS_E_SUCCESS;

fail:
	gnutls_deinit(*session);
	*session = NULL;
	return res;
}

static void server_ssl_deinit(gnutls_session_t *session)
{
	gnutls_deinit(*session);
	*session = NULL;
}
#endif /* GG_CONFIG_HAVE_GNUTLS */

static void* server_func(void* arg)
{
	int server_fds[PORT_COUNT];
	int client_fd = -1;
	enum { CLIENT_UNKNOWN, CLIENT_HUB, CLIENT_GG, CLIENT_GG_SSL, CLIENT_PROXY } ctype = CLIENT_UNKNOWN;
	int i;
	char buf[4096];
	size_t len = 0;
	const char welcome_packet[] = { 1, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4 };
	const char login_ok_packet[] = { 3, 0, 0, 0, 0, 0, 0, 0 };
	const char hub_reply[] = "HTTP/1.0 200 OK\r\n\r\n0 0 " HOST_LOCAL ":8074 " HOST_LOCAL "\r\n";
	const char hub_ssl_reply[] = "HTTP/1.0 200 OK\r\n\r\n0 0 " HOST_LOCAL ":443 " HOST_LOCAL "\r\n";
	const char proxy_reply[] = "HTTP/1.0 200 OK\r\n\r\n";
	const char proxy_error[] = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found\r\n";
#ifdef SERVER_TIMEOUT
	time_t started = 0;
#endif
#ifdef GG_CONFIG_HAVE_GNUTLS
	gnutls_session_t session = NULL;
#endif

	for (i = 0; i < PORT_COUNT; i++) {
		struct sockaddr_in sin;
		socklen_t sin_len = sizeof(sin);
		int value = 1;

		server_fds[i] = socket(AF_INET, SOCK_STREAM, 0);

		if (server_fds[i] == -1) {
			perror("socket");
			failure();
		}

		if (setsockopt(server_fds[i], SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) {
			perror("setsockopt");
			failure();
		}

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(HOST_LOCAL);

		if (bind(server_fds[i], (struct sockaddr*) &sin, sizeof(sin)) == -1) {
			perror("bind");
			failure();
		}

		if (getsockname(server_fds[i], (struct sockaddr*) &sin, &sin_len) == -1) {
			perror("getsockname");
			failure();
		}

		server_ports[i] = ntohs(sin.sin_port);

		if (i != PORT_CLOSED) {
			if (listen(server_fds[i], 1) == -1) {
				perror("listen");
				failure();
			}
		}
	}

	if (pthread_mutex_lock(&server_mutex) != 0) {
		fprintf(stderr, "pthread_mutex_lock failed!\n");
		failure();
	}
	server_init = true;
#ifndef GG_SIMULATE_WIN32_PTHREAD
	if (pthread_cond_signal(&server_cond) != 0) {
		fprintf(stderr, "pthread_cond_signal failed!\n");
		failure();
	}
#endif
	if (pthread_mutex_unlock(&server_mutex) != 0) {
		fprintf(stderr, "pthread_mutex_unlock failed!\n");
		failure();
	}

	for (;;) {
		struct timeval tv;
		fd_set rd, wr;
		int max_fd = -1;
		int res;

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&rd);
		FD_ZERO(&wr);

		for (i = 0; i < PORT_COUNT; i++) {
			if (i == PORT_CLOSED)
				continue;

			FD_SET(server_fds[i], &rd);

			if (server_fds[i] > max_fd)
				max_fd = server_fds[i];
		}

		if (client_fd != -1) {
			FD_SET(client_fd, &rd);

			if (client_fd > max_fd)
				max_fd = client_fd;
		}

		FD_SET(server_pipe[0], &rd);

		if (server_pipe[0] > max_fd)
			max_fd = server_pipe[0];

		res = select(max_fd + 1, &rd, &wr, NULL, &tv);

		if (res == -1 && errno != EINTR) {
			perror("select");
			failure();
		}
		if (res == -1)
			continue;

#ifdef SERVER_TIMEOUT
		if (client_fd != -1) {
			if (time(NULL) - started > SERVER_TIMEOUT) {
				debug("Server timeout!\n");
#ifdef GG_CONFIG_HAVE_GNUTLS
				server_ssl_deinit(&session);
#endif
				if (close(client_fd) == -1) {
					perror("close");
					failure();
				}
				client_fd = -1;
				continue;
			}
		}
#endif

		if (client_fd != -1 && FD_ISSET(client_fd, &rd)) {
			int res;
			test_param_t *test;

			test = get_test_param();

#ifdef GG_CONFIG_HAVE_GNUTLS
			if (ctype == CLIENT_GG_SSL)
				res = gnutls_record_recv(session, buf + len, sizeof(buf) - len - 1);
			else
#endif
				res = recv(client_fd, buf + len, sizeof(buf) - len - 1, 0);

			if (res < 1) {
#ifdef GG_CONFIG_HAVE_GNUTLS
				server_ssl_deinit(&session);
#endif
				if (close(client_fd) == -1) {
					perror("close");
					failure();
				}
				client_fd = -1;
				continue;
			}

			buf[len + res] = 0;
			len += res;

			switch (ctype) {
				case CLIENT_UNKNOWN:
					break;

				case CLIENT_HUB:
					if (strstr(buf, "\r\n\r\n") != NULL) {
						if (!test->ssl_mode) {
							if (send(client_fd, hub_reply,
								strlen(hub_reply), 0) !=
								(ssize_t)strlen(hub_reply))
							{
								fprintf(stderr, "send() not completed\n");
								failure();
							}
						} else {
							if (send(client_fd, hub_ssl_reply,
								strlen(hub_ssl_reply), 0) !=
								(ssize_t)strlen(hub_ssl_reply))
							{
								fprintf(stderr, "send() not completed\n");
								failure();
							}
						}
						if (close(client_fd) == -1) {
							perror("close");
							failure();
						}
						client_fd = -1;
					}
					break;

				case CLIENT_GG:
					if (len > 8 && len >= get32(buf + 4)) {
						if (send(client_fd, login_ok_packet,
							sizeof(login_ok_packet), 0) !=
							sizeof(login_ok_packet))
						{
							fprintf(stderr, "send() not completed\n");
							failure();
						}
					}
					break;

				case CLIENT_GG_SSL:
#ifdef GG_CONFIG_HAVE_GNUTLS
					if (len > 8 && len >= get32(buf + 4)) {
						if (gnutls_record_send(session,
							login_ok_packet,
							sizeof(login_ok_packet)) !=
							sizeof(login_ok_packet))
						{
							fprintf(stderr, "gnutls_record_send() not completed\n");
							failure();
						}
					}
#endif
					break;

				case CLIENT_PROXY:
					if (strstr(buf, "\r\n\r\n") != NULL) {
						test_param_t *test;

						test = get_test_param();

						if (strncmp(buf,
							"GET http://" GG_APPMSG_HOST,
							strlen("GET http://" GG_APPMSG_HOST)) == 0)
						{
							test->tried_80 = 1;
							if (test->plug_80 == PLUG_NONE) {
								if (!test->ssl_mode) {
									if (send(client_fd, hub_reply,
										strlen(hub_reply), 0) !=
										(ssize_t)strlen(hub_reply))
									{
										fprintf(stderr,
											"send() not completed\n");
										failure();
									}
								} else {
									if (send(client_fd, hub_ssl_reply,
										strlen(hub_ssl_reply), 0) !=
										(ssize_t)strlen(hub_ssl_reply))
									{
										fprintf(stderr,
											"send() not completed\n");
										failure();
									}
								}
							} else {
								if (send(client_fd, proxy_error,
									strlen(proxy_error), 0) !=
									(ssize_t)strlen(proxy_error))
								{
									fprintf(stderr, "send() not completed\n");
									failure();
								}
							}
							if (close(client_fd) == -1) {
								perror("close");
								failure();
							}
							client_fd = -1;
						} else if (strncmp(buf,
							"CONNECT " HOST_LOCAL ":443 ",
							strlen("CONNECT " HOST_LOCAL ":443 ")) == 0)
						{
							test->tried_443 = 1;

							if (test->plug_443 == PLUG_NONE) {
								if (send(client_fd, proxy_reply,
									strlen(proxy_reply), 0) !=
									(ssize_t)strlen(proxy_reply))
								{
									fprintf(stderr, "send() not completed\n");
									failure();
								}

#ifdef GG_CONFIG_HAVE_GNUTLS
								if (test->ssl_mode) {
									int res;

									res = server_ssl_init(&session, client_fd);
									if (res != GNUTLS_E_SUCCESS) {
										/* XXX: this indentation
										 * hits 80-th column
										 * with tabs only! */
										debug("Handshake failed: %d, %s\n",
											res, gnutls_strerror(res));
										if (close(client_fd) == -1) {
											perror("close");
											failure();
										}
										client_fd = -1;
										continue;
									}

									if (gnutls_record_send(session,
										welcome_packet,
										sizeof(welcome_packet)) !=
										sizeof(welcome_packet))
									{
										fprintf(stderr,
											"gnutls_record_send() "
											"not completed\n");
										failure();
									}

									ctype = CLIENT_GG_SSL;
								} else
#endif
								{
									if (send(client_fd, welcome_packet,
										sizeof(welcome_packet), 0) !=
										sizeof(welcome_packet))
									{
										fprintf(stderr,
											"send() not completed\n");
										failure();
									}
									ctype = CLIENT_GG;
								}
							} else {
								if (send(client_fd, proxy_error,
									strlen(proxy_error), 0) !=
									(ssize_t)strlen(proxy_error))
								{
									fprintf(stderr, "send() not completed\n");
									failure();
								}
							}
							len = 0;
						} else {
							debug("Invalid proxy request");
							if (send(client_fd, proxy_error,
								strlen(proxy_error), 0) !=
								(ssize_t)strlen(proxy_error))
							{
								fprintf(stderr, "send() not completed\n");
								failure();
							}
							if (close(client_fd) == -1) {
								perror("close");
								failure();
							}
							client_fd = -1;
						}
					}
					break;
			}
		}

		for (i = 0; i < PORT_COUNT; i++) {
			if (i == PORT_CLOSED)
				continue;

			if (FD_ISSET(server_fds[i], &rd)) {
				struct sockaddr_in sin;
				socklen_t sin_len = sizeof(sin);
				int new_fd;

				if ((new_fd = accept(server_fds[i], (struct sockaddr*) &sin, &sin_len)) == -1) {
					perror("accept");
					failure();
				}

				if (client_fd != -1) {
					debug("Overlapping connections\n");
					if (close(new_fd) == -1 || close(client_fd) == -1) {
						perror("close");
						failure();
					}
					client_fd = -1;
					continue;
				}

				client_fd = new_fd;
				memset(buf, 0, sizeof(buf));
				len = 0;
#ifdef SERVER_TIMEOUT
				started = time(NULL);
#endif

				if (i == PORT_80)
					ctype = CLIENT_HUB;
#ifdef GG_CONFIG_HAVE_GNUTLS
				else if (i == PORT_443 && get_test_param()->ssl_mode) {
					int res;

					ctype = CLIENT_GG_SSL;
					res = server_ssl_init(&session, client_fd);

					if (res != GNUTLS_E_SUCCESS) {
						debug("Handshake failed: %d, %s\n", res, gnutls_strerror(res));
						if (close(client_fd) == -1) {
							perror("close");
							failure();
						}
						client_fd = -1;
						continue;
					}

					if (gnutls_record_send(session, welcome_packet,
						sizeof(welcome_packet)) != sizeof(welcome_packet))
					{
						fprintf(stderr, "gnutls_record_send() not completed\n");
						failure();
					}
				}
#endif
				else if (i == PORT_443 || i == PORT_8074) {
					ctype = CLIENT_GG;
					if (send(client_fd, welcome_packet,
						sizeof(welcome_packet), 0) != sizeof(welcome_packet))
					{
						fprintf(stderr, "send() not completed\n");
						failure();
					}
				} else if (i == PORT_8080)
					ctype = CLIENT_PROXY;
			}
		}

		if (FD_ISSET(server_pipe[0], &rd))
			break;
	}

	for (i = 0; i < PORT_COUNT; i++)
		if (close(server_fds[i]) == -1) {
			perror("close");
			failure();
		}

	if (client_fd != -1)
		if (close(client_fd) == -1) {
			perror("close");
			failure();
		}

	return NULL;
}

static const char *plug_to_string(test_plug_t plug)
{
	switch (plug) {
		case PLUG_NONE:
			return "open,   ";
		case PLUG_RESET:
			return "closed, ";
		case PLUG_TIMEOUT:
			return "timeout,";
		default:
			return "unknown,";
	}
}

int main(int argc, char **argv)
{
	int i, test_from = 0, test_to = 0;
	int exit_code = 0;
#ifdef GG_CONFIG_HAVE_GNUTLS
	int res;
#endif
	pthread_t server_thread;
	const char *srcdir;
	size_t srcdir_len;
#ifdef GG_CONFIG_HAVE_GNUTLS
	char cert_file_path[2000], key_file_path[2000];
#endif

#ifdef _WIN32
	gg_win32_init_network();
	gg_win32_hook(connect, my_connect, &connect_hook);
	gg_win32_hook(gethostbyname, my_gethostbyname, NULL);
	gg_win32_hook(WSAGetLastError, my_get_last_error, &get_last_error_hook);
#endif

#ifdef GG_SIMULATE_WIN32_PTHREAD
	InitializeCriticalSection(&log_mutex);
	InitializeCriticalSection(&server_mutex);
#endif

	srcdir = getenv("srcdir");
	if (srcdir == NULL || srcdir[0] == '\0')
		srcdir = ".";

	srcdir_len = strlen(srcdir);
	if (srcdir_len > 1000) {
		fprintf(stderr, "srcdir path too long\n");
		failure();
	}

#ifdef GG_CONFIG_HAVE_GNUTLS
	strncpy(cert_file_path, srcdir, srcdir_len);
	strncpy(key_file_path, srcdir, srcdir_len);
	cert_file_path[srcdir_len] = '/';
	key_file_path[srcdir_len] = '/';
	strcpy(cert_file_path + srcdir_len + 1, CERT_FILE);
	strcpy(key_file_path + srcdir_len + 1, KEY_FILE);

	if ((res = gnutls_global_init()) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_global_init: %d, %s\n", res, gnutls_strerror(res));
		failure();
	}
	if ((res = gnutls_certificate_allocate_credentials(&x509_cred)) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_certificate_allocate_credentials: %d, %s\n", res, gnutls_strerror(res));
		failure();
	}
	if ((res = gnutls_certificate_set_x509_key_file(x509_cred,
		cert_file_path, key_file_path, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS)
	{
		fprintf(stderr, "gnutls_certificate_set_x509_key_file: %d, %s\n", res, gnutls_strerror(res));
		failure();
	}

	if ((res = gnutls_dh_params_init(&dh_params)) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_dh_params_init: %d, %s\n", res, gnutls_strerror(res));
		failure();
	}
	if ((res = gnutls_dh_params_generate2(dh_params, DH_BITS)) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_dh_params_generate2: %d, %s\n", res, gnutls_strerror(res));
		failure();
	}
	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	gnutls_initialized = true;
#endif

	if (argc > 1 && (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0)) {
		verbose = true;
		argv++;
		argc--;
	}

	if (argc > 2) {
		test_from = atoi(argv[1]);
		test_to = atoi(argv[2]);
	}

	if (argc < 3 || test_from < 1 || test_from > TEST_MAX ||
		test_from > test_to || test_to < 1 || test_to > TEST_MAX)
	{
		test_from = 1;
		test_to = TEST_MAX;
	}

	gg_debug_handler = debug_handler;
	gg_debug_level = ~0;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, server_pipe) == -1) {
		perror("server_pipe");
		failure();
	}

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, timeout_pipe) == -1) {
		perror("timeout_pipe");
		failure();
	}

	if (!gg_fd_set_nonblocking(timeout_pipe[0])) {
		perror("gg_fd_set_nonblocking() failed!");
		failure();
	}

	if (pthread_create(&server_thread, NULL, server_func, NULL) != 0) {
		fprintf(stderr, "pthread_create() failed!\n");
		failure();
	}

	if (pthread_mutex_lock(&server_mutex) != 0) {
		fprintf(stderr, "pthread_mutex_lock() failed!\n");
		failure();
	}
	while (!server_init) {
#ifdef GG_SIMULATE_WIN32_PTHREAD
		if (pthread_mutex_unlock(&server_mutex) != 0) {
			fprintf(stderr, "pthread_mutex_unlock() failed!\n");
			failure();
		}
		usleep(10000); /* 10ms */
		if (pthread_mutex_lock(&server_mutex) != 0) {
			fprintf(stderr, "pthread_mutex_lock() failed!\n");
			failure();
		}
#else
		if (pthread_cond_wait(&server_cond, &server_mutex) != 0) {
			fprintf(stderr, "pthread_cond_wait() failed!\n");
			failure();
		}
#endif
	}
	if (pthread_mutex_unlock(&server_mutex) != 0) {
		fprintf(stderr, "pthread_mutex_unlock() failed!\n");
		failure();
	}

	for (i = test_from - 1; i < test_to; i++) {
		int j;
		int expect = 0;
		test_param_t *test;

		test = get_test_param();
		memset(test, 0, sizeof(test_param_t));
		test->plug_80 = i % 3;
		test->plug_8074 = i / 3 % 3;
		test->plug_443 = i / 3 / 3 % 3;
		test->plug_resolver = i / 3 / 3 / 3 % 3;
		test->server =  i / 3 / 3 / 3 / 3 % 2;
		test->proxy_mode = i / 3 / 3 / 3 / 3 / 2 % 2;
		test->ssl_mode = i / 3 / 3 / 3 / 3 / 2 / 2 % 2;

#if !defined(GG_CONFIG_HAVE_GNUTLS) && !defined(GG_CONFIG_HAVE_OPENSSL)
		if (test->ssl_mode)
			continue;
#endif

		if (!test->proxy_mode) {
			if ((test->plug_resolver == PLUG_NONE && test->plug_80 == PLUG_NONE) || test->server)
				if ((!test->ssl_mode && test->plug_8074 == PLUG_NONE) || test->plug_443 == PLUG_NONE)
					expect = 1;
		} else {
			if (test->plug_resolver == PLUG_NONE &&
				test->plug_8080 == PLUG_NONE &&
				(test->plug_80 == PLUG_NONE || test->server) &&
				test->plug_443 == PLUG_NONE)
			{
				expect = 1;
			}
		}

		for (j = 0; j < 2; j++) {
			bool result;

			printf("%3d/%d: %s 80 %s 8074 %s 443 %s resolver %s server %s proxy %s ssl %s\n",
				i + 1, TEST_MAX,
				j ? "async," : "sync, ",
				plug_to_string(test->plug_80),
				plug_to_string(test->plug_8074),
				plug_to_string(test->plug_443),
				plug_to_string(test->plug_resolver),
				test->server ? "yes," : "no, ",
				test->proxy_mode ? "yes," : "no, ",
				test->ssl_mode ? "yes" : "no ");

			test->async_mode = j;

			/* perform test */
			result = (client_func(test) == expect);

			/* check for invalid behaviour */
			if (test->proxy_mode && test->tried_non_8080) {
				result = false;
				debug("Connected directly when proxy enabled\n");
			}

			if (!test->proxy_mode && test->tried_8080) {
				result = false;
				debug("Connected to proxy when proxy disabled\n");
			}

			if (test->server && !test->proxy_mode && (test->tried_resolver || test->tried_80)) {
				result = false;
				debug("Used resolver or hub when server provided\n");
			}

			if (!test->proxy_mode && !test->ssl_mode && test->tried_443 && !test->tried_8074) {
				result = false;
				debug("Didn't try 8074 although tried 443\n");
			}

			if (!test->server && test->plug_resolver == PLUG_NONE && !test->tried_80) {
				result = false;
				debug("Didn't use hub\n");
			}

			if (test->server && (!test->proxy_mode || test->plug_resolver == PLUG_NONE)
				&& !test->tried_8074 && !test->tried_443)
			{
				result = false;
				debug("Didn't try connecting directly\n");
			}

			if ((test->server || (test->plug_resolver == PLUG_NONE && test->plug_80 == PLUG_NONE)) &&
				test->plug_8074 != PLUG_NONE && !test->tried_443 && !test->proxy_mode)
			{
				result = false;
				debug("Didn't try 443\n");
			}

			if ((test->proxy_mode || test->ssl_mode) && test->tried_8074) {
				result = false;
				debug("Tried 8074 in proxy or SSL mode\n");
			}

			if (!result && !verbose)
				printf("%s", log_buffer);

			if (!result)
				exit_code = 1;

			free(log_buffer);
			log_buffer = NULL;
		}
	}

	if (send(server_pipe[1], "", 1, 0) != 1) {
		perror("send");
		failure();
	}

	if (pthread_join(server_thread, NULL) != 0) {
		fprintf(stderr, "pthread_join() failed!\n");
		failure();
	}

	if (close(timeout_pipe[0]) == -1 || close(timeout_pipe[1]) == -1 ||
		close(server_pipe[0]) == -1 || close(server_pipe[1]) == -1)
	{
		perror("close");
		failure();
	}

#ifdef GG_CONFIG_HAVE_GNUTLS
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_dh_params_deinit(dh_params);
	gnutls_global_deinit();
#endif

#ifdef GG_SIMULATE_WIN32_PTHREAD
	DeleteCriticalSection(&log_mutex);
	DeleteCriticalSection(&server_mutex);
#endif

	return exit_code;
}
