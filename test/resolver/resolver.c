#include <unistd.h>
#include <libgadu.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define LOCALHOST "127.0.0.1"

int delay_flag;
int connect_flag;

struct hostent *gethostbyname(const char *name)
{
	static struct hostent he;
	static struct in_addr addr;
	static char *addr_list[2];
	static char sname[128];

//	printf("gethostbyname(\"%s\")\n", name);

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

	if (delay_flag)
		sleep(2);
	
	return &he;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	struct hostent *tmp;

	if (buflen < sizeof(struct hostent)) {
//		printf("1\n");
		errno = ERANGE;
		*result = NULL;
		return -1;
	}

	tmp = gethostbyname(name);

	if (tmp != NULL) {
//		printf("0\n");
		*h_errnop = 0;
		memcpy(ret, tmp, sizeof(struct hostent));
		*result = ret;
	} else {
//		printf("2\n");
		*h_errnop = h_errno;
		*result = NULL;
	}

	return (*result != NULL) ? 0 : -1;
}

int connect(int fd, const struct sockaddr *sa, socklen_t sa_len)
{
	connect_flag = 1;
	return 0;
}

int test(int resolver, int delay)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	int loops = 0;

	delay_flag = delay;
	connect_flag = 0;

	memset(&glp, 0, sizeof(glp));
	glp.uin = 1;
	glp.password = "";
	glp.resolver = resolver;
	glp.async = 1;

	gs = gg_login(&glp);

	if (gs == NULL)
		return 0;

	if (!delay_flag) {
		for (loops = 0; loops < 5; loops++) {
			struct gg_event *ge;
			struct timeval tv;
			fd_set fds;

			FD_ZERO(&fds);
			FD_SET(gs->fd, &fds);

			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if (select(gs->fd + 1, &fds, NULL, NULL, &tv) == -1) {
				if (errno == EAGAIN)
					continue;

				gg_free_session(gs);

				return 0;
			}

			ge = gg_watch_fd(gs);

			if (ge == NULL) {
				gg_free_session(gs);
				return 0;
			} else {
				if (ge->type == GG_EVENT_CONN_FAILED) {
					gg_event_free(ge);
					gg_free_session(gs);
					return 0;
				}

				gg_event_free(ge);
			}

			if (connect_flag == 1)
				break;
		}
	} else {
		sleep(1);
	}

	gg_free_session(gs);

	if (loops == 5)
		return 0;

	return 1;
}
	
int main(int argc, char **argv)
{
	int i, j, k = 1;

	gg_debug_level = 255;

	for (i = GG_RESOLVER_DEFAULT; i <= GG_RESOLVER_PTHREAD; i++) {
		for (j = 0; j < 2; j++) {
			printf("*** TEST %d ***\n\n", k++);

			if (!test(i, j)) {
				printf("*** TEST FAILED ***\n");
				exit(1);
			}

			printf("\n");
		}
	}

	return 0;
}
