#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include "libgadu.h"

int disconnect_flag;

void sigint(int sig)
{
	disconnect_flag = 1;
}

void usage(const char *argv0)
{
	printf("usage: %s [OPTIONS] <uin> <password>\n"
		"\n"
		"  -s ADRES[:PORT]  direct server connection\n"
		"  -p ADRES:PORT    use proxy server\n"
		"  -H               use proxy server only for HTTP\n"
		"  -D               disable debugging\n"
		"  -S               synchronous connection\n"
		"  -l NUMBER        last system message received\n"
		"  -y               hide system message\n"
		"  -h               print this message\n"
		"\n", argv0);
}

void parse_address(const char *arg, char **host, int *port)
{
	const char *colon;

	colon = strchr(arg, ':');

	if (colon == NULL) {
		*host = strdup(arg);
		*port = 0;
	} else {
		int len;

		len = colon - arg;

		*host = malloc(len + 1);

		if (*host != NULL) {
			memcpy(*host, arg, len);
			(*host)[len] = 0;
		}

		*port = atoi(colon + 1);
	}
}

int main(int argc, char **argv)
{
	struct gg_session *gs;
	time_t last = 0;
	int hide_sysmsg = 0;
	int ch;

	gg_debug_level = 255;
	
	gs = gg_session_new();

	if (gs == NULL) {
		perror("gg_session_new");
		return 1;
	}

	gg_session_set_async(gs, 1);

	while ((ch = getopt(argc, argv, "DShHs:p:l:y")) != -1) {
		char *host;
		int port;

		switch (ch) {
			case 'D':
				gg_debug_level = 0;
				break;

			case 'S':
				gg_session_set_async(gs, 0);
				break;

			case 's':
				parse_address(optarg, &host, &port);
				gg_session_set_server(gs, inet_addr(host), port);
				free(host);
				break;

			case 'p':
				parse_address(optarg, &host, &port);
				gg_proxy_enabled = 1;
				gg_proxy_host = host;
				gg_proxy_port = port;
				break;

			case 'H':
				gg_proxy_http_only = 1;
				break;

			case 'l':
				gg_session_set_last_message(gs, atoi(optarg));
				break;

			case 'h':
				usage(argv[0]);
				gg_session_free(gs);
				return 0;

			case 'y':
				hide_sysmsg = 1;
				break;

			default:
				usage(argv[0]);
				gg_session_free(gs);
				return 1;
		}
	}

	if (argc - optind < 2) {
		usage(argv[0]);
		gg_session_free(gs);
		return 1;
	}

	gg_session_set_uin(gs, atoi(argv[optind]));
	gg_session_set_password(gs, argv[optind + 1]);

	signal(SIGINT, sigint);

	if (gg_session_connect(gs) == -1) {
		perror("gg_session_connect");
		gg_session_free(gs);
		free(gg_proxy_host);
		return 1;
	}

	for (;;) {
		struct timeval tv;
		fd_set rd, wd;
		int ret, fd, check;
		time_t now;

		FD_ZERO(&rd);
		FD_ZERO(&wd);

		fd = gg_session_get_fd(gs);
		check = gg_session_get_check(gs);

		if ((check & GG_CHECK_READ))
			FD_SET(fd, &rd);
		if ((check & GG_CHECK_WRITE))
			FD_SET(fd, &wd);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		
		ret = select(fd + 1, &rd, &wd, NULL, &tv);

		if (ret == -1) {
			if (errno == EINTR)
				continue;
			perror("select");
			break;
		}

		now = time(NULL);

		if (now != last) {
			if (gs->timeout != -1 && gs->timeout-- == 0 && !gs->soft_timeout) {
				printf("Timeout!\n");
				break;
			}
		}
	
		if (gs != NULL && (FD_ISSET(fd, &rd) || FD_ISSET(fd, &wd) || (gs->timeout == 0 && gs->soft_timeout))) {
			struct gg_event *ge;

			ge = gg_watch_fd(gs);

			if (ge == NULL) {
				printf("Connection broken!\n");
				break;
			}

			if (ge->type == GG_EVENT_CONN_SUCCESS) {
				printf("Connected (press Ctrl-C to disconnect)\n");
				gg_notify(gs, NULL, 0);
			}

			if (ge->type == GG_EVENT_CONN_FAILED) {
				printf("Connection failed!\n");
				gg_event_free(ge);
				break;
			}

			if (ge->type == GG_EVENT_DISCONNECT_ACK) {
				printf("Connection closed\n");
				gg_event_free(ge);
				break;
			}

			if (ge->type == GG_EVENT_MSG) {
				if (ge->event.msg.sender != 0 || !hide_sysmsg)
					printf("Received message from %d:\n- plain text: %s\n- html: %s\n", ge->event.msg.sender, ge->event.msg.message, ge->event.msg.xhtml_message);
			}

			gg_event_free(ge);
		}

		if (disconnect_flag) {
			gg_session_disconnect(gs, 1);
			disconnect_flag = 1;
		}
	}

	free(gg_proxy_host);
	
	gg_session_free(gs);

	return 0;
}

