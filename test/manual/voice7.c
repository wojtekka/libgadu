#if 0

/* this test-program is based on ekg1 sources. */

/*
 *  (C) Copyright 2002-2006 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Adam Wysocki <gophi@ekg.chmurka.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

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

/* audio, OSS */
#include <sys/ioctl.h>
#include <linux/soundcard.h>

#if HAVE_GSM
 #include <gsm/gsm.h>
#endif

#if HAVE_SPEEX
 #include <speex/speex.h>
#endif

#include "libgadu.h"
#include "userconfig.h"

#define EKG_CODEC_NONE    0x00
#define EKG_CODEC_GSM     0x01
#define EKG_CODEC_SPEEX   0x02
#define EKG_CODEC_MELP    0x04


int test_mode;
int connected;

enum {
	TEST_MODE_SEND = 0,
	TEST_MODE_RECEIVE,
	TEST_MODE_LAST
};

int voice_fd = -1;

#if HAVE_GSM
gsm voice_gsm_enc = NULL, voice_gsm_dec = NULL;
#endif

#if HAVE_SPEEX
void *voice_speex_enc = NULL;
void *voice_speex_dec = NULL;

SpeexBits speex_enc_bits;
SpeexBits speex_dec_bits;
#endif

static void debug(const char *msg, ...) GG_GNUC_PRINTF(1, 2);
static void debug(const char *msg, ...)
{
	va_list ap;

	fprintf(stderr, "\033[1m");

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, "\033[0m");
	fflush(stderr);
}

void voice_close()
{
	if (voice_fd != -1) {
		close(voice_fd);
		voice_fd = -1;
	}
#if HAVE_GSM
	if (voice_gsm_dec) {
		gsm_destroy(voice_gsm_dec);
		voice_gsm_dec = NULL;
	}

	if (voice_gsm_enc) {
		gsm_destroy(voice_gsm_enc);
		voice_gsm_enc = NULL;
	}
#endif

#if HAVE_SPEEX
	if (voice_speex_enc) {
		speex_encoder_destroy(voice_speex_enc);
		voice_speex_enc = NULL;
		speex_bits_destroy(&speex_enc_bits);
	}

	if (voice_speex_dec) {
		speex_decoder_destroy(voice_speex_dec);
		voice_speex_dec = NULL;
		speex_bits_destroy(&speex_dec_bits);
	}

#endif
}

int voice_open_ext(const char *pathname, int speed, int sample, int channels, int codec)
{
	int value;

	if (voice_fd != -1)
		return -1;

	if ((voice_fd = open(pathname, O_RDWR)) == -1)
		goto fail;

	if (ioctl(voice_fd, SNDCTL_DSP_SPEED, &speed) == -1)
		goto fail;

	if (ioctl(voice_fd, SNDCTL_DSP_SAMPLESIZE, &sample) == -1)
		goto fail;

	if (ioctl(voice_fd, SNDCTL_DSP_CHANNELS, &channels) == -1)
		goto fail;

	value = AFMT_S16_LE;

	if (ioctl(voice_fd, SNDCTL_DSP_SETFMT, &value) == -1)
		goto fail;

	if (codec & EKG_CODEC_GSM) {
#if HAVE_GSM
		gsm_signal tmp;

		if (read(voice_fd, &tmp, sizeof(tmp)) != sizeof(tmp))
			goto fail;

		if (!(voice_gsm_dec = gsm_create()) || !(voice_gsm_enc = gsm_create()))
			goto fail;

		value = 1;

		gsm_option(voice_gsm_dec, GSM_OPT_FAST, &value);
		gsm_option(voice_gsm_dec, GSM_OPT_VERBOSE, &value);
		gsm_option(voice_gsm_dec, GSM_OPT_LTP_CUT, &value);
		gsm_option(voice_gsm_enc, GSM_OPT_FAST, &value);
#else
		goto fail;
#endif
	}

	if (codec & EKG_CODEC_SPEEX) {
#if HAVE_SPEEX
		if (!(voice_speex_enc = speex_encoder_init(&speex_wb_mode)) ||
			!(voice_speex_dec = speex_decoder_init(&speex_wb_mode)))
		{
			goto fail;
		}

		speex_bits_init(&speex_enc_bits);
		speex_bits_init(&speex_dec_bits);
#else
		goto fail;
#endif
	}

	if (codec & EKG_CODEC_MELP) {
		goto fail;
	}

	return 0;

fail:
	voice_close();
	return -1;
}

int voice_record(char *buf, int length, int codec)
{
	gsm_signal input[160];
	const char *pos = buf;

	int ramki_dwie;

	switch (codec) {
		case EKG_CODEC_NONE:
			ramki_dwie = 32 + 33;
			break;

		case EKG_CODEC_GSM:
			ramki_dwie = 33 + 33;
			break;

		default:
			/* przeczytaj cokolwiek, zeby nam petelka z select()
			 * nie robila 100% CPU */
			return read(voice_fd, input, 320);
	}

	while (pos <= (buf + length - ramki_dwie)) {
		if (read(voice_fd, input, 320) != 320)
			return -1;

		switch (codec) {
			case EKG_CODEC_NONE:
				pos += 32;
				break;

			case EKG_CODEC_GSM:
				gsm_encode(voice_gsm_enc, input, (unsigned char *) pos);
				pos += 33;
				break;
		}

		if (read(voice_fd, input, 320) != 320)
			return -1;

		switch (codec) {
			case EKG_CODEC_NONE:
				pos += 33;
				break;

			case EKG_CODEC_GSM:
				gsm_encode(voice_gsm_enc, input, (unsigned char *) pos);
				pos += 33;
				break;
		}
	}

	return 0;
}

int voice_play(const char *buf, int length, int codec)
{
	if (length <= 0)
		return 0;

	if (codec == EKG_CODEC_SPEEX) {
#if HAVE_SPEEX
		spx_int16_t speex_output[320];

		speex_bits_read_from(&speex_dec_bits, buf, length);
		speex_decode_int(voice_speex_dec, &speex_dec_bits, speex_output);		/* XXX, != 0 return? */

		if (write(voice_fd, speex_output, sizeof(speex_output)) != sizeof(speex_output))
			return -1;

		return 0;
#else
		printf("voice_play() received speex packet, but HAVE_SPEEX\n");
		return -1;
#endif
	}

	if (codec == EKG_CODEC_GSM) {
#if HAVE_GSM
		const int ramki_dwie = 33 + 33;
		gsm_signal gsm_output[160];

		const char *pos = buf;

		while (pos <= (buf + length - ramki_dwie)) {
			switch (codec) {
				case EKG_CODEC_GSM:
					if (gsm_decode(voice_gsm_dec, (unsigned char *) pos, gsm_output)) return -1;
					pos += 33;
					break;
			}

			if (write(voice_fd, gsm_output, 320) != 320)
				return -1;

			switch (codec) {
				case EKG_CODEC_GSM:
					if (gsm_decode(voice_gsm_dec, (unsigned char *) pos, gsm_output)) return -1;
					pos += 33;
					break;
			}


			if (write(voice_fd, gsm_output, 320) != 320)
				return -1;
		}
		return 0;
#else
		printf("voice_play() received gsm packet, but HAVE_GSM\n");
		return -1;
#endif
	}

	return -1;
}

static void usage(const char *program) {
	fprintf(stderr, "usage: %s <mode>\n"
			"\n"
			"mode: 0 - send voice req\n"
			"      1 - receive voice req\n"
			"\n", program);
	exit(1);
}

int main(int argc, char **argv)
{
	struct gg_session *gs;
	struct gg_login_params glp;
	struct gg_dcc7 *gd = NULL;
	time_t ping = 0, last = 0;
	int once = 0;

	if (argc != 2)
		usage(argv[0]);

/* strtol() ? */
	if (!(argv[1][0] >= '0' && argv[1][0] <= '9'))
		usage(argv[0]);

	if (atoi(argv[1]) >= TEST_MODE_LAST)
		usage(argv[0]);

	test_mode = atoi(argv[1]);

	signal(SIGPIPE, SIG_IGN);
	gg_debug_file = stdout;
	gg_debug_level = ~0;

	if (config_read() == -1 || config_peer == 0) {
		perror("config");
		exit(1);
	}

	memset(&glp, 0, sizeof(glp));
	glp.uin = config_uin;
	glp.password = config_password;
	glp.async = 1;
	glp.status = GG_STATUS_AVAIL;
#if 0
	glp.client_addr = config_ip;
	glp.client_port = config_port;
#endif
	glp.protocol_version = 0x2a;
	glp.has_audio = 1;
	glp.last_sysmsg = -1;

	gg_dcc_ip = config_ip;

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

		if (voice_fd != -1) {
			FD_SET(voice_fd, &rds);

			if (voice_fd > maxfd)
				maxfd = voice_fd;
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
				/* vvvv XXX */
			if (gd && gd->timeout && gd->timeout != -1 && gd->timeout-- == 0 && !gd->soft_timeout) {
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

					if (!once && uin == config_peer && (GG_S_A(status) ||
						GG_S_B(status)) && test_mode == TEST_MODE_SEND)
					{
						debug("Sending voice request...\n");

						if (voice_open_ext("/dev/dsp", 8000, 16, 2, EKG_CODEC_GSM) == -1) {
							printf("voice_open_ext('/dev/dsp', "
								"8000, 16, 2, CODEC_GSM) failed\n");
							exit(1);
						}
						printf("+OK\n");

						gd = gg_dcc7_voice_chat(gs, config_peer, 0x00);

						if (!gd) {
							perror("gg_dcc7_voice_chat");
							exit(1);
						}
						once = 1;
					}

					gg_change_status(gs, GG_STATUS_AVAIL);	/* XXX, libgadu sobie nie radzi */

					break;

				case GG_EVENT_DCC7_NEW:
					debug("Incoming direct connection\n");

					if (test_mode == TEST_MODE_RECEIVE) {
						gd = ge->event.dcc7_new;

						if (voice_open_ext("/dev/dsp", 8000, 16, 2, EKG_CODEC_GSM) == -1) {
							printf("voice_open_ext('/dev/dsp', "
								"8000, 16, 2, CODEC_GSM) failed\n");
							exit(1);
						}
						printf("+OK\n");

						gg_dcc7_accept_voice(gd, 0x00);
					}

					break;

				case GG_EVENT_DCC7_ERROR:
					debug("Direct connection error\n");
					exit(1);

				case GG_EVENT_DCC7_ACCEPT:
					debug("Accepted\n");
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

		if (gd && gd->fd != -1 && (FD_ISSET(gd->fd, &rds) ||
			FD_ISSET(gd->fd, &wds) || (gd->timeout == 0 && gd->soft_timeout)))
		{
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

				case GG_EVENT_DCC7_VOICE_DATA:
					gg_debug(GG_DEBUG_MISC,
						"## GG_EVENT_DCC7_VOICE_DATA [%u]\n",
						ge->event.dcc7_voice_data.length);
					printf("## GG_EVENT_DCC7_VOICE_DATA [%u]\n",
						ge->event.dcc7_voice_data.length);

					if (voice_fd == -1) {
						printf("voice_fd == -1\n");
						exit(1);
					}

					if (ge->event.dcc7_voice_data.length == GG_DCC7_VOICE_FRAME_GSM_LENGTH)
						voice_play(ge->event.dcc7_voice_data.data,
							ge->event.dcc7_voice_data.length, EKG_CODEC_GSM);
					else if (ge->event.dcc7_voice_data.length == GG_DCC7_VOICE_FRAME_SPEEX_LENGTH)
						voice_play(ge->event.dcc7_voice_data.data,
							ge->event.dcc7_voice_data.length, EKG_CODEC_SPEEX);
					else if (ge->event.dcc7_voice_data.length == GG_DCC7_VOICE_FRAME_MELP_LENGTH)
						voice_play(ge->event.dcc7_voice_data.data,
							ge->event.dcc7_voice_data.length, EKG_CODEC_MELP);
					break;

				case GG_EVENT_NONE:
					break;

				default:
					debug("Unsupported event %d\n", ge->type);
					break;
			}

			gg_event_free(ge);
		}

		if (voice_fd != -1 && FD_ISSET(voice_fd, &rds)) {
			char buf[GG_DCC_VOICE_FRAME_LENGTH];	/* dłuższy z buforów */
			int length = GG_DCC_VOICE_FRAME_LENGTH;

			if (gd) {
				if (gd->state == GG_STATE_READING_VOICE_DATA) {
					/* XXX, implementowac speex */
					length = GG_DCC7_VOICE_FRAME_GSM_LENGTH;
					voice_record(buf, length, EKG_CODEC_GSM);

					if (1)
						gg_dcc7_voice_send(gd, buf, length);
					else {
						/* ten pakiet mamy wysylac co 1s */
						gg_dcc7_voice_mic_off(gd);
					}

				} else
					voice_record(buf, length, EKG_CODEC_NONE);
			} else
				voice_record(buf, length, EKG_CODEC_NONE);
		}
	}

	if (gg_debug_file != stdout)	/* w sumie stdout, tez moglibysmy zamknac.. czemu nie. */
		fclose(gg_debug_file);

	return 0;
}

#else

int main(void)
{
	return 0;
}

#endif
