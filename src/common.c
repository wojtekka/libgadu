/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>,
 *                          Robert J. Wo¼ny <speedy@ziew.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#ifndef _AIX
#  include <string.h>
#endif
#include <stdarg.h>
#include <pwd.h>
#include <time.h>
#ifdef sun
  #include <sys/filio.h>
#endif
#include "libgadu.h"
#include "config.h"

/*
 * gg_debug()
 *
 * wyrzuca komunikat o danym poziomie, o ile u¿ytkownik sobie tego ¿yczy.
 *
 *  - level - poziom wiadomo¶ci,
 *  - format... - tre¶æ wiadomo¶ci (printf-alike.)
 *
 * niczego nie zwraca.
 */
void gg_debug(int level, const char *format, ...)
{
	va_list ap;
	
	if ((gg_debug_level & level)) {
		va_start(ap, format);
		vprintf(format, ap);
		va_end(ap);
	}
}

/*
 * gg_alloc_sprintf()
 *
 * robi dok³adnie to samo, co sprintf(), tyle ¿e alokuje sobie wcze¶niej
 * miejsce na dane. powinno dzia³aæ na tych maszynach, które maj± funkcjê
 * vsnprintf() zgodn± z C99, jak i na wcze¶niejszych.
 *
 *  - format, ... - parametry takie same jak w innych funkcjach *printf()
 *
 * zwraca zaalokowany buforek, który wypada³oby pó¼niej zwolniæ, lub NULL
 * je¶li nie uda³o siê wykonaæ zadania.
 */
char *gg_alloc_sprintf(const char *format, ...)
{
        va_list ap;
        char *buf = NULL, *tmp;
        int size = 0, res;

        va_start(ap, format);

        if ((size = vsnprintf(buf, 0, format, ap)) < 1) {
                size = 128;
                do {
                        size *= 2;
                        if (!(tmp = realloc(buf, size))) {
                                free(buf);
                                return NULL;
                        }
                        buf = tmp;
                        res = vsnprintf(buf, size, format, ap);
                } while (res == size - 1);
        } else {
                if (!(buf = malloc(size + 1)))
                        return NULL;
        }

        vsnprintf(buf, size + 1, format, ap);

        va_end(ap);

        return buf;
}

/*
 * gg_get_line()
 * 
 * podaje kolejn± liniê z bufora tekstowego. psuje co bezpowrotnie, dziel±c
 * na kolejne stringi. zdarza siê, nie ma potrzeby pisania funkcji dubluj±cej
 * bufor ¿eby tylko mieæ nieruszone dane wej¶ciowe, skoro i tak nie bêd± nam
 * po¼niej potrzebne. obcina `\r\n'.
 * 
 *  - ptr - wska¼nik do zmiennej, która przechowuje aktualn± pozycjê
 *    w przemiatanym buforze.
 * 
 * wska¼nik do kolejnej linii tekstu lub NULL, je¶li to ju¿ koniec bufora.
 */
char *gg_get_line(char **ptr)
{
        char *foo, *res;

        if (!ptr || !*ptr || !strcmp(*ptr, ""))
                return NULL;

        res = *ptr;

        if (!(foo = strchr(*ptr, '\n')))
                *ptr += strlen(*ptr);
        else {
                *ptr = foo + 1;
                *foo = 0;
                if (res[strlen(res) - 1] == '\r')
                        res[strlen(res) - 1] = 0;
        }

        return res;
}

/*
 * gg_connect()
 *
 * ³±czy siê z serwerem. pierwszy argument jest typu (void *), ¿eby nie
 * musieæ niczego inkludowaæ w libgadu.h i nie psuæ jaki¶ g³upich zale¿no¶ci
 * na dziwnych systemach.
 *
 *  - addr - adres serwera (struct in_addr *),
 *  - port - port serwera,
 *  - async - ma byæ asynchroniczne po³±czenie?
 *
 * zwraca po³±czonego socketa lub -1 w przypadku b³êdu. zobacz errno.
 */
int gg_connect(void *addr, int port, int async)
{
	int sock, one = 1;
	struct sockaddr_in sin;
	struct in_addr *a = addr;

	gg_debug(GG_DEBUG_FUNCTION, "** gg_connect(%s, %d, %d);\n", inet_ntoa(*a), port, async);
	
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		gg_debug(GG_DEBUG_MISC, "-- socket() failed. errno = %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	if (async) {
		if (ioctl(sock, FIONBIO, &one) == -1) {
			gg_debug(GG_DEBUG_MISC, "-- ioctl() failed. errno = %d (%s)\n", errno, strerror(errno));
			close(sock);
			return -1;
		}
	}

	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = a->s_addr;
	
	if (connect(sock, (struct sockaddr*) &sin, sizeof(sin)) == -1) {
		if (errno && (!async || errno != EINPROGRESS)) {
			gg_debug(GG_DEBUG_MISC, "-- connect() failed. errno = %d (%s)\n", errno, strerror(errno));
			close(sock);
			return -1;
		}
		gg_debug(GG_DEBUG_MISC, "-- connect() in progress\n");
	}
	
	return sock;
}

/*
 * gg_read_line()
 *
 * czyta jedn± liniê tekstu z socketa.
 *
 *  - sock - socket,
 *  - buf - wska¼nik bufora,
 *  - length - d³ugo¶æ bufora.
 *
 * je¶li trafi na b³±d odczytu, zwraca NULL. inaczej zwraca buf.
 */
char *gg_read_line(int sock, char *buf, int length)
{
	int ret;

	for (; length > 1; buf++, length--) {
		do {
			if ((ret = read(sock, buf, 1)) < 1 && errno != EINTR) {
				gg_debug(GG_DEBUG_MISC, "-- gg_read_line(), eof reached\n");
				*buf = 0;
				return NULL;
			}
		} while (ret == -1 && errno == EINTR);

		if (*buf == '\n') {
			buf++;
			break;
		}
	}

	*buf = 0;
	return buf;
}

/*
 * gg_chomp()
 *
 * ucina "\r\n" lub "\n" z koñca linii.
 *
 *  - line - ofiara operacji plastycznej.
 *
 * niczego nie zwraca.
 */
void gg_chomp(char *line)
{
	if (!line || strlen(line) < 1)
		return;

	if (line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;
	if (line[strlen(line) - 1] == '\r')
		line[strlen(line) - 1] = 0;
}


/*
 * gg_urlencode() // funkcja wewnêtrzna
 *
 * zamienia podany tekst na ci±g znaków do formularza http. przydaje siê
 * przy szukaniu userów z dziwnymi znaczkami.
 *
 *  - str - ci±g znaków do poprawki.
 *
 * zwraca zaalokowany bufor, który wypada³oby kiedy¶ zwolniæ albo NULL
 * w przypadku b³êdu.
 */
char *gg_urlencode(const char *str)
{
	char *q, *buf, hex[] = "0123456789abcdef";
	const char *p;
	int size = 0;

	if (!str)
		str = strdup("");

	for (p = str; *p; p++, size++) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')))
			size += 2;
	}

	if (!(buf = malloc(size + 1)))
		return NULL;

	for (p = str, q = buf; *p; p++, q++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9'))
			*q = *p;
		else {
			*q++ = '%';
			*q++ = hex[*p >> 4 & 15];
			*q = hex[*p & 15];
		}
	}

	*q = 0;

	return buf;
}

/*
 * gg_http_hash()
 *
 * funkcja, która liczy hash dla adresu e-mail, has³a i paru innych.
 *
 *  - format - format kolejnych parametrów,
 *  - ... - kolejne parametry.
 *
 * zwraca hash wykorzystywany przy rejestracji i wszelkich
 * manipulacjach w³asnego wpisu w katalogu publicznym. ,,format''
 * zawiera znaki 's' je¶li dany parametr jest ci±giem znaków lub
 * 'u' je¶li jest numerkiem gg.
 */
int gg_http_hash(const char *format, ...)
{
	unsigned int a, c;
	va_list ap;
	int b = -1, i, j;

	va_start(ap, format);

	if (!format)
		return 0;
	
	for (j = 0; j < strlen(format); j++) {
		unsigned char *arg, buf[16];

		if (format[j] == 'u') {
			snprintf(buf, sizeof(buf), "%ld", va_arg(ap, uin_t));
			arg = buf;
		} else {
			if (!(arg = va_arg(ap, unsigned char*)))
				arg = "";
		}	

		i = 0;
		while ((c = (int) arg[i++]) != 0) {
			a = (c ^ b) + (c << 8);
			b = (a >> 24) | (a << 8);
		}
	}

	return (b < 0 ? -b : b);
}

/*
 * Local variables:
 * c-indentation-style: k&r
 * c-basic-offset: 8
 * indent-tabs-mode: notnil
 * End:
 *
 * vim: shiftwidth=8:
 */
