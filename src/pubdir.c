/* $Id$ */

/*
 *  (C) Copyright 2001-2002 Wojtek Kaniewski <wojtekka@irc.pl>
 *                          Dawid Jarosz <dawjar@poczta.onet.pl>
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

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libgadu.h"

/*
 * gg_register()
 *
 * rozpoczyna rejestracjê u¿ytkownika.
 *
 *  - email - adres e-mail klienta
 *  - password - has³o klienta
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_register_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_register(const char *email, const char *password, int async)
{
        struct gg_http *h;
	char *__pwd, *__email, *form, *query;

	if (!email | !password) {
		gg_debug(GG_DEBUG_MISC, "=> register, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}

	__pwd = gg_urlencode(password);
	__email = gg_urlencode(email);

	if (!__pwd || !__email) {
		gg_debug(GG_DEBUG_MISC, "=> register, not enough memory for form fields\n");
		free(__pwd);
		free(__email);
                errno = ENOMEM;
		return NULL;
	}

	form = gg_saprintf("pwd=%s&email=%s&code=%u", __pwd, __email,
			gg_http_hash("ss", email, password));

	free(__pwd);
	free(__email);

	if (!form) {
		gg_debug(GG_DEBUG_MISC, "=> register, not enough memory for form query\n");
                errno = ENOMEM;
		return NULL;
	}

	gg_debug(GG_DEBUG_MISC, "=> register, %s\n", form);

	query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"User-Agent: " GG_HTTP_USERAGENT "\r\n"
		"Content-Length: %d\r\n"
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s",
		(int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> register, gg_http_connect() failed mysteriously\n");
		free(query);
                return NULL;
	}

	h->type = GG_SESSION_REGISTER;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;
	
	if (!async)
		gg_pubdir_watch_fd(h);
	
	return h;
}

/*
 * gg_register2()
 *
 * rozpoczyna rejestracjê u¿ytkownika protoko³em GG 5.0.
 *
 *  - email - adres e-mail klienta
 *  - password - has³o klienta
 *  - qa - has³o pomocnicze i odpowied¼, oddzielone tyld±
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_register_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_register2(const char *email, const char *password, const char *qa, int async)
{
        struct gg_http *h;
	char *__pwd, *__email, *__qa, *form, *query;

	if (!email | !password) {
		gg_debug(GG_DEBUG_MISC, "=> register, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}

	__pwd = gg_urlencode(password);
	__email = gg_urlencode(email);
	__qa = gg_urlencode(qa);

	if (!__pwd || !__email) {
		gg_debug(GG_DEBUG_MISC, "=> register, not enough memory for form fields\n");
		free(__pwd);
		free(__email);
		free(__qa);
                errno = ENOMEM;
		return NULL;
	}

	form = gg_saprintf("pwd=%s&email=%s&qa=%s&code=%u", __pwd, __email,
			__qa, gg_http_hash("ss", email, password));

	free(__pwd);
	free(__email);
	free(__qa);

	if (!form) {
		gg_debug(GG_DEBUG_MISC, "=> register, not enough memory for form query\n");
                errno = ENOMEM;
		return NULL;
	}

	gg_debug(GG_DEBUG_MISC, "=> register, %s\n", form);

	query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"User-Agent: " GG_HTTP_USERAGENT "\r\n"
		"Content-Length: %d\r\n"
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s",
		(int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister2.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> register, gg_http_connect() failed mysteriously\n");
		free(query);
                return NULL;
	}

	h->type = GG_SESSION_REGISTER;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;
	
	if (!async)
		gg_pubdir_watch_fd(h);
	
	return h;
}

/*
 * gg_unregister()
 *
 * usuwa konto u¿ytkownika z serwera.
 *
 *  - uin - numerek GG
 *  - password - has³o klienta
 *  - email - adres e-mail klienta
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_unregister_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_unregister(uin_t uin, const char *password, const char *email, int async)
{
	struct gg_http *h;
	char *__fmemail, *__fmpwd, *__email, *__pwd, *form, *query;
	const char *email0 = "deletedaccount@gadu-gadu.pl";

	if (!password || !email) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}
    
	__pwd = gg_saprintf("%ld", random());
	__fmpwd = gg_urlencode(password);
	__fmemail = gg_urlencode(email);
	__email = gg_urlencode(email0);

	if (!__fmpwd || !__fmemail || !__pwd || !__email) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, not enough memory for form fields\n");
		free(__pwd);
		free(__fmpwd);
		free(__fmemail);
		free(__email);
                errno = ENOMEM;
		return NULL;
	}

	form = gg_saprintf("fmnumber=%d&fmpwd=%s&delete=1&fmemail=%s&"
			"pwd=%s&email=%s&code=%u",
			uin, __fmpwd, __fmemail, __pwd, __email,
			gg_http_hash("ss", email0, __pwd));

	free(__fmpwd);
	free(__fmemail);
	free(__pwd);
	free(__email);

	if (!form) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, not enough memory for form query\n");
		errno = ENOMEM;
		return NULL;
	}

	gg_debug(GG_DEBUG_MISC, "=> unregister, %s\n", form);

	query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"User-Agent: " GG_HTTP_USERAGENT "\r\n"
		"Content-Length: %d\r\n"
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s",
		(int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, gg_http_connect() failed mysteriously\n");
		free(query);
		return NULL;
	}

	h->type = GG_SESSION_UNREGISTER;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;
	
	if (!async)
		gg_pubdir_watch_fd(h);
	
	return h;
}

/*
 * gg_unregister2()
 *
 * usuwa konto u¿ytkownika z serwera protoko³em GG 5.0
 *
 *  - uin - numerek GG
 *  - password - has³o klienta
 *  - qa - pytanie pomocnicze i odpowied¼, oddzielone tyld±
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_unregister_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_unregister2(uin_t uin, const char *password, const char *qa, int async)
{
	struct gg_http *h;
	char *__fmpwd, *__qa, *__pwd, *form, *query;

	if (!password || !qa) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}
    
	__pwd = gg_saprintf("%ld", random());
	__fmpwd = gg_urlencode(password);
	__qa = gg_urlencode(qa);

	if (!__fmpwd || !__pwd || !__qa) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, not enough memory for form fields\n");
		free(__pwd);
		free(__fmpwd);
		free(__qa);
                errno = ENOMEM;
		return NULL;
	}

	form = gg_saprintf("fmnumber=%d&fmpwd=%s&delete=1&pwd=%s&qa=%s&code=%u", uin, __fmpwd, __pwd, __qa, gg_http_hash("s", __pwd));

	free(__fmpwd);
	free(__pwd);
	free(__qa);

	if (!form) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, not enough memory for form query\n");
		errno = ENOMEM;
		return NULL;
	}

	gg_debug(GG_DEBUG_MISC, "=> unregister, %s\n", form);

	query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"User-Agent: " GG_HTTP_USERAGENT "\r\n"
		"Content-Length: %d\r\n"
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s",
		(int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister2.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> unregister, gg_http_connect() failed mysteriously\n");
		free(query);
		return NULL;
	}

	h->type = GG_SESSION_UNREGISTER;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;
	
	if (!async)
		gg_pubdir_watch_fd(h);
	
	return h;
}

/*
 * gg_change_passwd()
 *
 * wysy³a ¿±danie zmiany has³a. funkcja nie dzia³a, ze wzglêdu na zmiany
 * w protokole. zosta³a tylko po to, by zachowaæ ABI biblioteki.
 *
 *  - uin - numer
 *  - passwd - stare has³o
 *  - newpasswd - nowe has³o
 *  - newemail - nowy adres e-mail
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_change_passwd_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_change_passwd(uin_t uin, const char *passwd, const char *newpasswd, const char *newemail, int async)
{
	struct gg_http *h;
	char *form, *query, *__fmpwd, *__pwd, *__email;

	if (!passwd || !newpasswd || !newemail) {
		gg_debug(GG_DEBUG_MISC, "=> change, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}
	
	__fmpwd = gg_urlencode(passwd);
	__pwd = gg_urlencode(newpasswd);
	__email = gg_urlencode(newemail);

	if (!__fmpwd || !__pwd || !__email) {
		gg_debug(GG_DEBUG_MISC, "=> change, not enough memory for form fields\n");
		free(__fmpwd);
		free(__pwd);
		free(__email);
		errno = ENOMEM;
		return NULL;
	}
	
	if (!(form = gg_saprintf("fmnumber=%d&fmpwd=%s&pwd=%s&email=%s&code=%u", uin, __fmpwd, __pwd, __email, gg_http_hash("ss", newemail, newpasswd)))) {
		gg_debug(GG_DEBUG_MISC, "=> change, not enough memory for form fields\n");
		free(__fmpwd);
		free(__pwd);
		free(__email);

		errno = ENOMEM;
		return NULL;
	}
	
	free(__fmpwd);
	free(__pwd);
	free(__email);
	
	gg_debug(GG_DEBUG_MISC, "=> change, %s\n", form);

        query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "User-Agent: " GG_HTTP_USERAGENT "\r\n"
                "Content-Length: %d\r\n"
                "Pragma: no-cache\r\n"
                "\r\n"
                "%s",
                (int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> change, gg_http_connect() failed mysteriously\n");
                free(query);
		return NULL;
	}

	h->type = GG_SESSION_PASSWD;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;

	if (!async)
		gg_pubdir_watch_fd(h);

	return h;
}

/*
 * gg_change_passwd2()
 *
 * wysy³a ¿±danie zmiany has³a, uwzglêdniaj±c zmiany w protokole.
 *
 *  - uin - numer
 *  - passwd - stare has³o
 *  - newpasswd - nowe has³o
 *  - email - stary adres e-mail
 *  - newemail - nowy adres e-mail
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_change_passwd_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_change_passwd2(uin_t uin, const char *passwd, const char *newpasswd, const char *email, const char *newemail, int async)
{
	struct gg_http *h;
	char *form, *query, *__fmpwd, *__pwd, *__fmemail, *__email;

	if (!passwd || !newpasswd || !email || !newemail) {
		gg_debug(GG_DEBUG_MISC, "=> change, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}
	
	__fmpwd = gg_urlencode(passwd);
	__pwd = gg_urlencode(newpasswd);
	__fmemail = gg_urlencode(email);
	__email = gg_urlencode(newemail);

	if (!__fmpwd || !__pwd || !__email) {
		gg_debug(GG_DEBUG_MISC, "=> change, not enough memory for form fields\n");
		free(__fmpwd);
		free(__pwd);
		free(__fmemail);
		free(__email);
		errno = ENOMEM;
		return NULL;
	}
	
	if (!(form = gg_saprintf("fmnumber=%d&fmpwd=%s&pwd=%s&fmemail=%s&email=%s&code=%u", uin, __fmpwd, __pwd, __fmemail, __email, gg_http_hash("ss", newemail, newpasswd)))) {
		gg_debug(GG_DEBUG_MISC, "=> change, not enough memory for form fields\n");
		free(__fmpwd);
		free(__pwd);
		free(__fmemail);
		free(__email);

		errno = ENOMEM;
		return NULL;
	}
	
	free(__fmpwd);
	free(__pwd);
	free(__fmemail);
	free(__email);
	
	gg_debug(GG_DEBUG_MISC, "=> change, %s\n", form);

        query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "User-Agent: " GG_HTTP_USERAGENT "\r\n"
                "Content-Length: %d\r\n"
                "Pragma: no-cache\r\n"
                "\r\n"
                "%s",
                (int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> change, gg_http_connect() failed mysteriously\n");
                free(query);
		return NULL;
	}

	h->type = GG_SESSION_PASSWD;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;

	if (!async)
		gg_pubdir_watch_fd(h);

	return h;
}

/*
 * gg_change_passwd3()
 *
 * wysy³a ¿±danie zmiany has³a zgodnie z protoko³em GG 5.0.4
 *
 *  - uin - numer
 *  - passwd - stare has³o
 *  - newpasswd - nowe has³o
 *  - qa - pytanie pomocnicze i odpowied¼ oddzielone tyld±
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_change_passwd_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_change_passwd3(uin_t uin, const char *passwd, const char *newpasswd, const char *qa, int async)
{
	struct gg_http *h;
	char *form, *query, *__fmpwd, *__pwd, *__qa;

	if (!passwd || !newpasswd) {
		gg_debug(GG_DEBUG_MISC, "=> change, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}
	
	__fmpwd = gg_urlencode(passwd);
	__pwd = gg_urlencode(newpasswd);
	__qa = gg_urlencode(qa);

	if (!__fmpwd || !__pwd) {
		gg_debug(GG_DEBUG_MISC, "=> change, not enough memory for form fields\n");
		free(__fmpwd);
		free(__pwd);
		free(__qa);
		errno = ENOMEM;
		return NULL;
	}
	
	if (!(form = gg_saprintf("fmnumber=%d&fmpwd=%s&pwd=%s&qa=&code=%u", uin, __fmpwd, __pwd, gg_http_hash("s", newpasswd)))) {
		gg_debug(GG_DEBUG_MISC, "=> change, not enough memory for form fields\n");
		free(__fmpwd);
		free(__pwd);
		free(__qa);

		errno = ENOMEM;
		return NULL;
	}
	
	free(__fmpwd);
	free(__pwd);
	free(__qa);
	
	gg_debug(GG_DEBUG_MISC, "=> change, %s\n", form);

        query = gg_saprintf(
		"Host: " GG_REGISTER_HOST "\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "User-Agent: " GG_HTTP_USERAGENT "\r\n"
                "Content-Length: %d\r\n"
                "Pragma: no-cache\r\n"
                "\r\n"
                "%s",
                (int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REGISTER_HOST, GG_REGISTER_PORT, async, "POST", "/appsvc/fmregister2.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> change, gg_http_connect() failed mysteriously\n");
                free(query);
		return NULL;
	}

	h->type = GG_SESSION_PASSWD;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;

	if (!async)
		gg_pubdir_watch_fd(h);

	return h;
}

/*
 * gg_remind_passwd()
 *
 * wysy³a ¿±danie przypomnienia has³a e-mailem.
 *
 *  - uin - numer
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_remind_passwd_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_remind_passwd(uin_t uin, int async)
{
	struct gg_http *h;
	char *form, *query;

	if (!(form = gg_saprintf("userid=%d&code=%u", uin, gg_http_hash("u", uin)))) {
		gg_debug(GG_DEBUG_MISC, "=> remind, not enough memory for form fields\n");
		errno = ENOMEM;
		return NULL;
	}
	
	gg_debug(GG_DEBUG_MISC, "=> remind, %s\n", form);

        query = gg_saprintf(
		"Host: " GG_REMIND_HOST "\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "User-Agent: " GG_HTTP_USERAGENT "\r\n"
                "Content-Length: %d\r\n"
                "Pragma: no-cache\r\n"
                "\r\n"
                "%s",
                (int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_REMIND_HOST, GG_REMIND_PORT, async, "POST", "/appsvc/fmsendpwd.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> remind, gg_http_connect() failed mysteriously\n");
                free(query);
		return NULL;
	}

	h->type = GG_SESSION_REMIND;

	free(query);

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;

	if (!async)
		gg_pubdir_watch_fd(h);

	return h;
}

/*
 * gg_change_info()
 *
 * zmienia w³asne dane w katalogu publicznym.
 *
 *  - uin - numer
 *  - passwd - has³o
 *  - request - struktura opisuj±ca ¿±dane zmiany
 *  - async - po³±czenie asynchroniczne
 *
 * zaalokowana struct gg_http, któr± po¼niej nale¿y zwolniæ
 * funkcj± gg_change_info_free(), albo NULL je¶li wyst±pi³ b³±d.
 */
struct gg_http *gg_change_info(uin_t uin, const char *passwd, const struct gg_change_info_request *request, int async)
{
	struct gg_http *h;
	char *form, *query, *__first, *__last, *__nick, *__email, *__city;
	char __born[5];

	if (!passwd || !request) {
		gg_debug(GG_DEBUG_MISC, "=> change_info, NULL parameter\n");
		errno = EINVAL;
		return NULL;
	}

	__first = gg_urlencode(request->first_name);
	__last = gg_urlencode(request->last_name);
	__nick = gg_urlencode(request->nickname);
	__email = gg_urlencode(request->email);
	__city = gg_urlencode(request->city);
	
	if (request->born)
		snprintf(__born, sizeof(__born), "%d", request->born);
	else
		strcpy(__born, "");
	
	if (!__first || !__last || !__nick || !__email || !__city) {
		free(__first);
		free(__last);
		free(__nick);
		free(__email);
		free(__city);

		gg_debug(GG_DEBUG_MISC, "=> change_info, not enough memory for form fields\n");
		errno = ENOMEM;
		return NULL;
	}
	
	form = gg_saprintf("FmNum=%d&Pass=%s&FirstName=%s&LastName=%s&NickName=%s&Email=%s&BirthYear=%s&Gender=%d&City=%s&Phone=",
	uin, passwd, __first, __last, __nick, __email, __born, request->gender, __city);

	free(__first);
	free(__last);
	free(__nick);
	free(__email);
	free(__city);

	if (!form) {
		gg_debug(GG_DEBUG_MISC, "=> change_info, not enough memory for form fields\n");
		errno = ENOMEM;
		return NULL;
	}
	
	gg_debug(GG_DEBUG_MISC, "=> change_info, %s\n", form);

        query = gg_saprintf(
		"Host: " GG_PUBDIR_HOST "\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "User-Agent: " GG_HTTP_USERAGENT "\r\n"
                "Content-Length: %d\r\n"
                "Pragma: no-cache\r\n"
                "\r\n"
                "%s",
                (int) strlen(form), form);

	free(form);

	if (!(h = gg_http_connect(GG_PUBDIR_HOST, GG_PUBDIR_PORT, async, "POST", "/appsvc/fmpubreg2.asp", query))) {
		gg_debug(GG_DEBUG_MISC, "=> change_info, gg_http_connect() failed mysteriously\n");
                free(query);
		return NULL;
	}

	h->type = GG_SESSION_CHANGE;

	h->callback = gg_pubdir_watch_fd;
	h->destroy = gg_pubdir_free;
	
	if (!async)
		gg_pubdir_watch_fd(h);

	return h;

}

/*
 * gg_pubdir_watch_fd()
 *
 * przy asynchronicznych operacjach na katalogu publicznym nale¿y wywo³ywaæ
 * t± funkcjê przy zmianach na obserwowanym deskryptorze.
 *
 *  - h - struktura opisuj±ca po³±czenie
 *
 * je¶li wszystko posz³o dobrze to 0, inaczej -1. operacja bêdzie
 * zakoñczona, je¶li h->state == GG_STATE_DONE. je¶li wyst±pi jaki¶
 * b³±d, to bêdzie tam GG_STATE_ERROR i odpowiedni kod b³êdu w h->error.
 */
int gg_pubdir_watch_fd(struct gg_http *h)
{
	struct gg_pubdir *p;
	char *tmp;

	if (!h) {
		errno = EINVAL;
		return -1;
	}

        if (h->state == GG_STATE_ERROR) {
                gg_debug(GG_DEBUG_MISC, "=> pubdir, watch_fd issued on failed session\n");
                errno = EINVAL;
                return -1;
        }
	
	if (h->state != GG_STATE_PARSING) {
		if (gg_http_watch_fd(h) == -1) {
			gg_debug(GG_DEBUG_MISC, "=> pubdir, http failure\n");
                        errno = EINVAL;
			return -1;
		}
	}

	if (h->state != GG_STATE_PARSING)
                return 0;
	
        h->state = GG_STATE_DONE;
	
	if (!(h->data = p = malloc(sizeof(struct gg_pubdir)))) {
		gg_debug(GG_DEBUG_MISC, "=> pubdir, not enough memory for results\n");
		return -1;
	}
	p->success = 0;
	p->uin = 0;
	
	gg_debug(GG_DEBUG_MISC, "=> pubdir, let's parse \"%s\"\n", h->body);

	if ((tmp = strstr(h->body, "success")) || (tmp = strstr(h->body, "results"))) {
		p->success = 1;
		if (tmp[7] == ':')
			p->uin = strtol(tmp + 8, NULL, 0);
		gg_debug(GG_DEBUG_MISC, "=> pubdir, success (uin=%d)\n", p->uin);
	} else
		gg_debug(GG_DEBUG_MISC, "=> pubdir, error.\n");

	return 0;
}

/*
 * gg_pubdir_free()
 *
 * zwalnia pamiêæ po efektach operacji na katalogu publicznym.
 *
 *  - h - zwalniana struktura
 */
void gg_pubdir_free(struct gg_http *h)
{
	if (!h)
		return;
	
	free(h->data);
	gg_http_free(h);
}

/*
 * gg_change_info_request_new()
 *
 * alokuje pamiêæ i tworzy struct gg_change_info_request do u¿ycia jako
 * parametr gg_change_info().
 * 
 *  - first_name - imiê
 *  - last_name - nazwisko
 *  - nickname - pseudonim
 *  - email - adres e-mail
 *  - born - data urodzenia
 *  - gender - p³eæ (GG_GENDER_UNKNOWN, GG_GENDER_MALE, GG_GENDER_FEMALE)
 *  - city - miasto zamieszkania
 *
 * zaalokowana struktura lub NULL w przypadku braku pamiêci.
 */
struct gg_change_info_request *gg_change_info_request_new(const char *first_name, const char *last_name, const char *nickname, const char *email, int born, int gender, const char *city)
{
	struct gg_change_info_request *r = calloc(1, sizeof(struct gg_change_info_request));

	if (!r)
		return NULL;

	r->first_name = strdup((first_name) ? first_name : "");
	r->last_name = strdup((last_name) ? last_name : "");
	r->nickname = strdup((nickname) ? nickname : "");
	r->email = strdup((email) ? email : "");
	r->city = strdup((city) ? city : "");
	r->born = born;
	r->gender = gender;

	return r;
}

/*
 * gg_change_info_request_free()
 *
 * zwalnia pamiêæ zajmowan± przez struct gg_change_info_request i jej pola.
 *
 *  - r - zwalniana struktura
 */
void gg_change_info_request_free(struct gg_change_info_request *r)
{
	if (!r)
		return;

	free(r->first_name);
	free(r->last_name);
	free(r->nickname);
	free(r->email);
	free(r->city);
	
	free(r);
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
