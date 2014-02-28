/*
 *  (C) Copyright 2008 Wojtek Kaniewski <wojtekka@irc.pl>
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
#include <string.h>
#include <expat.h>

#include "xml.h"

enum {
	ELEMENT_INVALID = -1,	/**< Nieprawidłowy XML, nie parsujemy */
	ELEMENT_NONE = 0,	/**< Brak lub nieznany, ignorowany element */
	ELEMENT_TOKEN,		/**< <oauth_token/> */
	ELEMENT_TOKEN_SECRET,	/**< <oauth_token_secret/> */
	ELEMENT_TOKEN_EXPIRES_IN, /**< <oauth_token_expires_in/> */
	ELEMENT_ERRORMSG,	/**< <errorMsg/> */
	ELEMENT_STATUS,		/**< <status/> */
};

struct parser_state {
	int depth;		/**< Poziom zagnieżdżenia tagów */
	int element;		/**< Typ aktualnego elementu */
	char *token;		/**< Zawartość <oauth_token/> lub NULL */
	char *token_secret;	/**< Zawartość <oauth_token_secret/> lub NULL */
	char *error_msg;	/**< Zawartość <errorMsg/> lub NULL */
	int status;		/**< Zawartość <status/> lub -1 */
	int token_expires_in;	/**< Zawartość <oauth_token_expiresin/> lub -1 */
};

static void handle_start_element(void *data, const char *elem, const char **attr)
{
	struct parser_state *state = data;

	if (state->element == ELEMENT_INVALID)
		return;

	state->depth++;

	if (state->depth == 1 && strcmp(elem, "result") != 0)
		state->element = ELEMENT_INVALID;
	else if (state->depth == 2 && strcmp(elem, "status") == 0)
		state->element = ELEMENT_STATUS;
	else if (state->depth == 2 && strcmp(elem, "oauth_token") == 0)
		state->element = ELEMENT_TOKEN;
	else if (state->depth == 2 && strcmp(elem, "oauth_token_secret") == 0)
		state->element = ELEMENT_TOKEN_SECRET;
	else if (state->depth == 2 && strcmp(elem, "oauth_token_expires_in") == 0)
		state->element = ELEMENT_TOKEN_EXPIRES_IN;
	else if (state->depth == 2 && strcmp(elem, "errorMsg") == 0)
		state->element = ELEMENT_ERRORMSG;
	else
		state->element = ELEMENT_NONE;
}

static void handle_end_element(void *data, const char *elem)
{
	struct parser_state *state = data;

	if (state->element == ELEMENT_INVALID)
		return;

	state->depth--;
	state->element = ELEMENT_NONE;
}

static void handle_cdata(void *data, const char *str, int len)
{
	struct parser_state *state = data;
	char *tmp;

	if (state->element == ELEMENT_INVALID || state->element == ELEMENT_NONE)
		return;

	tmp = malloc(len + 1);

	if (tmp == NULL)
		return;

	memcpy(tmp, str, len);
	tmp[len] = 0;

	switch (state->element)	{
		case ELEMENT_STATUS:
			state->status = atoi(tmp);
			free(tmp);
			break;
		case ELEMENT_TOKEN:
			free(state->token);
			state->token = tmp;
			break;
		case ELEMENT_TOKEN_SECRET:
			free(state->token_secret);
			state->token_secret = tmp;
			break;
		case ELEMENT_TOKEN_EXPIRES_IN:
			state->token_expires_in = atoi(tmp);
			free(tmp);
			break;
		case ELEMENT_ERRORMSG:
			free(state->error_msg);
			state->error_msg = tmp;
			break;
		default:
			free(tmp);
	}
}

int gg_parse_token_reply(const char *reply, char **token, char **token_secret)
{
	XML_Parser parser;
	struct parser_state state;

	memset(&state, 0, sizeof(state));
	state.status = -1;
	state.token_expires_in = -1;

	parser = XML_ParserCreate(NULL);

	if (parser == NULL)
		return -1;

	XML_SetUserData(parser, &state);

	XML_SetElementHandler(parser, handle_start_element, handle_end_element);
	XML_SetCharacterDataHandler(parser, handle_cdata);

	if (!XML_Parse(parser, reply, strlen(reply), 1)) {
		XML_ParserFree(parser);
		free(state.token);
		free(state.token_secret);
		free(state.error_msg);
		return -1;
	}

	XML_ParserFree(parser);

	if (state.element == ELEMENT_INVALID || state.status !=0 || state.token == NULL || state.token_secret == NULL) {
		free(state.token);
		free(state.token_secret);
		free(state.error_msg);
		return -1;
	}

	if (token)
		*token = state.token;
	else
		free(state.token);

	if (token_secret)
		*token_secret = state.token_secret;
	else
		free(state.token_secret);

	free(state.error_msg);

	return 0;
}

#ifdef STANDALONE

int main(void)
{
	const char *test = "<result>"
		"<oauth_token>c795432d623c3ec75137f50f66852b93</oauth_token>"
		"<oauth_token_secret>9de77905611fb965e3023e1ffbbfad3e</oauth_token_secret>"
		"<status>0</status></result>";
	char *token;
	char *token_secret;

	if (parse_token_reply(test, strlen(test), &token, &token_secret) == -1) {
		printf("error\n");
		return 1;
	}

	printf("token = %s\ntoken_secret = %s\n", token, token_secret);

	return 0;
}

#endif
