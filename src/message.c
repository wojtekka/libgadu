#include "message.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

gg_message_t *gg_message_new(void)
{
	gg_message_t *gm;

	gm = malloc(sizeof(gg_message_t));

	if (gm == NULL)
		return NULL;

	memset(gm, 0, sizeof(gg_message_t));

	gm->seq = (uint32_t) -1;

	return gm;
}

int gg_message_init(gg_message_t *gm, int msgclass, int seq, uin_t *recipients, int recipient_count, char *text, char *xhtml, char *attributes, size_t attributes_length)
{
	GG_MESSAGE_CHECK(gm, -1);

	memset(gm, 0, sizeof(gg_message_t));
	gm->recipients = recipients;
	gm->recipient_count = recipient_count;
	gm->text = (char*) text;
	gm->xhtml = xhtml;
	gm->attributes = attributes;
	gm->attributes_length = attributes_length;
	gm->msgclass = msgclass;
	gm->seq = seq;

	return 0;
}

void gg_message_free(gg_message_t *gm)
{
	if (gm == NULL) {
		errno = EINVAL;
		return;
	}	

	free(gm->recipients);

	free(gm);
}

int gg_message_set_recipients(gg_message_t *gm, const uin_t *recipients, unsigned int recipient_count)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (recipient_count >= INT_MAX / sizeof(uin_t)) {
		errno = EINVAL;
		return -1;
	}	

	if ((recipients == NULL) || (recipient_count == 0)) {
		free(gm->recipients);
		gm->recipients = NULL;
		gm->recipient_count = 0;
	} else {
		uin_t *tmp;

		tmp = realloc(gm->recipients, recipient_count * sizeof(uin_t));

		if (tmp == NULL)
			return -1;

		memcpy(tmp, recipients, recipient_count * sizeof(uin_t));

		gm->recipients = tmp;
		gm->recipient_count = recipient_count;
	}
	
	return 0;
}

int gg_message_set_recipient(gg_message_t *gm, uin_t recipient)
{
	return gg_message_set_recipients(gm, &recipient, 1);
}

int gg_message_get_recipients(gg_message_t *gm, const uin_t **recipients, unsigned int *recipient_count)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (recipients != NULL)
		*recipients = gm->recipients;

	if (recipient_count != NULL)
		*recipient_count = gm->recipient_count;

	return 0;
}

uin_t gg_message_recipient(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, (uin_t) -1);

	if ((gm->recipients == NULL) || (gm->recipient_count < 1)) {
		// errno = XXX;
		return (uin_t) -1;
	}

	return gm->recipients[0];
}

int gg_message_set_class(gg_message_t *gm, uint32_t msgclass)
{
	GG_MESSAGE_CHECK(gm, -1);

	gm->msgclass = msgclass;

	return 0;
}

uint32_t gg_message_get_class(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, (uint32_t) -1);

	return gm->msgclass;
}

int gg_message_set_seq(gg_message_t *gm, uint32_t seq)
{
	GG_MESSAGE_CHECK(gm, -1);

	gm->seq = seq;

	return 0;
}

uint32_t gg_message_get_seq(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, (uint32_t) -1);

	return gm->seq;
}

int gg_message_set_text(gg_message_t *gm, const char *text)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (text == NULL) {
		free(gm->text);
		gm->text = NULL;
	} else {
		char *tmp;

		tmp = strdup(text);

		if (tmp == NULL)
			return -1;

		free(gm->text);
		gm->text = tmp;
	}

	return 0;
}

const char *gg_message_get_text(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, NULL);

	return gm->text;
}

int gg_message_set_xhtml(gg_message_t *gm, const char *xhtml)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (xhtml == NULL) {
		free(gm->xhtml);
		gm->xhtml = NULL;
	} else {
		char *tmp;

		tmp = strdup(xhtml);

		if (tmp == NULL)
			return -1;

		free(gm->xhtml);
		gm->xhtml = tmp;
	}

	return 0;
}

const char *gg_message_get_xhtml(gg_message_t *gm)
{
	GG_MESSAGE_CHECK(gm, NULL);

	return gm->xhtml;
}

int gg_message_set_attributes(gg_message_t *gm, const char *attributes, size_t length)
{
	GG_MESSAGE_CHECK(gm, -1);

	if (length > 0xfffd) {
		// errno = XXX;
		return -1;
	}

	if ((attributes == NULL) || (length == 0)) {
		free(gm->attributes);
		gm->attributes = NULL;
		gm->attributes_length = 0;
	} else {
		char *tmp;

		tmp = realloc(gm->attributes, length);

		if (tmp == NULL)
			return -1;

		gm->attributes = tmp;
		gm->attributes_length = length;
	}

	return 0;
}

