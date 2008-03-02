/* Generated from script. Do not edit. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "script.h"

static struct gg_login_params script_glp_0 =
{
	.uin = 0x123456,
	.password = ""
};

static void script_call_6(struct gg_session *session)
{
	gg_send_message(session, GG_CLASS_CHAT, 0x123456, (unsigned char*) "Test");
}

static int script_check_event_9(int type, union gg_event_union *event)
{
	return (event->msg.sender == 0x11111111 && event->msg.seq == 0x22222222 && event->msg.time == 0x33333333 && event->msg.msgclass == 0x44444444 && strcmp((char*) event->msg.message , (char*) "ABC") == 0 && event->msg.recipients_count == 0 && event->msg.recipients == NULL && event->msg.formats_length == 0 && event->msg.formats == NULL);
}

static int script_check_event_11(int type, union gg_event_union *event)
{
	return (strcmp((char*) event->msg.message , (char*) "123") == 0);
}

state_t script[] =
{
	/* state 0 */
	{
		.type = ACTION_LOGIN,
		.glp = &script_glp_0,
	},

	/* state 1 */
	{
		.type = EXPECT_CONNECT,
	},

	/* state 2 */
	{
		.type = ACTION_SEND,
		.data = (unsigned char*) "\x01\x00\x00\x00\x04\x00\x00\x00\x12\x34\x56\x78",
		.data_len = 12,
	},

	/* state 3 */
	{
		.type = EXPECT_DATA,
		.data = (unsigned char*) "\x19\x00\x00\x00\x5c\x00\x00\x00\x56\x34\x12\x00\x02\x9b\xce\x73\xd0\xc8\xb9\xec\xa4\xf2\x41\x54\xf3\xbd\x3b\x8a\xa4\x73\xb1\xc3\xa9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe",
		.data_mask = (unsigned char*) "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
		.data_len = 100,
	},

	/* state 4 */
	{
		.type = ACTION_SEND,
		.data = (unsigned char*) "\x03\x00\x00\x00\x00\x00\x00\x00",
		.data_len = 8,
	},

	/* state 5 */
	{
		.type = EXPECT_EVENT,
		.event = GG_EVENT_CONN_SUCCESS,
	},

	/* state 6 */
	{
		.type = ACTION_CALL,
		.call = script_call_6,
	},

	/* state 7 */
	{
		.type = EXPECT_DATA,
		.data = (unsigned char*) "\x0b\x00\x00\x00\x11\x00\x00\x00\x56\x34\x12\x00\x00\x00\x00\x00\x08\x00\x00\x00\x54\x65\x73\x74\x00",
		.data_mask = (unsigned char*) "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff",
		.data_len = 25,
	},

	/* state 8 */
	{
		.type = ACTION_SEND,
		.data = (unsigned char*) "\x0a\x00\x00\x00\x14\x00\x00\x00\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44\x41\x42\x43\x00",
		.data_len = 28,
	},

	/* state 9 */
	{
		.type = EXPECT_EVENT,
		.event = GG_EVENT_MSG,
		.check_event = script_check_event_9,
	},

	/* state 10 */
	{
		.type = ACTION_SEND,
		.data = (unsigned char*) "\x0a\x00\x00\x00\x13\x00\x00\x00\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44\x31\x32\x33",
		.data_len = 27,
	},

	/* state 11 */
	{
		.type = EXPECT_EVENT,
		.event = GG_EVENT_MSG,
		.check_event = script_check_event_11,
	},

	/* state 12 */
	{
		.type = ACTION_LOGOFF,
	},

	/* state 13 */
	{
		.type = EXPECT_DISCONNECT,
	},

	/* state 14 */
	{
		.type = ACTION_END,
	},

};
