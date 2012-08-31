#ifndef SCRIPT_H
#define SCRIPT_H

#include "libgadu.h"

typedef enum {
	ACTION_LOGIN = 1,
	ACTION_SEND,
	ACTION_END,
	ACTION_CALL,
	ACTION_LOGOFF,
	EXPECT_DATA,
	EXPECT_EVENT,
	EXPECT_CONNECT,
	EXPECT_DISCONNECT,
} state_type_t;

typedef int (*state_check_event_func_t)(int type, union gg_event_union *);
typedef void (*state_api_call_func_t)(struct gg_session *);

typedef struct {
	const char *filename;
	int line;
	int test;
	state_type_t type;
	struct gg_login_params *glp;
	enum gg_event_t event;
	state_check_event_func_t check_event;
	state_api_call_func_t call;
	unsigned char *data;
	unsigned char *data_mask;
	int data_len;
} state_t;

extern state_t script[];

extern const char *tests[];

#ifdef false
#undef false
#endif
#define false 0

#ifdef true
#undef true
#endif
#define true 1

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE 1

#ifdef GG_CONFIG_BIGENDIAN
#define ip(a,b,c,d) ((a)<<24|(b)<<16|(c)<<8|(d))
#else
#define ip(a,b,c,d) ((a)|(b)<<8|(c)<<16|(d)<<24)
#endif

#endif /* SCRIPT_H */
