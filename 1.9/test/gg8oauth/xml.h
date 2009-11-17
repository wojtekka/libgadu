#ifndef XML_H
#define XML_H

#include <sys/types.h>

int gg_parse_token_reply(const char *reply, char **token, char **token_secret);

#endif /* XML_H */
