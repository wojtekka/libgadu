#ifndef URLENCODE_H
#define URLENCODE_H

#include <sys/types.h>

size_t gg_urlencode_strlen(const char *s);
char *gg_urlencode_strcpy(char *dest, const char *src);
char *gg_urlencode(const char *s);
char *gg_urlencode_printf(char *format, ...);

#endif /* URLENCODE_H */
