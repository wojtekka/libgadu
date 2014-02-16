#ifndef HTTP_H
#define HTTP_H

char *gg_http_fetch(const char *method, const char *url, const char *auth_header, char *post_data);
void http_init(void);

#endif /* HTTP_H */
