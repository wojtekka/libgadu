#ifndef OAUTH_H
#define OAUTH_H

char *gg_oauth_generate_header(const char *method, const char *url, const const char *consumer_key, const char *consumer_secret, const char *token, const char *token_secret);

#endif /* OAUTH_H */
