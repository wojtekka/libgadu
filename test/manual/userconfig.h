#ifndef USERCONFIG_H
#define USERCONFIG_H

unsigned int config_uin;
char *config_password;
unsigned int config_peer;
char *config_file;
char *config_dir;
unsigned int config_size;
unsigned long config_ip;
unsigned int config_port;
char *config_server;
char *config_proxy;

int config_read(void);
void config_free(void);

#endif /* USERCONFIG_H */
