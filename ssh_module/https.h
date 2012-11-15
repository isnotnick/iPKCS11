#ifndef _HTTPS_H_
#define _HTTPS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define STACK_SIZE 16
#define TIMEOUT_MS 1000

#define SSL_CERTIFICATE "~/.pkcs11server.crt"

void ssl_link_init(const char *url);
void ssl_link_cleanup(void);
char *send_string(char *str);

#ifdef __cplusplus
} /* end extern C */
#endif

#endif /* _HTTPS_H_ */
