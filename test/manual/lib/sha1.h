#ifndef SHA1_H
#define SHA1_H

#include "config.h"

#ifdef HAVE_OPENSSL

#include <openssl/sha.h>

#else

#include <inttypes.h>

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA_CTX;

void SHA1_Init(SHA_CTX* context);
void SHA1_Update(SHA_CTX* context, const unsigned char* data, unsigned int len);
void SHA1_Final(unsigned char digest[20], SHA_CTX* context);

#endif /* HAVE_OPENSSL */

#endif /* SHA1_H */
