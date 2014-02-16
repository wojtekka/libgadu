/*
 *  (C) Copyright 2008 Wojtek Kaniewski <wojtekka@irc.pl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License Version
 *  2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

#include "hmac.h"

#ifdef HAVE_OPENSSL

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

void gg_hmac_sha1(unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest)
{
	const unsigned char *res;
	unsigned int len;

	res = HMAC(EVP_sha1(), (char*) key, key_len, text, text_len, NULL, &len);

	memcpy(digest, res, len);
}

#else

#include <string.h>
#include "sha1.h"

void gg_hmac_sha1(unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest)
{
        SHA_CTX context;
        unsigned char k_ipad[64];    /* inner padding -
                                      * key XORd with ipad
                                      *                                       */
        unsigned char k_opad[64];    /* outer padding -
                                      * key XORd with opad
                                      *                                       */
        unsigned char tk[20];
        int i;
        /* if key is longer than 64 bytes reset it to key=SHA1(key) */
        if (key_len > 64) {

                SHA_CTX      tctx;

                SHA1_Init(&tctx);
                SHA1_Update(&tctx, key, key_len);
                SHA1_Final(tk, &tctx);

                key = tk;
                key_len = 20;
        }

        /*
         * the HMAC_SHA1 transform looks like:
         *
         * SHA1(K XOR opad, SHA1(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        memset( k_ipad, 0, sizeof k_ipad);
        memset( k_opad, 0, sizeof k_opad);
        memcpy( k_ipad, key, key_len);
        memcpy( k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner SHA1
         */
        SHA1_Init(&context);                   /* init context for 1st
                                                * pass */
        SHA1_Update(&context, k_ipad, 64);     /* start with inner pad */
        SHA1_Update(&context, text, text_len); /* then text of datagram */
        SHA1_Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer SHA1
         */
        SHA1_Init(&context);                   /* init context for 2nd
                                                * pass */
        SHA1_Update(&context, k_opad, 64);     /* start with outer pad */
        SHA1_Update(&context, digest, 20);     /* then results of 1st
                                                * hash */
        SHA1_Final(digest, &context);          /* finish up 2nd pass */
}

#endif /* HAVE_OPENSSL */
