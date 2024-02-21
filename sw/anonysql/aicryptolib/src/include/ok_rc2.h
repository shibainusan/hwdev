/* ok_rc2.h */
/*
 * Copyright (C) 1998-2002
 * Akira Iwata & Takuto Okuno
 * Akira Iwata Laboratory,
 * Nagoya Institute of Technology in Japan.
 *
 * All rights reserved.
 *
 * This software is written by Takuto Okuno(usapato@anet.ne.jp)
 * And if you want to contact us, send an email to Kimitake Wakayama
 * (wakayama@elcom.nitech.ac.jp)
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *    Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *     Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 *   THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT EXPRESS OR IMPLIED WARRANTY.
 *   AKIRA IWATA LABORATORY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 *   SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 *   IN NO EVENT SHALL AKIRA IWATA LABORATORY BE LIABLE FOR ANY SPECIAL,
 *   INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 *   FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 *   NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT OF OR IN CONNECTION
 *   WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef __OK_RC2_H__
#define __OK_RC2_H__

#include "key_type.h"
#include "ok_err.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct crypt_RC2_key{
    int   key_type;             /* key identifier */
    int   size;

    unsigned short S[64];
    unsigned short iv[4];
    unsigned short oiv[4];
}Key_RC2;


/* RC2 key */
Key_RC2 *RC2key_new_();
Key_RC2 *RC2key_new(int len,unsigned char *key);
Key_RC2 *RC2key_dup(Key_RC2 *org);
void RC2key_free(Key_RC2 *key);
int  RC2key_set(Key_RC2 *rck,int len,unsigned char *key);
void RC2_set_iv(Key_RC2 *key,unsigned char *ivc);

/* set clen with number of char blocks */
void uc2usLE(int clen,unsigned char *in,unsigned short *ret);
/* set slen with number of short blocks */
void us2ucLE(int slen,unsigned short *in,unsigned char *ret);

/* RC2 ECB mode */
void RC2_ecb_encrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret);
void RC2_ecb_decrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret);
void RC2_ecb_encrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret);
void RC2_ecb_decrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret);


/* RC2 CBC mode
 * you must set key->iv[4] before using this function.
 * 4 block of 'in' and 'ret' is better to multiply.
 */
void RC2_cbc_encrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret);
void RC2_cbc_decrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret);
void RC2_cbc_encrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret);
void RC2_cbc_decrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret);



#ifdef  __cplusplus
}
#endif

#endif /* __OK_RC2_H__ */
