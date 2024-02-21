/* ok_des.h */
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

#ifndef __OK_DES_H__
#define __OK_DES_H__

#include "aiconfig.h"
#include "key_type.h"
#include "ok_err.h"

#ifdef  __cplusplus
extern "C" {
#endif


typedef struct crypt_DES_key{
    int   key_type;		/* key identifier */
    int   size;

    ULLONG	list[16];
    ULLONG	iv;			/* current initialize vector */
	ULLONG	oiv;		/* original initialize vector */
}Key_DES;

typedef struct crypt_3DES_key{
    int   key_type;             /* key identifier */
    int   size;

    ULLONG	list1[16];
    ULLONG	list2[16];
    ULLONG	list3[16];
    ULLONG	iv;
	ULLONG	oiv;		/* original initialize vector */
}Key_3DES;


/* des_key.c */
Key_DES *DESkey_new_();
Key_DES *DESkey_new(int len,unsigned char *key);
Key_DES *DESkey_dup(Key_DES *org);
void DESkey_free(Key_DES *key);
int  DESkey_set(Key_DES *dk,int len,unsigned char *key);
void DES_set_iv(Key_DES *key,unsigned char *ivc);

Key_3DES *DES3key_new_();
Key_3DES *DES3key_new(Key_DES *key1,Key_DES *key2,Key_DES *key3);
Key_3DES *DES3key_new_c(int len,unsigned char *key);
Key_3DES *DES3key_dup(Key_3DES *org);
void DES3key_free(Key_3DES *key);
int DES3key_set(Key_3DES *dk,Key_DES *key1,Key_DES *key2,Key_DES *key3);
int DES3key_set_c(Key_3DES *dk,int len,unsigned char *key);
void DES3_set_iv(Key_3DES *key,unsigned char *ivc);

void c2ll(int len,unsigned char *in,ULLONG *ret);
void ll2c(int len,ULLONG *in,unsigned char *ret);


/*  DES (ECB mode) */
void DES_ecb_encrypt(Key_DES *key,int byte,unsigned char *in,unsigned char *out);
void DES_ecb_decrypt(Key_DES *key,int byte,unsigned char *in,unsigned char *out);
void DES_ecb_encrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out);
void DES_ecb_decrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out);

/*  DES (CBC mode) 
 *  iv .. initialization vector.
 */
void DES_cbc_encrypt(Key_DES *key,int byte,unsigned char *in,unsigned char *out);
void DES_cbc_decrypt(Key_DES *key,int byte,unsigned char *in, unsigned char *out);
void DES_cbc_encrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out);
void DES_cbc_decrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out);

/*  DES (CFB mode)
 *  iv .. initialization vector.
 *  k  .. bit sift size (k must be 1,2,4,8,16,32,64)
 */
void DES_cfb_encrypt_ll(Key_DES *key,int k,int len,ULLONG *in,ULLONG *out);
void DES_cfb_decrypt_ll(Key_DES *key,int k,int len,ULLONG *in,ULLONG *out);

/*  DES (EDE3 ECB mode) ... Triple DES
 */
void DES3_ecb_encrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out);
void DES3_ecb_decrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out);
void DES3_ecb_encrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out);
void DES3_ecb_decrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out);

/*  DES (EDE3 CBC mode) ... Triple DES
 *  iv .. initialization vector.
 */
void DES3_cbc_encrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out);
void DES3_cbc_decrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out);
void DES3_cbc_encrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out);
void DES3_cbc_decrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out);

#ifdef  __cplusplus
}
#endif

#endif /* __OK_DES_H__ */
