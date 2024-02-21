/* ok_rsa.h */
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

#ifndef __OK_RSA_H__
#define __OK_RSA_H__

#include "large_num.h"
#include "ok_x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Public_key_RSA{
  int	key_type; /* key identifier */
  int	size;

  LNm	*n;	/* public module */
  LNm	*e;	/* public exponent */
}Pubkey_RSA;

typedef struct Private_key_RSA{
  int 	key_type; /* key identifier */
  int	size;

  int	version;
  LNm	*n;	/* public module */
  LNm	*e;	/* public exponent */
  LNm	*d;	/* private exponent */
  LNm	*p;	/* prime1 */
  LNm	*q;	/* prime2 */
  LNm	*e1;	/* exponent1 -- d mod (p-1) */
  LNm	*e2;	/* exponent2 -- d mod (q-1) */
  LNm	*cof;	/* coefficient -- (q-1) mod p */

  /* DER encode strings */
  unsigned char *der;
}Prvkey_RSA;



/* rsa.c */
int RSApub_doCrypt(int len, unsigned char *from,
                          unsigned char *to, Pubkey_RSA *key);

int RSAprv_doCrypt(int len, unsigned char *from,
                          unsigned char *to, Prvkey_RSA *key);

void RSA_set_pubkey(Pubkey_RSA *key,LNm *n,LNm *e);
void RSA_set_prvkey(Prvkey_RSA *key,LNm *n,LNm *d);
/* old compatible name */
#define OK_RSA_docrypt_pubkey	RSApub_doCrypt
#define OK_RSA_docrypt_prvkey	RSAprv_doCrypt
#define OK_RSA_set_pubkey	RSA_set_pubkey
#define OK_RSA_set_prvkey	RSA_set_prvkey

/* rsa_asn1.c */
unsigned char *RSAprv_toDER(Prvkey_RSA *prv,unsigned char *buf,int *ret_len);
unsigned char *RSApub_toDER(Pubkey_RSA *pub,unsigned char *buf,int *ret_len);

/* rsa_key.c */
Pubkey_RSA *RSApubkey_new(void);
Prvkey_RSA *RSAprvkey_new(void);
void RSAkey_free(Key *key);
int  RSAprv_generate(Prvkey_RSA *ret,int byte);
void RSAprv_2pub(Prvkey_RSA *prv,Pubkey_RSA *pub);

Pubkey_RSA *RSApubkey_dup(Pubkey_RSA *src);
Prvkey_RSA *RSAprvkey_dup(Prvkey_RSA *src);

int RSApubkey_cmp(Pubkey_RSA *k1,Pubkey_RSA *k2);
int RSAprvkey_cmp(Prvkey_RSA *k1,Prvkey_RSA *k2);
int RSA_pair_cmp(Prvkey_RSA *prv,Pubkey_RSA *pub);

#ifdef  __cplusplus

}
#endif

#endif /* __OK_RSA_H__ */

