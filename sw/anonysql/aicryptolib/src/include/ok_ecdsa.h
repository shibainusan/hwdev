/* ok_ecdsa.h */
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

#ifndef __OK_ECDSA_H__
#define __OK_ECDSA_H__

#include "ok_ecc.h"
#include "ok_x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Public_key_ECDSA{
  int	key_type; /* key identifier */
  int	size;

  ECp		*W;	/* public Point */

  ECParam	*E; /* EC Parameter */

}Pubkey_ECDSA;

typedef struct Private_key_ECDSA{
  int 	key_type; /* key identifier */
  int	size;

  int	version;
  ECp		*W;	/* public Point */
  LNm		*k;	/* private base integer */

  ECParam	*E; /* EC Parameter */

  /* DER encode strings */
  unsigned char *der;
}Prvkey_ECDSA;


/* ecdsa.c */
/* get ECDSA signature */
unsigned char *ECDSA_get_signature(Prvkey_ECDSA *prv, unsigned char *data, int data_len, int *ret_len);
/* verify ECDSA signature */
int ECDSA_vfy_signature(Pubkey_ECDSA *pub, unsigned char *data, int data_len, unsigned char *sig);

/* inside functions of ECDSA generation and verification */
int ECDSA_sig_in(ECParam *E, Prvkey_ECDSA *prv, LNm *f, LNm *c, LNm *d);
int	ECDSA_vfy_in(ECParam *E, Pubkey_ECDSA *pub, LNm *f, LNm *c, LNm *d);


/* ecdsa_key.c */
Pubkey_ECDSA *ECDSApubkey_new(void);
Prvkey_ECDSA *ECDSAprvkey_new(void);
void ECDSAkey_free(Key *key);

int ECDSAprv_generate(ECParam *E,Prvkey_ECDSA *ret);
int ECDSAprv_2pub(Prvkey_ECDSA *prv,Pubkey_ECDSA *pub);

Pubkey_ECDSA *ECDSApubkey_dup(Pubkey_ECDSA *pub);
Prvkey_ECDSA *ECDSAprvkey_dup(Prvkey_ECDSA *prv);

int ECDSApubkey_cmp(Pubkey_ECDSA *k1,Pubkey_ECDSA *k2);
int ECDSAprvkey_cmp(Prvkey_ECDSA *k1,Prvkey_ECDSA *k2);
int ECDSA_pair_cmp(Prvkey_ECDSA *prv,Pubkey_ECDSA *pub);


/* ecdsa_asn1.c */
unsigned char *ECDSAprv_toDER(Prvkey_ECDSA *prv,unsigned char *buf,int *ret_len);
unsigned char *ECDSApub_toDER(Pubkey_ECDSA *pub,unsigned char *buf,int *ret_len);

int ECDSAprv_estimate_der_size(Prvkey_ECDSA *prv);
int ECDSApub_estimate_der_size(Pubkey_ECDSA *pub);

#ifdef  __cplusplus
}
#endif

#endif /* __OK_ECDSA_H__ */
