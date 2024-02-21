/* ok_dsa.h */
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

#ifndef __OK_DSA_H__
#define __OK_DSA_H__

#include "aiconfig.h"

#include "ok_err.h"
#include "large_num.h"
#include "ok_x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct DSA_Param{
	int version;

	/* DomainParameters */
	LNm *p;		/* odd prime, p=jq+1 */
	LNm *q;		/* factor of p-1 */
	LNm *g;		/* generator, g */

	/* DER */
	unsigned char *der;
}DSAParam;

typedef struct Public_key_DSA{
	int key_type;	/* key identifier */
	int size;

	LNm *w;			/* public integer */

	DSAParam *pm;	/* DSA Parameter */

}Pubkey_DSA;

typedef struct Private_key_DSA{
	int key_type; /* key identifier */
	int size;

	int	version;
	LNm *w;		/* public integer */
	LNm *k;		/* private base integer */

	DSAParam *pm;	/* DSA Parameter */

	/* DER encode strings */
	unsigned char *der;

}Prvkey_DSA;


/* dsa.c */
DSAParam *DSAPm_new();
void DSAPm_free(DSAParam *dpm);
DSAParam *DSAPm_dup(DSAParam *org);


/* dsa_key.c */
Pubkey_DSA *DSApubkey_new();
Prvkey_DSA *DSAprvkey_new();
void DSAkey_free(Key *key);

Pubkey_DSA *DSApubkey_dup(Pubkey_DSA *org);
Prvkey_DSA *DSAprvkey_dup(Prvkey_DSA *org);

int DSApubkey_cmp(Pubkey_DSA *k1, Pubkey_DSA *k2);
int DSAprvkey_cmp(Prvkey_DSA *k1, Prvkey_DSA *k2);
int DSA_pair_cmp(Prvkey_DSA *prv, Pubkey_DSA *pub);

int DSAprv_generate(DSAParam *pm,Prvkey_DSA *ret);
int DSAprv_2pub(Prvkey_DSA *prv,Pubkey_DSA *pub);


/* dsa_gen.c */
DSAParam *DSAPm_gen_parameter(int size /* bits */);


/* dsa_asn1.c */
unsigned char *DSAPm_toDER(DSAParam *dpm,unsigned char *buf,int *ret_len,int no_seq);
unsigned char *DSAprv_toDER(Prvkey_DSA *prv,unsigned char *buf,int *ret_len);
unsigned char *DSApub_toDER(Pubkey_DSA *pub,unsigned char *buf,int *ret_len);
int DSAPm_estimate_der_size(DSAParam *dpm);
int DSAprv_estimate_der_size(Prvkey_DSA *prv);
int DSApub_estimate_der_size(Pubkey_DSA *pub);


/* dsa_sig.c */
unsigned char *DSA_get_signature(Prvkey_DSA *prv, unsigned char *data, int data_len, int *ret_len);
int DSA_sig_in(Prvkey_DSA *prv, LNm *f, LNm *c, LNm *d);
int DSA_vfy_signature(Pubkey_DSA *pub, unsigned char *data, int data_len,unsigned char *sig);
int	DSA_vfy_in(Pubkey_DSA *pub, LNm *f, LNm *c, LNm *d);


#ifdef  __cplusplus
}
#endif

#endif /* __OK_DSA_H__ */
