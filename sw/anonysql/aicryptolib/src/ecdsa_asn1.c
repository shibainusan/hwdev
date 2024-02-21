/* ecdsa_asn1.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_ecc.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"

/*-----------------------------------
	ECDSA Private Key to DER
------------------------------------*/
unsigned char *ECDSAprv_toDER(Prvkey_ECDSA *prv,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=ECDSAprv_estimate_der_size(prv))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECDSA,ERR_PT_ECDSAASN,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	/* version */
	ASN1_set_integer(prv->version,ret,&i);
	cp = ret+i;

	if(prv->E==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECDSA,ERR_PT_ECDSAASN,NULL);
		goto error;
	}
	/* ECDSA parameter */
	if(ECPm_toDER(prv->E,cp,&j)==NULL) goto error;
	cp+= j; i+=j;

	/* public key W */
	if(ECPm_DER_ecpoint(prv->W,cp,&j)) goto error;
	cp+=j; i+=j;

	/* base integer k */
	if(ASN1_LNm2int(prv->k,cp,&j)) goto error;
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------
	ECDSA Private Key to DER
------------------------------------*/
unsigned char *ECDSApub_toDER(Pubkey_ECDSA *pub,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=ECDSApub_estimate_der_size(pub))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECDSA,ERR_PT_ECDSAASN+1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	cp = ret;
	if(pub->E==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECDSA,ERR_PT_ECDSAASN+1,NULL);
		goto error;
	}
	/* ECDSA parameter */
	if(ECPm_toDER(pub->E,cp,&i)==NULL) goto error;
	cp+=i;

	/* public key W */
	if(ECPm_DER_ecpoint(pub->W,cp,&j)) goto error;
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}


/*-----------------------------------
	estimate ECDSA param DER size
------------------------------------*/
int ECDSAprv_estimate_der_size(Prvkey_ECDSA *prv){
	int ret=16;

	ret += 4 + (prv->W->x->top<<2) + (prv->W->y->top<<2);
	ret += LN_now_byte(prv->k) +4;
	if(prv->E) ret += ECPm_estimate_der_size(prv->E);

	return ret;
}

int ECDSApub_estimate_der_size(Pubkey_ECDSA *pub){
	int ret=16;

	ret += 4 + (pub->W->x->top<<2) + (pub->W->y->top<<2);
	if(pub->E) ret += ECPm_estimate_der_size(pub->E);

	return ret;
}
