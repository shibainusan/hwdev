/* dsa_asn1.c */
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

#include "ok_dsa.h"
#include "ok_asn1.h"

/*-----------------------------------
	DSA ASN.1
------------------------------------*/
unsigned char *DSAPm_toDER(DSAParam *dpm,unsigned char *buf,int *ret_len,int no_seq){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=DSAPm_estimate_der_size(dpm))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSAASN,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	/* p INTEGER, -- odd prime, p=jq +1 */
	if(ASN1_LNm2int(dpm->p,ret,&i)) goto error;
	cp=ret+i;

	/* q INTEGER, -- factor of p-1 */
	if(ASN1_LNm2int(dpm->q,cp,&j)) goto error;
	cp+=j; i+=j;

	/* g INTEGER, -- generator, g */
	if(ASN1_LNm2int(dpm->g,cp,&j)) goto error;
	i+=j;

	if(no_seq){
		*ret_len = i;
	}else{
		ASN1_set_sequence(i,ret,ret_len);
	}

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------
	DSA Private Key to DER
------------------------------------*/
unsigned char *DSAprv_toDER(Prvkey_DSA *prv,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=DSAprv_estimate_der_size(prv))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSAASN+1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	/* version */
	ASN1_set_integer(prv->version,ret,&i);
	cp = ret+i;

	if(prv->pm==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DSA,ERR_PT_DSAASN+1,NULL);
		goto error;
	}
	/* DSA parameter */
	if(DSAPm_toDER(prv->pm,cp,&j,1)==NULL) goto error;
	cp+= j; i+=j;

	/* public key w */
	if(ASN1_LNm2int(prv->w,cp,&j)) goto error;
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
	DSA Public Key to DER
------------------------------------*/
unsigned char *DSApub_toDER(Pubkey_DSA *pub,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=DSApub_estimate_der_size(pub))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSAASN+2,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if(pub->pm==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DSA,ERR_PT_DSAASN+2,NULL);
		goto error;
	}
	/* DSA parameter */
	if(DSAPm_toDER(pub->pm,ret,&j,1)==NULL) goto error;
	cp = ret+j; i+=j;

	/* public key w */
	if(ASN1_LNm2int(pub->w,cp,&j)) goto error;
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------
  estimate DER size of Privatekey
------------------------------------*/
int DSAPm_estimate_der_size(DSAParam *dpm){
	int ret=16;

	ret += LN_now_byte(dpm->p) +4;
	ret += LN_now_byte(dpm->q) +4;
	ret += LN_now_byte(dpm->g) +4;
	return ret;
}

int DSAprv_estimate_der_size(Prvkey_DSA *prv){
	int ret=16;

	ret += LN_now_byte(prv->w) +4;
	ret += LN_now_byte(prv->k) +4;
	if(prv->pm) ret += DSAPm_estimate_der_size(prv->pm);

	return ret;
}

int DSApub_estimate_der_size(Pubkey_DSA *pub){
	int ret=16;

	ret += LN_now_byte(pub->w) +4;
	if(pub->pm) ret += DSAPm_estimate_der_size(pub->pm);

	return ret;
}
