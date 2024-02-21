/* rsa_asn1.c */
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

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>

#include "ok_asn1.h"
#include "ok_rsa.h"
#include "ok_x509.h"


/*-----------------------------------------------
  RSA Private Key to DER
-----------------------------------------------*/
unsigned char *RSAprv_toDER(Prvkey_RSA *prv,unsigned char *buf,int *ret_len){
	unsigned char *ret,*cp;
	int	i,j;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(prv->p->top*4*9+48))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RSA,ERR_PT_RSAASN,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	ASN1_set_integer(0,ret,&i);
	cp = ret+i;
	if(ASN1_LNm2int(prv->n,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->e,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->d,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->p,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->q,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->e1,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->e2,cp,&j)) goto error;
	cp+= j; i+=j;
	if(ASN1_LNm2int(prv->cof,cp,&j)) goto error;
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------------
  RSA Public Key to DER
-----------------------------------------------*/
unsigned char *RSApub_toDER(Pubkey_RSA *pub,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int i,j;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(pub->n->top*4+48))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RSA,ERR_PT_RSAASN+1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if(ASN1_LNm2int(pub->n,ret,&i)) goto error;
	cp= ret+i;
	if(ASN1_LNm2int(pub->e,cp,&j)) goto error;
	i+=j;
	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}
