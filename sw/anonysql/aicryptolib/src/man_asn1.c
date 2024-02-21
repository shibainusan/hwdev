/* man_asn1.c */
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

#include "ok_err.h"
#include "ok_asn1.h"
#include "ok_store.h"

/*-----------------------------------------------
   Store Manager : ASN.1 open stores
-----------------------------------------------*/
STManager *ASN1_read_stm(unsigned char *der, char *path){
	STManager *ret;
	unsigned char *cp;
	int	i;

	if((ret=STM_new())==NULL) goto error;

	if((STRDUP(ret->path,path))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_MANASN1,NULL);
		goto error;
	}

	cp = ASN1_next(der);

	/* check version */
	if((ret->version=ASN1_integer(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* read cert stores */
	if(asn1_stm_names(cp,ret)) goto error;

	/* set der */
	if(ret->der) FREE(ret->der);
	ret->der = der;

	return ret;
error:
	STM_free(ret);
	return NULL;
}

int asn1_stm_names(unsigned char *in,STManager *stm){
	unsigned char *cp,*t;
	int	i,j,len,dev,ctx;
	char *buf=NULL;
	CStore *hd,*cs=NULL;

	len = ASN1_tlen(in);
	cp = ASN1_next(in);
	for(i=0;i<len;){
		/* parse asn.1 context */
		t = ASN1_next(cp);

		if((buf=asn1_get_str(t,&j))==NULL) goto error;
		t=ASN1_next(t);

		if((dev=ASN1_integer(t,&j))<0) goto error;
		t=ASN1_next(t);

		if((ctx=ASN1_integer(t,&j))<0) goto error;

		/* open CStore */
		if((cs=CStore_open(dev,buf,ctx,stm->path))==NULL) goto error;
		if(stm->store==NULL){
			stm->store=hd=cs;
		}else{
			hd->next=cs; cs->prev=hd; hd=cs;
		}

		FREE(buf); buf=NULL;
		if((cp=ASN1_skip_(cp,&j))==NULL) goto error;
		i +=j;
	}
	return 0;
error:
	if(buf) FREE(buf);
	CStore_free(cs);
	return -1;
}

/*-----------------------------------------------
   Store Manager : toDER open stores
-----------------------------------------------*/
unsigned char *STM_toDER(STManager *stm, unsigned char *buf, int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=STM_estimate_der_size(stm))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_MANASN1+2,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	/* set version */
	ASN1_set_integer(stm->version,ret,&i);
	cp = ret+i;

	/* set store names */
	if(STM_DER_names(stm,cp,&j)) goto error;
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

int STM_DER_names(STManager *stm, unsigned char *ret, int *ret_len){
	CStore *cs;
	unsigned char *cp,*t;
	int	i,j,k;

	for(cp=ret,i=0,cs=stm->store; cs ; cs=cs->next){
		ASN1_set_t61(cs->name,cp,&j);
		t = cp+j;
		ASN1_set_integer(cs->dev_type,t,&k);
		t+= k; j+=k;
		ASN1_set_integer(cs->ctx_type,t,&k);
		t+= k; j+=k;
		ASN1_set_sequence(j,cp,&j);
		cp+=j; i+=j;
	}
	ASN1_set_explicit(i,0,ret,ret_len);

	return 0;
}

int STM_estimate_der_size(STManager *stm){
	int ret=16;
	CStore *cs;

	for(cs=stm->store; cs ; cs=cs->next){
		ret+=strlen(cs->name) + 16;
	}
	return ret;
}

