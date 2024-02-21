/* pkcs12.c */
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
#include <string.h>

#include "ok_asn1.h"
#include "ok_pkcs.h"

/*-----------------------------------------
  PKCS#12 allocate
-----------------------------------------*/
PKCS12 *P12_new(void){
	PKCS12	*ret;

	if((ret = (PKCS12*)MALLOC(sizeof(PKCS12)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_PKCS12,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(PKCS12));
	ret->version = 3;
	return ret;
}

/*-----------------------------------------
  PKCS#12 baggages allocate
-----------------------------------------*/
P12_KeyBag *P12_Key_new(void){
	P12_KeyBag *ret;

	if((ret=(P12_KeyBag*)MALLOC(sizeof(P12_KeyBag)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_PKCS12+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(P12_KeyBag));
	ret->type = OBJ_P12v1Bag_PKCS8;
	return ret;
}

P12_CertBag *P12_Cert_new(void){
	P12_CertBag	*ret;

	if((ret=(P12_CertBag*)MALLOC(sizeof(P12_CertBag)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_PKCS12+2,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(P12_CertBag));
	ret->type = OBJ_P12v1Bag_CERT;
	return ret;
}

P12_CRLBag *P12_CRL_new(void){
	P12_CRLBag *ret;

	if((ret=(P12_CRLBag*)MALLOC(sizeof(P12_CRLBag)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_PKCS12+3,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(P12_CRLBag));
	ret->type = OBJ_P12v1Bag_CRL;
	return ret;
}

/*-----------------------------------------
  PKCS#12 Bag FREE.
-----------------------------------------*/
void P12Bag_free(P12_Baggage *bg){
	switch(bg->type){
	case OBJ_P12v1Bag_KEY:
	case OBJ_P12v1Bag_PKCS8: Key_free(((P12_KeyBag*)bg)->key); break;
    case OBJ_P12v1Bag_CERT:  Cert_free(((P12_CertBag*)bg)->cert); break;
    case OBJ_P12v1Bag_CRL:   CRL_free(((P12_CRLBag*)bg)->crl); break;
	}
	if(bg->friendlyName) FREE(bg->friendlyName);
	FREE(bg);
}

void P12Bag_free_all(P12_Baggage *top){
	P12_Baggage	*next;
	while(top!=NULL){
		next=top->next;
		P12Bag_free(top);
		top=next;
	}
}

/*-----------------------------------------
  PKCS#12 FREE.
-----------------------------------------*/
void P12_free(PKCS12 *p12){
	if(p12==NULL) return;
	P12Bag_free_all(p12->bag);
	FREE(p12);
}

/*-----------------------------------------
  PKCS#12 add baggage
-----------------------------------------*/
void P12_add_bag(PKCS12 *p12,P12_Baggage *bg){
	P12_Baggage *tmp;

	tmp = p12->bag;
	p12->bag = bg;
	bg->next = tmp;
}
