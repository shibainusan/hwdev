/* man_search.c */
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
   Store Manager : Simple search 
-----------------------------------------------*/
CStore *STM_find_store(STManager *stm, CStore *dst){
	CStore *cs;

	for(cs=stm->store; cs ; cs=cs->next)
		if(cs == dst) return cs;
	return NULL;
}

CStore *STM_find_byName(STManager *stm, char *name, int dev, int ctx){
	CStore *cs;

	for(cs=stm->store; cs ; cs=cs->next)
		if(!strcmp(cs->name,name))
			if((cs->ctx_type==ctx)&&(cs->dev_type==dev))
			   return cs;
	return NULL;
}

/*-----------------------------------------------
   Store Manager : search a bag
-----------------------------------------------*/
CSBag *STM_find_byID(STManager *stm, char *name, int dev, int ctx, char *unique_id){
	CStore *cs;

	if((cs=STM_find_byName(stm,name,dev,ctx))==NULL) return NULL;
	
	return CStore_find_byID(CStore_get_firstBag(cs),unique_id);
}

/*-----------------------------------------------
   Store Manager : search a bag by Cert
-----------------------------------------------*/
CSBag *STM_find_byCert(STManager *stm, Cert *ct){
	CStore *cs;
	CSBag *ret;

	for(cs=stm->store; cs ; cs=cs->next){
		if(cs->ctx_type==CSTORE_CTX_CERT)
			if(ret=CStore_find_byCert(CStore_get_firstBag(cs),ct))
				return ret;
	}
	return NULL;
}

/*-----------------------------------------------
   Store Manager : search a bag by CRL
-----------------------------------------------*/
CSBag *STM_find_byCRL(STManager *stm, CRL *crl){
	CStore *cs;
	CSBag *ret;

	for(cs=stm->store; cs ; cs=cs->next){
		if(cs->ctx_type==CSTORE_CTX_CRL)
			if(ret=CStore_find_byCRL(CStore_get_firstBag(cs),crl))
				return ret;
	}
	return NULL;
}
