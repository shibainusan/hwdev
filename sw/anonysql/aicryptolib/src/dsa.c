/* dsa.c */
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
	allocate new DSAParam
------------------------------------*/
DSAParam *DSAPm_new(){
	DSAParam *ret;

	if((ret=(DSAParam*)MALLOC(sizeof(DSAParam)))==NULL) goto error;
	memset(ret,0,sizeof(DSAParam));

	if((ret->p=LN_alloc())==NULL) goto error;
	if((ret->q=LN_alloc())==NULL) goto error;
	if((ret->g=LN_alloc())==NULL) goto error;

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSA,NULL);
	if(ret) DSAPm_free(ret);
	return NULL;
}

/*-----------------------------------
	FREE DSAParam
------------------------------------*/
void DSAPm_free(DSAParam *dpm){
	if(dpm==NULL) return;
	if(dpm->p) LN_free(dpm->p);
	if(dpm->q) LN_free(dpm->q);
	if(dpm->g) LN_free(dpm->g);

	if(dpm->der) FREE(dpm->der);
	FREE(dpm);
}

/*-----------------------------------
    duplicate DSAParam
------------------------------------*/
DSAParam *DSAPm_dup(DSAParam *org){
	DSAParam *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DSA,ERR_PT_DSA+1,NULL);
		return NULL;
	}
	if((ret=DSAPm_new())==NULL) goto error;
	LN_copy(org->p,ret->p);
	LN_copy(org->g,ret->g);
	LN_copy(org->q,ret->q);

	if(org->der){
		if((ret->der=ASN1_dup(org->der))==NULL)
			goto error;
	}
	return ret;
error:
	if(ret) DSAPm_free(ret);
	return NULL;
}


