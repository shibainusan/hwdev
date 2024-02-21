/* ecc.c */
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
#include "ok_asn1.h"

/*-----------------------------------
	allocate new EC_Point
------------------------------------*/
ECp *ECp_new(){
	ECp *ret;

	if((ret=(ECp*)MALLOC(sizeof(ECp)))==NULL) goto error;
	memset(ret,0,sizeof(ECp));
	if((ret->x=LN_alloc())==NULL) goto error;
	if((ret->y=LN_alloc())==NULL) goto error;
	if((ret->z=LN_alloc())==NULL) goto error;
	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECC,ERR_PT_ECC,NULL);
	if(ret) ECp_free(ret);
	return NULL;
}

/*-----------------------------------
	FREE EC_Point
------------------------------------*/
void ECp_free(ECp *ecp){
	if(ecp==NULL) return;
	if(ecp->x) LN_free(ecp->x);
	if(ecp->y) LN_free(ecp->y);
	if(ecp->z) LN_free(ecp->z);
	FREE(ecp);
}

/*-----------------------------------
        duplicate EC point
------------------------------------*/
ECp *ECp_dup(ECp *src){
	ECp *ret;
 
	if(src==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECC,ERR_PT_ECC+1,NULL);
		return NULL;
	}
	if((ret=ECp_new())==NULL) return NULL;
	ECp_copy(src,ret);
	return ret;
}


/*-----------------------------------
	allocate new ECParam
------------------------------------*/
ECParam *ECPm_new(){
	ECParam *ret;
	int	i;

	if((ret=(ECParam*)MALLOC(sizeof(ECParam)))==NULL) goto error;
	memset(ret,0,sizeof(ECParam));
	if((ret->a=LN_alloc())==NULL) goto error;
	if((ret->b=LN_alloc())==NULL) goto error;
	if((ret->p=LN_alloc())==NULL) goto error;
	if((ret->n=LN_alloc())==NULL) goto error;
	if((ret->h=LN_alloc())==NULL) goto error;
	
	if((ret->G=ECp_new())==NULL)  goto error;

	for(i=0;i<E_LNm_BUF;i++)
		if((ret->buf[i]=LN_alloc())==NULL) goto error;
	for(i=0;i<ECP_BUF;i++)
		if((ret->pbf[i]=ECp_new())==NULL) goto error;

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECC,ERR_PT_ECC+2,NULL);
	if(ret) ECPm_free(ret);
	return NULL;
}

/*-----------------------------------
	allocate new ECParam
------------------------------------*/
void ECPm_free(ECParam *E){
	int	i;

	if(E==NULL) return;
	if(E->a) LN_free(E->a);
	if(E->b) LN_free(E->b);
	if(E->p) LN_free(E->p);
	if(E->n) LN_free(E->n);
	if(E->h) LN_free(E->h);

	if(E->G) ECp_free(E->G);

	for(i=0;i<E_LNm_BUF;i++)
	    if(E->buf[i]) LN_free(E->buf[i]);
	for(i=0;i<ECP_BUF;i++)
	    if(E->pbf[i]) ECp_free(E->pbf[i]);

	if(E->der) FREE(E->der);
	FREE(E);
}

/*-----------------------------------
  duplicate ECParam
------------------------------------*/
ECParam *ECPm_dup(ECParam *org){
	ECParam *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECC,ERR_PT_ECC+3,NULL);
		return NULL;
	}
	if((ret=ECPm_new())==NULL) return NULL;
	ret->version    = org->version;
	ret->curve_type = org->curve_type;
	ret->type  = org->type;
	ret->nsize = org->nsize;
	ret->psize = org->psize;
	LN_copy(org->a,ret->a);
	LN_copy(org->b,ret->b);
	LN_copy(org->p,ret->p);
	LN_copy(org->n,ret->n);
	LN_copy(org->h,ret->h);

	ECp_copy(org->G,ret->G);

	if(org->der){
		if((ret->der=ASN1_dup(org->der))==NULL){
			ECPm_free(ret);
			ret = NULL;
		}
	}

	return ret;	
}
