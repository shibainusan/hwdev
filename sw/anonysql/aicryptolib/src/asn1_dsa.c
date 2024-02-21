/* asn1_dsa.c */
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
	read DSA Parameter
------------------------------------*/
DSAParam *ASN1_read_dsaparam(unsigned char *der,int no_seq){
	DSAParam *ret;
	unsigned char *cp = der;
	int i;

	if(der == NULL) return NULL;

	if(!no_seq){
		if(*der != 0x30){
			OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1DSA,NULL);
			return NULL;}

		/* DomainParameters ::= SEQUENCE { */
		cp = ASN1_next(der);
	}
	if((ret=DSAPm_new())==NULL) goto error;

	/* p       INTEGER, -- odd prime, p=jq +1 */
	if(ASN1_int2LNm(cp,ret->p,&i)) goto error;
	cp = ASN1_next(cp);

	/* q       INTEGER, -- factor of p-1 */
	if(ASN1_int2LNm(cp,ret->q,&i)) goto error;
	cp = ASN1_next(cp);

	/* g       INTEGER, -- generator, g */
	if(ASN1_int2LNm(cp,ret->g,&i)) goto error;

	if(!no_seq) ret->der = der;

	return ret;
error:
	DSAPm_free(ret);
	return NULL;
}

/*-----------------------------------
	read DSA Private Key
------------------------------------*/
Prvkey_DSA *ASN1_read_dsaprv(unsigned char *der){
	Prvkey_DSA *ret;
	unsigned char *cp;
	int i;

	if(der == NULL) return NULL;
	if(*der != 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1DSA+1,NULL);
		return NULL;}

	if((ret=DSAprvkey_new())==NULL) goto error;
	cp = ASN1_next(der);

	/* version */
	if((ret->version=ASN1_integer(cp,&i)) != 0){
		OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1,ERR_PT_ASN1DSA+1,NULL);
		goto error;
	}
	cp = ASN1_next(cp);

	/* DSA parameter */
	if((ret->pm=ASN1_read_dsaparam(cp,1))==NULL) goto error;
	cp = ASN1_step(cp,3);

	/* public key -- w */
	if(ASN1_int2LNm(cp,ret->w,&i)) goto error;
	cp = ASN1_next(cp);

	/* base integer -- k */
	if(ASN1_int2LNm(cp,ret->k,&i)) goto error;

	ret->size = LN_now_byte(ret->pm->p);
	ret->der  = der;

	return ret;
error:
	DSAkey_free((Key*)ret);
	return NULL;
}
