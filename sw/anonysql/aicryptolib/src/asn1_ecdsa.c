/* asn1_ecdsa.c */
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
#include <string.h>
#include <stdlib.h>

#include "key_type.h"

#include "ok_ecc.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"

/*-----------------------------------------
  ASN.1 to struct Prvkey_ECDSA
-----------------------------------------*/
Prvkey_ECDSA *ASN1_read_ecdsaprv(unsigned char *der){
	Prvkey_ECDSA *ret;
	unsigned char *cp;
	int i;

	if(der == NULL) return NULL;
	if(*der != 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1_,ERR_PT_ASN1ECDSA,NULL);
		return NULL;
	}

	if((ret=ECDSAprvkey_new())==NULL) goto error;
	cp = ASN1_next(der);

	/* version */
	if((ret->version=ASN1_integer(cp,&i)) != 1){
		OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1_,ERR_PT_ASN1ECDSA,NULL);
		goto error;
	}
	cp = ASN1_next(cp);

	/* ECDSA parameter */
	if((ret->E=ASN1_read_ecparam(cp))==NULL) goto error;
	if((ret->E->der=ASN1_dup(cp))==NULL) goto error;
	if((cp = ASN1_skip(cp))==NULL) goto error;
	ret->size   =((ret->E->psize-1)>>3)+1;

	/* public key -- W */
	if(ret->W) ECp_free(ret->W);
	if((ret->W=ASN1_get_ecpoint(cp,ret->E))==NULL) goto error;
	if((cp = ASN1_skip(cp))==NULL) goto error;

	/* base integer -- k */
	if(ASN1_int2LNm(cp,ret->k,&i)) goto error;

	ret->der  = der;

	return ret;
error:
	ECDSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 to struct Pubkey_ECDSA
-----------------------------------------*/
Pubkey_ECDSA *ASN1_read_ecdsapub(unsigned char *der){
	Pubkey_ECDSA *ret;
	unsigned char *cp;

	if(der == NULL) return NULL;
	if(*der != 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1_,ERR_PT_ASN1ECDSA+1,NULL);
		return NULL;
	}

	if((ret=ECDSApubkey_new())==NULL) goto error;
	cp = ASN1_next(der);

	/* ECDSA parameter */
	if((ret->E=ASN1_read_ecparam(cp))==NULL) goto error;
	if((ret->E->der=ASN1_dup(cp))==NULL) goto error;
	if((cp = ASN1_skip(cp))==NULL) goto error;
	ret->size   =((ret->E->psize-1)>>3)+1;

	/* public key -- W */
	if(ret->W) ECp_free(ret->W);
	if((ret->W=ASN1_get_ecpoint(cp,ret->E))==NULL) goto error;
	if((cp = ASN1_skip(cp))==NULL) goto error;

	return ret;
error:
	ECDSAkey_free((Key*)ret);
	return NULL;
}
