/* asn1_crtp.c */
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

#include "ok_asn1.h"
#include "ok_x509.h"

/*-----------------------------------------
  ASN.1 to struct cert 
-----------------------------------------*/
CertPair *ASN1_read_crtp(unsigned char *in){
	unsigned char *cp;
	CertPair *ret;

	if(in == NULL){return NULL;}

	cp = ASN1_next(in);
	if((*in!=0x30)||((*cp!=0xa0)&&(*cp!=0xa1))){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1_,ERR_PT_ASN1CRTP,NULL);
		return NULL;
	}

	if((ret=CertPair_new())==NULL) goto error;

	if(*cp == 0xa0){
		cp = ASN1_next(cp);
		if((ret->issuedToThisCA=ASN1_read_cert(cp))==NULL) goto error;
		if((ret->issuedToThisCA->der=ASN1_dup(cp))==NULL) goto error;
		if((cp=ASN1_skip(cp))==NULL) goto error;
	}
	if(*cp == 0xa1){
		cp = ASN1_next(cp);
		if((ret->issuedByThisCA=ASN1_read_cert(cp))==NULL) goto error;
		if((ret->issuedByThisCA->der=ASN1_dup(cp))==NULL) goto error;
	}

	ret->der = in;
	return(ret);
error:
	CertPair_free(ret);
	return NULL;
}
