/* crtp.c */
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

#include "ok_err.h"
#include "ok_x509.h"

/*-----------------------------------------
  make new struct cert_pair
-----------------------------------------*/
CertPair *CertPair_new(void){
	CertPair *ret;

	if((ret=(CertPair*)MALLOC(sizeof(CertPair)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CRTP,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CertPair));
	return ret;
}

/*-----------------------------------------
  FREE struct cert_pair
-----------------------------------------*/
void CertPair_free(CertPair *ctp){
	if(ctp==NULL) return;
	Cert_free(ctp->issuedToThisCA);
	Cert_free(ctp->issuedByThisCA);
	if(ctp->der) FREE(ctp->der);
	FREE(ctp);
}

/*-----------------------------------------
  duplicate struct cert_pair
-----------------------------------------*/
CertPair *CertPair_dup(CertPair *org){
	CertPair *ret=NULL;

	if(org==NULL) goto error;
	if((ret=CertPair_new())==NULL) goto error;

	if(org->issuedToThisCA)
		if((ret->issuedToThisCA=Cert_dup(org->issuedToThisCA))==NULL)
			goto error;

	if(org->issuedByThisCA)
		if((ret->issuedByThisCA=Cert_dup(org->issuedByThisCA))==NULL)
			goto error;

	return  ret;
error:
	CertPair_free(ret);
	return NULL;
}
