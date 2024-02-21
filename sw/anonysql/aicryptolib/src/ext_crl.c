/* ext_crl.c */
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

#include "ok_x509.h"
#include "ok_x509ext.h"
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_sha1.h"


/*-----------------------------------------
  CertExt reasonCode
-----------------------------------------*/
/* support */
CertExt *Extnew_reason_code(int code){
	CE_Reason *ret;
	
	if((ret=(CE_Reason*)CertExt_new(OBJ_X509v3_CRLReason))==NULL) goto error;
	if((ret->der=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRLEXT,NULL);
		goto error;
	}
	/* set data */
	ret->code = code;
	/* get DER */
	ASN1_set_enumerated(code,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* option */
CertExt *Extnew_instruction_code(){
    return NULL;
}

/* option */
CertExt *Extnew_invalidity_date(){
    return NULL;
}

/* option */
CertExt *Extnew_certissuer(){
    return NULL;
}

/*-----------------------------------------
  CertExt CRL Number
-----------------------------------------*/
/* support */
CertExt *Extnew_crl_number(int num){
	CE_CRLNum *ret;
	
	if((ret=(CE_CRLNum*)CertExt_new(OBJ_X509v3_CRLNumber))==NULL) goto error;
	if((ret->der=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRLEXT+1,NULL);
		goto error;
	}
	/* set data */
	ret->num = num;
	/* get DER */
	ASN1_set_integer(num,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Issuing Dist Point
-----------------------------------------*/
/* support */
CertExt *Extnew_crl_issdistpt(ExtGenNames *distp,unsigned char *rflg,int bflg){
	CE_IssDistPt *ret;
	unsigned char *cp;
	int i,j,k=16,l;
	
	if((ret=(CE_IssDistPt*)CertExt_new(OBJ_X509v3_IssDistPoint))==NULL) goto error;

	/* estimate DER size */
	if(distp){
		if((i=ExtGN_estimate_der_size(distp))<0) goto error;
		k+=i;
	}
	k += ((bflg&EXT_IDP_UCert)?(4):(0)) + ((bflg&EXT_IDP_CACert)?(4):(0))
		+((bflg&EXT_IDP_indCRL)?(4):(0));

	if((ret->der=(unsigned char*)MALLOC(k))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCRL+2,NULL);
		goto error;
	}

	i=0; cp=ret->der;
	if(distp){
		/* set data */
		ret->distp.fullName = distp;
		ret->distp.FullorRDN= 1;
		/* get DER */
		if(ExtGN_toDER(distp,cp,&j)==NULL) goto error;	
		*cp = 0xa0; /* implicit */
		ASN1_set_explicit(j,0,cp,&j);
		cp+=j; i+=j;
	}
	if(bflg&EXT_IDP_UCert){
		ret->onlyContainsUserCerts = 1; /* TRUE */
		ASN1_set_boolean(1,cp,&j);
		*cp = 0x81; /* implicit */
		cp+=j; i+=j;
	}
	if(bflg&EXT_IDP_CACert){
		ret->onlyContainsCACerts = 1; /* TRUE */
		ASN1_set_boolean(1,cp,&j);
		*cp = 0x82; /* implicit */
		cp+=j; i+=j;		
	}
	if(rflg){
		/* set data */
		memcpy(ret->rflag,rflg,2);
		/* get DER */
		asn1_check_derbit(2,rflg,&k,&l);
		ASN1_set_bitstring(k,l,rflg,cp,&j);
		*cp = 0x83; /* implicit */
		cp+=j; i+=j;
	}
	if(bflg&EXT_IDP_indCRL){
		ret->indirectCRL = 1; /* TRUE */
		ASN1_set_boolean(1,cp,&j);
		*cp = 0x84; /* implicit */
		i+=j;		
	}
	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

