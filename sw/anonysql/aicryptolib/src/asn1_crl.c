/* asn1_crl.c */
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

#include "ok_asn1.h"
#include "ok_rsa.h"
#include "ok_x509.h"
#include "ok_md5.h"

/*-----------------------------------------
  Get X.509v3.0 CRL Extension (OPTIONAL)
  return 1...not CRL Extension 
  return 0...no error.
  return -1..error!!
-----------------------------------------*/
int ASN1_get_crlext(unsigned char *in,CRL *crl){
	CertExt *ext;
	int i;

	if(*in!=0xa0){return 1;} /* no extension */
	if(crl->version<1){
		OK_set_error(ERR_ST_BADVER,ERR_LC_ASN1,ERR_PT_ASN1CRL,NULL);
		return -1;
	}

	if((crl->ext=CertExt_new(OBJ_DUMMY))==NULL) return -1;
	ext=crl->ext;

	if(in[1]==0) return 1;

	in = ASN1_next(in); /* skip Explicit tag */
	if((ext->next = asn1_get_exts(in,&i))==NULL) return -1;

	return 0;
}

int ASN1_get_crlentext(unsigned char *in, Revoked *rv){
	unsigned char *cp;
	CertExt *ext;
	int i;

	/* check whether extension or not */
	if(*in!=0x30) return 1;
	cp = ASN1_next(in);
	if(*cp!=0x30) return 1;

	if((rv->entExt=CertExt_new(OBJ_DUMMY))==NULL) return -1;
	ext=rv->entExt;

	if((ext->next = asn1_get_exts(in,&i))==NULL) return -1;

	return 0;
}

int ASN1_get_revoked(unsigned char *in,CRL *crl){
	unsigned char *t;
	Revoked *rv;
	int i,k,len;

	len = ASN1_tlen(in);
	in  = ASN1_next(in);

	if((0x1f&*in) != ASN1_SEQUENCE) return 1; /* might be OID */

	for(i=0;i<len;){
		if(crl->next==NULL) rv =crl->next =Revoked_new();
		else{ rv->next =Revoked_new(); rv =rv->next;}

		if(rv==NULL) goto error;

		/* serial number */
		t = ASN1_next(in);
		if((rv->serialNumber=ASN1_integer(t,&k))<0)
			if(k==0) goto error;

		/* reserve serial number if bigger than 4... */
		if(ASN1_tlen(t)>4){
			if((rv->long_sn=ASN1_dup(t))==NULL) goto error;
		}

		/* get revocation date */
		t = ASN1_next(t);
		if(UTC2stm(t,&rv->revocationDate)) goto error;

		/* crlEntryExtensions OPTIONAL */
		t = ASN1_next(t);
		if(ASN1_get_crlentext(t,rv)<0) goto error;

		if((in=ASN1_skip_(in,&k))==NULL) goto error;
		i+= k;
	}
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  ASN.1 to struct CRL
-----------------------------------------*/
CRL *ASN1_read_crl(unsigned char *in){
    unsigned char *cp,*t;
	CRL *ret;
	int i,len;

	if(in == NULL){return NULL;}

	cp = ASN1_next(in);
	if((*in!=0x30)||(*cp!=0x30)){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1CRL+2,NULL);
		return NULL;
	}

	/* get CRL */
    if((ret=CRL_new())==NULL) goto error;

	/* read x509 Certificate Revoked List */
	cp = ASN1_step(in,2);
	if(*cp==ASN1_INTEGER){
		/* get version */
		ret->version = ASN1_integer(cp,&i);
		/* check version */
		if((ret->version<0)||(ret->version>1)){
			OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1,ERR_PT_ASN1CRL+2,NULL);
			goto error;
		}
		cp = ASN1_next(cp);

    }else if(*cp!=0x30){
		/* format error! */
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1CRL+2,NULL);
		goto error;
	}
    t = ASN1_next(cp);

	/* read signature algorithm */
	if((ret->signature_algo=ASN1_object_2int(t))<0) goto error;
	if((cp = ASN1_skip(cp))==NULL) goto error;

	/* read issuer */
	if((ret->issuer=ASN1_get_subject(cp,&(ret->issuer_dn)))==NULL) goto error;
	if((cp = ASN1_skip(cp))==NULL) goto error;

	/* read validity time */
	/* lastUpdate */
	if(UTC2stm(cp,&ret->lastUpdate)) goto error;
	cp = ASN1_next(cp);

	/* nextUpDate OPTIONAL */
	if((*cp==ASN1_UTCTIME)||(*cp==ASN1_GENERALIZEDTIME)){
		if(UTC2stm(cp,&ret->nextUpdate)) goto error;
		cp = ASN1_next(cp);
    }

	/* revoked list OPTIONAL */
	len=ASN1_tlen(cp);
    if(((0x1f&*cp)==ASN1_SEQUENCE) && (len)){
		if((i=ASN1_get_revoked(cp,ret))<0) goto error;
		if(i==0)
			if((cp = ASN1_skip(cp))==NULL) goto error;
	}else if(len==0){
		cp = ASN1_next(cp);
	}

	/* crlExtensions OPTIONAL */
	if(ASN1_get_crlext(cp,ret)<0) goto error;
	if(ret->ext)
		if((cp = ASN1_skip(cp))==NULL) goto error;

	/* read signature */
	t = ASN1_next(cp);
	if(ASN1_object_2int(t)<0) goto error;

	if((cp = ASN1_skip(cp))==NULL) goto error;

    /* read signature */
    if(ASN1_bitstring(cp,&i,&(ret->signature),&(ret->siglen),NULL)<0) goto error;

	ret->der = in;
	return(ret);

error:
	CRL_free(ret);
	return NULL;
}
