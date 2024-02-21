/* req_asn1.c */
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

#include "ok_asn1.h"
#include "ok_x509.h"

/*-----------------------------------------
  Get request DER from Cert
-----------------------------------------*/
unsigned char *Req_toDER(Req *req,Key *prv,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=Req_estimate_der_size(req))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509REQ,ERR_PT_REQASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if(Cert_set_sigalgo((Cert*)req,prv)) goto error;

	if(Req_DER_data(req,ret,&i)) goto error;

	if(x509_set_signature(ret,prv,&req->signature,&req->siglen)) goto error;
	cp = ret+i;

	if(x509_DER_algoid(req->signature_algo,NULL,cp,&j)) goto error;
	cp+=j; i+=j;

	ASN1_set_bitstring(0,req->siglen,req->signature,cp,&j);
	i+=j;
	ASN1_set_sequence(i,ret,ret_len);

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}


/*-----------------------------------------
  Get request data DER from cert
-----------------------------------------*/
int Req_DER_data(Req *req,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j;

	ASN1_set_integer(req->version,ret,&i);
	cp =ret+i;

	if(Cert_DER_subject(&(req->subject_dn),cp,&j)) goto error;
	cp+=j; i+=j;

	if(x509_DER_pubkey(req->pubkey,cp,&j)) goto error;
	cp+=j; i+=j;

	if(Req_DER_attrs(req->ext,cp,&j)) goto error;
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);

	return 0;
error:
	return -1;
}

/*-----------------------------------------
  Get certext DER from cert extent
-----------------------------------------*/		
int Req_DER_attrs(CertExt *top,unsigned char *ret,int *ret_len){
	unsigned char *cp,*sq;
	CertExt *ext;
	int	i,j,k;
  
	sq=ret; *ret_len=i=0;
	for(ext=top; ext ;ext=ext->next){
		if((ext->extnID<=0)&&(ext->objid==NULL))
			continue;

		cp=sq;
		if(ext->extnID>0){
			if(ASN1_int_2object(ext->extnID,cp,&j))
				continue;
			cp+=j;
		}else{
			j = ASN1_tlen(ext->objid) + 2;
			memcpy(cp,ext->objid,j);
			cp+=j;
		}

		k=ext->dlen;
		memcpy(cp,ext->der,k);

		ASN1_set_set(k,cp,&k);
		j+=k;

		ASN1_set_sequence(j,sq,&j);
		sq+=j; i+=j;
	}
	ASN1_set_explicit(i,0,ret,ret_len);

	return 0;
}
