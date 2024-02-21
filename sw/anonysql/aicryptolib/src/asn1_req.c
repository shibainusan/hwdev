/* asn1_req.c */
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
#include "ok_rsa.h"
#include "ok_x509.h"
#include "ok_md5.h"

/*-----------------------------------------
  Get PKCS#10 AttributeValues
-----------------------------------------*/
CertExt *asn1_get_reqatt(unsigned char *in, int *ret_len){
	CertExt *ret=NULL,*hd,*ext;
	unsigned char *t,*cp,*oid;
	int i,j,id,len,err=-1;

	len = ASN1_length(in+1,&i);
	*ret_len = len+i+1;

	cp = ASN1_next(in);

	for(t=cp,i=0;i<len;){
		oid = ASN1_next(t);

		if((id = ASN1_object_2int(oid))<0) goto done;
		cp = ASN1_next(oid);

		if((*cp&0x1f) != ASN1_SET){
			OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1REQ,NULL);
			goto done;
		}
		cp = ASN1_next(cp);

		/* get extension */
		if((ext=ASN1_get_ext(id,cp))==NULL) goto done;

		/* set other information */
		if((ext->objid=ASN1_dup(oid))==NULL) goto done;

		if(ret==NULL){
			ret= hd = ext;
		}else{
			hd->next= ext;
			hd = ext;
		}

		if((t=ASN1_skip_(t,&j))==NULL) goto done;
		i+=j;
	}
	err = 0;
done:
	if(err){ CertExt_free_all(ret); ret=NULL; }
	return ret;
}

int ASN1_get_reqext(unsigned char *in, Req *req){
	CertExt *ext;
	int i;

	if(*in != 0xa0) return 1;
	if((req->ext=CertExt_new(OBJ_DUMMY))==NULL) return -1;
	ext=req->ext;

	if(in[1] == 0) return 1;
	if((ext->next = asn1_get_reqatt(in,&i))==NULL) return -1;

	return 0;
}

/*-----------------------------------------
  ASN.1 to struct cert (read request)
-----------------------------------------*/
Req *ASN1_read_req(unsigned char *in){
	unsigned char *cp,*t;
	int	i;
	Req *ret;

	if(in == NULL) return NULL;
	if(*in != 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1REQ+2,NULL);
		return NULL;
	}

	cp = ASN1_step(in,2);

	/* get certificate request */
	if((ret=Cert_new())==NULL) goto error;

	/* read PKCS#10 CSR (certificate signing request) */
	if((ret->version=ASN1_integer(cp,&i))!= 0) goto error;

	/* read request subject */
	cp = ASN1_next(cp);
	if((ret->subject=ASN1_get_subject(cp,&(ret->subject_dn)))==NULL) goto error;

    /* read public key */
	if((cp = ASN1_skip(cp))==NULL) goto error;
	if((ret->pubkey=(Key*)ASN1_get_pubkey(cp))==NULL) goto error;
	ret->pubkey_algo = ret->pubkey->key_type;

	/* read request Attributes */
	if((cp = ASN1_skip(cp))==NULL) goto error;
	if(ASN1_get_reqext(cp,ret)<0) goto error;

	/* read signature */
	if(ret->ext)
		if((cp = ASN1_skip(cp))==NULL) goto error;

	if((t = ASN1_skip(cp))==NULL) goto error;
	cp = ASN1_next(cp);
	if((ret->signature_algo=ASN1_object_2int(cp))<0) goto error;

	if(ASN1_bitstring(t,&i,&(ret->signature),&(ret->siglen),NULL)<0) goto error;

	ret->der = in;
	return(ret);

error:
	Cert_free(ret);
	return NULL;
}


