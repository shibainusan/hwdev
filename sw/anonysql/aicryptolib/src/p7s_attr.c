/* p7s_attr.c */
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
#include "ok_pkcs.h"
#include "ok_tool.h"

AuthAtt *P7s_attr_smimecap(int cry_algo,int size){
	AuthAtt *ret=NULL;
	unsigned char buf[128],*cp,*ct;
	int	i,j,k;

	ASN1_int_2object(OBJ_P9_SMIME_CAP,buf,&i);
	cp=buf+i;

	if(ASN1_int_2object(cry_algo,cp,&j)) goto error;
	ct=cp+j;
	ASN1_set_integer(size,ct,&k);
	ASN1_set_sequence(j+k,cp,&j);
	ASN1_set_sequence(j,cp,&j);
	ASN1_set_set(j,cp,&j);

	ASN1_set_sequence(i+j,buf,&i);

	if((ret=P7_authatt_new())==NULL) goto error;
	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SATTR,NULL);
		goto error;
	}
	ret->der_size=i;
	memcpy(ret->der,buf,i);

	return ret;
error:
	P7_authatt_free(ret);
	return NULL;
}

AuthAtt *P7s_attr_cntType(int type){
	AuthAtt *ret=NULL;
	unsigned char buf[64],*cp;
	int	i,j;

	ASN1_int_2object(OBJ_P9_CONTENT_TYPE,buf,&i);
	cp=buf+i;

	if(ASN1_int_2object(type,cp,&j)) goto error;
	ASN1_set_set(j,cp,&j);

	ASN1_set_sequence(i+j,buf,&i);

	if((ret=P7_authatt_new())==NULL) goto error;
	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SATTR+1,NULL);
		goto error;
	}
	ret->der_size=i;
	memcpy(ret->der,buf,i);
	return ret;
error:
	P7_authatt_free(ret);
	return NULL;
}

AuthAtt *P7s_attr_signtime(){
	AuthAtt *ret;
	time_t t;
	struct tm *stm;
	unsigned char buf[64],*cp;
	int	i,j;

	time(&t);
	stm=(struct tm*)gmtime(&t);

	ASN1_int_2object(OBJ_P9_SIGN_TIME,buf,&i);
	cp=buf+i;

	if(Cert_DER_time(stm,cp,&j)) goto error;
	ASN1_set_set(j,cp,&j);

	ASN1_set_sequence(i+j,buf,&i);

	if((ret=P7_authatt_new())==NULL) goto error;
	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SATTR+2,NULL);
		goto error;
	}
	ret->der_size=i;
	memcpy(ret->der,buf,i);
	return ret;
error:
	P7_authatt_free(ret);
	return NULL;
}

AuthAtt *P7s_attr_digest(SignerInfo *si,unsigned char *data,int len){
	AuthAtt *ret;
	unsigned char buf[64],*digest,*cp;
	int	i,j;


	ASN1_int_2object(OBJ_P9_MESS_DGST,buf,&i);
	cp=buf+i;

	if((digest=OK_do_digest(si->digest_algo,data,len,NULL,&j))==NULL)
		return NULL;

	ASN1_set_octetstring(j,digest,cp,&j);
	ASN1_set_set(j,cp,&j);

	ASN1_set_sequence(i+j,buf,&i);
	FREE(digest);

	if((ret=P7_authatt_new())==NULL) goto error;
	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SATTR+1,NULL);
		goto error;
	}
	ret->der_size=i;
	memcpy(ret->der,buf,i);
	return ret;
error:
	P7_authatt_free(ret);
	return NULL;
}
