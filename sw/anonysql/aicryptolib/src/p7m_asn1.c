/* p7m_asn1.c */
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
#include "ok_hmac.h"
#include "ok_pkcs.h"
#include "ok_tool.h"

/*-----------------------------------------------
  PKCS#7 Enveloped-DATA get DER buffer.
-----------------------------------------------*/
unsigned char *P7_envelope_toDER(PKCS7 *p7,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	P7_Envelope	*p7env;
	int len,i;

	if((i=P7m_estimate_der_size(p7))<=0)
		return NULL;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7MASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	cp = ret;
	*cp=0x30; cp[1]=0x80; cp+=2;	/* SEQUENCE [30 80] */

	ASN1_int_2object(OBJ_P7_ENVELP,cp,&len);
	cp += len;

	*cp=0xa0; cp[1]=0x80; cp+=2;	/* cont[0] [a0 80] */
	*cp=0x30; cp[1]=0x80; cp+=2;	/* SEQUENCE [30 80] */

	p7env=(P7_Envelope*)p7->cont;

	/* set version number */
	ASN1_set_integer(p7env->version,cp,&i);
	len+=i; cp+=i;

	/* set set of recipientInfos */
	if(P7_DER_recipi(p7env->recipi,cp,&i)) goto error;
	len+=i; cp+=i;

	/* set encryptedContentInfo */
	if(P7_DER_encCnt(p7env->encCnt,cp,&i)) goto error;
	len+=i; cp+=i;

	ASN1_set_end(cp); cp+=2;
	ASN1_set_end(cp); cp+=2;
	ASN1_set_end(cp);

	*ret_len = len+12;
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

int P7_DER_recipi(RecipInfo *rci,unsigned char *ret,int *ret_len){
	unsigned char *st,*cp,*ct;
	int	len,i,j,k;

	st=ret;
	len=0;
	do{
		cp=st;
		/* set version */
		ASN1_set_integer(rci->version,cp,&i);
		cp+=i;
		/* set issuerAndSerialNumber */
		ct=cp;
		if(Cert_DER_subject(&rci->iss_dn,ct,&j)) goto error;
		ct+=j;
		ASN1_set_integer(rci->serialNum,ct,&k);
		ASN1_set_sequence(j+k,cp,&j);
		cp+=j; i+=j;

		/* set keyEncryptionAlgorithm */
		if(P7_DER_algoId(rci->enc_algo,cp,&j)) goto error;
		cp+=j; i+=j;

		/* set encryptedKey */
	    ASN1_set_octetstring(rci->size,rci->key,cp,&j);
		cp+=j; i+=j;

		ASN1_set_sequence(i,st,&i);

		len+=i;
		st +=i;
		rci=rci->next;
	}while(rci);

	ASN1_set_set(len,ret,ret_len);
	return 0;
error:
	return -1;
}

int P7_DER_encCnt(EncCntInfo *enc,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ed;
	int	len,i,tmp,sz;

	cp=ret;
	*cp=0x30; cp[1]=0x80; cp+=2;	/* SEQUENCE [30 80] */

	/* set object Identifier */
	if(ASN1_int_2object(enc->type,cp,&len)) goto error;
	cp += len;

	/* set contentEncryptionAlgorithmIdentifier */
	if(P7_DER_contentEncAlgo(enc,cp,&i)) goto error;
	cp +=i; len+=i;

	/* set encryptedData */
	*cp=0xa0; cp[1]=0x80; cp+=2;	/* cont[0] [a0 80] */

	tmp=enc->size;
	(tmp>2048)?(sz=2048):(sz=tmp);

	ed=enc->data;
	do{
		/*	this is IE compatible... */
		ASN1_set_octetstring(sz,ed,cp,&i);
		cp+=i; len+=i;

		tmp-=sz;
		ed+=sz;
		(tmp>2048)?(sz=2048):(sz=tmp);
	}while(tmp>0);

	ASN1_set_end(cp); cp+=2;
	ASN1_set_end(cp);
	*ret_len = len+8;
	return 0;
error:
	return -1;
}

int P7_DER_contentEncAlgo(EncCntInfo *enc,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int	i,j,k;

	if(ASN1_int_2object(enc->enc_algo,ret,&i)) return -1;
	cp = ret+i;
	
	switch(enc->enc_algo){
	case OBJ_CRYALGO_RC2CBC:
		ASN1_set_integer(enc->iter,cp,&j);
		ASN1_set_octetstring(enc->iv_size,enc->iv,cp+j,&k);

		ASN1_set_sequence(j+k,cp,&j);
		break;
	case OBJ_CRYALGO_DESCBC:
	case OBJ_CRYALGO_3DESCBC:
		ASN1_set_octetstring(enc->iv_size,enc->iv,cp,&j);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS7,ERR_PT_P7MASN1+3,NULL);
		return -1;
	}
	ASN1_set_sequence(i+j,ret,ret_len);

	return 0;
}

/*-----------------------------------------------
  estimate DER length of PKCS#7 Enveloped-DATA
-----------------------------------------------*/
int P7m_estimate_der_size(PKCS7 *p7){
	int i,len=0;
	RecipInfo *rci;

	if(p7==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_P7MASN1+4,NULL);
		return -1;
	}

	rci=((P7_Envelope*)p7->cont)->recipi;
	while(rci){
		for(i=0;i<RDN_MAX;i++){
			if(rci->iss_dn.rdn[i].tag)
				len+=strlen(rci->iss_dn.rdn[i].tag)+20;
		}
		len+=rci->size + 24;
		rci=rci->next;
	}
		
	len+=((P7_Envelope*)p7->cont)->encCnt->size + 128;
	return len;
}
