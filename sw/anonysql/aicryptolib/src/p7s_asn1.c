/* p7s_asn1.c */
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
  PKCS#7 Signed-DATA get DER buffer.
-----------------------------------------------*/
unsigned char *P7_signed_toDER(PKCS7 *p7,unsigned char *buf,int *ret_len){
	P7_Signed *p7sig;
	unsigned char *cp,*ret;
	int len,i,j,k,sigf=0;

	if((i=P7s_estimate_der_size(p7))<=0)
		return NULL;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	cp = ret;
	*cp=0x30; cp[1]=0x80; cp+=2;	/* SEQUENCE [30 80] */

	ASN1_int_2object(OBJ_P7_SIGNED,cp,&len);
	cp += len;

	*cp=0xa0; cp[1]=0x80; cp+=2;	/* cont[0] [a0 80] */
	*cp=0x30; cp[1]=0x80; cp+=2;	/* SEQUENCE [30 80] */

	if(p7sig=(P7_Signed*)p7->cont)
		if(p7sig->digest_algo) sigf=1;

	/* version number */
	(p7sig)?(k=p7sig->version):(k=1);
	ASN1_set_integer(k,cp,&i);
	cp += i; len+=i;

	/* digestAlgorithms */
	(sigf)?(k=p7sig->digest_algo):(k=0);
	if(k){
		if(P7_DER_algoId(k,cp,&j)) goto error;
		ASN1_set_set(j,cp,&j);
		cp+=j; len+=j;
	}else{
		ASN1_set_null(cp); *cp=0x31; /* set [31 00] */
		cp+= 2; len+=2;
	}

	/* contentInfo */
	if(sigf){
		if(P7_DER_sigCont(p7sig,cp,&j)) goto error;
		cp+=j; len+=j;
	}else{
		ASN1_int_2object(OBJ_P7_DATA,cp,&j);
		/*ASN1_set_null(cp+j);*/
		ASN1_set_sequence(j/*+2*/,cp,&j);
		cp+= j; len+=j;
	}

	/* check chain first */
	/* if(P12_check_chain((PKCS12*)p7,0)) goto error; */

	/* [0] ExtendedCertificatesAndCertificates */
	if(P7_DER_signed_cert(p7,cp,&j)) goto error;
	cp+= j; len+=j;
	/* [1] CertificateRevocationLists */
	if(P7_DER_signed_crl(p7,cp,&j)) goto error;
	cp+= j; len+=j;

	/* set of SignerInfo */
	if(sigf){
		if(P7_DER_signerInfo(p7sig->signer,cp,&j)) goto error;
		cp+=j;	len+=j;
	}else{
		ASN1_set_null(cp); *cp=0x31; /* set [31 00] */
		cp+= 2; len+=2;
	}

	ASN1_set_end(cp); cp+=2;
	ASN1_set_end(cp); cp+=2;
	ASN1_set_end(cp);
	*ret_len = len+12;
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

int P7_DER_sigCont(P7_Signed *sig,unsigned char *cp,int *ret_len){
	unsigned char *ct;
	int	i,tmp,sz,len;

	*cp=0x30; cp[1]=0x80; cp+=2;	/* SEQUENCE [30 80] */
	ASN1_int_2object(OBJ_P7_DATA,cp,&len);
	cp+=len;
	*cp=0xa0; cp[1]=0x80; cp+=2;	/* cont[0] [a0 80] */
	*cp=0x24; cp[1]=0x80; cp+=2;	/* cont[4] [24 80] */

	tmp=sig->cnt_size;
	(tmp>2048)?(sz=2048):(sz=tmp);

	ct=sig->content;
	do{
		/*	this is IE compatible... */
		ASN1_set_octetstring(sz,ct,cp,&i);
		cp+=i; len+=i;

		tmp-=sz;
		ct+=sz;
		(tmp>2048)?(sz=2048):(sz=tmp);
	}while(tmp>0);

	memset(cp,0,6);
	*ret_len = len+12;
	return 0;
}

int P7_DER_algoId(int algo_id,unsigned char *ret,int *ret_len){
	int	j;

	if(ASN1_int_2object(algo_id,ret,&j)) return -1;
	ASN1_set_null(ret+j);
	ASN1_set_sequence(j+2,ret,ret_len);
	return 0;
}

int P7_DER_signerInfo(SignerInfo *signer,unsigned char *ret,int *ret_len){
	SignerInfo *sig;
	unsigned char *st,*cp,*ct;
	int	len,i,j,k;

	cp=st=ret;
	len=0;
	sig=signer;
	do{
		cp=st;
		/* set version */
		ASN1_set_integer(sig->version,cp,&i);
		cp+=i;
		/* set issuerAndSerialNumber */
		ct=cp;
		if(Cert_DER_subject(&sig->iss_dn,ct,&j)) goto error;
		ct+=j;
		ASN1_set_integer(sig->serialNum,ct,&k);
		ASN1_set_sequence(j+k,cp,&j);
		cp+=j; i+=j;

		/* set digestAlgorithm */
		if(P7_DER_algoId(sig->digest_algo,cp,&j)) goto error;
		cp+=j; i+=j;

		/* set authenticatedAttribute (optional) */
		if(sig->auth){
			if(P7_DER_authatt(sig->auth,cp,&j)) goto error;
			cp+=j; i+=j;
		}

		/* set digestEncryptionAlgorithmIdentifer */
		if(P7_DER_algoId(sig->enc_algo,cp,&j)) goto error;
		cp+=j; i+=j;

		/* set encryptedDigest */
		ASN1_set_octetstring(sig->sig_size,sig->signature,cp,&j);
		cp+=j; i+=j;

		/* set unauthenticatedAttribute (optional) */
		if(sig->unauth){
			if(P7_DER_authatt(sig->unauth,cp,&j)) goto error;
			*cp=0xa1; cp+=j; i+=j;
		}

		ASN1_set_sequence(i,st,&i);
		len+=i;
		st +=i;
		sig=sig->next;
	}while(sig);

	ASN1_set_set(len,ret,ret_len);
	return 0;
error:
	return -1;
}

int P7_DER_authatt(AuthAtt *authatt,unsigned char *ret,int *ret_len){
	AuthAtt	*att;
	unsigned char *cp;
	int	len,i;

	cp=ret;
	len=0;
	att=authatt;
	while(att){
		/* copy data */
		if((i=att->der_size)<0){
			OK_set_error(ERR_ST_BADPARAM,ERR_LC_PKCS7,ERR_PT_P7SASN1+3,NULL);
			goto error;
		}
		memcpy(cp,att->der,i);

		len+=i;
		cp +=i;
		att=att->next;
	}

	ASN1_set_explicit(len,0,ret,ret_len);
	return 0;
error:
	return -1;
}


/*-----------------------------------------------
  PKCS#7 Signed-DATA get Cert DER.
-----------------------------------------------*/
int P7_DER_signed_cert(PKCS7 *p7,unsigned char *cn0,int *ret_len){
	P12_CertBag	*cb;
	unsigned char *cp,*cder;
	int len,i,j,k;

	i=P12_max_depth((PKCS12*)p7,OBJ_P12v1Bag_CERT);

	for(cp=cn0,k=0;i>=0;i--,cp+=len,k+=len){
		if((cb=(P12_CertBag*)P12_find_bag((PKCS12*)p7,OBJ_P12v1Bag_CERT,(unsigned char)i))==NULL)
			break;

		cder=cb->cert->der;

		/* calc DER length */
		len = ASN1_length(&cder[1],&j);
		len += j+1;

		memcpy(cp,cder,len);
	}

	if(!k){
		OK_set_error(ERR_ST_P12_NOCERT,ERR_LC_PKCS7,ERR_PT_P7SASN1+4,NULL);
		*ret_len = 0;
		return -1;
	}

	ASN1_set_explicit(k,0,cn0,ret_len);
	return 0;
}

/*-----------------------------------------------
  PKCS#7 Signed-DATA get CRL DER.
-----------------------------------------------*/
int P7_DER_signed_crl(PKCS7 *p7,unsigned char *cn1,int *ret_len){
	P12_CRLBag *cb;
	unsigned char *cp,*cder;
	int len,i,j,k;

	i=P12_max_depth((PKCS12*)p7,OBJ_P12v1Bag_CRL);

	for(cp=cn1,k=0;i>=0;i--,cp+=len,k+=len){
		if((cb=(P12_CRLBag*)P12_find_bag((PKCS12*)p7,OBJ_P12v1Bag_CRL,(unsigned char)i))==NULL)
			break; /* this might happen */

		cder=cb->crl->der;

		/* calc DER length */
		len = ASN1_length(&cder[1],&j);
		len+= j+1;

		memcpy(cp,cder,len);
	}

	if(k) ASN1_set_explicit(k,1,cn1,ret_len);
	else  *ret_len = 0;
	return 0;
}

/*-----------------------------------------------
  estimate DER length of PKCS#7 Signed-DATA
-----------------------------------------------*/
int P7s_estimate_der_size(PKCS7 *p7){
	P12_Baggage *bg;
	SignerInfo *sig;
	AuthAtt	*att;
	int i,j,len=0;

	if(p7==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_P7SASN1+6,NULL);
		return -1;
	}

	for(bg=p7->bag;bg!=NULL;bg=bg->next){
		switch(bg->type){
		case OBJ_P12v1Bag_CERT:
			i=ASN1_length(&(((P12_CertBag*)bg)->cert)->der[1],&j);
			len+=i+j+64;
			break;
		case OBJ_P12v1Bag_CRL:
			i=ASN1_length(&(((P12_CRLBag*)bg)->crl)->der[1],&j);
			len+=i+j+64;
			break;
		}
	}

	if(p7->cont==NULL){ /* "p7" might be PKCS12 structure */
		return len+64;
	}

	len+=((P7_Signed*)p7->cont)->cnt_size + 16;

	sig=((P7_Signed*)p7->cont)->signer;
	while(sig){
		for(i=0;i<RDN_MAX;i++){
			if(sig->iss_dn.rdn[i].tag)
				len+=strlen(sig->iss_dn.rdn[i].tag)+20;
		}
		for(att=sig->auth;att;att=att->next)
			len+=att->der_size;
		for(att=sig->unauth;att;att=att->next)
			len+=att->der_size;

		len+=sig->sig_size + 64;

		sig=sig->next;
	}

	return len;
}
