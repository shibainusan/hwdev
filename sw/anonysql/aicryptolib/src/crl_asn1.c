/* crl_asn1.c */
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
#include "ok_rsa.h"
#include "ok_tool.h"

/* just use OBJ_SIG_*, OBJ_HASH_*, because of object identifier */
int default_crl_sig_algo = OBJ_SIG_MD5RSA;

int set_digalgo_from_sigalgo(int algo);

/*-----------------------------------------
  Get CRL DER from CRL
-----------------------------------------*/
unsigned char *CRL_toDER(CRL *crl,Key *prv,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=CRL_estimate_der_size(crl))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRLASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}
	if(CRL_set_sigalgo(crl,prv)) goto error;

	if(CRL_DER_data(crl,ret,&i)) goto error;

	if(x509_set_signature(ret,prv,&crl->signature,&crl->siglen)) goto error;
	cp = ret+i;

	if(x509_DER_algoid(crl->signature_algo,NULL,cp,&j)) goto error;
	cp+=j; i+=j;

	ASN1_set_bitstring(0,crl->siglen,crl->signature,cp,&j);
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

int CRL_DER_data(CRL *crl,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int	i=0,j,err=-1;

	cp=ret;
	if(crl->version){ /* version 2 or more */
		ASN1_set_integer(crl->version,cp,&j);
		cp+=j; i+=j;
	}
	if(x509_DER_algoid(crl->signature_algo,NULL,cp,&j)) goto done;
	cp+=j; i+=j;

	if(Cert_DER_subject(&(crl->issuer_dn),cp,&j)) goto done;
	cp+=j; i+=j;

	if(Cert_DER_time(&crl->lastUpdate,cp,&j)) goto done;
	cp+=j; i+=j;

	if(Cert_DER_time(&crl->nextUpdate,cp,&j)) goto done;
	cp+=j; i+=j;

	if(CRL_DER_revoked(crl,cp,&j)) goto done;
	cp+=j; i+=j;

	if(crl->version){ /* version 2 or more */
		if(x509_DER_exts(crl->ext,cp,&j)) goto done;
		if(j) ASN1_set_explicit(j,0,cp,&j);
		i+=j;
	}

	ASN1_set_sequence(i,ret,ret_len);
	err=0;
done:
	return err;
}

/*-----------------------------------------
  Get CRL data DER from CRL
-----------------------------------------*/
int CRL_DER_revoked(CRL *crl,unsigned char *ret,int *ret_len){
	unsigned char *sq,*cp;
	Revoked *rv;
	int	i,j,k;

	*ret_len=i=0;
	if(!crl->next) return 0; /* not error */

	sq=ret;
	for(rv=crl->next;rv!=NULL;rv=rv->next){
		ASN1_set_integer(rv->serialNumber,sq,&j);
		cp=sq+j;

		if(Cert_DER_time(&rv->revocationDate,cp,&k)) return -1;
		cp+=k; j+=k;

		if(x509_DER_exts(rv->entExt,cp,&k)) return -1;
		j+=k;

		ASN1_set_sequence(j,sq,&j);
		i+=j; sq+=j;
	}
	ASN1_set_sequence(i,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  Set CRL signature algo
-----------------------------------------*/
int CRL_set_sigalgo(CRL *crl,Key *prv){
	int kt;

	if((kt=set_digalgo_from_sigalgo(default_crl_sig_algo))<0)
		return -1;

	if(kt!=prv->key_type){
		OK_set_error(ERR_ST_UNMATCHEDPARAM,ERR_LC_X509CRL,ERR_PT_CRLASN1+3,NULL);
		return -1;
	}

	crl->signature_algo = default_crl_sig_algo;
	return 0;
}


/*-----------------------------------------
  estimate CRL DER size from CRL
-----------------------------------------*/
int CRL_estimate_der_size(CRL *crl){
	Revoked *rv;
	CertExt *ext;
	int ret,i,j;

	if(crl==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CRL,ERR_PT_CRLASN1+4,NULL);
		return -1;
	}
	/* version & serial & algorithm */
	ret=32;

	/* check issuer & subject size */
	for(i=j=0;i<RDN_MAX;i++){
		if(crl->issuer_dn.rdn[i].tag)
			j+=strlen(crl->issuer_dn.rdn[i].tag)+20;
	}
	ret+=j;

	/* validity */
	ret+=40;

	/* revoked list */
	for(j=0,rv=crl->next;rv!=NULL;rv=rv->next){
		j+=(rv->entExt)?(16):(0); /* only ReasonCode ? */
		j+=32;
	}
	ret+=j;

	/* count extension */
	for(j=0,ext=crl->ext;ext!=NULL;ext=ext->next){
		if(ext->extnID<=0) continue;
		j+=(ext->critical)?(4):(0);
		j+=ext->dlen+16;
	}
	ret+=j;

	/* signature len */
	/* actually, signature will be set in CRL_toDER.
	 * therefore, signature length might be depened on Private key length.
	 * if current CRL doesn't have signature information, just set
	 * enough big size of signature. (currently it's 2048bit)
	 */
	if((crl->signature==NULL)||(crl->siglen<=0))
		ret+=256+24;
	else
		ret+=crl->siglen+24;
	return ret;
}
