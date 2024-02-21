/* signature.c */
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
#include "ok_rsa.h"
#include "ok_x509.h"
#include "ok_tool.h"

int obj_sig2hash(int sig_oid);
int hash_size(int hash_algo);
int set_digalgo_from_sigalgo(int algo);

/*-------------------------------------------------
  get signature from data 
-------------------------------------------------*/
int OK_do_signature(Key *prv, unsigned char *data, int data_len, unsigned char **signature,int *sig_len, int sig_algo){
	unsigned char	digest[20];
	int dlen;

	if(set_digalgo_from_sigalgo(sig_algo)<0) goto error;

	if(OK_do_digest(sign_digest_algo,data,data_len,digest,&dlen)==NULL) goto error;
	
	switch(prv->key_type){
	case KEY_RSA_PRV:
		if((*signature=P1_sign_digest(prv,digest,dlen,sign_digest_algo))==NULL)
			goto error;
		*sig_len=prv->size;
		break;
	case KEY_DSA_PRV:
		if((*signature=DSA_get_signature((Prvkey_DSA*)prv,digest,dlen,sig_len))==NULL)
			goto error;
		break;
	case KEY_ECDSA_PRV:
		if((*signature=ECDSA_get_signature((Prvkey_ECDSA*)prv,digest,dlen,sig_len))==NULL)
			goto error;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_TOOL,ERR_PT_SIG,NULL);
		goto error;
	}

	return 0;
error:
	return -1;
}

/*-------------------------------------------------
  Verify signature
  0 ... signature OK
  1 ... signature error;
  -1... system error
  -2... PKCS#1 padding error or else
-------------------------------------------------*/
/* data should be smaller than key size (RSA) */
int OK_do_verify(Key *pub, unsigned char *digest, unsigned char *sig, int sig_algo){
	unsigned char *org=NULL,*dec=NULL;
	int i,halgo,slen,dlen,ret=-1;

	if((halgo= obj_sig2hash(sig_algo))<0) goto done;
	if((dlen = hash_size(halgo))<0) goto done;

	switch(pub->key_type){
	case KEY_RSA_PUB:
		/* decode certificate signature */
		slen= pub->size;
		if((dec=OK_do_sign(pub,sig,slen,NULL))==NULL)
			goto done;

		/* PKCS#1 Signature Check
		 * check padding and OBJECT IDENTIFIER */
		if((org = P1_pad2digest(dec,&i))==NULL) goto done;

		if(i != halgo){
			OK_set_error(ERR_ST_BADPARAM,ERR_LC_TOOL,ERR_PT_SIG+4,NULL);
			ret = -2;
			goto done;
		}

		ret = 0;
		if(memcmp(digest,org,dlen)) ret = 1;
		break;

	case KEY_DSA_PUB:
		ret = DSA_vfy_signature((Pubkey_DSA*)pub,digest,dlen,sig);
		break;

	case KEY_ECDSA_PUB:
		ret = ECDSA_vfy_signature((Pubkey_ECDSA*)pub,digest,dlen,sig);
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_TOOL,ERR_PT_SIG+1,NULL);
		goto done;
	}
done:
	if(org) FREE(org);
	if(dec) FREE(dec);
	return ret;
}

/*-----------------------------------------------------
  Low level signing function (not generate signature)
-----------------------------------------------------*/
/* data_len must be smaller than key size */
unsigned char *OK_do_sign(Key *key,unsigned char *data,int data_len,unsigned char *ret){
	unsigned char *tmp,*cp=ret;
	int i;

	if(key->size<data_len){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_TOOL,ERR_PT_SIG+2,NULL);
		return NULL;
	}

	if(ret==NULL){
		if((cp=ret=(unsigned char*)MALLOC(key->size))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_TOOL,ERR_PT_SIG+2,NULL);
			return NULL;
		}
	}
	switch(key->key_type){
	case KEY_RSA_PRV:
		if(RSAprv_doCrypt(data_len,data,cp,(Prvkey_RSA*)key)) goto error;
		break;
	case KEY_RSA_PUB:
		if(RSApub_doCrypt(data_len,data,cp,(Pubkey_RSA*)key)) goto error;
		break;
	case KEY_DSA_PRV:
		if((tmp=DSA_get_signature((Prvkey_DSA*)key,data,data_len,&i))==NULL) goto error;
		if(cp!=ret){ memcpy(ret,tmp,i); FREE(tmp); }
		else { FREE(cp); cp=tmp; }
		break;
	case KEY_ECDSA_PRV:
		if((tmp=ECDSA_get_signature((Prvkey_ECDSA*)key,data,data_len,&i))==NULL) goto error;
		if(cp!=ret){ memcpy(ret,tmp,i); FREE(tmp); }
		else { FREE(cp); cp=tmp; }
		break;
	case KEY_DSA_PUB:
	case KEY_ECDSA_PUB:
		/* DSA public key cannot be used for key encryption */
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_TOOL,ERR_PT_SIG+2,NULL);
		goto error;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_TOOL,ERR_PT_SIG+2,NULL);
		goto error;
	}
	return cp;
error:
	if(ret!=cp) FREE(cp);
	return NULL;
}

/*-------------------------------------------------
  Get signature from digest with PKCS1 padding
-------------------------------------------------*/
unsigned char *P1_do_sign(Key *prv,unsigned char *data,int *ret_len){
	unsigned char	digest[20],*ret;

	if(ASN1_do_digest(sign_digest_algo,data,digest,ret_len))
		return NULL;

	ret=P1_sign_digest(prv,digest,*ret_len,sign_digest_algo);
	*ret_len=prv->size;

	return ret;
}

/*-------------------------------------------------
  Get digest with PKCS1 padding
-------------------------------------------------*/
int P1_DER_digestinfo(unsigned char *dig,int dig_size,int dig_type,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int	i,j;

	if(ASN1_int_2object(dig_type,ret,&i)) return -1;
	cp = ret+i;
	ASN1_set_null(cp);
	ASN1_set_sequence(i+2,ret,&i);
	cp = ret+i;
	ASN1_set_octetstring(dig_size,dig,cp,&j);
	i+=j;
	ASN1_set_sequence(i,ret,ret_len);
	return 0;
}

unsigned char *P1_sign_digest(Key *key,unsigned char *digest,int dig_size,int dig_type){
	unsigned char *ret,*sign,dinfo[64];
	int	ks,dis;

	if((dig_size>20)||(dig_size<0)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_TOOL,ERR_PT_SIG+5,NULL);
		return NULL;
	}
	if(P1_DER_digestinfo(digest,dig_size,dig_type,dinfo,&dis))
		return NULL;

	ks=key->size;

	if((sign=(unsigned char*)MALLOC(ks))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_TOOL,ERR_PT_SIG+5,NULL);
		return NULL;
	}
 
	/* set PKCS#1 padding */
	memset(sign,0xff,ks);
	sign[0]=0; sign[1]=1;
	memcpy(&sign[ks-dis],dinfo,dis);
	sign[ks-dis-1]=0;

	/* if ret is NULL, something's wrong with key X( */
	ret=OK_do_sign(key,sign,ks,NULL);

	FREE(sign);
	return ret;
}

unsigned char *P1_pad2digest(unsigned char *dec,int *dig_algo){
	unsigned char *dtop,*ret,*cp;
	int i,j;

	/* check PKCS#1 Padding */
	if((dec[0]!=0)||(dec[1]!=1)){ /* bad Padding or decryption error */
		OK_set_error(ERR_ST_P1_BADPADDING,ERR_LC_TOOL,ERR_PT_SIG+6,NULL);
		return NULL;
	}

	for(i=2;dec[i];i++){
		if(dec[i]!=0xff){
			OK_set_error(ERR_ST_P1_BADPADDING,ERR_LC_TOOL,ERR_PT_SIG+6,NULL);
			return NULL;
		}
	}

	dtop = &dec[i+1];
	dtop =ASN1_next(dtop);
	cp   =ASN1_next(dtop);

	if((*dig_algo=ASN1_object_2int(cp))<=0){
		OK_set_errorlocation(ERR_LC_TOOL,ERR_PT_SIG+6);
		return NULL;
	}

	/* Algorithm is OK, so check byte strings */
	if((cp=ASN1_skip(dtop))==NULL) return NULL;

	if(ASN1_octetstring(cp,&i,&ret,&j))
		OK_set_errorlocation(ERR_LC_TOOL,ERR_PT_SIG+6);

	return ret;
}

