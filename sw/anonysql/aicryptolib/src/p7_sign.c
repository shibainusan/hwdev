/* p7_sign.c */
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

#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_md2.h"
#include "ok_md5.h"
#include "ok_sha1.h"

#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_tool.h"


int get_usercert_and_key(PKCS7 *p7, Cert **ucert, Key **ukey);
int get_enc_algo(Key *key);

/*----------------------------------------------------------------------
  get PKCS#7 Signed-DATA
  #caution# return-p7 has inputed "data" and "len" as a content..
	we should FREE them when we just want to get app/pkcs7-signature
----------------------------------------------------------------------*/
PKCS7 *P7s_get_signed(PKCS12 *p12, unsigned char *data, int len, int digest_algo){
	PKCS7	*p7;
	P7_Signed	*p7sig;

	if((p7=P7_new(OBJ_P7_SIGNED))==NULL) goto error;
	p7sig = (P7_Signed*)p7->cont;

	/* set version 1 */
	p7sig->version = 1;
	p7sig->digest_algo = digest_algo;

	/* set context of PKCS#7 Signed Data*/
	p7sig->cnt_size = len;
	if((p7sig->content=(unsigned char*)MALLOC(len))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SIGN,NULL);
		goto error;
	}
	memcpy(p7sig->content,data,len);

	/* copy user certs and private key into p7 */
	if(P12_copy_p12bags((PKCS12*)p7,p12)) goto error;

	if(P7s_get_signerInfo(p7,data,len)) goto error;

	return p7;
error:
	P7_free(p7);
	return NULL;
}


/* just set single signer of private key user */
int P7s_get_signerInfo(PKCS7 *p7, unsigned char *data, int len){
	SignerInfo	*si;
	Cert *cert;
	Key *key;

	if(get_usercert_and_key(p7,&cert,&key)) goto error;

	if((si=((P7_Signed*)p7->cont)->signer)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_P7SIGN+1,NULL);
		goto error;
	}

	/* set version */
	si->version = 1;

	/* set issuerAndSerialNumber */
	si->serialNum = cert->serialNumber;
	if(Cert_dncopy(&(cert->issuer_dn),&(si->iss_dn))) goto error;

	/* set digestAlgorithm */
	si->digest_algo = ((P7_Signed*)p7->cont)->digest_algo;

	/* set authenticatedAttribute (optional) */
	if(P7s_get_authatt(si,data,len)) goto error;

	/* set encryptedDigest */
	if(P7s_get_signature(si,key,data,len)) goto error;

	/* set unauthenticatedAttribute (optional) */
	/* si->unauth = NULL */
	return 0;
error:
	return -1;
}

int P7s_get_authatt(SignerInfo *sig,unsigned char *data,int len){
	AuthAtt *att;

	if((att=P7s_attr_cntType(OBJ_P7_DATA))==NULL) goto error;
	sig->auth=att;

	if((att->next=P7s_attr_signtime())==NULL) goto error;
	att=att->next;
	/* in this case just set one cryptograph */
	/* it should be listed .... */
	if((att->next=P7s_attr_smimecap(default_p7env_cry_algo,default_p7env_passwd_len))==NULL)
		goto error;
	att=att->next;

	if((att->next=P7s_attr_digest(sig,data,len))==NULL) goto error;

	return 0;
error:
	P7_authatt_free(sig->auth);
	sig->auth=NULL;
	return -1;
}

int P7s_get_signature(SignerInfo *sig,Key *key,unsigned char *data,int len){
	unsigned char *digest=NULL;
	int	i,err=-1;

	sig->sig_size = key->size;
	if((sig->enc_algo=get_enc_algo(key))<0) goto done;

	if(sig->auth){
		if((digest=P7s_get_attdigest(sig,data,len,&i))==NULL) goto done;
	}else{
		if((digest=OK_do_digest(sig->digest_algo,data,len,NULL,&i))==NULL) goto done;
	}

	switch(key->key_type){
	case KEY_RSA_PRV:
		if((sig->signature=P1_sign_digest(key,digest,i,sig->digest_algo))==NULL)
			goto done;
		break;
	case KEY_DSA_PRV:
		if((sig->signature=DSA_get_signature((Prvkey_DSA*)key,digest,i,&sig->sig_size))==NULL)
			goto done;
		break;
	case KEY_ECDSA_PRV:
		if((sig->signature=ECDSA_get_signature((Prvkey_ECDSA*)key,digest,i,&sig->sig_size))==NULL)
			goto done;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS7,ERR_PT_P7SIGN+2,NULL);
		break;
	}
	err=0;
done:
	if(digest) FREE(digest);
	return err;
}

/*------------------------------------------------------------*/

int get_enc_algo(Key *key){
	switch(key->key_type){
	case KEY_RSA_PUB:
	case KEY_RSA_PRV:
	case OBJ_CRYPT_RSA:
		return OBJ_CRYPT_RSA;
	case KEY_DSA_PUB:
	case KEY_DSA_PRV:
	case OBJ_CRYPT_DSA:
		return OBJ_CRYPT_DSA;
	case KEY_ECDSA_PUB:
	case KEY_ECDSA_PRV:
	case OBJ_CRYPT_ECDSA:
		return OBJ_CRYPT_ECDSA;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS7,ERR_PT_P7SIGN+3,NULL);
		return -1;
	}
}

int get_usercert_and_key(PKCS7 *p7, Cert **ucert, Key **ukey){
	P12_CertBag *cb;
	P12_KeyBag *kb;
	unsigned char c;

	*ucert=NULL;
	*ukey=NULL;

	if(P12_check_chain((PKCS12*)p7,0)) goto error;

	c = (unsigned char)P12_max_depth((PKCS12*)p7,OBJ_P12v1Bag_CERT);

	if((cb=(P12_CertBag*)P12_find_bag((PKCS12*)p7,OBJ_P12v1Bag_CERT,c))==NULL){
		OK_set_error(ERR_ST_P12_NOCERT,ERR_LC_PKCS7,ERR_PT_P7SIGN+4,NULL);
		goto error;
	}
	*ucert=cb->cert;

	if((kb=(P12_KeyBag*)P12_find_bag((PKCS12*)p7,OBJ_P12v1Bag_PKCS8,c))==NULL){
		OK_set_error(ERR_ST_P12_NOKEY,ERR_LC_PKCS7,ERR_PT_P7SIGN+4,NULL);
		goto error;
	}
	*ukey=kb->key;
	return 0;
error:
	return -1;
}

/*-----------------------------------------------------------
  verify PKCS#7 Signed-DATA
  return 0...ok, -1...failed
-----------------------------------------------------------*/
int P7s_verify_signed(PKCS7 *p7, unsigned char *data, int len){
	unsigned char *decry,*digest,*org,*msgdst;
	SignerInfo	*sig;
	Cert *cert;
	Key *key;
	int i,err=-1;

	decry=org=digest=msgdst=NULL;

	if((sig=((P7_Signed*)p7->cont)->signer)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_P7SIGN+5,NULL);
		goto done;
	}

	/* get user certificate */
	if((cert=P12_get_usercert((PKCS12*)p7))==NULL){
		OK_set_error(ERR_ST_P12_NOCERT,ERR_LC_PKCS7,ERR_PT_P7SIGN+5,NULL);
		goto done;
	}

	/* get user public key */
	key=cert->pubkey;
	if(key==NULL){
		OK_set_error(ERR_ST_NULLKEY,ERR_LC_PKCS7,ERR_PT_P7SIGN+5,NULL);
		goto done;
	}

	if(data==NULL){
		data = ((P7_Signed*)p7->cont)->content;
		len  = ((P7_Signed*)p7->cont)->cnt_size;
	}

	/* get original signature --- if algorithm is RSA */
	if(key->key_type == KEY_RSA_PUB){
		if((decry=OK_do_sign(key,sig->signature,sig->sig_size,NULL))==NULL)
			goto done;

		/* PKCS#1 Signature Check
		 * check padding and OBJECT IDENTIFIER */
		if((org=P1_pad2digest(decry,&i))==NULL) goto done;

		if(i != sig->digest_algo){
			OK_set_error(ERR_ST_UNMATCHEDPARAM,ERR_LC_PKCS7,ERR_PT_P7SIGN+5,NULL);
			goto done;
		}
	}

	/* get message digest with current message */
	if(sig->auth){
		/* AuthenticatedAttributes are attatched !!*/
		/* check contentInfo digest first. then check
		 * "message digest"
		 */
		if((msgdst=P7s_get_messagedigest_attr(sig))==NULL)
			goto done;

		if((digest=OK_do_digest(sig->digest_algo,data,len,NULL,&i))==NULL)
			goto done;

		if(err=memcmp(digest,msgdst,i)) goto done;
		FREE(digest); digest=NULL;

		if((digest=P7s_get_attdigest(sig,data,len,&i))==NULL)
			goto done;

	}else{
		/* just check contentInfo digest. */
		if((digest=OK_do_digest(sig->digest_algo,data,len,NULL,&i))==NULL)
			goto done;
	}

	/* verify signature */
	switch(key->key_type){
	case KEY_RSA_PUB:
		err = memcmp(digest,org,i);
		break;

	case KEY_DSA_PUB:
		err = DSA_vfy_signature((Pubkey_DSA*)key,digest,i,sig->signature);
		break;

	case KEY_ECDSA_PUB:
		err = ECDSA_vfy_signature((Pubkey_ECDSA*)key,digest,i,sig->signature);
		break;
	}

done:
	if(org) FREE(org);
	if(decry) FREE(decry);
	if(msgdst) FREE(msgdst);
	if(digest) FREE(digest);
	return err;
}

unsigned char *P7s_get_messagedigest_attr(SignerInfo *sig){
	unsigned char *cp,*ret;
	AuthAtt		*au;
	int i,j;

	ret=NULL;
	for(au=sig->auth;au!=NULL;au=au->next){
		cp = ASN1_next(au->der);
		if(ASN1_object_2int(cp)==OBJ_P9_MESS_DGST){
			cp = ASN1_step(cp,2);
			ASN1_octetstring(cp,&j,&ret,&i); /* if error, ret must be NULL */
			break;
		}
	}
	return ret;
}

unsigned char *P7s_get_attdigest(SignerInfo *sig, unsigned char *data, int len, int *ret_len){
	unsigned char tmp[16],*ret=NULL;
	AuthAtt		*au;
	MD5_CTX		mctx;
	SHA1_CTX	sctx;
	int i,j,algo;

	/* count length of authenticatedAttributes */
	for(i=0,au=sig->auth;au!=NULL;au=au->next)
		i+=au->der_size;

	tmp[0]=ASN1_SET|0x20;
	ASN1_set_length(i,&tmp[1],&j);
	j+=1;	/* header length */

	switch(sig->digest_algo){
	case OBJ_HASH_SHA1:
	case OBJ_SIG_SHA1RSA:
	case OBJ_SIG_SHA1DSA:
	case OBJ_SIG_SHA1ECDSA:
	case OBJ_SIGOIW_SHA1RSA:
		*ret_len = 20; /* byte */
		algo = OBJ_HASH_SHA1;
		SHA1init(&sctx);
		SHA1update(&sctx,tmp,j);
		break;
	case OBJ_HASH_MD5:
	case OBJ_SIG_MD5RSA:
	case OBJ_SIGOIW_MD5RSA:
		*ret_len = 16; /* byte */
		algo = OBJ_HASH_MD5;
		MD5Init(&mctx);
		MD5Update(&mctx,tmp,j);
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS7,ERR_PT_P7SIGN+6,NULL);
		goto error;
	}

	for(au=sig->auth;au!=NULL;au=au->next){
		switch(algo){
		case OBJ_HASH_SHA1: SHA1update(&sctx,au->der,au->der_size);break;
		case OBJ_HASH_MD5:  MD5Update(&mctx,au->der,au->der_size);break;
		}
	}

	if((ret=(unsigned char*)MALLOC(*ret_len))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7SIGN+6,NULL);
		goto error;
	}
	switch(algo){
	case OBJ_HASH_SHA1: SHA1final(ret,&sctx);break;
	case OBJ_HASH_MD5:  MD5Final(ret,&mctx);break;
	}
	return ret;
error:
	if(ret) FREE(ret);
	return NULL;
}
