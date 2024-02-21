/* sto_tool.c */
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

#include "ok_err.h"
#include "ok_sha1.h"
#include "ok_asn1.h"
#include "ok_store.h"


/*-----------------------------------------
  add a bag to the store
-----------------------------------------*/
int CStore_add_bag(CStore *cs, void *ct, char *unique_id, int stat, int ctx){
	CSBag *bg;

	if(cs->ctx_type != ctx){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STADD,NULL);
		return -1;
	}
	if(CStore_find_byID(CStore_get_firstBag(cs),unique_id)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STADD,NULL);
		goto error;
	}
	if(cs->data2bag==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD,NULL);
		goto error;
	}
	if((bg=cs->data2bag(cs,ct,unique_id,stat))==NULL) goto error;
	cs->csf_stat.st_mtime = -1; /* set update flag */

	bg->next = cs->bags;
	cs->bags = bg;
	if(bg->next) bg->next->prev = bg;
	
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  certificate to store bag
-----------------------------------------*/
CSBag *CS_cert2bag(CStore *cs, Cert *ct, char *unique_id, int stat){
	CSBag *ret;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD+1,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	/* set DER */
	if((ret->der=ASN1_dup(ct->der))==NULL) goto error;
	/* set cache */
	if(cs->mode & CSMODE_CACHE)
		if((ret->cache=Cert_dup(ct))==NULL) goto error;

	/* set other context */
	ret->ctx_type     = CSTORE_CTX_CERT;
	ret->status       = stat;
	ret->serialNumber = ct->serialNumber;

	if(cs_get_keyhash(ct->pubkey,ret->key_hash,&ret->hlen)) goto error;

	if((STRDUP(ret->issuer,ct->issuer))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+1,NULL);
		goto error;
	}
	if((STRDUP(ret->subject,ct->subject))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+1,NULL);
		goto error;
	}
	if((STRDUP(ret->unique_id,unique_id))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+1,NULL);
		goto error;
	}
	return ret;
error:
	CSBag_free(cs,ret);
	return NULL;
}

/*-----------------------------------------
  CRL to store bag
-----------------------------------------*/
CSBag *CS_crl2bag(CStore *cs, CRL *crl, char *unique_id, int stat){
	CSBag *ret;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD+3,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	/* set DER */
	if((ret->der=ASN1_dup(crl->der))==NULL) goto error;
	/* set cache */
	if(cs->mode & CSMODE_CACHE)
		if((ret->cache=CRL_dup(crl))==NULL) goto error;

	/* set other context */
	ret->ctx_type = CSTORE_CTX_CRL;
	ret->status   = stat;

	if((STRDUP(ret->issuer,crl->issuer))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+3,NULL);
		goto error;
	}
	if((STRDUP(ret->unique_id,unique_id))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+3,NULL);
		goto error;
	}
	return ret;
error:
	CSBag_free(cs,ret);
	return NULL;
}

/*-----------------------------------------
  Req to store bag
-----------------------------------------*/
CSBag *CS_req2bag(CStore *cs, Req *req, char *unique_id, int stat){
	CSBag *ret;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD+4,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	/* set DER */
	if((ret->der=ASN1_dup(req->der))==NULL) goto error;
	/* set cache */
	if(cs->mode & CSMODE_CACHE)
		if((ret->cache=Req_dup(req))==NULL) goto error;

	/* set other context */
	ret->ctx_type = CSTORE_CTX_CSR;
	ret->status   = stat;

	if(cs_get_keyhash(req->pubkey,ret->key_hash,&ret->hlen)) goto error;

	if((STRDUP(ret->subject,req->subject))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+4,NULL);
		goto error;
	}
	if((STRDUP(ret->unique_id,unique_id))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+4,NULL);
		goto error;
	}
	return ret;
error:
	CSBag_free(cs,ret);
	return NULL;
}

/*-----------------------------------------
  Key to store bag
-----------------------------------------*/
CSBag *CS_key2bag(CStore *cs, Key *key, char *unique_id, int stat){
	CSBag *ret;
	int i;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD+5,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	/* set DER */
	if((ret->der=P8_encrypted_toDER(key,OBJ_P12Pbe_3K3DES,NULL,&i))==NULL) goto error;

	/* set cache */
	if(cs->mode & CSMODE_CACHE)
		if((ret->cache=Key_dup(key))==NULL) goto error;

	/* set other context */
	ret->ctx_type = CSTORE_CTX_KEY;
	ret->status   = stat;

	if(cs_get_keyhash(key,ret->key_hash,&ret->hlen)) goto error;

	if((STRDUP(ret->unique_id,unique_id))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+5,NULL);
		goto error;
	}
	return ret;
error:
	CSBag_free(cs,ret);
	return NULL;
}

int cs_get_keyhash(Key *key,unsigned char *ret,int *ret_len){
	Pubkey_RSA *tmp;
	unsigned char *buf=NULL;
	int	j,err=-1;

	switch(key->key_type){
	case KEY_RSA_PRV:
		if((tmp=RSApubkey_new())==NULL) goto done;
		RSAprv_2pub((Prvkey_RSA*)key,tmp);
		if((buf=RSApub_toDER((Pubkey_RSA*)tmp,NULL,&j))==NULL) goto done;
		Key_free((Key*)tmp);
		break;
	case KEY_RSA_PUB:
		if((buf=RSApub_toDER((Pubkey_RSA*)key,NULL,&j))==NULL) goto done;
		break;

	case KEY_DSA_PRV:
		if((buf=MALLOC(((Prvkey_DSA*)key)->size+8))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_STADD+6,NULL);
			goto done;
		}
		if(ASN1_LNm2int(((Prvkey_DSA*)key)->w,buf,&j)) goto done;
		break;
	case KEY_DSA_PUB:
		if((buf=MALLOC(((Pubkey_DSA*)key)->size+8))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_STADD+6,NULL);
			goto done;
		}
		if(ASN1_LNm2int(((Pubkey_DSA*)key)->w,buf,&j)) goto done;
		break;

	case KEY_ECDSA_PRV:
		if((buf=ECp_P2OS(((Prvkey_ECDSA*)key)->W,4,&j))==NULL) return -1;
		break;
	case KEY_ECDSA_PUB:
		if((buf=ECp_P2OS(((Pubkey_ECDSA*)key)->W,4,&j))==NULL) return -1;
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_STORE,ERR_PT_STADD+6,NULL);
		goto done;
	}
	OK_SHA1(j,buf,ret);
	*ret_len = 20;

	err=0;
done:
	if(buf) FREE(buf);
	return err;
}

/*-----------------------------------------
  raw DER to store bag
-----------------------------------------*/
CSBag *CS_der2bag(CStore *cs, unsigned char *der, char *unique_id, int stat){
	CSBag *ret;
	int i;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD+7,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	/* set DER */
	if((ret->der=ASN1_dup(der))==NULL) goto error;

	/* set other context */
	ret->ctx_type     = CSTORE_CTX_DER;
	ret->status       = stat;

	/* set hash */
	ASN1_skip_(der,&i);
	OK_SHA1(i,der,ret->key_hash);
	ret->hlen = 20;

	/* set unique_id */
	if((STRDUP(ret->unique_id,unique_id))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+1,NULL);
		goto error;
	}
	return ret;
error:
	CSBag_free(cs,ret);
	return NULL;
}

/*-----------------------------------------
  encrypted DER to store bag
-----------------------------------------*/
CSBag *CS_encder2bag(CStore *cs, unsigned char *der, char *unique_id, int stat){
	unsigned char *tmp;
	CSBag *ret;
	int i;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STADD+7,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	/* set other context */
	ret->ctx_type     = CSTORE_CTX_ENCDER;
	ret->status       = stat;

	/* set hash (with non-encrypted data) */
	ASN1_skip_(der,&i);
	OK_SHA1(i,der,ret->key_hash);
	ret->hlen = 20;

	/* set DER (encrypted data) */
	if((ret->der=(unsigned char*)MALLOC(i+64))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_STADD+7,NULL);
		return NULL;
	}
	/* PKCS#8 function destroys "der" buffer
	 * so it is neccesary to allocate new memory
	 */
	if((tmp=(unsigned char*)MALLOC(i+16))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_STADD+7,NULL);
		return NULL;
	}
	memcpy(tmp,der,i);
	if(P8_encrypted_toDER_in(tmp,OBJ_P12Pbe_3K3DES,ret->der,&i)) goto error;
	FREE(tmp);

	/* set unique_id */
	if((STRDUP(ret->unique_id,unique_id))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_STADD+7,NULL);
		goto error;
	}
	return ret;
error:
	FREE(tmp);
	CSBag_free(cs,ret);
	return NULL;
}

