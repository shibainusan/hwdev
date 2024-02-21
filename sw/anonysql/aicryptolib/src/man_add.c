/* man_add.c */
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
#include "ok_asn1.h"
#include "ok_store.h"

/*-----------------------------------------------
   Store Manager : regist store
-----------------------------------------------*/
int STM_regist_store(STManager *stm, CStore *reg){
	CStore *cs,*pv=NULL;

	for(cs=stm->store; cs ; cs=cs->next){
		if(!strcmp(cs->name,reg->name))
			if((cs->ctx_type==reg->ctx_type)&&(cs->dev_type==reg->dev_type))
				break;
		pv = cs;
	}
	if(cs){
		OK_set_error(ERR_ST_BADNAME,ERR_LC_STORE,ERR_PT_MANADD,NULL);
		return -1;
	}
	/* pv should be last item in the list */
	if(pv==NULL){
		stm->store = reg;
		reg->prev  = NULL;
	}else{
		pv->next   = reg;
		reg->prev  = pv;
	}
	return 0;
}

/*-----------------------------------------------
   Store Manager : import cert
-----------------------------------------------*/
/* return value is...
 * 1..rootCA, 2..MID-CA, 3..other, 4..MY, -1..error
 */
int STM_cert_type(STManager *stm, Cert *cert){
	CStore *cs;
	CSBag *bag=NULL;
	int ca,rt,i,ret=-1;
	unsigned char hash[32];

	/* this certificate doesn't have private key, so
	 * this should be "other", "middle-CA", or "root CA"
	 * check these information.
	 */
	ca = Cert_is_CA(cert);
	rt = Cert_is_root(cert);

	if(rt && (ca>=0)){ /* put into root store */
		ret = 1;
	}else if(ca > 0){
		ret = 2;
	}else{
		if(cs=STM_find_byName(stm,STORE_MY,CSTORE_ON_STORAGE,CSTORE_CTX_KEY)){
			if(CStore_find_bySubject(CStore_get_firstBag(cs),cert->subject)){
				if(cs_get_keyhash(cert->pubkey,hash,&i)==0){
					if(bag=CStore_find_byKeyHash(CStore_get_firstBag(cs),hash)){
						ret = 4;
		}}}}
		if(bag==NULL){
			ret = 3;
		}
	}
	return ret;
}

int STM_import_cert(STManager *stm, Cert *cert, char *unique_id){
	switch(STM_cert_type(stm,cert)){
	case 1:
		if(STM_import_cert_byName(stm,cert,CSTORE_ON_STORAGE,STORE_ROOT,unique_id)==NULL)
			goto error;
		break;
	case 2:
		if(STM_import_cert_byName(stm,cert,CSTORE_ON_STORAGE,STORE_MIDCA,unique_id)==NULL)
			goto error;
		break;
	case 3:
		if(STM_import_cert_byName(stm,cert,CSTORE_ON_STORAGE,STORE_OTHER,unique_id)==NULL)
			goto error;
		break;
	case 4:
		if(STM_import_cert_byName(stm,cert,CSTORE_ON_STORAGE,STORE_MY,unique_id)==NULL)
			goto error;
		break;
	default:
		goto error;
	}
	return 0;
error:
	return -1;
}

int STM_import_certkey(STManager *stm, Cert *cert, Key *key, char *unique_id){
	CSBag *cb,*kb;
	/* check key pair */
	if(Key_pair_cmp(key,cert->pubkey)){
		OK_set_error(ERR_ST_BADKEY,ERR_LC_STORE,ERR_PT_MANADD+1,NULL);
		goto error;
	}
	/* this should be "MY" store */
	if((cb=STM_import_cert_byName(stm,cert,CSTORE_ON_STORAGE,STORE_MY,unique_id))==NULL)
		goto error;

	if((kb=STM_import_key_byName(stm,key,CSTORE_ON_STORAGE,STORE_MY,unique_id))==NULL)
		goto error;

	if((STRDUP(kb->issuer,cb->issuer))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_MANADD+1,NULL);
		goto error;
	}
	if((STRDUP(kb->subject,cb->subject))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_MANADD+1,NULL);
		goto error;
	}
	kb->serialNumber = cb->serialNumber;

	return 0;
error:
	return -1;
}

int STM_import_reqkey(STManager *stm, Req *req, Key *key, char *unique_id){
	CSBag *cb,*kb;
	/* check key pair */
	if(Key_pair_cmp(key,req->pubkey)){
		OK_set_error(ERR_ST_BADKEY,ERR_LC_STORE,ERR_PT_MANADD+1,NULL);
		goto error;
	}
	/* this should be "MY" store */
	if((cb=STM_import_req_byName(stm,req,CSTORE_ON_STORAGE,STORE_MY,unique_id))==NULL)
		goto error;

	if((kb=STM_import_key_byName(stm,key,CSTORE_ON_STORAGE,STORE_MY,unique_id))==NULL)
		goto error;

	if((STRDUP(kb->subject,cb->subject))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_MANADD+2,NULL);
		goto error;
	}

	return 0;
error:
	return -1;
}

/* return value is...
 * 1..RootCA, 2..MID-CA, 3..Other, -1..error
 */
int STM_crl_type(STManager *stm, CRL *crl){
	CStore *cs;
	CSBag *bag=NULL;

	if(cs=STM_find_byName(stm,STORE_ROOT,CSTORE_ON_STORAGE,CSTORE_CTX_CERT)){
		if(CStore_find_bySbjDN(cs,CStore_get_firstBag(cs),&crl->issuer_dn)){
			return 1;
		}
	}
	if(cs=STM_find_byName(stm,STORE_MIDCA,CSTORE_ON_STORAGE,CSTORE_CTX_CERT)){
		if(CStore_find_bySbjDN(cs,CStore_get_firstBag(cs),&crl->issuer_dn)){
			return 2;
		}
	}
	if(cs=STM_find_byName(stm,STORE_OTHER,CSTORE_ON_STORAGE,CSTORE_CTX_CERT)){
		if(CStore_find_bySbjDN(cs,CStore_get_firstBag(cs),&crl->issuer_dn)){
			return 3;
		}
	}
	return -1;
}

int STM_import_crl(STManager *stm, CRL *crl, char *unique_id){
	switch(STM_crl_type(stm,crl)){
	case 1:
		if(STM_import_crl_byName(stm,crl,CSTORE_ON_STORAGE,STORE_ROOT,unique_id)==NULL)
			goto error;
		break;
	case 2:
		if(STM_import_crl_byName(stm,crl,CSTORE_ON_STORAGE,STORE_MIDCA,unique_id)==NULL)
			goto error;
		break;
	case 3:
		if(STM_import_crl_byName(stm,crl,CSTORE_ON_STORAGE,STORE_OTHER,unique_id)==NULL)
			goto error;
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_MANADD+3,NULL);
		goto error;
	}

	return 0;
error:
	return -1;
}

/*-----------------------------------------------
   import certficate & private key
-----------------------------------------------*/
CSBag* STM_import_cert_byName(STManager *stm, Cert *cert, int dev, char *name, char *unique_id){
	CStore *cs;
	CSBag *bag;
	int st = 0;

	if((cs=STM_find_byName(stm,name,dev,CSTORE_CTX_CERT))==NULL){
		OK_set_error(ERR_ST_STO_STORENOTFOUND,ERR_LC_STORE,ERR_PT_MANADD+5,NULL);
		goto error;
	}

	/* check unique_id */
	if(unique_id && (*unique_id)){
		if(CStore_find_byID(CStore_get_firstBag(cs),unique_id)){
			OK_set_error(ERR_ST_STO_BADID,ERR_LC_STORE,ERR_PT_MANADD+5,NULL);
			goto error;
		}
	}else{ /* get unique id */
		unique_id = CStore_get_unique_id(cs,&cert->subject_dn); /* return static char */
	}

	/* check a cert already exists or not */
	bag = CStore_find_byCert(CStore_get_firstBag(cs),cert);

	/* set certificate status */
	if(!strcmp(cs->name,STORE_MY)){
		st = AIST_OK|AIST_MY;
	}else if(!strcmp(cs->name,STORE_ROOT)){
		st = AIST_OK|AIST_CA|AIST_ROOT|AIST_TRUST;
	}else if(!strcmp(cs->name,STORE_MIDCA)){
		st = AIST_OK|AIST_CA|AIST_OTHER;
	}else if(!strcmp(cs->name,STORE_OTHER)){
		st = AIST_OK|AIST_OTHER;
	}

	/* add certificate */
	if(CStore_add_bag(cs,cert,unique_id,st,CSTORE_CTX_CERT))
		goto error;

	/* if same certificate exists, replace it */
	if(bag){
		if(CStore_del_bag(cs,bag)) goto error;
	}

	return CStore_find_byID(CStore_get_firstBag(cs),unique_id);
error:
	return NULL;
}

CSBag* STM_import_key_byName(STManager *stm, Key *key, int dev, char *name, char *unique_id){
	unsigned char hash[32];
	int i;
	CStore *cs;
	CSBag *bag;

	if((cs=STM_find_byName(stm,name,dev,CSTORE_CTX_KEY))==NULL){
		OK_set_error(ERR_ST_STO_STORENOTFOUND,ERR_LC_STORE,ERR_PT_MANADD+6,NULL);
		goto error;
	}

	/* check unique_id */
	if(unique_id && (*unique_id)){
		if(CStore_find_byID(CStore_get_firstBag(cs),unique_id)){
			OK_set_error(ERR_ST_STO_BADID,ERR_LC_STORE,ERR_PT_MANADD+6,NULL);
			goto error;
		}
	}else{ /* get unique id */
		unique_id = CStore_get_unique_idk(cs, key);
	}

	/* check a same private key already exists or not */
	if(cs_get_keyhash(key,hash,&i)) goto error;
	bag = CStore_find_byKeyHash(CStore_get_firstBag(cs),hash);

	/* add private key */
	if(CStore_add_bag(cs,key,unique_id,AIST_OK,CSTORE_CTX_KEY))
		goto error;

	/* if same private key exists, replace it */
	if(bag){
		if(CStore_del_bag(cs,bag)) goto error;
	}

	return CStore_find_byID(CStore_get_firstBag(cs),unique_id);
error:
	return NULL;
}

CSBag* STM_import_crl_byName(STManager *stm, CRL *crl, int dev, char *name, char *unique_id){
	CStore *cs;
	CSBag *bag;

	if((cs=STM_find_byName(stm,name,dev,CSTORE_CTX_CRL))==NULL){
		OK_set_error(ERR_ST_STO_STORENOTFOUND,ERR_LC_STORE,ERR_PT_MANADD+7,NULL);
		goto error;
	}

	/* check unique_id */
	if(unique_id && (*unique_id)){
		if(CStore_find_byID(CStore_get_firstBag(cs),unique_id)){
			OK_set_error(ERR_ST_STO_BADID,ERR_LC_STORE,ERR_PT_MANADD+7,NULL);
			goto error;
		}
	}else{ /* get unique id */
		unique_id = CStore_get_unique_id(cs,&crl->issuer_dn); /* return static char */
	}

	/* check a CRL already exists or not */
	bag = CStore_find_byCRL(CStore_get_firstBag(cs),crl);

	/* add crl */
	if(CStore_add_bag(cs,crl,unique_id,AIST_OK,CSTORE_CTX_CRL))
		goto error;

	/* if same CRL exists, replace it */
	if(bag){
		if(CStore_del_bag(cs,bag)) goto error;
	}

	return CStore_find_byID(CStore_get_firstBag(cs),unique_id);
error:
	return NULL;
}

CSBag* STM_import_req_byName(STManager *stm, Req *req, int dev, char *name, char *unique_id){
	CStore *cs;
	CSBag *bag;

	if((cs=STM_find_byName(stm,name,dev,CSTORE_CTX_CSR))==NULL){
		OK_set_error(ERR_ST_STO_STORENOTFOUND,ERR_LC_STORE,ERR_PT_MANADD+8,NULL);
		goto error;
	}

	/* check unique_id */
	if(unique_id && (*unique_id)){
		if(CStore_find_byID(CStore_get_firstBag(cs),unique_id)){
			OK_set_error(ERR_ST_STO_BADID,ERR_LC_STORE,ERR_PT_MANADD+8,NULL);
			goto error;
		}
	}else{ /* get unique id */
		unique_id = CStore_get_unique_id(cs,&req->subject_dn); /* return static char */
	}

	/* check a Reqest already exists or not */
	bag = CStore_find_byReq(CStore_get_firstBag(cs),req);

	/* add a request */
	if(CStore_add_bag(cs,req,unique_id,AIST_OK,CSTORE_CTX_CSR))
		goto error;

	/* if same certificate exists, replace it */
	if(bag){
		if(CStore_del_bag(cs,bag)) goto error;
	}

	return CStore_find_byID(CStore_get_firstBag(cs),unique_id);
error:
	return NULL;
}
