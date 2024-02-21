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
  get Cert, Key, ... from bags
-----------------------------------------*/
void *cstore_get_data(void *(*cb)(CSBag*), CSBag *bg, int ctx){
	if(bg->ctx_type != ctx){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STTOOL,NULL);
		goto error;
	}
	if(cb==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STORE,ERR_PT_STTOOL,NULL);
		goto error;
	}
	return cb(bg);
error:
	return NULL;
}

Cert *CStore_get_cert(CStore *cs, CSBag *bg){
	return cstore_get_data((void *(*)(CSBag*))cs->bag2data,bg,CSTORE_CTX_CERT);
}

CRL *CStore_get_crl(CStore *cs, CSBag *bg){
	return cstore_get_data((void *(*)(CSBag*))cs->bag2data,bg,CSTORE_CTX_CRL);
}

Req *CStore_get_req(CStore *cs, CSBag *bg){
	return cstore_get_data((void *(*)(CSBag*))cs->bag2data,bg,CSTORE_CTX_CSR);
}

Key *CStore_get_key(CStore *cs, CSBag *bg){
	return cstore_get_data((void *(*)(CSBag*))cs->bag2data,bg,CSTORE_CTX_KEY);
}

/*-----------------------------------------
  count bags
-----------------------------------------*/
int CStore_count_bag(CStore *cs){
	CSBag *bg;
	int ret=0;

	for(bg=cs->bags; bg ; bg=bg->next)
		ret++;
	return ret;
}

/*-----------------------------------------
  get unique ID by cert
-----------------------------------------*/
/* return buffer should be more than 64 byte */
int get_dn_for_unique_id(CertDN *dn, char *ret){
	int i,j,t[4]={OBJ_DIR_CN,OBJ_DIR_EMAIL,OBJ_DIR_OU,OBJ_DIR_O};
	char *tmp;

	for(i=0;i<4;i++){
		if(tmp = Cert_find_dn(dn,t[i],&j)){
			memset(ret,0,64);
			strncpy(ret,tmp,62);
			break;
		}
	}
	return 0;
}

char *CStore_get_unique_id(CStore *cs, CertDN *dn){
	static char buf[256];
	char tmp[128];
	int i,j=0;
		
	/* return should be smaller than 64 byte */
	if(get_dn_for_unique_id(dn,tmp))
		strcpy(tmp,"null");

	memset(buf,0,256);
	strncpy(buf,tmp,128);
		
	i = 0;
	while(CStore_find_byID(CStore_get_firstBag(cs),buf)){
		SNPRINTF (buf,128,"%s_%02d",tmp,i++);
	}
	return buf;
}

char *CStore_get_unique_idk(CStore *cs, Key *key){
	static char buf[256];
	char buf2[32];
	int i;

	switch(key->key_type){
	case KEY_RSA_PRV:   strcpy(buf2,"key-rsa"); break;
	case KEY_DSA_PRV:   strcpy(buf2,"key-dsa"); break;
	case KEY_ECDSA_PRV:   strcpy(buf2,"key-ecdsa"); break;
	}
		
	i = 0;
	do{
		SNPRINTF (buf,200,"%s_%02d",buf2,i++);
	}while(CStore_find_byID(CStore_get_firstBag(cs),buf));

	return buf;
}

/*-----------------------------------------
  store to certlist
-----------------------------------------*/
CertList* CStore_2certlist(CStore *cs){
	CertList *now,*hd,*ret=NULL;
	Cert *ct=NULL;
	CSBag *bg;

	if(cs->ctx_type != CSTORE_CTX_CERT){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STTOOL+3,NULL);
		goto error;
	}

	for(bg=cs->bags; bg ; bg=bg->next){
		if(bg->ctx_type == CSTORE_CTX_CERT){
			if(bg->cache){
				if((now=Cert_2Certlist((Cert*)bg->cache))==NULL) goto error;
			}else{
				if((ct=CStore_get_cert(cs,bg))==NULL) goto error;
				if((now=Cert_2Certlist(ct))==NULL) goto error;
				Cert_free(ct); ct=NULL;
			}
			/* incert to the end */
			if(ret==NULL){
				ret = hd = now;
			}else{
				hd->next  = now;
				now->prev = hd;
				hd = now;
			}
		}
	}
	return ret;
error:
	Cert_free(ct);
	Certlist_free(ret);
	return NULL;
}

/*-----------------------------------------
  store to crllist
-----------------------------------------*/
CRLList* CStore_2crllist(CStore *cs){
	CRLList *now,*hd,*ret=NULL;
	CRL *crl=NULL;
	CSBag *bg;

	if(cs->ctx_type != CSTORE_CTX_CRL){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STTOOL+4,NULL);
		goto error;
	}

	for(bg=cs->bags; bg ; bg=bg->next){
		if(bg->ctx_type == CSTORE_CTX_CRL){
			if(bg->cache){
				if((now=CRL_2CRLlist((CRL*)bg->cache))==NULL) goto error;
			}else{
				if((crl=CStore_get_crl(cs,bg))==NULL) goto error;
				if((now=CRL_2CRLlist((CRL*)crl))==NULL) goto error;
				CRL_free(crl); crl=NULL;
			}
			/* incert to the end */
			if(ret==NULL){
				ret = hd = now;
			}else{
				hd->next  = now;
				now->prev = hd;
				hd = now;
			}
		}
	}
	return ret;
error:
	CRL_free(crl);
	CRLlist_free(ret);
	return NULL;
}
