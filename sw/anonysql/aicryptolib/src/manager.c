/* manager.c */
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
   Alloc & Free Certificate Store Manager
-----------------------------------------------*/
STManager *STM_new(){
	STManager *ret;

	if((ret=(STManager*)MALLOC(sizeof(STManager)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_MANAGER,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(STManager));
	return ret;
}

void STM_free(STManager *stm){
	if(stm==NULL) return;

	CStore_free_all(stm->store);
	if(stm->path) FREE(stm->path);
	if(stm->der)  FREE(stm->der);
	FREE(stm);
}

/*-----------------------------------------------
   Store Manager : open & close stores
-----------------------------------------------*/
STManager *STM_open(char *path){
	STManager *ret=NULL;
	unsigned char *der=NULL;
	char buf[256];

	strncpy(buf,path,200);
	strncat(buf,PATH_DELI,8);
	strncat(buf,"ai00sto.sm0",32);
	if((der=ASN1_read_der(buf))==NULL) goto error;

	if((ret=ASN1_read_stm(der,path))==NULL) goto error;

	return ret;
error:
	if(ret){ STM_free(ret); der=NULL; }
	if(der){ FREE(der); }
	return NULL;
}

int STM_reload(STManager *stm){
	CStore *cs;

	for(cs=stm->store; cs ; cs=cs->next)
		if(CStore_reload(cs)) return -1;

	return 0;
}

int STM_update(STManager *stm){
	CStore *cs;

	if(stm_file_update(stm)) return -1;

	for(cs=stm->store; cs ; cs=cs->next)
		if(CStore_update(cs)) return -1;

	return 0;
}

void STM_close(STManager *stm){
	CStore *cs,*next;

	for(cs=stm->store; cs ; cs=next){
		next=cs->next;
		CStore_close(cs);
	}
	stm->store = NULL;
	STM_free(stm);
}

int stm_file_update(STManager *stm){
	unsigned char *der=NULL;
	char buf[256];
	int i;

	strncpy(buf,stm->path,200);
	strncat(buf,PATH_DELI,8);
	strncat(buf,"ai00sto.sm0",32);

	if((der=STM_toDER(stm,NULL,&i))==NULL) goto error;
	if(ASN1_write_der(der,buf)) goto error;

	if(stm->der) FREE(stm->der);
	stm->der = der;
	return 0;
error:
	if(der) FREE(der);
	return -1;
}

/*-----------------------------------------------
   Generate new system store
-----------------------------------------------*/
STManager *STM_system_new(char *path){
	STManager *ret;
	CStore *cs;
	char buf[256];

	strncpy(buf,path,200);
	strncat(buf,PATH_DELI,8);
	strncat(buf,"ai00sto.sm0",32);

	if((ret=STM_new())==NULL) goto error;
	if((STRDUP(ret->path,path))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STORE,ERR_PT_MANAGER+3,NULL);
		goto error;
	}

	/* get MY store */
	if((cs=CStore_new_file(path,STORE_MY,CSTORE_CTX_CERT,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;
	if((cs=CStore_new_file(path,STORE_MY,CSTORE_CTX_CSR,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;
	if((cs=CStore_new_file(path,STORE_MY,CSTORE_CTX_KEY,CSMODE_NULL))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;

	/* get OTHRE store */
	if((cs=CStore_new_file(path,STORE_OTHER,CSTORE_CTX_CERT,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;
	if((cs=CStore_new_file(path,STORE_OTHER,CSTORE_CTX_CRL,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;

	/* get MIDCA store */
	if((cs=CStore_new_file(path,STORE_MIDCA,CSTORE_CTX_CERT,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;
	if((cs=CStore_new_file(path,STORE_MIDCA,CSTORE_CTX_CRL,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;

	/* get ROOT store */
	if((cs=CStore_new_file(path,STORE_ROOT,CSTORE_CTX_CERT,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;
	if((cs=CStore_new_file(path,STORE_ROOT,CSTORE_CTX_CRL,CSMODE_CACHE))==NULL)
		goto error;
	if(STM_regist_store(ret, cs)) goto error;

	if(STM_update(ret)) goto error;

	return ret;
error:
	STM_free(ret);
	return NULL;
}
