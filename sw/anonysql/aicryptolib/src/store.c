/* store.c */
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
#include "ok_store.h"

/*-----------------------------------------------
   Alloc & Free Certificate Store
-----------------------------------------------*/
CStore *CStore_new(){
	CStore *ret;

	if((ret=(CStore*)MALLOC(sizeof(CStore)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_STORE,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CStore));
	return ret;
}

void CStore_free(CStore *cs){
	if(cs==NULL) return;

	CSBag_free_all(cs,cs->bags);
	if(cs->name) FREE(cs->name);
	if(cs->dev_info_free) cs->dev_info_free(cs->dev_info);
	FREE(cs);
}

void CStore_free_all(CStore *top){
	CStore *next;
	while(top){
		next = top->next;
		CStore_free(top);
		top = next;
	}
}

/*-----------------------------------------------
   Open & Close Certificate Store
-----------------------------------------------*/
CStore *CStore_open(int dev_type, char *name, int ctx_type, char *path){
	CStore *ret;
	int mode=0;

	switch(dev_type){
	case CSTORE_ON_STORAGE:
		mode = (ctx_type==CSTORE_CTX_KEY)?(CSMODE_NULL):(CSMODE_CACHE);
		if((ret=CStore_open_file(path,name,ctx_type,mode))==NULL) goto error;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_STORE,ERR_PT_STORE+1,NULL);
		break;
	}
	return ret;
error:
	return NULL;
}

/*
 * reload store data
 */
int CStore_reload(CStore *cs){
	int ret = -1;

	switch(cs->dev_type){
	case CSTORE_ON_STORAGE:
		ret = cstore_reload_file(cs); break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_STORE,ERR_PT_STORE+2,NULL);
		break;
	}
	return ret;
}

/*
 * update strage image sync with cache memory.
 */
int CStore_update(CStore *cs){
	int ret = -1;

	switch(cs->dev_type){
	case CSTORE_ON_STORAGE:
		ret = cstore_save_file(cs); break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_STORE,ERR_PT_STORE+3,NULL);
		break;
	}
	return ret;
}

void CStore_close(CStore *cs){
	switch(cs->dev_type){
	case CSTORE_ON_STORAGE: CStore_close_file(cs); break;
	}
	CStore_free(cs);
}

/*-----------------------------------------
  alloc & FREE store bag
-----------------------------------------*/
CSBag* CSBag_new(){
	CSBag *ret=NULL;

	if((ret=(CSBag*)MALLOC(sizeof(CSBag)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STORE,ERR_PT_STORE+4,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CSBag));
	return ret;
}

void CSBag_free(CStore *cs,CSBag *bg){
	if(bg==NULL) return;
	if(bg->unique_id) FREE(bg->unique_id);
	if(bg->issuer) FREE(bg->issuer);
	if(bg->subject) FREE(bg->subject);
	if(bg->der) FREE(bg->der);
	if(bg->dev_info){
		if(cs) cs->dev_info_free(bg->dev_info);
	}
	if(bg->cache){
		switch(bg->ctx_type){
		case CSTORE_CTX_CERT: Cert_free(bg->cache); break;
		case CSTORE_CTX_CSR: Req_free(bg->cache); break;
		case CSTORE_CTX_KEY: Key_free(bg->cache); break;
		case CSTORE_CTX_CRL: CRL_free(bg->cache); break;
		case CSTORE_CTX_DER:
		case CSTORE_CTX_ENCDER: FREE(bg->cache); break;
		}
	}
	FREE(bg);
}

void CSBag_free_all(CStore *cs,CSBag *top){
	CSBag *next;
	while(top){
		next = top->next;
		CSBag_free(cs,top);
		top = next;
	}
}

