/* pkcs7.c */
/* this is PKCS#7 functions */
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
#include "ok_pkcs.h"

/*-----------------------------------------------
	Get New PKCS#7 Structure
-----------------------------------------------*/
PKCS7 *P7_new(int type){
	PKCS7 *ret=NULL;

	if((ret = (PKCS7*)MALLOC(sizeof(PKCS7)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7,NULL);
		goto error;
	}

	memset(ret,0,sizeof(PKCS7));
	if((ret->cont=P7_cont_new(type))==NULL) goto error;

	return ret;
error:
	P7_free(ret);
	return NULL;
}

P7_Content *P7_cont_new(int type){
	P7_Content *ret;
	switch(type){
	case OBJ_P7_SIGNED:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Signed)))==NULL) goto error;
		memset(ret,0,sizeof(P7_Signed));
		if((((P7_Signed*)ret)->signer=P7_signer_new())==NULL) goto error;
		break;
	case OBJ_P7_ENVELP:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Envelope)))==NULL) goto error;
		memset(ret,0,sizeof(P7_Envelope));
		if((((P7_Envelope*)ret)->recipi=P7_recip_new())==NULL) goto error;
		if((((P7_Envelope*)ret)->encCnt=P7_enccont_new())==NULL) goto error;
		break;
	case OBJ_P7_SIGandENV:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_SignEnv)))==NULL) goto error;
		memset(ret,0,sizeof(P7_SignEnv));
		if((((P7_SignEnv*)ret)->recipi=P7_recip_new())==NULL) goto error;
		if((((P7_SignEnv*)ret)->encCnt=P7_enccont_new())==NULL) goto error;
		if((((P7_SignEnv*)ret)->signer=P7_signer_new())==NULL) goto error;
		break;
	case OBJ_P7_DIGESTED:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Digest)))==NULL) goto error;
		memset(ret,0,sizeof(P7_Digest));
		break;
	case OBJ_P7_ENCRYPTED:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Encrypted)))==NULL) goto error;
		memset(ret,0,sizeof(P7_Encrypted));
		if((((P7_Encrypted*)ret)->encCnt=P7_enccont_new())==NULL) goto error;
		break;
	case OBJ_P7_DATA:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Content)))==NULL) goto error;
		memset(ret,0,sizeof(P7_Content));
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_PKCS7,ERR_PT_PKCS7+1,NULL);
		return NULL;
	}
	ret->p7type = type;
	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+1,NULL);
	P7_cont_free(ret);
	return NULL;
}

SignerInfo *P7_signer_new(){
	SignerInfo *ret;

	if((ret=(SignerInfo*)MALLOC(sizeof(SignerInfo)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+2,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(SignerInfo));
	return ret;
}

AuthAtt *P7_authatt_new(){
	AuthAtt *ret;
	if((ret=(AuthAtt*)MALLOC(sizeof(AuthAtt)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+3,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(AuthAtt));
	return ret;
}

RecipInfo *P7_recip_new(){
	RecipInfo *ret;
	if((ret=(RecipInfo*)MALLOC(sizeof(RecipInfo)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+4,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(RecipInfo));
	return ret;
}

EncCntInfo *P7_enccont_new(){
	EncCntInfo *ret;
	if((ret=(EncCntInfo*)MALLOC(sizeof(EncCntInfo)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+5,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(EncCntInfo));
	return(ret);
}

/*-----------------------------------------------
	Free PKCS#7 Structure
-----------------------------------------------*/
void P7_free(PKCS7 *p7){
	if(p7==NULL) return;

	P7_cont_free(p7->cont);
	if(p7->der) FREE(p7->der);
	if(p7->bag)	P12_free((PKCS12*)p7);
	else FREE(p7);
}

void P7_cont_free(P7_Content *cont){
	if(cont==NULL) return;

	switch(cont->p7type){
	case OBJ_P7_SIGNED:
		P7_signer_free(((P7_Signed*)cont)->signer);
		if(((P7_Signed*)cont)->content) FREE(((P7_Signed*)cont)->content);
		break;
	case OBJ_P7_ENVELP:
		P7_recip_free(((P7_Envelope*)cont)->recipi);
		P7_enccont_free(((P7_Envelope*)cont)->encCnt);
		break;
	case OBJ_P7_SIGandENV:
		P7_signer_free(((P7_SignEnv*)cont)->signer);
		P7_recip_free(((P7_SignEnv*)cont)->recipi);
		P7_enccont_free(((P7_SignEnv*)cont)->encCnt);
		break;
	case OBJ_P7_DIGESTED:
		if(((P7_Digest*)cont)->digest) FREE(((P7_Digest*)cont)->digest);
		break;
	case OBJ_P7_ENCRYPTED:
		P7_enccont_free(((P7_Encrypted*)cont)->encCnt);
		break;
	case OBJ_P7_DATA:
		if(cont->data) FREE(cont->data);
		break;
	}
	FREE(cont);
}

void P7_signer_free(SignerInfo *sig){
	SignerInfo *tmp;
	while(sig){
		cert_dn_free(&(sig->iss_dn));
		if(sig->iss_str) FREE(sig->iss_str);
		if(sig->signature) FREE(sig->signature);
		if(sig->auth) P7_authatt_free(sig->auth);
		if(sig->unauth) P7_authatt_free(sig->unauth);

		tmp=sig->next;
		FREE(sig);
		sig=tmp;
	}
}

void P7_authatt_free(AuthAtt *att){
	AuthAtt *tmp;
	while(att){
		if(att->der) FREE(att->der);
		tmp=att->next;
		FREE(att);
		att=tmp;
	}
}

void P7_recip_free(RecipInfo *rci){
	RecipInfo *tmp;
	while(rci){
		cert_dn_free(&(rci->iss_dn));
		if(rci->iss_str) FREE(rci->iss_str);
		if(rci->key) FREE(rci->key);
		tmp=rci->next;
		FREE(rci);
		rci=tmp;
	}
}

void P7_enccont_free(EncCntInfo *eci){
	if(eci==NULL) return;
	if(eci->iv) FREE(eci->iv);
	if(eci->data) FREE(eci->data);
	FREE(eci);
}

/*-----------------------------------------------
	Duplicate PKCS#7 Structure
-----------------------------------------------*/
PKCS7 *P7_dup(PKCS7 *org){
	PKCS7 *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_PKCS7+6,NULL);
		return NULL;
	}
	if((ret = (PKCS7*)MALLOC(sizeof(PKCS7)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+6,NULL);
		goto error;
	}

	memset(ret,0,sizeof(PKCS7));
	ret->version = org->version;

	if((ret->cont=P7_cont_dup(org->cont))==NULL) goto error;
	if(org->der){
		if((ret->der=ASN1_dup(org->der))==NULL) goto error;
	}
	if(P12_copy_p12bags((PKCS12*)ret,(PKCS12*)org)) goto error;

	return ret;
error:
	P7_free(ret);
	return NULL;
}

/* internal function of P7_dup */
P7_Content *P7_cont_dup(P7_Content *org){
	P7_Content *ret=NULL;

	if(org==NULL) return NULL;
	switch(org->p7type){
	case OBJ_P7_SIGNED:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Signed)))==NULL) goto error;
		memcpy(ret,org,sizeof(P7_Signed));
		if(((P7_Signed*)org)->content){
			if((((P7_Signed*)ret)->content = (unsigned char*)MALLOC(((P7_Signed*)org)->cnt_size))==NULL) goto error;
			memcpy(((P7_Signed*)ret)->content,((P7_Signed*)org)->content,((P7_Signed*)ret)->cnt_size);
		}
		if((((P7_Signed*)ret)->signer = P7_signer_dup(((P7_Signed*)org)->signer))==NULL) goto error;
		break;

	case OBJ_P7_ENVELP:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Envelope)))==NULL) goto error;
		memcpy(ret,org,sizeof(P7_Envelope));
		if((((P7_Envelope*)ret)->recipi = P7_recip_dup(((P7_Envelope*)org)->recipi))==NULL) goto error;
		if((((P7_Envelope*)ret)->encCnt = P7_enccont_dup(((P7_Envelope*)org)->encCnt))==NULL) goto error;
		break;

	case OBJ_P7_SIGandENV:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_SignEnv)))==NULL) goto error;
		memcpy(ret,org,sizeof(P7_SignEnv));
		if((((P7_SignEnv*)ret)->recipi = P7_recip_dup(((P7_SignEnv*)org)->recipi))==NULL) goto error;
		if((((P7_SignEnv*)ret)->encCnt = P7_enccont_dup(((P7_SignEnv*)org)->encCnt))==NULL) goto error;
		if((((P7_SignEnv*)ret)->signer = P7_signer_dup(((P7_SignEnv*)org)->signer))==NULL) goto error;
		break;

	case OBJ_P7_DIGESTED:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Digest)))==NULL) goto error;
		memcpy(ret,org,sizeof(P7_Digest));
		if(((P7_Digest*)org)->digest){
			if((((P7_Digest*)ret)->digest = (unsigned char*)MALLOC(((P7_Digest*)ret)->size))==NULL) goto error;
			memcpy(((P7_Digest*)ret)->digest,((P7_Digest*)org)->digest,((P7_Digest*)ret)->size);
		}
		break;
	case OBJ_P7_ENCRYPTED:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Encrypted)))==NULL) goto error;
		memcpy(ret,org,sizeof(P7_Encrypted));
		if((((P7_Encrypted*)ret)->encCnt = P7_enccont_dup(((P7_Encrypted*)ret)->encCnt))==NULL) goto error;
		break;
	case OBJ_P7_DATA:
		if((ret=(P7_Content*)MALLOC(sizeof(P7_Content)))==NULL) goto error;
		memcpy(ret,org,sizeof(P7_Content));
		if(((P7_Content*)org)->data){
			if((((P7_Content*)ret)->data = (unsigned char*)MALLOC(((P7_Content*)ret)->size))==NULL) goto error;
			memcpy(((P7_Content*)ret)->data,((P7_Content*)org)->data,((P7_Content*)ret)->size);
		}
		break;
	}
	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+7,NULL);
	P7_cont_free(ret);
	return NULL;
}

SignerInfo *P7_signer_dup(SignerInfo *org){
	SignerInfo *ret,*si;

	if(org==NULL) return NULL;
	ret=NULL;
	do{
		if(ret==NULL){
			if((ret=si=P7_signer_new())==NULL) goto error;
		}else{
			if((si->next=P7_signer_new())==NULL) goto error;
			si = si->next;
		}
		memcpy(si,org,sizeof(SignerInfo));

		if(org->iss_str){
			if((STRDUP(si->iss_str,org->iss_str))==NULL) goto error;
		}
		if(org->signature){
			if((si->signature = (unsigned char*)MALLOC(org->sig_size))==NULL) goto error;
			memcpy(si->signature,org->signature,org->sig_size);
		}
		if(Cert_dncopy(&org->iss_dn,&si->iss_dn)) goto error;
		if(org->auth){
			if((si->auth = P7_authatt_dup(org->auth))==NULL) goto error;
		}
		if(org->unauth){
			if((si->unauth = P7_authatt_dup(org->unauth))==NULL) goto error;
		}

		org=org->next;
	}while(org);

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+8,NULL);
	P7_signer_free(ret);
	return NULL;
}

AuthAtt *P7_authatt_dup(AuthAtt *org){
	AuthAtt *ret,*aa;

	if(org==NULL) return NULL;
	ret=NULL;
	do{
		if(ret==NULL){
			if((ret=aa=P7_authatt_new())==NULL) goto error;
		}else{
			if((aa->next=P7_authatt_new())==NULL) goto error;
			aa = aa->next;
		}
		if(org->der){
			if((aa->der = ASN1_dup(org->der))==NULL) goto error;
		}
		aa->der_size= org->der_size;
		org=org->next;
	}while(org);

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+9,NULL);
	P7_authatt_free(ret);
	return NULL;
}

RecipInfo *P7_recip_dup(RecipInfo *org){
	RecipInfo *ret,*ri;

	if(org==NULL) return NULL;
	ret=NULL;
	do{
		if(ret==NULL){
			if((ret=ri=P7_recip_new())==NULL) goto error;
		}else{
			if((ri->next=P7_recip_new())==NULL) goto error;
			ri = ri->next;
		}
		memcpy(ri,org,sizeof(RecipInfo));

		if(org->iss_str){
			if((STRDUP(ri->iss_str,org->iss_str))==NULL) goto error;
		}
		if(org->key){
			if((ri->key = (unsigned char*)MALLOC(org->size))==NULL) goto error;
			memcpy(ri->key,org->key,org->size);
		}
		if(Cert_dncopy(&org->iss_dn,&ri->iss_dn)) goto error;

		org=org->next;
	}while(org);

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+10,NULL);
	P7_recip_free(ret);
	return NULL;
}

EncCntInfo *P7_enccont_dup(EncCntInfo *org){
	EncCntInfo *ret;

	if(org==NULL) return NULL;

	if((ret=P7_enccont_new())==NULL) goto error;
	memcpy(ret,org,sizeof(EncCntInfo));

	if(org->iv){
		if((ret->iv = (unsigned char*)MALLOC(org->iv_size))==NULL) goto error;
		memcpy(ret->iv  ,org->iv  ,org->iv_size);
	}
	if(org->data){
		if((ret->data= (unsigned char*)MALLOC(org->size))==NULL) goto error;
		memcpy(ret->data,org->data,org->size);
	}

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_PKCS7+11,NULL);
	P7_enccont_free(ret);
	return NULL;
}
