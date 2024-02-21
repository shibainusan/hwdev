/* cmp.c */
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
#include "ok_cmp.h"

/*
 * Certificate Template
 */
/*-----------------------------------------
  struct CertTemplate alloc & free
-----------------------------------------*/
CertTemplate *CMP_certtmpl_new(){
	CertTemplate *ret;

	if((ret=(CertTemplate*)MALLOC(sizeof(CertTemplate)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CertTemplate));
	ret->version      =-1;
	ret->serialNumber =-1;

	return ret;
}

void CMP_certtmpl_free(CertTemplate *ctt){
	if(ctt==NULL) return;
	if(ctt->snum_der) FREE(ctt->snum_der);
	cert_dn_free(&ctt->issuer);
	cert_dn_free(&ctt->subject);
	Key_free(ctt->publicKey);
	CertExt_free_all(ctt->ext);
	FREE(ctt);
}

/*
 * Proof of Possession
 */
/*-----------------------------------------
  struct POfP alloc & free
-----------------------------------------*/
POfP *CMP_pofp_new(){
	POfP *ret;
	if((ret=(POfP*)MALLOC(sizeof(POfP)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(POfP));
	ret->choice = -1;
	return ret;
}

void CMP_pofp_free(POfP *pp){
	if(pp==NULL) return;
	CMP_poposign_free(pp->signature);
	CMP_popopriv_free(pp->keyEncipherment);
	CMP_popopriv_free(pp->keyAgreement);
	FREE(pp);
}

/*-----------------------------------------
  struct POPOSigningKey alloc & free
-----------------------------------------*/
POPOSigningKey *CMP_poposign_new(){
	POPOSigningKey *ret;
	if((ret=(POPOSigningKey*)MALLOC(sizeof(POPOSigningKey)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+2,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(POPOSigningKey));
	return ret;
}

void CMP_poposign_free(POPOSigningKey *pps){
	if(pps==NULL) return;
	cert_dn_free(&pps->poposkInput.sender);
	CMP_pkmacv_free(pps->poposkInput.publicKeyMac);
	Key_free(pps->poposkInput.publicKey);
	if(pps->signature) FREE(pps->signature);
	FREE(pps);
}

/*-----------------------------------------
  struct POPOPrivKey alloc & free
-----------------------------------------*/
POPOPrivKey *CMP_popopriv_new(){
	POPOPrivKey *ret;
	if((ret=(POPOPrivKey*)MALLOC(sizeof(POPOPrivKey)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+3,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(POPOPrivKey));
	ret->subsequentMessage = -1;
	ret->choice = -1;
	return ret;
}

void CMP_popopriv_free(POPOPrivKey *ppp){
	if(ppp==NULL) return;
	if(ppp->thisMessage) FREE(ppp->thisMessage);
	if(ppp->dhMAC) FREE(ppp->dhMAC);
	FREE(ppp);
}

/*-----------------------------------------
  struct PKMACValue alloc & free
-----------------------------------------*/
PKMACValue *CMP_pkmacv_new(){
	PKMACValue *ret;
	if((ret=(PKMACValue*)MALLOC(sizeof(PKMACValue)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+4,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(PKMACValue));
	return ret;
}

void CMP_pkmacv_free(PKMACValue *mac){
	if(mac==NULL) return;
	if(mac->value) FREE(mac->value);
	FREE(mac);
}

/*
 * CertifiedKeyPair & EncryptedValue
 */
/*-----------------------------------------
  struct EncryptedValue alloc & free
-----------------------------------------*/
EncryptedValue *CMP_encval_new(){
	EncryptedValue *ret;
	if((ret=(EncryptedValue*)MALLOC(sizeof(EncryptedValue)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+5,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(EncryptedValue));
	return ret;	
}

void CMP_encval_free(EncryptedValue *ev){
	if(ev==NULL) return;
	if(ev->symmKey) Key_free(ev->symmKey);
	if(ev->enc_symmkey) FREE(ev->enc_symmkey);
	if(ev->valueHint) FREE(ev->valueHint);
	if(ev->encValue) FREE(ev->encValue);
	FREE(ev);
}

/*-----------------------------------------
  struct PKIPubInfo alloc & free
-----------------------------------------*/
PKIPubInfo *CMP_pubinfo_new(){
	PKIPubInfo *ret;
	int i;
	if((ret=(PKIPubInfo*)MALLOC(sizeof(PKIPubInfo)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+6,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(PKIPubInfo));
	for(i=0;i<4;i++){
		ret->pubInfo[i].pubMethod = -1; /* means NULL */
	}
	return ret;	
}

void CMP_pubinfo_free(PKIPubInfo *ppi){
	int i;

	if(ppi==NULL) return;
	for(i=0;i<4;i++){
		ExtGN_free(ppi->pubInfo[i].pubLocation);
	}
	FREE(ppi);
}

/*-----------------------------------------
  struct CertifiedKeyPair alloc & free
-----------------------------------------*/
CertifiedKeyPair *CMP_ctkeypair_new(){
	CertifiedKeyPair *ret;
	if((ret=(CertifiedKeyPair*)MALLOC(sizeof(CertifiedKeyPair)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+7,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CertifiedKeyPair));
	return ret;	
}

void CMP_ctkeypair_free(CertifiedKeyPair *ckp){
	if(ckp==NULL) return;
	Cert_free(ckp->certOrEncCert.cert);
	CMP_encval_free(ckp->certOrEncCert.encCert);

	CMP_encval_free(ckp->privateKey);
	CMP_pubinfo_free(ckp->publicationInfo);
	FREE(ckp);
}

void CMP_ctkeypair_free_all(CertifiedKeyPair *top){
	CertifiedKeyPair *tmp;
	while(top){
		tmp=top->next;
		CMP_ctkeypair_free(top);
		top=tmp;
	}
}

/*
 *	CertId
 */
/*-----------------------------------------
  struct CertId alloc & free
-----------------------------------------*/
CertId *CMP_certid_new(){
	CertId *ret;
	if((ret=(CertId*)MALLOC(sizeof(CertId)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+8,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CertId));
	return ret;	
}

void CMP_certid_free(CertId *cid){
	if(cid==NULL) return;
	cert_dn_free(&cid->issuer);
	FREE(cid);
}

void CMP_certid_free_all(CertId *top){
	CertId *tmp;
	if(top==NULL) return;
	while(top){
		tmp=top->next;
		CMP_certid_free(top);
		top=tmp;
	}
}

/*
 *	CertResponse
 */
/*-----------------------------------------
  struct CertResponse alloc & free
-----------------------------------------*/
CertResponse *CMP_certrsp_new(){
	CertResponse *ret;
	if((ret=(CertResponse*)MALLOC(sizeof(CertResponse)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_CMP+9,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CertResponse));
	return ret;	
}

void CMP_certrsp_free(CertResponse *cr){
	if(cr==NULL) return;
	PKI_statinfo_free_all(cr->status);
	CMP_ctkeypair_free(cr->certifiedKeyPair);
	if(cr->rspInfo) FREE(cr->rspInfo);
	FREE(cr);
}

void CMP_certrsp_free_all(CertResponse *top){
	CertResponse *tmp;
	while(top){
		tmp=top->next;
		CMP_certrsp_free(top);
		top=tmp;
	}
}
