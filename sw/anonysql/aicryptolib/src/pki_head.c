/* pki_head.c */
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

/*-----------------------------------------
  struct PKIHeader alloc & free
-----------------------------------------*/
PKIHeader *PKIhead_new(){
	PKIHeader *ret;

	if((ret=(PKIHeader*)MALLOC(sizeof(PKIHeader)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIHEAD,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(PKIHeader));
	return ret;
}

void PKIhead_free(PKIHeader *hd){
	int i;
	if(hd==NULL) return;

	cert_dn_free(&hd->sender);
	cert_dn_free(&hd->recipient);

	if(hd->senderKID) FREE(hd->senderKID);
	if(hd->recipKID)  FREE(hd->recipKID);

	if(hd->transactionID) FREE(hd->transactionID);

	if(hd->senderNonce) FREE(hd->senderNonce);
	if(hd->recipNonce) FREE(hd->recipNonce);

	for(i=0;i<8;i++){
		if(hd->freeText[i]) FREE(hd->freeText[i]);
	}
	CMP_infotype_free_all(hd->generalInfo);

	memset(hd,0,sizeof(PKIHeader));
	FREE(hd);
}

/*-----------------------------------------
  struct InfoTypeAndValue alloc & free
-----------------------------------------*/
InfoTAV *CMP_infotype_new(unsigned char *oid, void *value){
	InfoTAV *ret;

	if((ret=(InfoTAV*)MALLOC(sizeof(InfoTAV)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIHEAD+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(InfoTAV));
	ret->extnID    = ASN1_object_2int(oid);
	ret->objid     = oid;
	ret->infoValue = value;
	return ret;
}

void CMP_infotype_free(InfoTAV *info){
	switch(info->extnID){
	case OBJ_PKIX_IDIT_CAPROT:
		if(info->infoValue) Cert_free((Cert*)info->infoValue);
		break;
	case OBJ_PKIX_IDIT_SIGNKEY:
	case OBJ_PKIX_IDIT_ENCKEY:
	case OBJ_PKIX_IDIT_PREFSYM:
		/* infoValue is just int value */
		break;
	case OBJ_PKIX_IDIT_CAKEYUPD:
		if(info->infoValue) PKIbody_free((PKIBody*)info->infoValue);
		break;
	case OBJ_PKIX_IDIT_CURCRL:
		if(info->infoValue) CRL_free((CRL*)info->infoValue);
		break;
	}
	CertExt_free((CertExt*)info);
}

void CMP_infotype_free_all(InfoTAV *top){
	InfoTAV *next;
	while(top){
		next = (InfoTAV*)top->next;
		CMP_infotype_free(top);
		top = next;
	}
}

