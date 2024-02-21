/* pki_body.c */
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

#include "ok_cmp.h"

/*-----------------------------------------
  struct PKIBody alloc & free
-----------------------------------------*/
PKIBody *PKIbody_new(int type){
	PKIBody *ret;
	int size;

	switch(type){
	case PKIBD_INIT_REQ:
	case PKIBD_CERT_REQ:
	case PKIBD_KEYUPD_REQ:
	case PKIBD_KEYRCV_REQ:
	case PKIBD_CCERT_REQ:
		size = sizeof(PKIBD_CertReqMsg);
		break;
	case PKIBD_INIT_RSP:
	case PKIBD_CERT_RSP:
	case PKIBD_KEYUPD_RSP:
	case PKIBD_CCERT_RSP:
		size = sizeof(PKIBD_CertRepMsg);
		break;
	case PKIBD_PKCS10:
	case PKIBD_CERT_ANN:
		size = sizeof(PKIBD_CertAnn); 
		break;
	case PKIBD_POP_CHALL:
		size = sizeof(PKIBD_PopoCH);
		break;
	case PKIBD_POP_RSP:
		size = sizeof(PKIBD_PopoRS);
		break;
	case PKIBD_KEYRCV_RSP:
		size = sizeof(PKIBD_RecRep);
		break;
	case PKIBD_RVOC_REQ:
		size = sizeof(PKIBD_RevReq);
		break;
	case PKIBD_RVOC_RSP:
		size = sizeof(PKIBD_RevRep);
		break;
	case PKIBD_CAKEYUPD_ANN:
		size = sizeof(PKIBD_KeyUpDAnn);
		break;
	case PKIBD_RVOC_ANN:
		size = sizeof(PKIBD_RevAnn);
		break;
	case PKIBD_CRL_ANN:
		size = sizeof(PKIBD_CRLAnn);
		break;
	case PKIBD_CONFIRM:
		size = sizeof(PKIBody);
		break;
	case PKIBD_NESTED_MSG:
		size = sizeof(PKIBD_Nested);
		break;

	case PKIBD_GEN_MSG:
	case PKIBD_GEN_RSP:
		size = sizeof(PKIBD_GenMsg);
		break;

	case PKIBD_ERR_MSG:
		size = sizeof(PKIBD_ErrMsg);
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_PKIBODY,NULL);
		return NULL;
	}

	if((ret=(PKIBody*)MALLOC(size))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIBODY,NULL);
		return NULL;
	}
	memset(ret,0,size);
	ret->msg_type = type;

	return ret;
}

void PKIbody_free(PKIBody *bd){
	if(bd==NULL) return;

	switch(bd->msg_type){
	case PKIBD_INIT_REQ:
	case PKIBD_CERT_REQ:
	case PKIBD_KEYUPD_REQ:
	case PKIBD_KEYRCV_REQ:
	case PKIBD_CCERT_REQ:
		PKIbd_creqmsg_free_all((PKIBD_CertReqMsg*)bd);
		break;
	case PKIBD_INIT_RSP:
	case PKIBD_CERT_RSP:
	case PKIBD_KEYUPD_RSP:
	case PKIBD_CCERT_RSP:
		PKIbd_crspmsg_free((PKIBD_CertRepMsg*)bd);
		break;
	case PKIBD_PKCS10:
	case PKIBD_CERT_ANN:
		PKIbd_ctann_free((PKIBD_CertAnn*)bd);
		break;
	case PKIBD_POP_CHALL:
		PKIbd_popch_free((PKIBD_PopoCH*)bd);
		break;
	case PKIBD_POP_RSP:
		PKIbd_poprs_free((PKIBD_PopoRS*)bd);
		break;
	case PKIBD_KEYRCV_RSP:
		PKIbd_recrsp_free((PKIBD_RecRep*)bd);
		break;
	case PKIBD_RVOC_REQ:
		PKIbd_revreq_free_all((PKIBD_RevReq*)bd);
		break;
	case PKIBD_RVOC_RSP:
		PKIbd_revrsp_free((PKIBD_RevRep*)bd);
		break;
	case PKIBD_CAKEYUPD_ANN:
		PKIbd_keyupd_free((PKIBD_KeyUpDAnn*)bd);
		break;
	case PKIBD_RVOC_ANN:
		PKIbd_revann_free((PKIBD_RevAnn*)bd);
		break;
	case PKIBD_CRL_ANN:
		PKIbd_crlann_free((PKIBD_CRLAnn*)bd);
		break;
	case PKIBD_CONFIRM:
		/* just PKIBody */
		FREE(bd);
		break;
	case PKIBD_NESTED_MSG:
		PKImsg_free(((PKIBD_Nested*)bd)->msg);
		FREE(bd);
		break;

	case PKIBD_GEN_MSG:
	case PKIBD_GEN_RSP:
		PKIbd_genmsg_free((PKIBD_GenMsg*)bd);
		break;

	case PKIBD_ERR_MSG:
		PKIbd_errmsg_free((PKIBD_ErrMsg*)bd);
		break;
	}
}

/*-----------------------------------------
  PKIStatusInfo alloc & free
-----------------------------------------*/
PKIStatusInfo *PKI_statinfo_new(int status){
	PKIStatusInfo *ret;
	if((ret=(PKIStatusInfo*)MALLOC(sizeof(PKIStatusInfo)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIBODY+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(PKIStatusInfo));
	ret->status = status;
	ret->failInfo[1] = 0xff; /* means NULL */
	return ret;
}

void PKI_statinfo_free(PKIStatusInfo *si){
	int i;
	for(i=0;i<8;i++)
		if(si->freeText[i]) FREE(si->freeText[i]);
	FREE(si);
}

void PKI_statinfo_free_all(PKIStatusInfo *top){
	PKIStatusInfo *next;
	while(top){
		next = top->next;
		PKI_statinfo_free(top);
		top = next;
	}
}

/*-----------------------------------------
  struct free actual body.
-----------------------------------------*/
void PKIbd_creqmsg_free_all(PKIBD_CertReqMsg *bd){
	PKIBD_CertReqMsg *next;
	while(bd){
		next = bd->next;
		CertExt_free_all(bd->certReq.controls);
		CMP_certtmpl_free(bd->certReq.certTemplate);

		CMP_pofp_free(bd->pop);
		CertExt_free_all(bd->regInfo);
		FREE(bd);

		bd = next;
	}
}

void PKIbd_crspmsg_free(PKIBD_CertRepMsg *bd){
	if(bd==NULL) return;
	Certlist_free_all(bd->caPubs);
	CMP_certrsp_free_all(bd->response);
	FREE(bd);
}

void PKIbd_popch_free(PKIBD_PopoCH *bd){
	int i;
	if(bd==NULL) return;
	for(i=0;i<8;i++){
		if(bd->chall[i].challenge) FREE(bd->chall[i].challenge);
		if(bd->chall[i].witness) FREE(bd->chall[i].witness);
	}
	FREE(bd);
}

void PKIbd_poprs_free(PKIBD_PopoRS *bd){
	if(bd==NULL) return;
	FREE(bd);
}

void PKIbd_recrsp_free(PKIBD_RecRep *bd){
	if(bd==NULL) return;
	PKI_statinfo_free_all(bd->status);
	Cert_free(bd->newSigCert);
	Certlist_free_all(bd->caCerts);
	CMP_ctkeypair_free_all(bd->keyPairHist);
	FREE(bd);
}

void PKIbd_revreq_free(PKIBD_RevReq *bd){
	if(bd==NULL) return;
	CMP_certtmpl_free(bd->certDetails);
	CertExt_free_all(bd->crlEntryDetails);
	FREE(bd);
}

void PKIbd_revreq_free_all(PKIBD_RevReq *bd){
	PKIBD_RevReq *next;
	while(bd){
		next=bd->next;
		PKIbd_revreq_free(bd);
		bd=next;
	}
}

void PKIbd_revrsp_free(PKIBD_RevRep *bd){
	if(bd==NULL) return;
	PKI_statinfo_free_all(bd->status);
	CMP_certid_free_all(bd->revCerts);
	CRL_free(bd->crl);
	FREE(bd);
}

void PKIbd_keyupd_free(PKIBD_KeyUpDAnn *bd){
	if(bd==NULL) return;
	Cert_free(bd->newWithNew);
	Cert_free(bd->newWithOld);
	Cert_free(bd->oldWithNew);
	FREE(bd);
}

void PKIbd_ctann_free(PKIBD_CertAnn *bd){
	if(bd==NULL) return;
	Cert_free(bd->cert);
	FREE(bd);
}

void PKIbd_revann_free(PKIBD_RevAnn *bd){
	if(bd==NULL) return;
	cert_dn_free(&bd->certId.issuer);
	CertExt_free_all(bd->crlDetails);
	FREE(bd);
}

void PKIbd_crlann_free(PKIBD_CRLAnn *bd){
	if(bd==NULL) return;
	CRL_free(bd->crl);
	FREE(bd);
}

void PKIbd_genmsg_free(PKIBD_GenMsg *bd){
	if(bd==NULL) return;
	CMP_infotype_free_all(bd->content);
	FREE(bd);
}

void PKIbd_errmsg_free(PKIBD_ErrMsg *bd){
	int i;
	if(bd==NULL) return;
	PKI_statinfo_free_all(bd->status);
	for(i=0;i<8;i++)
		if(bd->errorDetails[i]) FREE(bd->errorDetails[i]);
	FREE(bd);
}
