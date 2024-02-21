/* pkibd_asn1sz.c */
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
  estimate PKIbody DER size.
-----------------------------------------*/
int PKIbody_estimate_der_size(PKIBody *pki){
	int ret;

	switch(pki->msg_type){
	case PKIBD_INIT_REQ:
	case PKIBD_CERT_REQ:
	case PKIBD_KEYUPD_REQ:
	case PKIBD_KEYRCV_REQ:
	case PKIBD_CCERT_REQ:
		if((ret=der_size_creqmsg((PKIBD_CertReqMsg*)pki))<0) goto error;
		break;
	case PKIBD_INIT_RSP:
	case PKIBD_CERT_RSP:
	case PKIBD_KEYUPD_RSP:
	case PKIBD_CCERT_RSP:
		if((ret=der_size_crspmsg((PKIBD_CertRepMsg*)pki))<0) goto error;
		break;

	case PKIBD_PKCS10:
	case PKIBD_CERT_ANN:
		if((ret=der_size_ctann((PKIBD_CertAnn*)pki))<0) goto error;
		break;

	case PKIBD_POP_CHALL:
		if((ret=der_size_popch((PKIBD_PopoCH*)pki))<0) goto error;
		break;
	case PKIBD_POP_RSP:
		if((ret=der_size_poprs((PKIBD_PopoRS*)pki))<0) goto error;
		break;

	case PKIBD_KEYRCV_RSP:
		if((ret=der_size_recrsp((PKIBD_RecRep*)pki))<0) goto error;
		break;
	case PKIBD_RVOC_REQ:
		if((ret=der_size_revreq((PKIBD_RevReq*)pki))<0) goto error;
		break;
	case PKIBD_RVOC_RSP:
		if((ret=der_size_revrsp((PKIBD_RevRep*)pki))<0) goto error;
		break;

	case PKIBD_CAKEYUPD_ANN:
		if((ret=der_size_keyupd((PKIBD_KeyUpDAnn*)pki))<0) goto error;
		break;
	case PKIBD_RVOC_ANN:
		if((ret=der_size_revann((PKIBD_RevAnn*)pki))<0) goto error;
		break;
	case PKIBD_CRL_ANN:
		if((ret=der_size_crlann((PKIBD_CRLAnn*)pki))<0) goto error;
		break;

	case PKIBD_GEN_MSG:
	case PKIBD_GEN_RSP:
		if((ret=der_size_infotype(((PKIBD_GenMsg*)pki)->content))<0) goto error;
		break;

	case PKIBD_ERR_MSG:
		if((ret=der_size_errmsg((PKIBD_ErrMsg*)pki))<0) goto error;
		break;

	case PKIBD_CONFIRM:
		ret=2;
		break;
	case PKIBD_NESTED_MSG:
		if((ret=PKImsg_estimate_der_size(((PKIBD_Nested*)pki)->msg))<0)
			goto error;
		break;

	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
		goto error;
	}

	return ret+8;
error:
	return -1;
}

int der_size_creqmsg(PKIBD_CertReqMsg *bd){
	int i,ret = 4;

	while(bd){
		/* hmm, MOJ version doesn't have certrequest...
		 * (it's not RFC compatible!!)
		 */
		if(bd->certReq.certTemplate){
			/* CertRequest -- INTEGER */
			ret += 6;
			/* CertRequest -- CertTemplate */
			if((i=der_size_certtmpl(bd->certReq.certTemplate))<0) goto error;
			ret += i;
			/* CertRequest -- Controls OPTIONAL */
			if(bd->certReq.controls){
				if((i=der_size_exts(bd->certReq.controls))<0) goto error;
				ret += i;
			}
		}
		/* ProofOfPossession OPTIONAL */
		if(bd->pop){
			if((i=der_size_pofp(bd->pop))<0) goto error;
			ret += i;
		}
		/* SEQ OF AttributeTypeAndValue OPTIONAL */
		if(bd->regInfo){
			if((i=der_size_exts(bd->regInfo))<0) goto error;
			ret += i;
		}
		bd=bd->next;
	}
	return ret;
error:
	return -1;
}

int der_size_crspmsg(PKIBD_CertRepMsg *bd){
	int i,ret = 4;
	CertResponse *cr;

	/* SEQ OF Certificate OPTIONAL */
	if(bd->caPubs){
		if((i=der_size_seqofcert(bd->caPubs))<0) goto error;
		ret+=i;
	}
	/* SEQ OF CertResponse */
	cr = bd->response;
	while(cr){
		if((i=der_size_certrsp(cr))<0) goto error;
		ret+=i;
		cr = cr->next;
	}
	return ret;
error:
	return -1;
}

int der_size_popch(PKIBD_PopoCH *bd){
	int i,ret = 4;
	/* SEQ OF Challenge */
	for(i=0;i<bd->num;i++){
		/* AlgorithmIdentifier OPTIONAL */
		if(bd->chall[i].owf) ret+=16;
		/* OCTET STRING */
		ret +=bd->chall[i].wit_len +4;
		/* OCTET STRING */
		ret +=bd->chall[i].ch_len + 4 + 4;
	}
	return ret;
}

int der_size_poprs(PKIBD_PopoRS *bd){
	int ret = 4;
	/* SEQ OF INTEGER */
	ret+= bd->num * 6;
	return ret;
}

int der_size_recrsp(PKIBD_RecRep *bd){
	int i,ret = 8;
	CertifiedKeyPair *ckp;

	/* PKIStatusInfo */
	if((i=der_size_statinfo(bd->status))<0) goto error;
	ret+=i;
	/* Certificate OPTIONAL */
	if(bd->newSigCert){
		ret+= ASN1_length(&bd->newSigCert->der[1],&i);
		ret+= i+1; 
	}
	/* SEQ OF Certificate OPTIONAL */
	if((i=der_size_seqofcert(bd->caCerts))<0) goto error;
	ret+=i;
	/* SEQ OF CertifiedKeyPair OPTIONAL */
	ckp=bd->keyPairHist;
	while(ckp){
		if((i=der_size_ctkeypair(ckp))<0) goto error;
		ret+=i;
		ckp =ckp->next;
	}
	return ret;
error:
	return -1;
}

int der_size_revreq(PKIBD_RevReq *bd){
	int i,ret = 4;
	
	/* SEQ OF RevDetails */
	while(bd){
		/* CertTemplate */
		if((i=der_size_certtmpl(bd->certDetails))<0) goto error;
		ret+=i + 4;
		/* ReasonFlags OPTIONAL */
		if(bd->revocationReason[1] != 0xff) ret+= 6;
		/* GeneralizedTime OPTIONAL */
		if(bd->badSinceDate.tm_year) ret+= 16;
		/* Extensions OPTIONAL */
		if(bd->crlEntryDetails){
			if((i=der_size_exts(bd->crlEntryDetails))<0) goto error;
			ret+= i;
		}
		bd = bd->next;
	}
	return ret;
error:
	return -1;
}

int der_size_revrsp(PKIBD_RevRep *bd){
	int i,ret = 4;

	/* SEQ OF PKIStatusInfo */
	if((i=der_size_statinfo(bd->status))<0) goto error;
	ret+=i;
	/* SEQ OF CertId OPTIONAL */
	if(bd->revCerts){
		if((i=der_size_certid(bd->revCerts))<0) goto error;
		ret+=i;
	}
	/* SEQ OF CertificateList OPTIONAL */
	if(bd->crl){
		if(bd->crl->der==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
			return -1;
		}
		ret+= ASN1_length(&bd->crl->der[1],&i);
		ret+= i+1; 
	}
	return ret;
error:
	return -1;
}

int der_size_keyupd(PKIBD_KeyUpDAnn *bd){
	int i,ret = 4;
	if((bd->oldWithNew==NULL)||(bd->newWithOld==NULL)||(bd->newWithNew==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
		return -1;
	}
	if((bd->oldWithNew->der==NULL)||(bd->newWithOld->der==NULL)
		  ||(bd->newWithNew->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
		return -1;
	}
	/* Certificate */
	ret+= ASN1_length(&bd->oldWithNew->der[1],&i);
	ret+= i+1;
	/* Certificate */
	ret+= ASN1_length(&bd->newWithOld->der[1],&i);
	ret+= i+1;
	/* Certificate */
	ret+= ASN1_length(&bd->newWithNew->der[1],&i);
	ret+= i+1;
	return ret;
}

int der_size_ctann(PKIBD_CertAnn *bd){
	int i,ret = 4;
	if((bd->cert==NULL)||(bd->cert->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
		return -1;
	}
	/* Certificate */
	ret+= ASN1_length(&bd->cert->der[1],&i);
	ret+= i+1;
	return ret;
}

int der_size_revann(PKIBD_RevAnn *bd){
	int i,ret = 4;

	/* PKIStatus */
	ret+= 4;
	/* CertId */
	if((i=der_size_certid(&bd->certId))<0) goto error;
	ret+= i;
	/* GeneralizedTime *2 */
	ret+= 30;
	/* Extensions OPTIONAL */
	if((i=der_size_exts(bd->crlDetails))<0) goto error;
	ret+= i;
	return ret;
error:
	return -1;
}

int der_size_crlann(PKIBD_CRLAnn *bd){
	int i,ret = 8;
	if((bd->crl==NULL)||(bd->crl->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
		return -1;
	}
	/* CertificateList */
	ret+= ASN1_length(&bd->crl->der[1],&i);
	ret+= i+1;
	return ret;
}

int der_size_errmsg(PKIBD_ErrMsg *msg){
	int i,ret = 4;

	if((i=der_size_statinfo(msg->status))<0) return -1;
	ret+=i;
	if(msg->errorCode) ret+=4;
	if((i=der_size_freetext(msg->errorDetails))<0) return -1;
	ret+=i;
	return ret;
}

/*
 * StatusInfo
 */
int der_size_statinfo(PKIStatusInfo *stat){
	int i,ret=5;

	if((i=der_size_freetext(stat->freeText))<0) return -1;
	ret+=i;
	if(stat->failInfo[1] != 0xff) ret+=6;

	return ret;
}

int der_size_freetext(char *ftxt[]){
	int j,ret=3;

	for(j=0;j<8;j++){
		if(ftxt[j])
			ret+=strlen(ftxt[j])+3;
	}
	return ret;
}

int der_size_exts(CertExt *top){
	int ret=4;

	while(top){
		if(top->extnID>0){
			ret+=(top->critical)?(4):(0);
			ret+=top->dlen+16;
		}
		top=top->next;
	}
	return ret;
}

/*
 * CertList
 */
int der_size_seqofcert(CertList *cl){
	int i,ret=4;

	for(;cl;cl=cl->next){
		if(cl->cert==NULL) continue;
		if(cl->cert->der==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASNSZ,NULL);
			return -1;
		}

		/* Certificate */
		ret+= ASN1_length(&cl->cert->der[1],&i);
		ret+= i+1;
	}
	return ret;
}


