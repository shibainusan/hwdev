/* pkibd_asn1.c */
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
  Get pki body DER.
-----------------------------------------*/
unsigned char *PKIbody_toDER(PKIBody *pki,unsigned char *buf,int *ret_len){
	unsigned char *ret;
	int	i;

	if(buf==NULL){
		if((i=PKIbody_estimate_der_size(pki))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIBD_ASN,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	switch(pki->msg_type){
	case PKIBD_INIT_REQ:
	case PKIBD_CERT_REQ:
	case PKIBD_KEYUPD_REQ:
	case PKIBD_KEYRCV_REQ:
	case PKIBD_CCERT_REQ:
		if(PKIbd_DER_creqmsg((PKIBD_CertReqMsg*)pki,ret,&i)) goto error;
		break;
	case PKIBD_INIT_RSP:
	case PKIBD_CERT_RSP:
	case PKIBD_KEYUPD_RSP:
	case PKIBD_CCERT_RSP:
		if(PKIbd_DER_crspmsg((PKIBD_CertRepMsg*)pki,ret,&i)) goto error;
		break;

	case PKIBD_PKCS10:
	case PKIBD_CERT_ANN:
		if(PKIbd_DER_ctann((PKIBD_CertAnn*)pki,ret,&i)) goto error;
		break;

	case PKIBD_POP_CHALL:
		if(PKIbd_DER_popch((PKIBD_PopoCH*)pki,ret,&i)) goto error;
		break;
	case PKIBD_POP_RSP:
		if(PKIbd_DER_poprs((PKIBD_PopoRS*)pki,ret,&i)) goto error;
		break;

	case PKIBD_KEYRCV_RSP:
		if(PKIbd_DER_recrsp((PKIBD_RecRep*)pki,ret,&i)) goto error;
		break;
	case PKIBD_RVOC_REQ:
		if(PKIbd_DER_revreq((PKIBD_RevReq*)pki,ret,&i)) goto error;
		break;
	case PKIBD_RVOC_RSP:
		if(PKIbd_DER_revrsp((PKIBD_RevRep*)pki,ret,&i)) goto error;
		break;

	case PKIBD_CAKEYUPD_ANN:
		if(PKIbd_DER_keyupd((PKIBD_KeyUpDAnn*)pki,ret,&i)) goto error;
		break;
	case PKIBD_RVOC_ANN:
		if(PKIbd_DER_revann((PKIBD_RevAnn*)pki,ret,&i)) goto error;
		break;
	case PKIBD_CRL_ANN:
		if(PKIbd_DER_crlann((PKIBD_CRLAnn*)pki,ret,&i)) goto error;
		break;

	case PKIBD_CONFIRM:
		/* set NULL */
		ASN1_set_null(ret);
		i=2;
		break;
	case PKIBD_NESTED_MSG:
		if(PKIbd_DER_nested((PKIBD_Nested*)pki,ret,&i)) goto error;
		break;

	case PKIBD_GEN_MSG:
	case PKIBD_GEN_RSP:
		if(PKIbd_DER_genmsg((PKIBD_GenMsg*)pki,ret,&i)) goto error;
		break;

	case PKIBD_ERR_MSG:
		if(PKIbd_DER_errmsg((PKIBD_ErrMsg*)pki,ret,&i)) goto error;
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_PKIBD_ASN,NULL);
		return NULL;
	}

	ASN1_set_explicit(i,(unsigned char)pki->msg_type,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  Get PKIbd DER.
-----------------------------------------*/
int PKIbd_DER_creqmsg(PKIBD_CertReqMsg *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	int i,j,k,l;

	/* SEQUENCE SIZE(1..MAX) OF CertReqMsg */
	cp = ret; k=0;
	while(bd){
		ct = cp; l=j=0;
		/* certReq CertRequest 
		 * hmm, MOJ version doesn't have certrequest...
		 * (it's not RFC compatible!!)
		 */
		if(bd->certReq.certTemplate){
			/* -- certReqId INTEGER */
			ASN1_set_integer(bd->certReq.certReqId,ct,&j);
			ct+=j;
			/* -- certTemplate CertTemplate */
			if(CMP_DER_certtmpl(bd->certReq.certTemplate,ct,&i)) goto error;
			ct+=i; j+=i;
			/* -- controls Controls OPTIONAL */
			if(bd->certReq.controls){
				if(x509_DER_attrs(bd->certReq.controls,ct,&i)) goto error;
				j+=i;
			}
		}
		ASN1_set_sequence(j,cp,&j);
		ct=cp+j; l+=j;

		/* pop ProofOfPossession OPTIONAL */
		if(bd->pop){
			if(CMP_DER_pofp(bd->pop,ct,&i)) goto error;
			ct+=i; l+=i;
		}
		/* regInfo SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL */
		if(bd->regInfo){
			if(x509_DER_attrs(bd->regInfo,ct,&i)) goto error;
			l+=i;
		}
		ASN1_set_sequence(l,cp,&i);
		cp+=i; k+=i;

		bd = bd->next;
	}

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_crspmsg(PKIBD_CertRepMsg *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	CertResponse *cr;
	int i,j,k;

	/* caPubs [1] SEQUENCE SIZE(1..MAX) OF Certificate OPTIONAL */
	cp = ret; k=0;
	if(bd->caPubs){
		if(Certlist_DER_data(bd->caPubs,cp,&i)) goto error;
		ASN1_set_explicit(i,1,cp,&i);
		cp+=i; k+=i;
	}
	/* response SEQUENCE OF CertResponse */
	cr = bd->response;
	ct = cp; j=0;
	while(cr){
		if(CMP_DER_certrsp(cr,ct,&i)) goto error;
		ct+=i; j+=i;

		cr=cr->next;
	}
	ASN1_set_sequence(j,cp,&j);
	cp+=j; k+=j;

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_popch(PKIBD_PopoCH *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	int i,j,k,l;
	/* SEQUENCE OF Challenge */
	cp = ret;
	for(i=k=0;i<bd->num;i++){
		/* owf AlgorithmIdentifier OPTIONAL */
		ct = cp; l=0;
		if(bd->chall[i].owf){
			if(x509_DER_algoid(bd->chall[i].owf,NULL,ct,&j)) return -1;
			ct+=j; l+=j;
		}
		/* witness OCTET STRING */
		ASN1_set_octetstring(bd->chall[i].wit_len,bd->chall[i].witness,ct,&j);
		ct+=j; l+=j;

		/* challenge OCTET STRING */
		ASN1_set_octetstring(bd->chall[i].ch_len,bd->chall[i].challenge,ct,&j);
		l+=j;

		ASN1_set_sequence(l,cp,&j);
		cp+=j; k+=j;
	}
	ASN1_set_sequence(k,ret,ret_len);
	return 0;
}

int PKIbd_DER_poprs(PKIBD_PopoRS *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,k;

	/* POPODecKeyRespContent ::= SEQUENCE OF INTEGER */
	cp = ret;
	for(i=k=0;i<bd->num;i++){
		ASN1_set_integer(bd->content[i],cp,&j);
		cp+=j; k+=j;
	}
	ASN1_set_sequence(k,ret,ret_len);
	return 0;
}

int PKIbd_DER_recrsp(PKIBD_RecRep *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	CertifiedKeyPair *ckp;
	int i,j,k;

	/* status PKIStatusInfo */
	if(PKI_DER_statinfo(bd->status,ret,&k)) goto error;
	cp = ret+k;

	/* newSigCert [0] Certificate OPTIONAL */
	if(bd->newSigCert){
		if(bd->newSigCert->der == NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+4,NULL);
			goto error;
		}
		i = ASN1_length(&bd->newSigCert->der[1],&j);
		i+= j+1;

		memcpy(cp,bd->newSigCert->der,i);
		ASN1_set_explicit(i,0,cp,&i);
		cp+=i; k+=i;
	}
	/* caCerts [1] SEQUENCE SIZE (1..MAX) OF Certificate OPTIONAL */
	if(bd->caCerts){
		if(Certlist_DER_data(bd->caCerts,cp,&i)) goto error;
		ASN1_set_explicit(i,1,cp,&i);
		cp+=i; k+=i;
	}
	/* keyPairHist [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair OPTIONAL */
	ckp = bd->keyPairHist;
	ct  = cp; j=0;
	while(ckp){
		if(CMP_DER_ctkeypair(ckp,ct,&i)) goto error;
		ct+=i; j+=i;

		ckp = ckp->next;
	}
	if(j){
		ASN1_set_sequence(j,cp,&i);
		ASN1_set_explicit(i,2,cp,&i);
		k+=i;
	}

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_revreq(PKIBD_RevReq *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	int i,j,k,a,b;

	/* RevReqContent ::= SEQUENCE OF RevDetails */
	cp=ret; k=0;
	while(bd){
		/* certDetails CertTemplate */
		if(CMP_DER_certtmpl(bd->certDetails,cp,&j)) goto error;
		ct = cp+j;

		/* revocationReason ReasonFlags OPTIONAL */
		if(bd->revocationReason[1] != 0xff){
			asn1_check_derbit(2,bd->revocationReason,&b,&a);
			ASN1_set_bitstring(b,a,bd->revocationReason,ct,&i);
			ct+=i; j+=i;
		}

		/* badSinceDate GeneralizedTime OPTIONAL */
		if(bd->badSinceDate.tm_year){

			stm2UTC(&bd->badSinceDate,ct,ASN1_GENERALIZEDTIME);
			i=ASN1_tlen(ct)+2;
			ct+=i; j+=i;
		}
		/* crlEntryDetails Extensions OPTIONAL */
		if(bd->crlEntryDetails){
			if(x509_DER_exts(bd->crlEntryDetails,ct,&i)) goto error;
			j+=i;
		}
		/* RevDetails ::= SEQUENCE { */
		ASN1_set_sequence(j,cp,&i);
		cp+=i; k+=i;

		bd = bd->next;
	}
	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_revrsp(PKIBD_RevRep *bd,unsigned char *ret,int *ret_len){
	PKIStatusInfo *stat;
	CertId *cid;
	unsigned char *cp,*ct;
	int i,j,k;

	/* status SEQUENCE SIZE (1..MAX) OF PKIStatusInfo */
	stat= bd->status;
	cp  = ret; j=k=0;
	while(stat){
		if(PKI_DER_statinfo(stat,cp,&i)) goto error;
		cp+=i; j+=i;

		stat=stat->next;
	}
	ASN1_set_sequence(j,ret,&j);
	cp = ret+j; k=j;

	/* revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL */
	cid = bd->revCerts;
	ct  = cp; j=0;
	while(cid){
		if(CMP_DER_certid(cid,ct,&i)) goto error;
		ct+=i; j+=i;

		cid=cid->next;
	}
	if(j){
		ASN1_set_sequence(j,cp,&j);
		ASN1_set_explicit(j,0,cp,&j);
		cp+=j; k+=j;
	}
	/* crls [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL */
	/* attach just one CRL */
	if(bd->crl){
		if(bd->crl->der==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+6,NULL);
			goto error;
		}
		i =ASN1_length(&bd->crl->der[1],&j);
		i+=j+1;
		memcpy(cp,bd->crl->der,i);

		ASN1_set_sequence(i,cp,&i);
		ASN1_set_explicit(i,1,cp,&i);
		k+=i;
	}

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_keyupd(PKIBD_KeyUpDAnn *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,k;

	/* oldWithNew Certificate */
	if((bd->oldWithNew==NULL)||(bd->oldWithNew->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+7,NULL);
		goto error;
	}
	i =ASN1_length(&bd->oldWithNew->der[1],&j);
	i+=j+1;
	memcpy(ret,bd->oldWithNew->der,i);
	cp=ret+i; k=i;

	/* newWithOld Certificate */
	if((bd->newWithOld==NULL)||(bd->newWithOld->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+7,NULL);
		goto error;
	}
	i =ASN1_length(&bd->newWithOld->der[1],&j);
	i+=j+1;
	memcpy(cp,bd->newWithOld->der,i);
	cp+=i; k+=i;

	/* newWithNew Certificate */
	if((bd->newWithNew==NULL)||(bd->newWithNew->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+7,NULL);
		goto error;
	}
	i =ASN1_length(&bd->newWithNew->der[1],&j);
	i+=j+1;
	memcpy(cp,bd->newWithNew->der,i);
	k+=i;

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_ctann(PKIBD_CertAnn *bd,unsigned char *ret,int *ret_len){
	int j;

	/* ::= Certificate */
	if((bd->cert==NULL)||(bd->cert->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+8,NULL);
		return -1;
	}
	*ret_len =ASN1_length(&bd->cert->der[1],&j);
	*ret_len+=j+1;
	memcpy(ret,bd->cert->der,*ret_len);
	return 0;
}

int PKIbd_DER_revann(PKIBD_RevAnn *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j;

	/* status PKIStatus */
	ASN1_set_integer(bd->status,ret,&j);
	cp=ret+j;

	/* certId CertId */
	if(CMP_DER_certid(&bd->certId,cp,&i)) goto error;
	cp+=i; j+=i;

	/* willBeRevokedAt GeneralizedTime */
	stm2UTC(&bd->willBeRevokedAt,cp,ASN1_GENERALIZEDTIME);
	i=ASN1_tlen(cp)+2;
	cp+=i; j+=i;

	/* badSinceDate GeneralizedTime */
	stm2UTC(&bd->badSinceData,cp,ASN1_GENERALIZEDTIME);
	i=ASN1_tlen(cp)+2;
	cp+=i; j+=i;

	/* crlDetails Extensions OPTIONAL */
	if(bd->crlDetails){
		if(x509_DER_exts(bd->crlDetails,cp,&i)) goto error;
		j+=i;
	}

	ASN1_set_sequence(j,ret,ret_len);
	return 0;
error:
	return -1;
}

int PKIbd_DER_crlann(PKIBD_CRLAnn *bd,unsigned char *ret,int *ret_len){
	int i,j;

	/* set just one CRL */
	if((bd->crl==NULL)||(bd->crl->der==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+9,NULL);
		return -1;
	}
	/* SEQUENCE OF CertificateList */
	i =ASN1_length(&bd->crl->der[1],&j);
	i+=j+1;
	memcpy(ret,bd->crl->der,i);
	ASN1_set_sequence(i,ret,ret_len);
	return 0;
}

int PKIbd_DER_nested(PKIBD_Nested *bd,unsigned char *ret,int *ret_len){
	/* ::= PKIMessage */
	if(bd->msg==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+10,NULL);
		return -1;
	}
	if(PKImsg_toDER(bd->msg,ret,ret_len)==NULL) return -1;
	return 0;
}

int PKIbd_DER_genmsg(PKIBD_GenMsg *bd,unsigned char *ret,int *ret_len){
	InfoTAV *itv;
	unsigned char *cp;
	int i,j;

	/* SEQUENCE OF InfoTypeAndValue */
	itv=bd->content;
	cp= ret;
	j =*ret_len=0;
	while(itv){
		/* depend on the content */
		if(CMP_DER_infotype(itv,cp,&i)) return -1;
		cp+=i; j+=i;

		itv=(InfoTAV*)itv->next;
	}
	ASN1_set_sequence(j,ret,ret_len);
	return 0;
}

int PKIbd_DER_errmsg(PKIBD_ErrMsg *bd,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j;

	/* pKIStatusInfo PKIStatusInfo */
	if(PKI_DER_statinfo(bd->status,ret,&i)) return -1;
	cp=ret+i; j=i;

	/* errorCode INTEGER OPTIONAL */
	if(bd->errorCode){
		ASN1_set_integer(bd->errorCode,cp,&i);
		cp+=i; j+=i;
	}

	/* errorDetails PKIFreeText OPTIONAL */
	if(PKI_DER_freetext(bd->errorDetails,cp,&i)) return -1;
	j+=i;

	ASN1_set_sequence(j,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  get other DER PKI structures.
-----------------------------------------*/
int PKI_DER_statinfo(PKIStatusInfo *stat,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,k,l;

	if(stat==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIBD_ASN+13,NULL);
		return -1;
	}

	/* status PKIStatus ::=INTEGER */
	ASN1_set_integer(stat->status,ret,&i);
	cp = ret+i; j=i;

	/* statusString PKIFreeText OPTIONAL */
	if(PKI_DER_freetext(stat->freeText,cp,&i)) return -1;
	cp+= i; j+=i;

	/* failInfo PKIFailureInfo OPTIONAL */
	if(stat->failInfo[1]!=0xff){
		asn1_check_derbit(2,stat->failInfo,&k,&l);
		ASN1_set_bitstring(k,l,stat->failInfo,cp,&i);
		j+=i;
	}
	ASN1_set_sequence(j,ret,ret_len);

	return 0;
}

int PKI_DER_freetext(char *ftxt[],unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,k,l;

	*ret_len = 0;
	for(cp=ret,k=l=0;k<8;k++){
		if(ftxt[k]){
			ASN1_set_octetstring(strlen(ftxt[k]),ftxt[k],cp,&i);
			*cp = ASN1_UTF8STRING;
			cp+=i; l+=i;
		}
	}
	if(l) ASN1_set_sequence(l,ret,ret_len);

	return 0;
}

