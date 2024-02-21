/* asn1_pkibd.c */
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
  ASN.1 read PKI body.
-----------------------------------------*/
PKIBody *ASN1_read_pkibody(unsigned char *der){
	PKIBody *ret;
	unsigned char *cp;
	int type;

	if(der == NULL) return NULL;
	cp  = ASN1_next(der); /* skip explicit */
	type= *der&0x1f;

	switch(type){
	case PKIBD_INIT_REQ:
	case PKIBD_CERT_REQ:
	case PKIBD_KEYUPD_REQ:
	case PKIBD_KEYRCV_REQ:
	case PKIBD_CCERT_REQ:
		ret = (PKIBody*)ASN1_pkibd_creqmsg(cp,type);
		break;
	case PKIBD_INIT_RSP:
	case PKIBD_CERT_RSP:
	case PKIBD_KEYUPD_RSP:
	case PKIBD_CCERT_RSP:
		ret = (PKIBody*)ASN1_pkibd_crspmsg(cp,type);
		break;

	case PKIBD_PKCS10:
		ret = (PKIBody*)ASN1_pkibd_p10(cp);
		break;
	case PKIBD_CERT_ANN:
		ret = (PKIBody*)ASN1_pkibd_ctann(cp);
		break;

	case PKIBD_POP_CHALL:
		ret = (PKIBody*)ASN1_pkibd_popch(cp);
		break;
	case PKIBD_POP_RSP:
		ret = (PKIBody*)ASN1_pkibd_poprs(cp);
		break;

	case PKIBD_KEYRCV_RSP:
		ret = (PKIBody*)ASN1_pkibd_recrsp(cp);
		break;
	case PKIBD_RVOC_REQ:
		ret = (PKIBody*)ASN1_pkibd_revreq(cp);
		break;
	case PKIBD_RVOC_RSP:
		ret = (PKIBody*)ASN1_pkibd_revrsp(cp);
		break;

	case PKIBD_CAKEYUPD_ANN:
		ret = (PKIBody*)ASN1_pkibd_keyupd(cp);
		break;
	case PKIBD_RVOC_ANN:
		ret = (PKIBody*)ASN1_pkibd_revann(cp);
		break;
	case PKIBD_CRL_ANN:
		ret = (PKIBody*)ASN1_pkibd_crlann(cp);
		break;

	case PKIBD_CONFIRM:
		ret = PKIbody_new(PKIBD_CONFIRM);
		break;
	case PKIBD_NESTED_MSG:
		ret = (PKIBody*)ASN1_pkibd_nested(cp);
		break;

	case PKIBD_GEN_MSG:
	case PKIBD_GEN_RSP:
		ret = (PKIBody*)ASN1_pkibd_genmsg(cp,type);
		break;

	case PKIBD_ERR_MSG:
		ret = (PKIBody*)ASN1_pkibd_errmsg(cp);
		break;
	default:
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1CMP,ERR_PT_ASN_PKIBD,NULL);
		return NULL;
	}
	return ret;
}

/*-----------------------------------------
  ASN.1 read specific PKI body.
-----------------------------------------*/
PKIBD_CertReqMsg *ASN1_pkibd_creqmsg(unsigned char *in,int type){
	PKIBD_CertReqMsg *crm,*hd=NULL,*ret=NULL;
	unsigned char *cp;
	int i,j,len;

	/* SEQUENCCE OF CertReqMsg */
	len = ASN1_length(&in[1],&j);
	in  = ASN1_next(in);
	for(i=0;i<len;){

		if((crm=(PKIBD_CertReqMsg*)PKIbody_new(type))==NULL) goto error;

		i+= ASN1_length(&in[1],&j);
		i+= 1+j;

		/* CertRequest */
		cp = ASN1_next(in);
		if(asn1_pki_certreq(cp,&crm->certReq)) goto error;
		cp = ASN1_skip(cp);

		/* ProofOfPossession OPTIONAL */
		if((*cp&0x80)&&((*cp&0x1f)<4)){ /* implicit */
			if((crm->pop=ASN1_cmp_pofp(cp))==NULL)
				goto error;
			cp = ASN1_skip(cp);
		}
		in = ASN1_skip(in);

		/* SEQUENCE OF AttributeTypeAndValue OPTIONAL */
		if((*cp==0x30)&&(cp[1]>0)&&(in!=cp)){
			if((crm->regInfo=asn1_get_attrs(cp,&j))==NULL)
				goto error;
		}
		if(ret==NULL){
			ret = hd = crm;
		}else{
			hd->next = crm; hd = crm;
		}
	}

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_CertRepMsg *ASN1_pkibd_crspmsg(unsigned char *in,int type){
	PKIBD_CertRepMsg *ret;
	CertResponse *rsp,*hd=NULL;
	unsigned char *cp;
	int i,j,len;

	if((ret=(PKIBD_CertRepMsg*)PKIbody_new(type))==NULL) goto error;
	in = ASN1_next(in);

	/* [1] SEQUENCE OF Certificate OPTIONAL */
	if(*in==0xa1){
		cp = ASN1_next(in); /* skip explicit */
		if((ret->caPubs=asn1_seq_certlist(cp))==NULL) goto error;
		in = ASN1_skip(in);
	}

	/* SEQUENCE OF CertResponse */
	len = ASN1_length(&in[1],&i);
	cp  = ASN1_next(in);
	for(i=0;i<len;i+=j){
		/* keep original order */
		if((rsp=ASN1_cmp_certrsp(cp,&j))==NULL) goto error;
		if(hd==NULL){
			ret->response = hd =rsp;
		}else{
			hd->next=rsp; hd=rsp;
		}
		cp = ASN1_skip(cp);
	}

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_CertAnn *ASN1_pkibd_p10(unsigned char *in){
	PKIBD_CertAnn *ret;
	unsigned char st;

	if((ret=(PKIBD_CertAnn*)PKIbody_new(PKIBD_PKCS10))==NULL) goto error;

	st=*in; *in=0x30; /* set SEQUENCE */
	if((ret->cert=ASN1_read_req(in))==NULL) goto error;
	if((ret->cert->der=ASN1_dup(in))==NULL) goto error;
	*in=st;

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_CertAnn *ASN1_pkibd_ctann(unsigned char *in){
	PKIBD_CertAnn *ret;
	unsigned char st;

	if((ret=(PKIBD_CertAnn*)PKIbody_new(PKIBD_CERT_ANN))==NULL) goto error;

	st=*in; *in=0x30; /* set SEQUENCE */
	if((ret->cert=ASN1_read_cert(in))==NULL) goto error;
	if((ret->cert->der=ASN1_dup(in))==NULL) goto error;
	*in=st;

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_PopoCH *ASN1_pkibd_popch(unsigned char *in){
	PKIBD_PopoCH *ret;
	unsigned char *cp,*ct;
	int i,j,k,len;

	if((ret=(PKIBD_PopoCH*)PKIbody_new(PKIBD_POP_CHALL))==NULL) goto error;

	/* SEQUENCE OF Cahallenge */
	len = ASN1_length(&in[1],&i);
	in  = ASN1_next(in);
	for(i=k=0;(i<len)&&(k<8);k++){
		i+= ASN1_length(&in[1],&j);
		i+= 1+j;

		cp = ASN1_next(in);
		/* AlgorithmIdentifier OPTIONAL */
		if(*cp==0x30){
			ct = ASN1_next(cp);
			if((ret->chall[k].owf=ASN1_object_2int(ct))<0) goto error;
			cp = ASN1_skip(cp);
		}
		/* OCTETSTRING */
		if(ASN1_octetstring(cp,&j,&ret->chall[k].witness,&ret->chall[k].wit_len))
			goto error;
		cp = ASN1_next(cp);

		/* OCTETSTRING */
		if(ASN1_octetstring(cp,&j,&ret->chall[k].challenge,&ret->chall[k].ch_len))
			goto error;

		in = ASN1_skip(in);
	}
	ret->num = k;

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_PopoRS *ASN1_pkibd_poprs(unsigned char *in){
	PKIBD_PopoRS *ret;
	int i,j,k,len;

	if((ret=(PKIBD_PopoRS*)PKIbody_new(PKIBD_POP_RSP))==NULL) goto error;

	/* SEQUENCE OF INTEGER */
	len = ASN1_length(&in[1],&i);
	in  = ASN1_next(in);
	for(i=k=0;(i<len)&&(k<8);i+=j,k++){
		ret->content[k] = ASN1_integer(in,&j);
		if(j==0) goto error;
	}
	ret->num = k;

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_RecRep *ASN1_pkibd_recrsp(unsigned char *in){
	PKIBD_RecRep *ret;
	CertifiedKeyPair *ckp,*hd=NULL;
	unsigned char *cp;
	int i,j,len;

	if((ret=(PKIBD_RecRep*)PKIbody_new(PKIBD_KEYRCV_RSP))==NULL) goto error;

	in = ASN1_next(in);

	/* PKIStatusInfo */
	if((ret->status=ASN1_read_statinfo(in,&i))==NULL) goto error;
	in = ASN1_skip(in);

	/* [0] Certificate OPTIONAL */
	if(*in==0xa0){
		cp = ASN1_next(in);
		if((ret->newSigCert=ASN1_read_cert(cp))==NULL) goto error;
		if((ret->newSigCert->der=ASN1_dup(cp))==NULL) goto error;
		in = ASN1_skip(in);
	}
	/* [1] SEQUENCE OF Certificate OPTIONAL */
	if(*in==0xa1){
		cp = ASN1_next(in); /* skip explicit */
		if((ret->caCerts=asn1_seq_certlist(cp))==NULL) goto error;
		in = ASN1_skip(in);
	}

	/* [2] SEQUENCE OF CertifiedKeyPair OPTIONAL */
	if(*in==0xa2){
		cp = ASN1_next(in); /* skip explicit */
		len= ASN1_length(&cp[1],&j);
		cp = ASN1_next(cp);
		for(i=0;i<len;i+=j){
			/* keep original order */
			if((ckp=ASN1_cmp_ctkeypair(cp,&j))==NULL) goto error;
			if(hd==NULL){
				ret->keyPairHist = hd = ckp;
			}else{
				hd->next=ckp; hd=ckp;
			}
			cp = ASN1_skip(cp);
		}
		in = ASN1_skip(in);
	}

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_RevReq *ASN1_pkibd_revreq(unsigned char *in){
	PKIBD_RevReq *ret=NULL,*rr;
	unsigned char *cp,*ct,*rflg;
	int i,j,k,len;

	len= ASN1_tlen(in);
	ct = ASN1_next(in);

	/* SEQUENCE OF RevDetails */
	for(k=0;k<len;){
		k+= ASN1_length(&ct[1],&i);
		k+= i+1;
		cp= ASN1_next(ct);

		if((rr=(PKIBD_RevReq*)PKIbody_new(PKIBD_RVOC_REQ))==NULL) goto error;
		rr->revocationReason[1] = 0xff; /* means NULL */
		rr->next = ret;
		ret = rr;
		
		/* CertTemplate */
		if((ret->certDetails=ASN1_cmp_certtmpl(cp,&j))==NULL) goto error;
		cp = ASN1_skip(cp);

		/* ReasonFlags OPTIONAL */
		if(*cp==ASN1_BITSTRING){
			if(ASN1_bitstring(cp,&i,&rflg,&j,&j)) goto error;
			memcpy(ret->revocationReason,rflg,2);
			FREE(rflg);
			cp = ASN1_next(cp);
		}
		/* GeneralizedTime OPTIONAL */
		if(*cp==ASN1_GENERALIZEDTIME){
			if(UTC2stm(cp,&ret->badSinceDate)) goto error;
			cp = ASN1_next(cp);
		}

		ct = ASN1_skip(ct);

		/* Extensions OPTIONAL */
		if((*cp==0x30)&&(ct!=cp)){
			if((ret->crlEntryDetails=asn1_get_exts(cp,&i))==NULL)
				goto error;
		}
	}

	return ret;

error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_RevRep *ASN1_pkibd_revrsp(unsigned char *in){
	PKIBD_RevRep *ret;
	PKIStatusInfo *stat;
	CertId *cid;
	unsigned char *cp,*ct,tmp;
	char *buf;
	int i,j,k,len;

	if((ret=(PKIBD_RevRep*)PKIbody_new(PKIBD_RVOC_RSP))==NULL) goto error;

	in = ASN1_next(in);

	/* SEQUENCE OF PKIStatus */
	len = ASN1_length(&in[1],&i);
	cp = ASN1_next(in);
	for(i=0;i<len;i+=j){
		if((stat=ASN1_read_statinfo(cp,&j))==NULL) goto error;
		stat->next = ret->status;
		ret->status= stat;
		cp = ASN1_skip(cp);
	}

	/* [0] SEQUENCE OF CertId OPTIONAL */
	in = ASN1_skip(in);
	if(*in==0xa0){
		cp = ASN1_next(in); /* skip explicit */
		len = ASN1_length(&cp[1],&i);
		cp = ASN1_next(cp);
		for(i=0;i<len;i+=j,cp+=j){
			j = ASN1_length(&cp[1],&k);
			j+= k+1;

			if((cid=CMP_certid_new())==NULL) goto error;
			cid->next = ret->revCerts;
			ret->revCerts = cid;

			ct = ASN1_next(cp);
			tmp= *ct; *ct=0x30;
			if((buf=ASN1_get_subject(ct,&cid->issuer))==NULL) goto error;
			*ct= tmp; FREE(buf);

			ct = ASN1_skip(ct);
			cid->serialNumber = ASN1_integer(ct,&k);
			if(k==0) goto error;
		}
		in = ASN1_skip(in);
	}

	/* [1] SEQUENCE OF CertificateList OPTIONAL */
	if(*in==0xa1){
		/* here, it only get a first CRL */
		cp = ASN1_next(in); /* skip explicit */
		cp = ASN1_next(cp); /* skip sequence of */
		if((ret->crl=ASN1_read_crl(cp))==NULL) goto error;
		if((ret->crl->der=ASN1_dup(cp))==NULL) goto error;
	}

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_KeyUpDAnn *ASN1_pkibd_keyupd(unsigned char *in){
	PKIBD_KeyUpDAnn *ret;

	if((ret=(PKIBD_KeyUpDAnn*)PKIbody_new(PKIBD_CAKEYUPD_ANN))==NULL) goto error;

	in = ASN1_next(in);
	if((ret->oldWithNew=ASN1_read_cert(in))==NULL) goto error;
	if((ret->oldWithNew->der=ASN1_dup(in))==NULL) goto error;
	in = ASN1_skip(in);
	if((ret->newWithOld=ASN1_read_cert(in))==NULL) goto error;
	if((ret->newWithOld->der=ASN1_dup(in))==NULL) goto error;
	in = ASN1_skip(in);
	if((ret->newWithNew=ASN1_read_cert(in))==NULL) goto error;
	if((ret->newWithNew->der=ASN1_dup(in))==NULL) goto error;

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_RevAnn *ASN1_pkibd_revann(unsigned char *in){
	PKIBD_RevAnn *ret;
	unsigned char *cp,tmp;
	char *buf;
	int i;

	if((ret=(PKIBD_RevAnn*)PKIbody_new(PKIBD_RVOC_ANN))==NULL) goto error;

	/* PKIStatus */
	in = ASN1_next(in);
	if((ret->status=ASN1_integer(in,&i))<0) goto error;

	/* CertId */
	in = ASN1_skip(in);
	cp = ASN1_next(in);
	tmp= *cp; *cp=0x30;
	if((buf=ASN1_get_subject(cp,&ret->certId.issuer))==NULL) goto error;
	*cp= tmp; FREE(buf);

	cp = ASN1_skip(cp);
	ret->certId.serialNumber = ASN1_integer(cp,&i);
	if(i==0) goto error;

	/* GeneralizedTime */
	in = ASN1_skip(in);
	if(UTC2stm(in,&ret->willBeRevokedAt)) goto error;

	/* GeneralizedTime */
	in = ASN1_next(in);
	if(UTC2stm(in,&ret->badSinceData)) goto error;

	/* Extensions OPTIONAL */
	in = ASN1_next(in);
	if(*in==0x30){
		if((ret->crlDetails=asn1_get_exts(in,&i))==NULL)
			goto error;
	}

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_CRLAnn *ASN1_pkibd_crlann(unsigned char *in){
	PKIBD_CRLAnn *ret;

	if((ret=(PKIBD_CRLAnn*)PKIbody_new(PKIBD_CRL_ANN))==NULL) goto error;

	/* SEQUENCE Of CertificateList */
	/* In RFC2510, it assumes that several CRLs are announced at once,
	 * but I just read a first CRL in this content for the imprementation.
	 */
	in = ASN1_next(in);
	if((ret->crl=ASN1_read_crl(in))==NULL) goto error;

	/* so far, crl->der is just pointer... */
	if((ret->crl->der=ASN1_dup(in))==NULL) goto error;

	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_Nested *ASN1_pkibd_nested(unsigned char *in){
	PKIBD_Nested *ret;
	unsigned char st;

	if((ret=(PKIBD_Nested*)PKIbody_new(PKIBD_NESTED_MSG))==NULL) goto error;

	st=*in; *in=0x30;
	if((ret->msg=ASN1_read_pkimsg(in))==NULL) goto error;
	*in=st;
	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_GenMsg *ASN1_pkibd_genmsg(unsigned char *in,int type){
	PKIBD_GenMsg *ret;
	InfoTAV *val,*hd=NULL;
	int i,j,len;

	if((ret=(PKIBD_GenMsg*)PKIbody_new(type))==NULL) goto error;

	/* SEQUENCE Of InfoTypeAndValue */
	len = ASN1_tlen(in);
	in  = ASN1_next(in);
	for(i=0;i<len;i+=j){
		if((val=ASN1_cmp_infotype(in,&j))==NULL) goto error;
		if(hd==NULL){
			ret->content = hd = val;
		}else{
			hd->next=(CertExt*)val; hd=val;
		}
		in = ASN1_skip(in);
	}
	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

PKIBD_ErrMsg *ASN1_pkibd_errmsg(unsigned char *in){
	PKIBD_ErrMsg *ret;
	unsigned char *cp;
	int i;

	if((ret=(PKIBD_ErrMsg*)PKIbody_new(PKIBD_ERR_MSG))==NULL) goto error;

	/* PKIStatusInfo */
	cp = ASN1_next(in);
	if((ret->status=ASN1_read_statinfo(cp,&i))==NULL) goto error;

	/* INTEGER OPTIONAL */
	cp = ASN1_skip(cp);
	if(*cp==ASN1_INTEGER){
		if((ret->errorCode=ASN1_integer(cp,&i))<0) goto error;
		cp = ASN1_next(cp);
	}
	/* PKIFreeText OPTIONAL */
	if(*cp==0x30){
		if(asn1_pki_freetext(cp,ret->errorDetails)) goto error;
	}
	return ret;
error:
	PKIbody_free((PKIBody*)ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 read other PKI structures.
-----------------------------------------*/
PKIStatusInfo *ASN1_read_statinfo(unsigned char *in,int *mv){
	PKIStatusInfo *ret=NULL;
	unsigned char *cp,*finfo;
	int stat,i,j;

	i = ASN1_length(&in[1],&j);
	*mv = i+1+j;

	/* PKIStatus */
	cp = ASN1_next(in);
	if((stat=ASN1_integer(cp,&i))<0) goto error;
	if((ret=(PKIStatusInfo*)PKI_statinfo_new(stat))==NULL) goto error;

	/* PKIFreeText OPTIONAL */
	cp = ASN1_next(cp);
	if((*cp==0x30)&&(*ASN1_next(cp)==ASN1_UTF8STRING)){
		if(asn1_pki_freetext(cp,ret->freeText)) goto error;
		cp = ASN1_skip(cp);
	}

	/* PKIFaillureInfo OPTIONAL */
	if(*cp==ASN1_BITSTRING){
		if(ASN1_bitstring(cp,&i,&finfo,&j,&j)) goto error;
		memcpy(ret->failInfo,finfo,2);
		FREE(finfo);
	}
	return ret;
error:
	PKI_statinfo_free_all(ret);
	return NULL;
}

int asn1_pki_freetext(unsigned char *in, char *ftxt[]){
	unsigned char *cp;
	int i,j,k,len;

	if(*in!=0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1CMP,ERR_PT_ASN_PKIBD,NULL);
		return -1;
	}
	len= ASN1_tlen(in);
	cp = ASN1_next(in);

	for(i=j=0;j<len;i++){
		if((ftxt[i]=ASN1_utf8(cp,&k))==NULL) return -1;
		j+= k;
		cp= ASN1_next(cp);
	}
	return 0;
}

int asn1_pki_certreq(unsigned char *in, struct CertRequest *req){
	int j;

	in = ASN1_next(in);
	/* INTEGER */
	req->certReqId = ASN1_integer(in,&j);
	if(j==0) goto error;
	in = ASN1_next(in);

	/* CertTemplate */
	if((req->certTemplate=ASN1_cmp_certtmpl(in,&j))==NULL)
		goto error;
	in = ASN1_skip(in);

	/* Controls OPTIONAL */
	/* hmm.., this poor checking might be problem with
	 * next CertReqMsg or regInfo (SEQ OF AttTypeAndValue OPTIONAL)
	 */
	if((*in==0x30)&&(in[1]>0)){
		if((req->controls=asn1_get_attrs(in,&j))==NULL)
			goto error;
	}

	return 0;
error:
	return -1;
}
