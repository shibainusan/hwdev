/* pkihd_asn1.c */
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
  Get pki head DER.
-----------------------------------------*/
unsigned char *PKIhead_toDER(PKIHeader *pki,unsigned char *buf,int *ret_len){
	InfoTAV *itv;
	unsigned char *cp,*ct,*ret;
	int	i,j,l;

	if(buf==NULL){
		if((i=PKIhead_estimate_der_size(pki))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIHD_ASN,NULL);
			return NULL;
		}
		memset(ret,0,i);
	}else{
		ret=buf;
	}

	/* pvno INTEGERR */
	ASN1_set_integer(pki->pvno,ret,&i);
	cp =ret+i; j=i;

	/* sender GeneralName [4] */
	if(Cert_DER_subject(&pki->sender,cp,&i)) goto error;
	ASN1_set_explicit(i,4,cp,&i);
	cp+=i; j+=i;

	/* recipient GeneralName [4] */
	if(Cert_DER_subject(&pki->recipient,cp,&i)) goto error;
	ASN1_set_explicit(i,4,cp,&i);
	cp+=i; j+=i;

	/* messageTime [0] GeneralizedTime OPTIONAL */
	if(pki->messageTime.tm_year){
		stm2UTC(&pki->messageTime,cp,ASN1_GENERALIZEDTIME);
		i=ASN1_tlen(cp)+2;
		ASN1_set_explicit(i,0,cp,&i);
		cp+=i; j+=i;
	}
	/* protectionAlg [1] AlgorithmIdentifier OPTIONAL */
	if(pki->protectionAlg){
		if(x509_DER_algoid(pki->protectionAlg,NULL,cp,&i)) goto error;
		ASN1_set_explicit(i,1,cp,&i);
		cp+=i; j+=i;
	}
	/* senderKID [2] KeyIdentifier OPTIONAL */
	if(pki->senderKID){
		ASN1_set_octetstring(pki->skid_len,pki->senderKID,cp,&i);
		ASN1_set_explicit(i,2,cp,&i);
		cp+=i; j+=i;
	}
	/* recipKID  [3] KeyIdentifier OPTIONAL */
	if(pki->recipKID){
		ASN1_set_octetstring(pki->rkid_len,pki->recipKID,cp,&i);
		ASN1_set_explicit(i,3,cp,&i);
		cp+=i; j+=i;
	}
	/* transactionID [4] OCTET STRING OPTIONAL */
	if(pki->transactionID){
		ASN1_set_octetstring(pki->trid_len,pki->transactionID,cp,&i);
		ASN1_set_explicit(i,4,cp,&i);
		cp+=i; j+=i;
	}
	/* senderNonce [5] OCTET STRING OPTIONAL */
	if(pki->senderNonce){
		ASN1_set_octetstring(pki->snon_len,pki->senderNonce,cp,&i);
		ASN1_set_explicit(i,5,cp,&i);
		cp+=i; j+=i;
	}
	/* recipNonce [6] OCTET STRING OPTIONAL */
	if(pki->recipNonce){
		ASN1_set_octetstring(pki->rnon_len,pki->recipNonce,cp,&i);
		ASN1_set_explicit(i,6,cp,&i);
		cp+=i; j+=i;
	}
	/* freeText [7] PKIFreeText OPTIONAL */
	if(PKI_DER_freetext(pki->freeText,cp,&i)) goto error;
	if(i) ASN1_set_explicit(i,7,cp,&i);
	cp+=i; j+=i;

	/* generalInfo [8] SEQUENCE SIZE (1..MAX) OF 
	 *             InfoTypeAndValue OPTIONAL */
	itv=pki->generalInfo;
	ct=cp; l=0;
	while(itv){
		/* depend on the content */
		if(CMP_DER_infotype(itv,ct,&i)) goto error;
		ct+=i; l+=i;

		itv=(InfoTAV*)itv->next;
	}
	if(l){
		ASN1_set_sequence(l,cp,&i);
		ASN1_set_explicit(i,8,cp,&i);
		cp+=i; j+=i;
	}

	ASN1_set_sequence(j,ret,ret_len);

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  Get InfoTypeAndValue DER.
-----------------------------------------*/
int CMP_DER_infotype(InfoTAV *itv,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,k;

	/* OBJECT IDENTIFIER */
	if(ASN1_int_2object(itv->extnID,ret,&j)<0) goto error;
	cp =ret+j;

	/* ANY DEFINED BY infoType OPTIONAL */
	if((itv->infoValue)||(itv->der)){
		switch(itv->extnID){
		case OBJ_PKIX_IDIT_CAPROT: /* Certificate */
			if(((Cert*)itv->infoValue)->der==NULL){
				OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIHD_ASN+1,NULL);
				goto error;
			}
			k =ASN1_length(&((Cert*)itv->infoValue)->der[1],&i);
			k+=i+1;
			j+=k;
			memcpy(cp,((Cert*)itv->infoValue)->der,k);
			break;

		case OBJ_PKIX_IDIT_SIGNKEY:
		case OBJ_PKIX_IDIT_ENCKEY: /* SEQUENCE OF AlgorithmIdentifier */
			/* not supported now */
			break;

		case OBJ_PKIX_IDIT_PREFSYM: /* AlgorithmIdentifier */
			if(x509_DER_algoid((int)itv->infoValue,NULL,cp,&i)) goto error;
			j+=i;
			break;

		case OBJ_PKIX_IDIT_CAKEYUPD:
			if(PKIbd_DER_keyupd((PKIBD_KeyUpDAnn*)itv->infoValue,cp,&i)) goto error;
			j+=i;
			break;

		case OBJ_PKIX_IDIT_CURCRL:
			if(((CRL*)itv->infoValue)->der==NULL){
				OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIHD_ASN+1,NULL);
				goto error;
			}
			k =ASN1_length(&((CRL*)itv->infoValue)->der[1],&i);
			k+=i+1;
			j+=k;
			memcpy(cp,((CRL*)itv->infoValue)->der,k);
			break;

		default: /* set like CertExt */
			ASN1_skip_(itv->der,&k);
			memcpy(cp,itv->der,k);
			j+=k;
		}
	}
	ASN1_set_sequence(j,ret,ret_len);
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  estimate size of PKIheader DER
-----------------------------------------*/
int PKIhead_estimate_der_size(PKIHeader *pki){
	int j,i=32;

	if(pki->messageTime.tm_year) i+=18;
	if(pki->protectionAlg) i+=16;

	i+=der_size_name(&pki->sender);
	i+=der_size_name(&pki->recipient);

	i+=pki->skid_len+4;
	i+=pki->rkid_len+4;
	i+=pki->trid_len+4;
	i+=pki->snon_len+4;
	i+=pki->rnon_len+4;

	if((j=der_size_freetext(pki->freeText))<0) return -1;
	i+=j;

	if((j=der_size_infotype(pki->generalInfo))<0) return -1;
	i+=j;

	return i;
}

int der_size_infotype(InfoTAV *itv){
	int i,ret=4;

	while(itv){
		/* depend on the content */
		ret+=20;
		if((itv->infoValue)||(itv->der)){
			switch(itv->extnID){
			case OBJ_PKIX_IDIT_CAPROT: /* Certificate */
				if(((Cert*)itv->infoValue)->der==NULL){
					OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIHD_ASN+3,NULL);
					goto error;
				}
				ret+=ASN1_length(&((Cert*)itv->infoValue)->der[1],&i);
				ret+=i+1;
				break;

			case OBJ_PKIX_IDIT_SIGNKEY:
			case OBJ_PKIX_IDIT_ENCKEY: /* SEQUENCE OF AlgorithmIdentifier */
				break;

			case OBJ_PKIX_IDIT_PREFSYM: /* AlgorithmIdentifier */
				ret+=16;
				break;

			case OBJ_PKIX_IDIT_CAKEYUPD:
				if((i=der_size_keyupd((PKIBD_KeyUpDAnn*)itv->infoValue))<0) goto error;
				ret+=i;
				break;

			case OBJ_PKIX_IDIT_CURCRL:
				if(((CRL*)itv->infoValue)->der==NULL){
					OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIHD_ASN+3,NULL);
					goto error;
				}
				ret+=ASN1_length(&((CRL*)itv->infoValue)->der[1],&i);
				ret+=i+1;
				break;

			default: /* count Extention length */
				ret+=itv->dlen;
				break;
			}
		}

		itv=(InfoTAV*)itv->next;
	}
	return ret;
error:
	return -1;
}

