/* asn1_pkihd.c */
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
  ASN.1 read PKI Header.
-----------------------------------------*/
PKIHeader *ASN1_read_pkihead(unsigned char *der){
	PKIHeader *ret=NULL;
	InfoTAV *val,*hd=NULL;
	unsigned char *cp,*ct;
	char *buf;
	int i,j,len;

	if(der==NULL) goto error;

	if(*der!=0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1CMP,ERR_PT_ASN_PKIHD,NULL);
		goto error;
	}

	if((ret=PKIhead_new())==NULL) goto error;

	/* INTEGER */
	cp = ASN1_next(der);
	if((ret->pvno=ASN1_integer(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* GeneralName -- this should be "Name" */
	if((buf=ASN1_get_subject(ASN1_next(cp),&ret->sender))==NULL) goto error;
	cp = ASN1_skip(cp);
	FREE(buf);

	/* GeneralName -- this should be "Name" */
	if((buf=ASN1_get_subject(ASN1_next(cp),&ret->recipient))==NULL) goto error;
	cp = ASN1_skip(cp);
	FREE(buf);

	ct = ASN1_next(cp);
	/* [0] GeneralizedTime OPTIONAL */
	if((*cp==0xa0)&&((*ct==ASN1_UTCTIME)||(*ct==ASN1_GENERALIZEDTIME))){
		ct = ASN1_next(cp); /* skip explicit */
		if(UTC2stm(ct,&ret->messageTime)) goto error;
		cp = ASN1_skip(cp);
	}

	ct = ASN1_next(cp);
    /* [1] Algorithm Identifier OPTIONAL */
	if((*cp==0xa1)&&(*ct==0x30)){
		ct = ASN1_step(cp,2); /* skip explicit */
		if((ret->protectionAlg=ASN1_object_2int(ct))<0) goto error;
		cp = ASN1_skip(cp);
	}

	ct = ASN1_next(cp);
	/* [2] KeyIdentifier (OCTETSTRING) OPTIONAL */
	if((*cp==0xa2)&&(*ct==ASN1_OCTETSTRING)){
		ct = ASN1_next(cp); /* skip explicit */
		if(ASN1_octetstring(ct,&i,&ret->senderKID,&ret->skid_len))
			goto error;
		cp = ASN1_skip(cp);
	}

	ct = ASN1_next(cp);
	/* [3] KeyIdentifier OPTIONAL */
	if((*cp==0xa3)&&(*ct==ASN1_OCTETSTRING)){
		ct = ASN1_next(cp); /* skip explicit */
		if(ASN1_octetstring(ct,&i,&ret->recipKID,&ret->rkid_len))
			goto error;
		cp = ASN1_skip(cp);
	}

	ct = ASN1_next(cp);
	/* [4] OCTET STRING OPTIONAL */
	if((*cp==0xa4)&&(*ct==ASN1_OCTETSTRING)){
		ct = ASN1_next(cp); /* skip explicit */
		if(ASN1_octetstring(ct,&i,&ret->transactionID,&ret->trid_len))
			goto error;
		cp = ASN1_skip(cp);
	}

	ct = ASN1_next(cp);
	/* [5] OCTET STRING OPTIONAL */
	if((*cp==0xa5)&&(*ct==ASN1_OCTETSTRING)){
		ct = ASN1_next(cp); /* skip explicit */
		if(ASN1_octetstring(ct,&i,&ret->senderNonce,&ret->snon_len))
			goto error;
		cp = ASN1_skip(cp);
	}

	ct = ASN1_next(cp);
	/* [6] OCTET STRING OPTIONAL */
	if((*cp==0xa6)&&(*ct==ASN1_OCTETSTRING)){
		ct = ASN1_next(cp); /* skip explicit */
		if(ASN1_octetstring(ct,&i,&ret->recipNonce,&ret->rnon_len))
			goto error;
		cp = ASN1_skip(cp);
	}

	/* [7] PKIFreeText OPTIONAL */
	if(*cp==0xa7){
		ct = ASN1_next(cp); /* skip explicit */
		if(asn1_pki_freetext(ct,ret->freeText)) goto error;
		cp = ASN1_skip(cp);
	}

	/* [8] SEQUENCE OF InfoTypeAndValue OPTIONAL */
	if(*cp==0xa8){
		ct = ASN1_next(cp); /* skip explicit */
		len= ASN1_tlen(ct);
		ct = ASN1_next(ct);

		for(i=0;i<len;i+=j){
			if((val=ASN1_cmp_infotype(ct,&j))==NULL) goto error;
			if(hd==NULL){
				ret->generalInfo = hd = val;
			}else{
				hd->next=(CertExt*)val; hd=val;
			}
			ct = ASN1_skip(ct);
		}
	}

	return ret;
error:
	PKIhead_free(ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 read InfoTypeAndValue.
-----------------------------------------*/
InfoTAV *ASN1_cmp_infotype(unsigned char *in,int *mv){
	InfoTAV *ret;
	unsigned char *cp;
	int i,j;

	*mv = ASN1_length(&in[1],&i);
	*mv+= 1+i;

	in = ASN1_next(in);

	/* OBJECT IDENTIFIER */
	if((i=ASN1_object_2int(in))<=0) goto error;
	cp = ASN1_next(in);

	/* any defined by infoType OPTIONAL */
	switch(i){
	case OBJ_PKIX_IDIT_CAPROT: /* Certificate */
		{
			Cert *ct;
			if(ct=ASN1_read_cert(cp)){
				/* the ct->der has a same pointer of "cp", then this should have
				 * allocated memory buffer because Cert_free() operation frees 
				 * ct->der memory pointer.
				 */
				if((ct->der=ASN1_dup(cp))==NULL) goto error;

				if((ret=CMP_infotype_new(ASN1_dup(in),ct))==NULL) /* set oid */
					goto error;
			}
		}
		break;

	case OBJ_PKIX_IDIT_SIGNKEY:
	case OBJ_PKIX_IDIT_ENCKEY: /* SEQUENCE OF AlgorithmIdentifier */
		/* not supported now */
		break;

	case OBJ_PKIX_IDIT_PREFSYM: /* AlgorithmIdentifier */
		if(*cp==0x30){
			cp = ASN1_next(cp);
			if((j=ASN1_object_2int(cp))>0){
				if((ret=CMP_infotype_new(ASN1_dup(in),(void*)j))==NULL)
					goto error;
			}
		}
		break;

	case OBJ_PKIX_IDIT_CAKEYUPD:
		{
			PKIBD_KeyUpDAnn *kupd;
			if(kupd=ASN1_pkibd_keyupd(cp)){
				if((ret=CMP_infotype_new(ASN1_dup(in),kupd))==NULL)
					goto error;
			}
		}
		break;

	case OBJ_PKIX_IDIT_CURCRL:
		{
			CRL *crl;
			if(crl=ASN1_read_crl(cp)){
				/* the crl->der has a same pointer of "cp", then this should have
				 * allocated memory buffer because CRL_free() operation frees 
				 * crl->der memory pointer.
				 */
				if((crl->der=ASN1_dup(cp))==NULL) goto error;

				if((ret=CMP_infotype_new(ASN1_dup(in),crl))==NULL)
					goto error;
			}
		}
		break;

	default:
		ret = (InfoTAV*)ASN1_get_ext(i, cp);
	}

	return ret;
error:
	CMP_infotype_free_all(ret);
	return NULL;
}
