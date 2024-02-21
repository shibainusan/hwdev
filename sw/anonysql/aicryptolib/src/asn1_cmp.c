/* asn1_cmp.c */
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
  ASN.1 read struct CertTemplate
-----------------------------------------*/
CertTemplate *ASN1_cmp_certtmpl(unsigned char *in,int *mv){
	CertTemplate *ret;
	unsigned char *t,*cp;
	char *buf;
	int i;

	*mv = ASN1_length(&in[1],&i);
	*mv+= 1+i;

	if((ret=CMP_certtmpl_new())==NULL) goto error;

	in = ASN1_next(in);
	/* [0] implicit Version OPTIONAL */
	if(*in==0x80){
		if((ret->version=ASN1_integer_(in,&i,1))<0) goto error;
		in = ASN1_skip(in);
	}
	/* [1] implicit INTEGER OPTIONAL */
	if(*in==0x81){
		if(ASN1_tlen(in)>4){ /* long serial number */
			if((ret->snum_der=ASN1_dup(in))==NULL) goto error;
			ret->snum_der[0] = ASN1_INTEGER;
		}else{
			if((ret->serialNumber=ASN1_integer_(in,&i,1))<0) goto error;
		}
		in = ASN1_skip(in);
	}
	/* [2] implicit AlgorithmIdentifier OPTIONAL */
	if(*in==0xa2){
		cp = ASN1_next(in);
		if((ret->signingAlg=ASN1_object_2int(cp))<0) goto error;
		in = ASN1_skip(in);
	}
	/* [3] implicit Name OPTIONAL */
	if(*in==0xa3){
		cp = ASN1_next(in);
		if((buf=ASN1_get_subject(cp,&ret->issuer))==NULL) goto error;
		in = ASN1_skip(in);
		FREE(buf);
	}
	/* [4] implicit OptionalValidity OPTIONAL */
	if(*in==0xa4){
		cp = ASN1_next(in);
		if(*cp==0xa0){ /* OPTIONAL */
			t  = ASN1_next(cp);
			if(UTC2stm(t,&ret->validity.notBefore)) goto error;
			cp = ASN1_skip(cp);
		}
		if(*cp==0xa1){ /* OPTIONAL */
			t  = ASN1_next(cp);
			if(UTC2stm(t,&ret->validity.notAfter)) goto error;
		}
		in = ASN1_skip(in);
	}
	/* [5] implicit Name OPTIONAL */
	if(*in==0xa5){
		cp = ASN1_next(in);
		if((buf=ASN1_get_subject(cp,&ret->subject))==NULL) goto error;
		in = ASN1_skip(in);
		FREE(buf);
	}
	/* [6] implicit SubjectPublicKeyInfo OPTIONAL */
	if(*in==0xa6){
		if((ret->publicKey=ASN1_get_pubkey(in))==NULL) goto error;
		in = ASN1_skip(in);
	}

	/* [7] implicit UniqueIdentifier OPTIONAL */
	if(*in==0xa7){
		/* not used any more */
		in = ASN1_skip(in);
	}
	/* [8] implicit UniqueIdentifier OPTIONAL */
	if(*in==0xa8){
		/* not used any more */
		in = ASN1_skip(in);
	}

	/* [9] implicit Extensions OPTIONAL */
	if((*in==0xa9)&&(in[1]>0)){
		if((ret->ext=asn1_get_exts(in,&i))==NULL) goto error;
	}
	return ret;

error:
	CMP_certtmpl_free(ret);
	return NULL;
}

/*
 * Proof of Possession
 */
/*-----------------------------------------
  ASN.1 read struct POfP
-----------------------------------------*/
POfP *ASN1_cmp_pofp(unsigned char *in){
	POfP *ret;

	if((ret=CMP_pofp_new())==NULL) goto error;

	ret->choice=(*in&0x1f);
	switch(ret->choice){
	case 0: /* NULL */
		break;
	case 1:
		if((ret->signature=ASN1_cmp_poposign(in))==NULL) goto error;
		break;
	case 2:
		if((ret->keyEncipherment=ASN1_cmp_popopriv(in))==NULL) goto error;
		break;
	case 3:
		if((ret->keyAgreement=ASN1_cmp_popopriv(in))==NULL) goto error;
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ASN1CMP,ERR_PT_ASN_CMP+1,NULL);
		goto error;
	}
	return ret;
error:
	CMP_pofp_free(ret);
	return NULL;
}

POPOSigningKey *ASN1_cmp_poposign(unsigned char *in){
	POPOSigningKey *ret;
	unsigned char *cp,st;
	char *buf;
	int i,j;

	if((ret=CMP_poposign_new())==NULL) goto error;
	in = ASN1_next(in);

	/* [0] implicit POPOSigningKeyInput OPTIONAL */
	if(*in==0xa0){
		cp = ASN1_next(in);
		ret->poposkInput.option = 1;
		/* authInfo CHOICE */
		if(*cp==0xa0){
			st=*cp; *cp=0x30;
			if((buf=ASN1_get_subject(cp,&ret->poposkInput.sender))==NULL)
				goto error;
			*cp=st; FREE(buf);
		}else{
			if((ret->poposkInput.publicKeyMac=ASN1_cmp_pkmacv(cp))==NULL)
				goto error;
		}
		/* SubjectPublicKeyInfo */
		cp = ASN1_skip(cp);
		if((ret->poposkInput.publicKey=ASN1_get_pubkey(cp))==NULL)
			goto error;
		in = ASN1_skip(in);
	}

	/* AlgorithmIdentifier */
	cp = ASN1_next(in);
	if((ret->algo_id=ASN1_object_2int(cp))<0) goto error;
	in = ASN1_skip(in);

	/* BITSTRING */
	if(ASN1_bitstring(in,&i,&ret->signature,&ret->sig_len,&j)) goto error;

	return ret;
error:
	CMP_poposign_free(ret);
	return NULL;
}

POPOPrivKey *ASN1_cmp_popopriv(unsigned char *in){
	POPOPrivKey *ret;
	unsigned char st;
	int i,j;

	if((ret=CMP_popopriv_new())==NULL) goto error;

	/* CHOICE */
	ret->choice=(*in&0x1f);
	st=*in;
	switch(ret->choice){
	case 0: /* [0] implicit BITSTRING */
		*in=ASN1_BITSTRING;
		if(ASN1_bitstring(in,&i,&ret->thisMessage,&ret->tm_len,&j))
			goto error;
		break;
	case 1: /* [1] implicit INTEGER */
		*in=ASN1_INTEGER;
		if((ret->subsequentMessage=ASN1_integer(in,&i))<0)
			goto error;
		break;
	case 2: /* [2] implicit BITSTRING */
		*in=ASN1_BITSTRING;
		if(ASN1_bitstring(in,&i,&ret->dhMAC,&ret->dh_len,&j))
			goto error;
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ASN1CMP,ERR_PT_ASN_CMP+3,NULL);
		goto error;
	}
	*in=st;

	return ret;
error:
	CMP_popopriv_free(ret);
	return NULL;
}

PKMACValue *ASN1_cmp_pkmacv(unsigned char *in){
	PKMACValue *ret;
	unsigned char *cp;
	int i,j;

	if((ret=CMP_pkmacv_new())==NULL) goto error;
	in = ASN1_next(in);

	/* AlgorithmIdentifier */
	cp = ASN1_next(in);
	if((ret->algId=ASN1_object_2int(cp))<0) goto error;
	in = ASN1_skip(in);

	/* BITSTRING */
	if(ASN1_bitstring(in,&i,&ret->value,&ret->vlen,&j))
		goto error;

	return ret;
error:
	CMP_pkmacv_free(ret);
	return NULL;
}



/*
 * CertifiedKeyPair & EncryptedValue
 */
/*-----------------------------------------
  ASN.1 read struct EncryptedValue
-----------------------------------------*/
EncryptedValue *ASN1_cmp_encval(unsigned char *in){
	EncryptedValue *ret;
	unsigned char *cp,*tmp;
	int i,j;

	if((ret=CMP_encval_new())==NULL) goto error;
	in = ASN1_next(in);

	/* [0] implicit AlgorithmIdentifier OPTIONAL */
	if(*in==0xa0){
		cp = ASN1_next(in);
		if((ret->intendedAlg=ASN1_object_2int(cp))<0) goto error;
		in = ASN1_skip(in);
	}
	/* [1] implicit AlgorithmIdentifier OPTIONAL */
	if(*in==0xa1){
		cp = ASN1_next(in);
		if((ret->symmAlg=ASN1_object_2int(cp))<0) goto error;
		if((ret->symmKey=Key_new(ret->symmAlg))==NULL) goto error;

		cp = ASN1_next(cp);
		if(*cp==ASN1_OCTETSTRING){
			if(ASN1_octetstring_(cp,&i,&tmp,&j,1)) goto error;
			if(Key_set_iv(ret->symmKey,tmp)) goto error;
			FREE(tmp);
		}
		in = ASN1_skip(in);
	}

	/* [2] implicit BITSTRING OPTIONAL */
	if(*in==0x82){
		if(ASN1_bitstring_(in,&i,&ret->enc_symmkey,&ret->esymm_len,&j,1)) goto error;
		in = ASN1_next(in);
	}

	/* [3] implicit AlgorithmIdentifier OPTIONAL */
	if(*in==0xa3){
		cp = ASN1_next(in);
		if((ret->keyAlg=ASN1_object_2int(cp))<0) goto error;
		in = ASN1_skip(in);
	}

	/* [4] implicit OCTETSTRING OPTIONAL */
	if(*in==0x84){
		if(ASN1_octetstring_(in,&i,&ret->valueHint,&ret->hint_len,1)) goto error;
		in = ASN1_next(in);
	}

	/* BITSTRING */
	if(ASN1_bitstring(in,&i,&ret->encValue,&ret->enc_len,&j)) goto error;

	return ret;
error:
	CMP_encval_free(ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 read struct PKIPubInfo
-----------------------------------------*/
PKIPubInfo *ASN1_cmp_pubinfo(unsigned char *in){
	PKIPubInfo *ret;
	unsigned char *cp;
	int i,j,k,l,len;

	if((ret=CMP_pubinfo_new())==NULL) goto error;
	in = ASN1_next(in);

	/* INTEGER */
	if((ret->action=ASN1_integer(in,&i))<0) goto error;
	in = ASN1_next(in);

	/* SEQUENCE OF SinglePubInfo OPTIONAL
	 * -- List Max is 4 */
	if(*in==0x30){
		len= ASN1_length(&in[1],&i);
		in = ASN1_next(in);
		for(i=k=0;(i<len)&&(k<4);i+=j,in+=j,k++){
			j = ASN1_length(&in[1],&l);
			j+= l+1;

			/* INTEGER */
			cp = ASN1_next(in);
			if((ret->pubInfo[k].pubMethod=ASN1_integer(cp,&l))<0) goto error;

			/* GeneralName OPTIONAL */
			cp = ASN1_next(cp);
			if(*cp&0x80){ /* implicit tag */
				if((ret->pubInfo[k].pubLocation=asn1_get_genname(cp))==NULL)
					goto error;
			}
		}
	}
	return ret;
error:
	CMP_pubinfo_free(ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 read struct CertifiedKeyPair
-----------------------------------------*/
CertifiedKeyPair *ASN1_cmp_ctkeypair(unsigned char *in,int *mv){
	CertifiedKeyPair *ret;
	unsigned char *cp;
	int i;

	*mv = ASN1_length(&in[1],&i);
	*mv+= i+1;

	if((ret=CMP_ctkeypair_new())==NULL) goto error;

	in = ASN1_next(in);

	/* CertOrEncCert CHOICE */
	if(*in==0xa0){
		/* [0] Certificate */
		cp = ASN1_next(in);
		if((ret->certOrEncCert.cert=ASN1_read_cert(cp))==NULL) goto error;
		if((ret->certOrEncCert.cert->der=ASN1_dup(cp))==NULL) goto error;
	}else{
		/* [1] EncryptedValue */
		cp = ASN1_next(in);
		if((ret->certOrEncCert.encCert=ASN1_cmp_encval(cp))==NULL) goto error;
	}
	in = ASN1_skip(in);

	/* [0] EncryptedValue OPTIONAL */
	if((*in==0xa0)&&(*ASN1_next(in)==0x30)){
		cp = ASN1_next(in);
		if((ret->privateKey=ASN1_cmp_encval(cp))==NULL) goto error;
		in = ASN1_skip(in);
	}

	/* [1] PKIPublicationInfo OPTIONAL */
	if((*in==0xa1)&&(*ASN1_next(in)==0x30)){
		cp = ASN1_next(in);		
		if((ret->publicationInfo=ASN1_cmp_pubinfo(cp))==NULL) goto error;
	}
	return ret;
error:
	CMP_ctkeypair_free(ret);
	return NULL;
}

/*
 *	CertResponse
 */
/*-----------------------------------------
  ASN.1 read struct CertResponse
-----------------------------------------*/
CertResponse *ASN1_cmp_certrsp(unsigned char *in,int *mv){
	CertResponse *ret;
	int i;

	*mv = ASN1_length(&in[1],&i);
	*mv+= i+1;
	
	if((ret=CMP_certrsp_new())==NULL) goto error;
	in = ASN1_next(in);

	/* INTEGER */
	ret->certReqID=ASN1_integer(in,&i);
	if(i==0) goto error;
	in = ASN1_next(in);

	/* PKIStatusInfo */
	if((ret->status=ASN1_read_statinfo(in,&i))==NULL) goto error;
	in = ASN1_skip(in);

	/* CertifiedKeyPair OPTIONAL */
	if((ret->certifiedKeyPair=ASN1_cmp_ctkeypair(in,&i))==NULL) goto error;
	in = ASN1_skip(in);

	/* OCTETSTRING OPTIONAL */
	if(*in==ASN1_OCTETSTRING){
		if(ASN1_octetstring(in,&i,&ret->rspInfo,&ret->rsp_len))
			goto error;
	}

	return ret;
error:
	CMP_certrsp_free(ret);
	return NULL;
}

