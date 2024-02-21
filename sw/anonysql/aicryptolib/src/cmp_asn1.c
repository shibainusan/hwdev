/* cmp_asn1.c */
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
  Get CertTemplate DER
-----------------------------------------*/
int CMP_DER_certtmpl(CertTemplate *ctp,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	int i,j,k;

	if(ctp == NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN,NULL);
		goto error;
	}
	cp = ret; k=0;
	/* implicit TAGs */
	/* version  [0] Version OPTIONAL */
	if(ctp->version != -1){
		ASN1_set_integer(ctp->version,cp,&i);
		*cp = 0x80; cp+=i; k+=i;
	}
	/* serialNumber [1] INTEGER OPTIONAL */
	if(ctp->snum_der){
		ASN1_skip_(ctp->snum_der,&i);
		memcpy(cp,ctp->snum_der,i);
		*cp = 0x81; cp+=i; k+=i;
	}else if(ctp->serialNumber != -1){
		ASN1_set_integer(ctp->serialNumber,cp,&i);
		*cp = 0x81; cp+=i; k+=i;
	}
	/* signingAlg [2] AlgorithmIdentifier OPTIONAL */
	if(ctp->signingAlg){
		if(x509_DER_algoid(ctp->signingAlg,ctp->publicKey,cp,&i)) goto error;
		*cp = 0xa2; cp+=i; k+=i;
	}
	/* issuer   [3] Name OPTIONAL */
	if(ctp->issuer.num){
		if(Cert_DER_subject(&ctp->issuer,cp,&i)) goto error;
		ASN1_set_explicit(i,3,cp,&i);
		cp+=i; k+=i;
	}
	/* validity [4] OptionalValidity OPTIONAL */
	ct=cp; j=0;
	if(ctp->validity.notBefore.tm_year){
		if(Cert_DER_time(&ctp->validity.notBefore,ct,&i)) goto error;
		ASN1_set_explicit(i,0,ct,&i);
		ct+=i; j+=i;
	}
	if(ctp->validity.notAfter.tm_year){
		if(Cert_DER_time(&ctp->validity.notAfter,ct,&i)) goto error;
		ASN1_set_explicit(i,1,ct,&i);
		j+=i;
	}
	if(j){
		ASN1_set_explicit(j,4,cp,&i);
		cp+=i; k+=i;
	}

	/* subject  [5] Name OPTIONAL */
	if(ctp->subject.num){
		if(Cert_DER_subject(&ctp->subject,cp,&i)) goto error;
		ASN1_set_explicit(i,5,cp,&i);
		cp+=i; k+=i;
	}
	/* publicKey [6] SubjectPublicKeyInfo OPTIONAL */
	if(ctp->publicKey){
		if(x509_DER_pubkey(ctp->publicKey,cp,&i)) goto error;
		*cp = 0xa6; cp+=i; k+=i;
	}

	/* issuerUID [7] UniqueIdentifier OPTIONAL -- ignore it*/
	/* subjectUID [8] UniqueIdentifier OPTIONAL -- ignore it */

	/* extensions [9] Extensions OPTIONAL */
	if(ctp->ext){
		if(x509_DER_exts(ctp->ext,cp,&i)) goto error;
		*cp = 0xa9; k+=i;
	}
	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

/*
 * Proof of Possession
 */
/*-----------------------------------------
  Get POfP DER
-----------------------------------------*/
int CMP_DER_pofp(POfP *pop,unsigned char *ret,int *ret_len){

	if(pop == NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+1,NULL);
		goto error;
	}

	/* ProofOfPossession ::= CHOICE { */
	switch(pop->choice){
	case 0: /* raVerified [0] NULL */
		ASN1_set_null(ret);
		*ret = 0x80;
		*ret_len = 2;
		break;

	case 1: /* signauture [1] POPOSigningKey */
		if(CMP_DER_poposign(pop->signature,ret,ret_len))
			goto error;
		*ret = 0xa1;
		break;

	case 2: /* keyEncipherment [2] POPOPrivKey */
		if(CMP_DER_popopriv(pop->keyEncipherment,ret,ret_len))
			goto error;
		*ret = 0xa2;
		break;

	case 3: /* keyAgreement [3] POPOPrivKey */
		if(CMP_DER_popopriv(pop->keyAgreement,ret,ret_len))
			goto error;
		*ret = 0xa3;
		break;

	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_CMP_ASN+1,NULL);
		goto error;
	}
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  Get POPOSigningKey DER
-----------------------------------------*/
int CMP_DER_poposign(POPOSigningKey *pps,unsigned char *ret,int *ret_len){
	unsigned char *cp=ret;
	int i,k=0;

	if(pps == NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+2,NULL);
		goto error;
	}
	/* poposkInput [0]POPOSigningKeyInput OPTIONAL */
	if(pps->poposkInput.option){
		/* authInfo CHOICE { */
		if(pps->poposkInput.sender.num){
			/* sender [0] GeneralName */
			if(Cert_DER_subject(&pps->poposkInput.sender,ret,&k)) goto error;
			cp= ret+k; *ret = 0xa0;

		}else if(pps->poposkInput.publicKeyMac){
			/* publicKeyMAC PKMACValue */
			if(CMP_DER_pkmacv(pps->poposkInput.publicKeyMac,ret,&k)) goto error;
			cp= ret+k;

		}else{
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+2,NULL);
			goto error;
		}
		/* publicKey SubjectPublicKeyInfo */
		if(x509_DER_pubkey(pps->poposkInput.publicKey,cp,&i)) goto error;
		k+=i;

		/* it's not explicit but implicit [0] of POPOSigningKeyInput :-)
		 */
		ASN1_set_explicit(k,0,ret,&k);
		cp = ret+k;
	}

	/* algorithmIdentifier AlgorithmIdentifier */
	if(x509_DER_algoid(pps->algo_id,pps->poposkInput.publicKey,cp,&i)) goto error;
	cp+=i; k+=i;
	
	/* signature BITSTRING */
	ASN1_set_bitstring(0,pps->sig_len,pps->signature,cp,&i);
	k+=i;

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  Get POPOPrivKey DER
-----------------------------------------*/
int CMP_DER_popopriv(POPOPrivKey *pp,unsigned char *ret,int *ret_len){

	if(pp == NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+3,NULL);
		goto error;
	}

	/* POPOPrivKey ::= CHOICE { */
	switch(pp->choice){
	case 0: /* thisMessage [0] BIT STRING */
		if(pp->thisMessage == NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+3,NULL);
			goto error;
		}
		ASN1_set_bitstring(0,pp->tm_len,pp->thisMessage,ret,ret_len);
		break;

	case 1: /* subsequentMessage [1] SubsequentMessage */
		if(pp->subsequentMessage<0){
			OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_CMP_ASN+3,NULL);
			goto error;
		}
		ASN1_set_integer(pp->subsequentMessage,ret,ret_len);
		break;

	case 2: /* dhMAC [2] BIT STRING */
		if(pp->dhMAC == NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+3,NULL);
			goto error;
		}
		ASN1_set_bitstring(0,pp->dh_len,pp->dhMAC,ret,ret_len);
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_CMP_ASN+3,NULL);
		goto error;
	}
	*ret = (unsigned char)pp->choice;
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  Get PKMACValue DER
-----------------------------------------*/
int CMP_DER_pkmacv(PKMACValue *pkm,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j;

	/* algId AlgorithmIdentifier */
	if(x509_DER_algoid(pkm->algId,NULL,ret,&j)) return -1;
	cp = ret+j;

	/* value BIT STRING */
	ASN1_set_bitstring(0,pkm->vlen,pkm->value,cp,&i);
	j+=i;

	ASN1_set_sequence(j,ret,ret_len);
	return 0;
}

/*
 * CertifiedKeyPair & EncryptedValue
 */
/*-----------------------------------------
  Get EncryptedValue DER
-----------------------------------------*/
int CMP_DER_encval(EncryptedValue *ev,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,k;

	cp = ret;
	k  = 0;
	/* intendedAlg [0] AlgorithmIdentifier OPTIONAL */
	if(ev->intendedAlg){
		if(x509_DER_algoid(ev->intendedAlg,NULL,cp,&i)) goto error;
		*cp = 0xa0;
		cp+=i; k+=i;
	}
	/* symmAlg [1] AlgorithmIdentifier OPTIONAL */
	if(ev->symmKey){
		if(x509_DER_algoid(ev->symmAlg,ev->symmKey,cp,&i)) goto error;
		*cp = 0xa1;
		cp+=i; k+=i;
	}
	/* encSymmKey [2] BIT STRING OPTIONAL */
	if(ev->enc_symmkey){
		ASN1_set_bitstring(0,ev->esymm_len,ev->enc_symmkey,cp,&i);
		*cp = 0x82;
		cp+=i; k+=i;
	}
	/* keyAlg [3] AlgorithmIdentifier OPTIONAL */
	if(ev->keyAlg){
		if(x509_DER_algoid(ev->keyAlg,NULL,cp,&i)) goto error;
		*cp = 0xa3;
		cp+=i; k+=i;
	}
	/* valueHint [4] OCTET STRING OPTIONAL */
	if(ev->valueHint){
		ASN1_set_octetstring(ev->hint_len,ev->valueHint,cp,&i);
		*cp = 0x84;
		cp+=i; k+=i;
	}
	/* encValue BIT STRING */
	ASN1_set_bitstring(0,ev->enc_len,ev->encValue,cp,&i);
	cp+=i; k+=i;

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}


/*-----------------------------------------
  Get PKIPubInfo DER
-----------------------------------------*/
int CMP_DER_pubinfo(PKIPubInfo *pi,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct;
	int i,j,k,l,m;

	/* action INTEGER */
	ASN1_set_integer(pi->action,ret,&k);
	cp = ret+k;

	/* pubInfos SEQUENCE SIZE(1..MAX) OF SinglePubInfo OPTIONAL */
	ct = cp;
	for(i=m=0;i<4;i++){
		if(pi->pubInfo[i].pubMethod != -1){
			l =0;

			ASN1_set_integer(pi->pubInfo[i].pubMethod,ct,&j);
			l+=j;

			if(pi->pubInfo[i].pubLocation){
				if(ExtGN_DER_gname(pi->pubInfo[i].pubLocation,ct+j,&j))
					goto error;
				l+=j;
			}
			ASN1_set_sequence(l,ct,&j);
			ct+=j; m+=j;
		}
	}
	ASN1_set_sequence(m,cp,&j);
	k+=j;

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}


/*-----------------------------------------
  Get CertifiedKeyPair DER
-----------------------------------------*/
int CMP_DER_ctkeypair(CertifiedKeyPair *ckp,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,k;

	/* certOrEncCert CertOrEncCert ::= CHOICE */
	cp = ret;
	k  = 0;
	if(ckp->certOrEncCert.cert){
		if(ckp->certOrEncCert.cert->der == NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+7,NULL);
			goto error;
		}
		k =ASN1_length(&ckp->certOrEncCert.cert->der[1],&j);
		k+=j+1;
		memcpy(cp,ckp->certOrEncCert.cert->der,k);
		ASN1_set_explicit(k,0,cp,&k);
		cp += k;

	}else if(ckp->certOrEncCert.encCert){
		if(CMP_DER_encval(ckp->certOrEncCert.encCert,cp,&k)) goto error;
		ASN1_set_explicit(k,1,cp,&k);
		cp += k;

	}else{
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASN+7,NULL);
		goto error;
	}
	/* privateKey [0] EncryptedValue OPTIONAL */
	if(ckp->privateKey){
		if(CMP_DER_encval(ckp->privateKey,cp,&i)) goto error;
		ASN1_set_explicit(i,0,cp,&i);
		cp+=i; k+=i;
	}	
	/* publicationInfo [1] PKIPublicationInfo OPTIONAL */
	if(ckp->publicationInfo){
		if(CMP_DER_pubinfo(ckp->publicationInfo,cp,&i)) goto error;
		ASN1_set_explicit(i,1,cp,&i);
		cp+=i; k+=i;
	}

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}


/*
 * CertId
 */
/*-----------------------------------------
  Get CertId DER 
-----------------------------------------*/
int CMP_DER_certid(CertId *cid,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j;

	/* issuer GeneralName */
	if(Cert_DER_subject(&cid->issuer,ret,&j)) return -1;
	*ret=0xa4; cp=ret+j; /* implicit [4] */

	/* serialNumber INTEGER */
	ASN1_set_integer(cid->serialNumber,cp,&i);
	j+=i;

	ASN1_set_sequence(j,ret,ret_len);
	return 0;
}

/*
 *	CertResponse
 */
/*-----------------------------------------
  struct CertResponse alloc & free
-----------------------------------------*/
int CMP_DER_certrsp(CertResponse *cr,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,k;

	/* certReqId INTEGER */
	ASN1_set_integer(cr->certReqID,ret,&k);
	cp = ret+k;

	/* status PKIStatusInfo */
	if(PKI_DER_statinfo(cr->status,cp,&i)) goto error;
	cp+=i; k+=i;

	/* certifiedKeyPair CertifiedKeyPair OPTIONAL */
	if(cr->certifiedKeyPair){
		if(CMP_DER_ctkeypair(cr->certifiedKeyPair,cp,&i)) goto error;
		cp+=i; k+=i;
	}
	/* rspInfo OCTET STRING OPTIONAL */
	if(cr->rspInfo){
		ASN1_set_octetstring(cr->rsp_len,cr->rspInfo,cp,&i);
		cp+=i; k+=i;
	}

	ASN1_set_sequence(k,ret,ret_len);
	return 0;
error:
	return -1;
}
