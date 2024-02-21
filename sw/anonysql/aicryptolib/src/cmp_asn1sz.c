/* cmp_asn1sz.c */
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
int der_size_certtmpl(CertTemplate *ctp){
	int i,ret = 8;

	if(ctp == NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASNSZ,NULL);
		goto error;
	}
	/* Version OPTIONAL */
	if(ctp->version != -1) ret+= 4;
	/* serialNumber [1] INTEGER OPTIONAL */
	if(ctp->snum_der) ret+=ASN1_tlen(ctp->snum_der) + 4;
	else if(ctp->serialNumber != -1) ret+=10;
	/* AlgorithmIdentifier OPTIONAL */
	if(ctp->signingAlg) ret+= 16;
	/* Name OPTIONAL */
	if(ctp->issuer.num){
		if((i=der_size_name(&ctp->issuer))<0) goto error;
		ret+=i;
	}
	/* OptionalValidity OPTIONAL */
	if(ctp->validity.notBefore.tm_year) ret+= 16;
	if(ctp->validity.notAfter.tm_year)  ret+= 16;

	/* Name OPTIONAL */
	if(ctp->subject.num){
		if((i=der_size_name(&ctp->subject))<0) goto error;
		ret+=i;
	}
	/* SubjectPublicKeyInfo OPTIONAL */
	if(ctp->publicKey){
		if((i=der_size_pubkeyinfo(ctp->publicKey))<0) goto error;
		ret+=i;
	}
	/* Extensions OPTIONAL */
	if(ctp->ext){
		if((i=der_size_exts(ctp->ext))<0) goto error;
		ret+=i;
	}
	return ret;
error:
	return -1;
}

int der_size_pubkeyinfo(Key *pub){
	int ret = 4;
	switch(pub->key_type){
	case KEY_RSA_PUB:
		ret+=pub->size+32;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_CMP,ERR_PT_CMP_ASNSZ+1,NULL);
		return -1;
	}
	return ret;
}

/*
 * Proof of Possession
 */
int der_size_poposign(POPOSigningKey *pps){
	int i,ret=4;

	/* POPOSigningKeyInput OPTIONAL */
	if(pps->poposkInput.option){
		/* authInfo CHOICE */
		if(pps->poposkInput.publicKeyMac){
			/* PKMACValue */
			if((i=der_size_pkmacv(pps->poposkInput.publicKeyMac))<0)
				goto error;
			ret+=i;
		}else{
			/* GeneralName */
			if((i=der_size_name(&pps->poposkInput.sender))<0)
				goto error;
			ret+=i;
		}
		/* poposign -- SubjectPublicKeyInfo */
		if((i=der_size_pubkeyinfo(pps->poposkInput.publicKey))<0)
			goto error;
		ret+=i;
	}
	/* AlgorithmIdentifier */
	if(pps->algo_id) ret += 16;
	/* BIT STRING */
	ret += pps->sig_len + 4;

	return ret;
error:
	return -1;
}

int der_size_popopriv(POPOPrivKey *pp){
	int ret=4;
	switch(pp->choice){
	case 0: ret+=pp->tm_len+4; break; /* BIT STRING */
	case 1: ret+=4; break; /* INTEGER */
	case 2: ret+=pp->dh_len+4; break; /* BIT STRING */
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_CMP_ASNSZ+3,NULL);
		return -1;
	}
	return ret;
}

int der_size_pkmacv(PKMACValue *pkm){
	int ret=4;
	/* AlgorithmIdentifier */
	ret+=16;
	/* BIT STRING */
	ret+=pkm->vlen+4;
	return ret;
}

int der_size_pofp(POfP *pop){
	int i,ret = 4;
	switch(pop->choice){
	case 0: break;
	case 1:
		if((i=der_size_poposign(pop->signature))<0) goto error;
		ret+=i; break;
	case 2:
		if((i=der_size_popopriv(pop->keyEncipherment))<0) goto error;
		ret+=i; break;
	case 3:
		if((i=der_size_popopriv(pop->keyAgreement))<0) goto error;
		ret+=i; break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_CMP,ERR_PT_CMP_ASNSZ+5,NULL);
		goto error;
	}
	return ret;
error:
	return -1;
}

/*
 * CertifiedKeyPair & EncryptedValue
 */
int der_size_encval(EncryptedValue *ev){
	int ret = 4;
	/* AlgorithmIdentifier OPTIONAL */
	if(ev->intendedAlg) ret+= 16;
	/* AlgorithmIdentifier OPTIONAL */
	if(ev->symmKey) ret+=24; /* hmm, this might be problem... */
	/* BIT STRING OPTIONAL */
	if(ev->enc_symmkey) ret+= ev->esymm_len + 12;
	/* AlgorithmIdentifier OPTIONAL */
	if(ev->keyAlg) ret+= 16;
	/* OCTET STRING OPTIONAL */
	if(ev->valueHint) ret+= ev->hint_len + 4;
	/* encValue BITSTRING */
	ret+= ev->enc_len + 4;
	return ret;
}

int der_size_pubinfo(PKIPubInfo *pi){
	int i,j,ret = 4;
	/* INTEGER */
	ret+=4;
	/* SEQ OF SinglePubInfo OPTIONAL */
	for(i=0;i<4;i++){
		if(pi->pubInfo[i].pubMethod != -1){
			/* INTEGER */
			ret+=4 + 4;
			/* GeneralName OPTIONAL */
			if(pi->pubInfo[i].pubLocation){
				/* pubLocation is just GeneralName but not GeneralNames.
				 * however, this function is available :-)
				 */
				if((j=ExtGN_estimate_der_size(pi->pubInfo[i].pubLocation))<0)
					return -1;
				ret+=j;
			}
		}
	}
	return ret;
}

int der_size_ctkeypair(CertifiedKeyPair *ckp){
	int i,ret = 4;

	/* CertOrEncCert */
	if(ckp->certOrEncCert.cert){
		ret+=ASN1_length(&ckp->certOrEncCert.cert->der[1],&i);
		ret+=i+1;
	}else if(ckp->certOrEncCert.encCert){
		if((i=der_size_encval(ckp->certOrEncCert.encCert))<0) goto error;
		ret+=i;
	}else{
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_CMP_ASNSZ+8,NULL);
		goto error;
	}
	/* EncryptedValue OPTIONAL */
	if(ckp->privateKey){
		if((i=der_size_encval(ckp->privateKey))<0) goto error;
		ret+=i;
	}
	/* PKIPublicationInfo OPTIONAL */
	if(ckp->publicationInfo){
		if((i=der_size_pubinfo(ckp->publicationInfo))<0) goto error;
		ret+=i;
	}
	return ret;
error:
	return -1;
}

/*
 * CertId
 */
int der_size_name(CertDN *dir){
	int i,ret=4;
	for(i=0;i<RDN_MAX;i++){
		if(dir->rdn[i].tag)
			ret+=strlen(dir->rdn[i].tag)+20;
	}
	return ret;
}

int der_size_certid(CertId *id){
	int i,ret=0;
	while(id){
		/* generalName */
		if((i=der_size_name(&id->issuer))<0) return -1;
		ret+=i;
		/* integer */
		ret+=10;
		id = id->next;
	}
	return ret;
}


/*
 *	CertResponse
 */
int der_size_certrsp(CertResponse *cr){
	int i,ret=0;
	/* INTEGER */
	ret+= 6;
	/* PKIStatusInfo */
	if((i=der_size_statinfo(cr->status))<0) goto error;
	ret+=i;
	/* CertifiedKeyPair OPTIONAL */
	if(cr->certifiedKeyPair){
		if((i=der_size_ctkeypair(cr->certifiedKeyPair))<0) goto error;
		ret+=i;
	}
	/* OCTET STRING OPTIONAL */
	if(cr->rspInfo) ret+= cr->rsp_len + 4;	

	return ret;
error:
	return -1;
}
