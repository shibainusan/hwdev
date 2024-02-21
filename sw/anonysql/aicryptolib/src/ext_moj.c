/* ext_moj.c */
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

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_sha1.h"
#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_x509ext.h"

#include "ok_uconv.h"

/*-----------------------------------------
  CertExt MOJ-corpinfo
-----------------------------------------*/
CertExt *Extnew_moj_corpinfo(char *corpName, char *regNum, char *corpAddress,
	char *directorName, char *directorTitle, char *resv, char *regOffice, int sjis){

	CE_MOJCoInfo *ret;
	unsigned char *cp,tmp[256];
	int i=8,j,k;

	if((ret=(CE_MOJCoInfo*)CertExt_new(OBJ_MOJ_RegCoInfo))==NULL) return NULL;

	i+=((corpName)?(strlen(corpName)+4):(0)) + ((regNum)?(strlen(regNum)+4):(0));
	i+=((corpAddress)?(strlen(corpAddress)+4):(0)) + ((directorName)?(strlen(directorName)+4):(0));
	i+=((directorTitle)?(strlen(directorTitle)+4):(0)) + ((resv)?(strlen(resv)+4):(0));
	i+=((regOffice)?(strlen(regOffice)+4):(0));

	if((ret->der=(unsigned char*)MALLOC((i>>1)*3+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ,NULL);
		goto error;
	}

	/* set data */
	if(corpName) 
		if((STRDUP(ret->corpInfo[0],corpName))==NULL) goto dup_error;
	if(regNum) 
		if((STRDUP(ret->corpInfo[1],regNum))==NULL) goto dup_error;
	if(corpAddress) 
		if((STRDUP(ret->corpInfo[2],corpAddress))==NULL) goto dup_error;
	if(directorName) 
		if((STRDUP(ret->corpInfo[3],directorName))==NULL) goto dup_error;
	if(directorTitle) 
		if((STRDUP(ret->corpInfo[4],directorTitle))==NULL) goto dup_error;
	if(resv) 
		if((STRDUP(ret->corpInfo[5],resv))==NULL) goto dup_error;
	if(regOffice) 
		if((STRDUP(ret->corpInfo[6],regOffice))==NULL) goto dup_error;

	/* set DER */
	cp = ret->der;
	memset(tmp,0,256);

	for(i=k=0;i<7;i++){
		if(ret->corpInfo[i]){
			if(i==1){
				if(ASN1_set_printable(ret->corpInfo[i],cp,&j)) goto error;
			}else if(sjis){ // MOJ register mode
				if(ASN1_set_t61(ret->corpInfo[i],cp,&j)) goto error;
				*cp = ASN1_UTF8STRING;
			}else{ // MOJ certificate mode
				if(UC_conv(UC_LOCAL_JCODE,UC_CODE_UTF8,ret->corpInfo[i],
					strlen(ret->corpInfo[i]),tmp,254)<0)
					goto error;
				if(ASN1_set_utf8(tmp,cp,&j)) goto error;
			}
			ASN1_set_explicit(j,(char)i,cp,&j);
			cp+=j; k+=j;
		}
	}
	ASN1_set_sequence(k,ret->der,&ret->dlen);

	return (CertExt*)ret;
dup_error:
	OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTMOJ,NULL);
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  AttrTAV (CertExt) MOJ attribute
-----------------------------------------*/
AttrTAV *Extnew_moj_timelimit(int limit){
	CE_Com *ret;

	if((ret=(CE_Com*)CertExt_new(OBJ_MOJ_TimeLimit))==NULL) return NULL;

	if((ret->der=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+1,NULL);
		goto error;
	}
	if((ret->comment=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+1,NULL);
		goto error;
	}
	SNPRINTF (ret->comment,4,"%.02d",limit);

	/* get DER */
	ASN1_set_octetstring(strlen(ret->comment),ret->comment,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* hash_algo should be OBJ_HASH_SHA1 */
AttrTAV *Extnew_moj_suspcode(int hash_algo, unsigned char *data, int len){
	CE_MOJSuspCode *ret;
	unsigned char *cp;
	int i,j;

	if((ret=(CE_MOJSuspCode*)CertExt_new(OBJ_MOJ_SuspCode))==NULL) return NULL;
	ret->hash_algo = hash_algo;

	switch(hash_algo){
	case OBJ_HASH_SHA1: OK_SHA1(len,data,ret->hash); ret->hlen=20; break;
	}
	if((ret->der=(unsigned char*)MALLOC(40))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+2,NULL);
		goto error;
	}

	/* get DER */
	if(x509_DER_algoid(OBJ_HASH_SHA1,NULL,ret->der,&i)) goto error;
	cp = ret->der+i;
	ASN1_set_octetstring(ret->hlen,ret->hash,cp,&j);
	i+=j;

	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* MOJ Attribute */
AttrTAV *Extnew_moj_genmreq(int symm, int pubkey, int hash){
	CE_MOJGenmReq *ret;
	unsigned char *cp;
	int i,j;

	if((ret=(CE_MOJGenmReq*)CertExt_new(OBJ_MOJ_GenmReq))==NULL) return NULL;
	ret->nego_num = 1;
	ret->nego[0].symm_algo = symm;
	ret->nego[0].pub_algo  = pubkey;
	ret->nego[0].hash_algo = hash;

	if((ret->der=(unsigned char*)MALLOC(4+48*ret->nego_num))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+3,NULL);
		goto error;
	}

	/* get DER */
	cp = ret->der; i=0;
	/* nego key */
	if(x509_DER_algoid(symm,NULL,cp,&j)) goto error;
	cp+=j; i+=j;
	if(x509_DER_algoid(pubkey,NULL,cp,&j)) goto error;
	cp+=j; i+=j;
	if(x509_DER_algoid(hash,NULL,cp,&j)) goto error;
	i+=j;
	ASN1_set_sequence(i,ret->der,&i);

	/* GenmInfoReq */
	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* MOJ Attribute */
AttrTAV *Extnew_moj_genpres(int pkistat, int symm, int pubkey, int hash){
	CE_MOJGenpRes *ret;
	unsigned char *cp,*t;
	int i,j,k;

	if((ret=(CE_MOJGenpRes*)CertExt_new(OBJ_MOJ_GenpRes))==NULL) return NULL;
	if(symm>0){ /* means OPTIONAL NegotiationKey */
		ret->nego_num = 1;
		ret->nego[0].symm_algo = symm;
		ret->nego[0].pub_algo  = pubkey;
		ret->nego[0].hash_algo = hash;
	}
	ret->pki_status = pkistat;

	if((ret->der=(unsigned char*)MALLOC(16+48*ret->nego_num))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+4,NULL);
		goto error;
	}

	/* get DER */
	cp = ret->der; i=0;
	/* PKIStatus */
	ASN1_set_integer(pkistat,cp,&i);
	ASN1_set_sequence(i,cp,&i);
	cp+=i; 

	/* NegotiationKey OPTIONAL */
	if(symm>0){
		t = cp;
		if(x509_DER_algoid(symm,NULL,cp,&j)) goto error;
		cp+=j;
		if(x509_DER_algoid(pubkey,NULL,cp,&k)) goto error;
		cp+=k; j+=k;
		if(x509_DER_algoid(hash,NULL,cp,&k)) goto error;
		j+=k;
		ASN1_set_sequence(j,t,&j); /* NegotiationKey */
		ASN1_set_sequence(j,t,&j); /* SEQUENCE OF NegotiationKey */
		i+=j;
	}
	/* GenmInfoReq */
	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* MOJ Attribute */
AttrTAV *Extnew_moj_genspreq(unsigned char *snum_der, CertDN *dn, unsigned char revReason, int suspReason,
							 Key *pub, unsigned char *data, int dlen)
{
	CE_MOJGenSpReq *ret;
	unsigned char *cp,*t;
	int i,j,k,l;

	if((ret=(CE_MOJGenSpReq*)CertExt_new(OBJ_MOJ_GenSpReq))==NULL) return NULL;

	/* set data */
	ret->snum_der     = snum_der;
	ret->revReason[0] = revReason;
	ret->suspReason   = suspReason;	
	switch(pub->key_type){
	case KEY_RSA_PUB:   ret->keyAlg = OBJ_CRYPT_RSA; break;
	case KEY_DSA_PUB:   ret->keyAlg = OBJ_CRYPT_DSA; break;
	case KEY_ECDSA_PUB: ret->keyAlg = OBJ_CRYPT_ECDSA; break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_X509EXT,ERR_PT_EXTMOJ+4,NULL);
		goto error;
	}
	if(Cert_dncopy(dn,&ret->issuer_dn)) goto error;

	/* get encrypted data */
	if((ret->encValue=P7m_recip_get_key(pub,data,dlen))==NULL) goto error;
	ret->enc_len = pub->size;

	for(i=0,k=32;i<RDN_MAX;i++)
		if(dn->rdn[i].tag) k+=strlen(dn->rdn[i].tag)+20;
	k+= pub->size + 8;

	if((ret->der=(unsigned char*)MALLOC(k))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+4,NULL);
		goto error;
	}

	/* get DER */
	cp = t = ret->der; i=0;

	/* CertTemplate */
	ASN1_skip_(snum_der,&i);
	memcpy(cp,snum_der,i);
	*cp = 0x81; cp+=i; 
	if(Cert_DER_subject(dn,cp,&j)) goto error;
	ASN1_set_explicit(j,3,cp,&j);
	ASN1_set_sequence(i+j,t,&i);
	cp=t+i;

	/* reasonFlag */
	asn1_check_derbit(2,ret->revReason,&k,&l);
	ASN1_set_bitstring(k,l,ret->revReason,cp,&j);
	cp+=j; i+=j;
	/* suspentionReasonCode */
	ASN1_set_integer(suspReason,cp,&j);
	cp+=j; i+=j;

	/* suspensionDetail */
	t=cp;
	if(x509_DER_algoid(ret->keyAlg,NULL,cp,&k)) goto error;
	*cp=0xa3; cp+=k;
	ASN1_set_bitstring(0,ret->enc_len,ret->encValue,cp,&j);
	ASN1_set_sequence(k+j,t,&j);
	i+=j;

	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* MOJ Attribute */
AttrTAV *Extnew_moj_genspres(int pkistat, CertDN *dn, unsigned char *snum_der){
	CE_MOJGenSpRes *ret;
	unsigned char *cp,*t;
	int i,j,k;

	if((ret=(CE_MOJGenSpRes*)CertExt_new(OBJ_MOJ_GenSpRes))==NULL) return NULL;

	/* set data */
	ret->snum_der     = snum_der;
	ret->status       = pkistat;
	if(Cert_dncopy(dn,&ret->issuer_dn)) goto error;

	/* allocate memory */
	for(i=0,k=32;i<RDN_MAX;i++)
		if(dn->rdn[i].tag) k+=strlen(dn->rdn[i].tag)+20;

	if((ret->der=(unsigned char*)MALLOC(k))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTMOJ+4,NULL);
		goto error;
	}

	/* get DER */
	cp = ret->der; i=0;
	/* PKIStatus */
	ASN1_set_integer(pkistat,cp,&i);
	ASN1_set_sequence(i,cp,&i);
	cp+=i; 

	/* CertID */
	t = cp;
	if(Cert_DER_subject(dn,cp,&j)) goto error;
	ASN1_set_explicit(j,4,cp,&j);
	cp+=j;
	ASN1_skip_(snum_der,&k);
	memcpy(cp,snum_der,k);
	ASN1_set_sequence(j+k,t,&j);
	i +=j;
	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  x509_DER_attrs (AttributeTypeAndValue)
-----------------------------------------*/
int x509_DER_attrs(AttrTAV *top,unsigned char *ret,int *ret_len){
	unsigned char *cp,*sq;
	AttrTAV *ext;
	int	i,j,k;
  
	sq=ret; *ret_len=i=0;
	for(ext=top;ext!=NULL;ext=ext->next){
		if((ext->extnID<=0)&&(ext->objid==NULL))
			continue;

		cp=sq;
		if(ext->extnID>0){
			if(ASN1_int_2object(ext->extnID,cp,&j))
				continue;
			cp+=j;
		}else{
			j = ASN1_tlen(ext->objid) + 2;
			memcpy(cp,ext->objid,j);
			cp+=j;
		}
		
		ASN1_skip_(ext->der,&k);
		memcpy(cp,ext->der,k);
		j+=k;

		ASN1_set_sequence(j,sq,&j);
		sq+=j; i+=j;
	}
	if(i) ASN1_set_sequence(i,ret,ret_len);
	return 0;
}
