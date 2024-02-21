/* cert_asn1.c */
/* make struct Cert to DER */
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
#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_tool.h"

#include "ok_uconv.h"

/* just use OBJ_SIG_*, OBJ_HASH_*, because of object identifier */
int default_cert_sig_algo = OBJ_SIG_MD5RSA;
int sign_digest_algo = OBJ_HASH_MD5; /* this one depends on default_cert_sig_algo */

/* asn1 tag information for notAfter, notBefore,...*/
int asn1_time_tag = ASN1_UTCTIME;

/*-----------------------------------------
  Get certificate DER from Cert
-----------------------------------------*/
unsigned char *Cert_toDER(Cert *ct,Key *prv,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=Cert_estimate_der_size(ct))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERTASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}
	if(Cert_set_sigalgo(ct,prv)) goto error;

	if(Cert_DER_data(ct,ret,&i)) goto error;

	if(x509_set_signature(ret,prv,&ct->signature,&ct->siglen)) goto error;
	cp = ret+i;

	if(x509_DER_algoid(ct->signature_algo,NULL,cp,&j)) goto error;
	cp+=j; i+=j;

	ASN1_set_bitstring(0,ct->siglen,ct->signature,cp,&j);
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  Get certificate data DER from cert
-----------------------------------------*/
int Cert_DER_data(Cert *ct,unsigned char *ret,int *ret_len){
	unsigned char *cp,*sq;
	int i,j,k,err=-1;

	ASN1_set_integer(ct->version,ret,&i);
	ASN1_set_explicit(i,0,ret,&i);
	cp = ret+i;

	if(ct->long_sn){
		/* set long integer */
		j = ASN1_tlen(ct->long_sn);
		ASN1_set_binary(ASN1_INTEGER,j,&ct->long_sn[2],cp,&j);
	}else{
		ASN1_set_integer(ct->serialNumber,cp,&j);
	}
	cp+=j; i+=j;

	if(x509_DER_algoid(ct->signature_algo,NULL,cp,&j)) goto done;
	cp+=j; i+=j;
	if(Cert_DER_subject(&(ct->issuer_dn),cp,&j)) goto done;
	sq=cp+j; i+=j;
  
	if(Cert_DER_time(&ct->time.notBefore,sq,&j)) goto done;
	cp=sq+j;
	if(Cert_DER_time(&ct->time.notAfter,cp,&k)) goto done;
	j+=k;
	ASN1_set_sequence(j,sq,&j);
	cp=sq+j; i+=j;

	if(Cert_DER_subject(&(ct->subject_dn),cp,&j)) goto done;
	cp+=j; i+=j;

	if(x509_DER_pubkey(ct->pubkey,cp,&j)) goto done;
	cp+=j; i+=j;

	if(ct->version){ /* version should be 3 or more */
		if(Cert_DER_certext(ct,cp,&j)) goto done;
		i+=j;
	}
	ASN1_set_sequence(i,ret,ret_len);
	err=0;
done:
	return err;
}

/*-----------------------------------------
  Get certificate data DER from cert
-----------------------------------------*/
int x509_DER_algoid(int id,Key *key,unsigned char *ret,int *ret_len){
	unsigned char *cp,buf[16];
	int i,j,err=-1;

	if(ASN1_int_2object(id,ret,&i)) return -1;
	cp = ret+i;

	if(key==NULL){
		ASN1_set_null(cp); i+=2;
	}else{
		switch(key->key_type){
		case KEY_RSA_PRV:
		case KEY_RSA_PUB:
			ASN1_set_null(cp); i+=2;
			break;

		case KEY_DSA_PRV: /* PKCS#8 */
			if(DSAPm_toDER(((Prvkey_DSA*)key)->pm,cp,&j,0)==NULL)
				goto done;
			i+=j;
			break;
		case KEY_DSA_PUB:
			if(DSAPm_toDER(((Pubkey_DSA*)key)->pm,cp,&j,0)==NULL)
				goto done;
			i+=j;
			break;

		case KEY_ECDSA_PRV: /* PKCS#8 */
			if(ECPm_toDER(((Prvkey_ECDSA*)key)->E,cp,&j)==NULL)
				goto done;
			i+=j;
			break;
		case KEY_ECDSA_PUB:
			if(ECPm_toDER(((Pubkey_ECDSA*)key)->E,cp,&j)==NULL)
				goto done;
			i+=j;
			break;
		case KEY_DES:
			if(((Key_DES*)key)->iv){
				ll2c(8,&((Key_DES*)key)->oiv,buf);
				ASN1_set_octetstring(8,buf,cp,&j); i+=j;
			}else{
				ASN1_set_null(cp); i+=2;
			}
			break;
		case KEY_3DES:
			if(((Key_3DES*)key)->iv){
				ll2c(1,&((Key_3DES*)key)->oiv,buf);
				ASN1_set_octetstring(8,buf,cp,&j); i+=j;
			}else{
				ASN1_set_null(cp); i+=2;
			}
			break;
		case KEY_RC2:
			if(((Key_RC2*)key)->iv){
				us2ucLE(4,((Key_RC2*)key)->oiv,buf);
				ASN1_set_octetstring(8,buf,cp,&j); i+=j;
			}else{
				ASN1_set_null(cp); i+=2;
			}
		default:
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509CERT,ERR_PT_CERTASN1+2,NULL);
			goto done;
		}
	}
	ASN1_set_sequence(i,ret,ret_len);

	err=0;
done:
	return err;
}

/*-----------------------------------------
  Get UTC or General time DER
-----------------------------------------*/
int Cert_DER_time(struct tm *time,unsigned char *ret,int *ret_len){
	if(stm2UTC(time,ret,(unsigned char)asn1_time_tag)==NULL)
		return -1;

	*ret_len=ASN1_tlen(ret)+2;
	return 0;
}

/*-----------------------------------------
  Get subject DER from cert dir
-----------------------------------------*/
int x509_DER_pubkey(Key *key,unsigned char *ret,int *ret_len){
	unsigned char *cp,*pub=NULL;
	int	i,j,algo,err=-1;

	switch(key->key_type){
	case KEY_RSA_PUB:
		if((pub=RSApub_toDER((Pubkey_RSA*)key,NULL,&j))==NULL) goto done;
		algo = OBJ_CRYPT_RSA;
		break;

	case KEY_DSA_PUB:
		if((pub=MALLOC(((Pubkey_DSA*)key)->size+8))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERTASN1+4,NULL);
			goto done;
		}
		if(ASN1_LNm2int(((Pubkey_DSA*)key)->w,pub,&j)) goto done;
		algo = OBJ_CRYPT_DSA;
		break;

	case KEY_ECDSA_PUB:
		if((pub=ECp_P2OS(((Pubkey_ECDSA*)key)->W,4,&j))==NULL) return -1;
		algo = OBJ_CRYPT_ECDSA;
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509CERT,ERR_PT_CERTASN1+4,NULL);
		goto done;
	}

	if(x509_DER_algoid(algo,key,ret,&i)) goto done;
	cp =ret+i;

	ASN1_set_bitstring(0,j,pub,cp,&j);
	i+=j;
	ASN1_set_sequence(i,ret,ret_len);

	err=0;
done:
	if(pub) FREE(pub);
	return err;
}

/*-----------------------------------------
  Get subject DER from cert dir
-----------------------------------------*/
int Cert_DER_subject(CertDN *dn,unsigned char *ret,int *ret_len){
	unsigned char *tmp,*cp,uc[256];
	int		i,j,k,l,t;

	tmp=ret;
	memset(uc,0,256);
	for(l=k=0;k<dn->num;k++){
		cp =tmp;

		if(ASN1_int_2object(dn->rdn[k].tagoid,cp,&i)) goto error;
		cp +=i;

		switch(dn->rdn[k].derform){
		case ASN1_UTF8STRING:
			if((t=UC_conv(UC_LOCAL_JCODE,UC_CODE_UTF8,dn->rdn[k].tag,strlen(dn->rdn[k].tag),uc,254))<0) goto error;
			if(ASN1_set_utf8(uc,cp,&j)) goto error;
			break;
		case ASN1_IA5STRING:
			if(ASN1_set_ia5(dn->rdn[k].tag,cp,&j)) goto error;
			break;
		case ASN1_T61STRING:
			if(ASN1_set_t61(dn->rdn[k].tag,cp,&j)) goto error;
			break;
		case ASN1_PRINTABLE_STRING:
		default:
			if(ASN1_set_printable(dn->rdn[k].tag,cp,&j)) goto error;
			break;
		}

		i+=j;
		ASN1_set_sequence(i,tmp,&i);
		ASN1_set_set(i,tmp,&i);
		tmp+=i; l+=i;
	}

	ASN1_set_sequence(l,ret,ret_len);
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  Get certext DER from cert extent
-----------------------------------------*/
int Cert_DER_certext(Cert *ct,unsigned char *ret,int *ret_len){
	int i;

	*ret_len = 0;
	if(x509_DER_exts(ct->ext,ret,&i)) return -1;
	if(i) ASN1_set_explicit(i,3,ret,ret_len);
	return 0;
}
		
int x509_DER_exts(CertExt *top,unsigned char *ret,int *ret_len){
	unsigned char *cp,*sq;
	CertExt *ext;
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

		if(ext->critical){
			ASN1_set_boolean(1,cp,&k);
			cp+=k; j+=k;
		}

		k=ext->dlen;
		ASN1_set_octetstring(k,ext->der,cp,&k);
		j+=k;

		ASN1_set_sequence(j,sq,&j);
		sq+=j; i+=j;
	}
	if(i) ASN1_set_sequence(i,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  estimate certificate DER size from Cert
-----------------------------------------*/
int Cert_estimate_der_size(Cert *ct){
	CertExt *ext;
	int ret,i,j;

	if(ct==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CERT,ERR_PT_CERTASN1+7,NULL);
		return -1;
	}

	/* version & serial & algorithm */
	ret=32;

	/* check issuer & subject size */
	for(i=j=0;i<RDN_MAX;i++){
		if(ct->issuer_dn.rdn[i].tag)
			j+=strlen(ct->issuer_dn.rdn[i].tag)+20;
		if(ct->subject_dn.rdn[i].tag)
			j+=strlen(ct->subject_dn.rdn[i].tag)+20;
	}
	ret+=j;

	/* validity */
	ret+=40;
	/* public key */
	switch(ct->pubkey_algo){
	case KEY_RSA_PUB:
		ret+=ct->pubkey->size+32;
		break;
	case KEY_DSA_PUB:
		ret+=DSApub_estimate_der_size((Pubkey_DSA*)ct->pubkey);
		break;
	case KEY_ECDSA_PUB:
		ret+=ECDSApub_estimate_der_size((Pubkey_ECDSA*)ct->pubkey);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509CERT,ERR_PT_CERTASN1+7,NULL);
		return -1;
	}
	/* count extension */
	for(j=0,ext=ct->ext;ext!=NULL;ext=ext->next){
		if(ext->extnID<=0) continue;

		j+=(ext->critical)?(4):(0);
		j+=ext->dlen+16;
	}
	ret+=j;

	/* signature len */
	/* actually, signature will be set in Cert_toDER or Req_toDER.
	 * therefore, signature length might be depened on Private key length.
	 * if current certificate doesn't have signature information, just set
	 * enough big size of signature. (currently it's 2048bit)
	 */
	if((ct->signature==NULL)||(ct->siglen<=0))
		ret+=256+24;
	else
		ret+=ct->siglen+24;
	return ret;
}

