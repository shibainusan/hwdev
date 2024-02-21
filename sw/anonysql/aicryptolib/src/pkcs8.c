/* pkcs8.c */
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

#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_tool.h"

Prvkey_RSA *ASN1_read_rsaprv(unsigned char *in);

/*-----------------------------------------
  PKCS#8 get data.-> key struct
  *in is PrivateKeyInfo DER top.
-----------------------------------------*/
Key *ASN1_p8_prvkey(unsigned char *in){
	unsigned char *cp,*buf=NULL;
	int cry,i,j;
	Prvkey_ECDSA *ek=NULL;	
	Key *ret;
	void *pm;

	cp = ASN1_next(in);
	if(ASN1_integer(cp,&i)){
		OK_set_error(ERR_ST_BADVER,ERR_LC_PKCS,ERR_PT_PKCS8,NULL);
		goto error;
	}

	/* get algorithm Identifier */
	cp = ASN1_next(cp);
	if((cry=asn1_get_algoid(cp,&pm))<0) goto error;

	/* get private key */
	cp = ASN1_skip(cp);
	if(ASN1_octetstring(cp,&i,&buf,&j)) goto error;

	/* decode DER string to private key */
	switch(cry){
	case OBJ_CRYPT_RSA:
		if((ret=(Key*)ASN1_read_rsaprv(buf))==NULL)
			goto error;
		break;

	case OBJ_CRYPT_DSA:
		/* hmm, I don't know ... what kind of standard is this..
		 * OpenSSL uses this ASN.1 file format.
		 */
		if((ret=(Key*)DSAprvkey_new())==NULL) goto error;

		if(ASN1_int2LNm(buf,((Prvkey_DSA*)ret)->k,&i)) goto error;

		/* calcrate public key */
		if(LN_exp_mod(((DSAParam*)pm)->g,((Prvkey_DSA*)ret)->k,((DSAParam*)pm)->p,((Prvkey_DSA*)ret)->w))
			goto error;

		ret->size = LN_now_byte(((DSAParam*)pm)->p);
		((Prvkey_DSA*)ret)->pm = (DSAParam*)pm;
		if((((Prvkey_DSA*)ret)->der=DSAprv_toDER((Prvkey_DSA*)ret,NULL,&i))==NULL)
			goto error;
		FREE(buf);
		break;

	case OBJ_CRYPT_ECDSA:
		/* hmm, I don't know ... what kind of standard is this..
		 * This is kind of original format..
		 */
		if((ek=ECDSAprvkey_new())==NULL) goto error;
		ret=(Key*)ek;

		if(ASN1_int2LNm(buf,ek->k,&i)) goto error;

		/* calcrate public key */
		((Prvkey_ECDSA*)ek)->E = (ECParam*)pm;
		LN_long_set(ek->E->G->z,1);
		if(ECp_pmulti(ek->E,ek->E->G,ek->k,ek->W)) goto error;
		if(ECp_proj2af(ek->E,ek->W)) goto error;

		ek->version = 1;
		ek->size    = ek->E->psize >> 3;
		if((((Prvkey_ECDSA*)ret)->der=ECDSAprv_toDER((Prvkey_ECDSA*)ret,NULL,&i))==NULL)
			goto error;
		FREE(buf);
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PKCS8,NULL);
		goto error;
	}
	/* buf is used by ret->der.
	 * so cannot FREE it.
	 *  FREE(buf); */

	return ret;
error:
	if(buf) FREE(buf);
	return NULL;
}

/*-----------------------------------------
  PKCS#8 get decrypted data.
  *in is EncryptedPrivateKeyInfo DER top.
-----------------------------------------*/
unsigned char *ASN1_p8_decrypted(unsigned char *in,int *ret_len){
	unsigned char *cp,*ret=NULL;
	Dec_Info *dif;
	int i,err=-1;

	if((dif=DInfo_new())==NULL) goto done;

	cp = ASN1_next(in);
	if(ASN1_pbe_algorithm(cp,&(dif->info),&(dif->salt),&(dif->slen),&(dif->iter))<0)
		goto done;

	/* set password */
	if((OBJ_P5_MD2DES <= dif->info)&&(dif->info <= OBJ_P5_SHA1RC2)){
		/* PBES1 type */
		if((dif->pass=(unsigned char*)MALLOC(32))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+1,NULL);
			return NULL;
		}
#ifdef __WINDOWS__
		OK_get_passwd("Open Private Key: ",dif->pass,0);
#else
		OK_get_passwd("Input PASS Phrase: ",dif->pass,0);
#endif
		dif->plen = strlen(dif->pass);
	}else{
		OK_get_password_p12(NULL,dif,0x0100);
	}


	if((cp = ASN1_skip(cp))==NULL) goto done;

	if((*ret_len=ASN1_length((++cp),&i))<0){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_PKCS,ERR_PT_PKCS8+1,NULL);
		goto done;
	}
	if((ret=(unsigned char*)MALLOC(*ret_len + 8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+1,NULL);
		goto done;
	}
	cp +=i;
  
	dif->clen = *ret_len;
	dif->cry  = cp;
	if(Pbe_get_decrypted(dif,ret)) goto done;

	err=0;
done:
	DInfo_free(dif);
	if(err&&ret){FREE(ret);ret=NULL;}
	return ret;
}


/*-----------------------------------------
  Get PKCS#8 DER from Key
-----------------------------------------*/
unsigned char *P8_toDER(Key *key,unsigned char *buf,int *ret_len){
	unsigned char *cp,*kd,*ret;
	int i,j,len,mc=0;

	if(buf==NULL){
		if((i=P8_estimate_der_size(key))<=0)
			return NULL;

		if((cp=ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+2,NULL);
			return NULL;
		}
	}else{
		cp=ret=buf;
	}

	ASN1_set_integer(0,cp,&i);
	cp+= i;

	switch(key->key_type){
	case KEY_RSA_PRV:
		if(x509_DER_algoid(OBJ_CRYPT_RSA,key,cp,&j)) goto error;
		cp+=j; i+=j;

		if((kd=((Prvkey_RSA*)key)->der)==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS,ERR_PT_PKCS8+2,NULL);
			goto error;
		}
		if(ASN1_skip_(kd,&len)==NULL) goto error;
		break;

	case KEY_DSA_PRV:
		if(x509_DER_algoid(OBJ_CRYPT_DSA,key,cp,&j)) goto error;
		cp+=j; i+=j;

		/* ((Prvkey_DSA*)key)->der is not compatible with this.
		 * so it needs to create new memory buffer :-(
		 */
		if((kd=(unsigned char*)MALLOC(key->size+4))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+2,NULL);
			goto error;
		}
		/* set a flag in order to free memory later */
		mc = 1; 

		/* just put private key "k" */
		if(ASN1_LNm2int(((Prvkey_DSA*)key)->k,kd,&len)) goto error;
		break;

	case KEY_ECDSA_PRV:
		if(x509_DER_algoid(OBJ_CRYPT_ECDSA,key,cp,&j)) goto error;
		cp+=j; i+=j;

		/* ((Prvkey_DSA*)key)->der is not compatible with this.
		 * so it needs to create new memory buffer :-(
		 */
		if((kd=(unsigned char*)MALLOC(key->size+4))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+2,NULL);
			goto error;
		}
		/* set a flag in order to free memory later */
		mc = 1; 

		/* just put private key "k" */
		if(ASN1_LNm2int(((Prvkey_ECDSA*)key)->k,kd,&len)) goto error;
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PKCS8+2,NULL);
		goto error;
	}

	ASN1_set_octetstring(len,kd,cp,&j);
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);

	if(mc) FREE(kd);
	return ret;
error:
	if(mc) FREE(kd);
	if(ret!=buf) FREE(ret);
	return NULL;
}

int P8_estimate_der_size(Key *key){
	int ret=16;
	switch(key->key_type){
	case KEY_RSA_PRV:
		ret += key->size*7;
		break;
	case KEY_DSA_PRV:
		ret += DSAprv_estimate_der_size((Prvkey_DSA*)key);
		break;
	case KEY_ECDSA_PRV:
		ret += ECDSAprv_estimate_der_size((Prvkey_ECDSA*)key);
		break;
	default:
		ret = -1;
	}
	return ret;
}

/*-----------------------------------------
  PKCS#8 DER encrypted
-----------------------------------------*/
unsigned char *P8_encrypted_toDER(Key *key,int algo,unsigned char *buf,int *ret_len){
	unsigned char *cry=NULL,*ret=NULL;
	int i,j,err=-1;

	if(buf==NULL){
		if((i=P8_estimate_der_size(key))<=0)
			return NULL;
		if((ret=(unsigned char*)MALLOC(i+64))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+4,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if((cry=P8_toDER(key,NULL,&j))==NULL) goto done;

	if(P8_encrypted_toDER_in(cry,algo,ret,ret_len)) goto done;

	err=0;
done:
	if(cry) FREE(cry); /* DInfo_free() doesn't free this one */
	if(err){
		if(ret!=buf) FREE(ret);
		ret=NULL;
	}
	return ret;
}

/*-----------------------------------------
  PKCS#8 DER encrypted
-----------------------------------------*/
int P8_encrypted_toDER_in(unsigned char *in,int algo,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	Dec_Info *dif;
	int i,j,err=-1;

	if((dif=DInfo_new())==NULL) goto done;

	/* set password */
	if((OBJ_P5_MD2DES <= algo)&&(algo <= OBJ_P5_SHA1RC2)){
		/* PBES1 type */
		if((dif->pass=(unsigned char*)MALLOC(32))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PKCS8+4,NULL);
			goto done;
		}
#ifdef __WINDOWS__
		OK_get_passwd("Save Private Key",dif->pass,1);
#else
		OK_get_passwd("Input PASS Phrase: ",dif->pass,1);
#endif
		dif->plen = strlen(dif->pass);
	}else{
		OK_get_password_p12(NULL,dif,0);
	}
	dif->iter = 1000;
	dif->info = algo;
	if(dif_set_salt(dif)) goto done;

	/* set DER */
	if(Pbe_DER_algorithm(dif,ret,&i)) goto done;
	cp = ret+i;

	dif->cry = in;
	ASN1_skip_(in,(int*)&dif->clen);
	if(Pbe_set_encrypted(dif)) goto done;

	ASN1_set_octetstring(dif->clen,dif->cry,cp,&j);
	i+=j;

	ASN1_set_sequence(i,ret,ret_len);

	err=0;
done:
	DInfo_free(dif);
	return err;
}
