/* p12_asn1.c */
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ok_asn1.h"
#include "ok_hmac.h"
#include "ok_pkcs.h"
#include "ok_tool.h"

/* just use OBJ_P12Pbe_*, because of object identifier */
int default_p12_cb_cry_algo = OBJ_P12Pbe_40RC2;
int default_p12_kb_cry_algo = OBJ_P12Pbe_3K3DES;

/* asn1_set.c */
int bmp_len(char *str);

/*-----------------------------------------------
  PKCS#12 get DER buffer.
-----------------------------------------------*/
unsigned char *P12_toDER(PKCS12 *p12,unsigned char *buf,int *ret_len){
	unsigned char *cp,*safe=NULL,*ret;
	int i,j,slen,err=-1;

	if((i=P12_estimate_der_size(p12,P12_ALLBAGS))<=0)
		return NULL;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12ASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if((safe=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12ASN1,NULL);
		return NULL;
	}

	*ret_len = 0;
	ASN1_set_integer(p12->version,ret,&i);
	cp = ret+i;

	if(P12_DER_authsafe(p12,safe,&slen)) goto done;
	if(P7_data_toDER(slen,safe,0,cp,&j)==NULL) goto done;
	cp+=j; i+=j;

	if(P12_DER_mac(safe,cp,&j)) goto done;
	i+=j;
	ASN1_set_sequence(i,ret,ret_len);
	err=0;
done:
	if(safe) FREE(safe);
	if(err){
		if(ret!=buf) FREE(ret);
		ret=NULL;
	}
	return ret;
}

int P12_DER_mac(unsigned char *safe,unsigned char *der,int *ret_len){
	unsigned char *cp,mac[20],salt[8];
	time_t t;
	int i,j;

	time(&t);
	for(i=0;i<8;i++) salt[i]=(unsigned char)(rand()+t);
	if(P12_new_mac(safe,salt,mac))
		return -1;

	ASN1_int_2object(OBJ_HASH_SHA1,der,&i);
	cp = der+i;
	ASN1_set_null(cp);
	ASN1_set_sequence(i+2,der,&i);
	cp = der+i;

	ASN1_set_octetstring(20,mac,cp,&j);
	ASN1_set_sequence(i+j,der,&i);
	cp = der+i;

	ASN1_set_octetstring(8,salt,cp,&j);
	ASN1_set_sequence(i+j,der,ret_len);
	memset(salt,0,8);

	return 0;
}

/*-----------------------------------------------
  PKCS#12 get DER AuthSafes.
-----------------------------------------------*/
int P12_DER_authsafe(PKCS12 *p12,unsigned char *safe,int *ret_len){
	unsigned char *p8=NULL,*cp;
	Dec_Info *dif=NULL;
	Key *key;
	int i,j,k,err=-1;

	/* use microsoft compatible order (keybag -> certbag)
	 * no longer use netscape compatible (certbag -> keybag)
	 */
	if((dif=DInfo_new())==NULL) goto done;

	/* set password */
#ifdef __WINDOWS__
	OK_get_password_p12("Export PKCS#12: ",dif,0x01);
#else
	OK_get_password_p12("Input Export Password: ",dif,0x01);
#endif

	/* get key bag DER */
	if((key=P12_get_privatekey(p12))==NULL) goto done;

	if((k=P12_estimate_der_size(p12,OBJ_P12v1Bag_PKCS8))<=0) goto done;

	if((p8=(unsigned char*)MALLOC(k))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12ASN1+2,NULL);
		goto done;
	}
	if(P12_DER_keybag(p12,p8,&j)) goto done;
	if(P7_data_toDER(j,p8,0,safe,&i)==NULL) goto done;
	cp = safe+i;

	/* get cert bag DER */
	if(P12_DER_certbags(p12,cp,&j)) return -1;
	i+=j;

	ASN1_set_sequence(i,safe,ret_len);
	err=0;
done:
	if(p8) FREE(p8);
	DInfo_free(dif);
	return err;
}


/*-----------------------------------------------
  PKCS#12 get DER CertBags
-----------------------------------------------*/
int P12_DER_certbags(PKCS12 *p12,unsigned char *der,int *ret_len){
	unsigned char *buf,*cp;
	P12_CertBag	*bg;
	int i,j,dp,err=-1;

	if((i=P12_estimate_der_size(p12,OBJ_P12v1Bag_CERT))<=0)
		return -1;
	if((buf=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12ASN1+3,NULL);
		goto done;
	}
	dp=P12_max_depth(p12,OBJ_P12v1Bag_CERT);

	/* get certificate bags */
	for(i=0,cp=buf;dp>=0;dp--){
		if(bg=(P12_CertBag*)P12_find_bag(p12,OBJ_P12v1Bag_CERT,(unsigned char)dp)){
			if(P12_get_DER_certbag(bg,cp,&j))
				goto done;
			cp+=j; i+=j;
		}
	}

	ASN1_set_sequence(i,buf,&i);

	if(P7_encrypted_toDER(i,buf,default_p12_cb_cry_algo,der,ret_len)==NULL)
		goto done;

	err=0;
done:
	if(buf) FREE(buf);
	return err;
}

/*-----------------------------------------------
  PKCS#12 get DER PKCS8 KeyBags
-----------------------------------------------*/
int P12_DER_keybag(PKCS12 *p12,unsigned char *der,int *ret_len){
	P12_KeyBag *bg;
	int k,err=-1;

	k=P12_max_depth(p12,OBJ_P12v1Bag_PKCS8);
	if(bg=(P12_KeyBag*)P12_find_bag(p12,OBJ_P12v1Bag_PKCS8,(unsigned char)k)){
		if(P12_get_DER_keybag(bg,der,ret_len)==0)
			err=0;
	}
	return err;
}

/*-----------------------------------------------
  PKCS#12 get DER friendlyName & localKeyID
-----------------------------------------------*/
int P12_get_DER_f_l(P12_Baggage *bg,unsigned char *der,int *ret_len){
	unsigned char *cp,*sq;
	int i,j,k;

	i=j=0; sq = der;

	if(bg->friendlyName){
		ASN1_int_2object(OBJ_P9_Friendly,sq,&i);
		cp=sq+i;
		ASN1_set_bmp(bg->friendlyName,cp,&k);
		ASN1_set_set(k,cp,&k);
		i+=k;
		ASN1_set_sequence(i,sq,&i);
		sq+=i;
	}
	if(bg->localKeyID[0]){
		ASN1_int_2object(OBJ_P9_LocalKEY,sq,&j);
		cp=sq+j;
		ASN1_set_octetstring(4,bg->localKeyID,cp,&k);
		ASN1_set_set(k,cp,&k);
		j+=k;
		ASN1_set_sequence(j,sq,&j);
	}
	ASN1_set_set(i+j,der,ret_len);
	return 0;
}

/*-----------------------------------------------
  PKCS#12 get DER KeyBag
-----------------------------------------------*/
int P12_get_DER_keybag(P12_KeyBag *kb,unsigned char *der,int *ret_len){
	unsigned char *cp;
	int i,j,err=-1;

	*ret_len=0;
	if(kb->key==NULL){
		OK_set_error(ERR_ST_NULLKEY,ERR_LC_PKCS12,ERR_PT_P12ASN1+6,NULL);
		goto done;
	}

	ASN1_int_2object(OBJ_P12v1Bag_PKCS8,der,&i);
	cp=der+i;
	if(P8_encrypted_toDER(kb->key,default_p12_kb_cry_algo,cp,&j)==NULL)
		goto done;

	ASN1_set_explicit(j,0,cp,&j);
	cp+=j; i+=j;

	if(P12_get_DER_f_l((P12_Baggage*)kb,cp,&j)) goto done;
	i+=j;

	ASN1_set_sequence(i,der,&i);
	ASN1_set_sequence(i,der,ret_len);
	err=0;
done:
	return err;
}

/*-----------------------------------------------
  PKCS#12 get DER CertBag
-----------------------------------------------*/
int P12_get_DER_certbag(P12_CertBag *cb,unsigned char *der,int *ret_len){
	unsigned char *cp,*ct,*cder;
	int i,j,k,len,err=-1;

	ASN1_int_2object(OBJ_P12v1Bag_CERT,der,&i);
	ct=der+i;

	ASN1_int_2object(OBJ_P9_X509CERT,ct,&j);
	cp=ct+j;
	if(cb->cert->der==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS12,ERR_PT_P12ASN1+7,NULL);
		goto done;
	}
	cder=cb->cert->der;

	/* calc DER length */
	len = ASN1_length(&cder[1],&k);
	len += k+1;

	ASN1_set_octetstring(len,cder,cp,&k);
	ASN1_set_explicit(k,0,cp,&k);
	j+=k;
	ASN1_set_sequence(j,ct,&j);
	ASN1_set_explicit(j,0,ct,&j);
	i+=j; ct=der+i;

	if(P12_get_DER_f_l((P12_Baggage*)cb,ct,&j)) goto done;
	i+=j;

	ASN1_set_sequence(i,der,ret_len);
	err=0;
done:
	return err;
}

/*-----------------------------------------
  estimate P12 DER size from PKCS#12
-----------------------------------------*/
int P12_estimate_der_size(PKCS12 *p12,int bag_type){
	P12_Baggage *bg;
	int ret,i,j;

	if(p12==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS12,ERR_PT_P12ASN1+8,NULL);
		return -1;
	}

	for(ret=0,bg=p12->bag;bg!=NULL;bg=bg->next){
		if(bg->type!=bag_type)
			if(bag_type!=P12_ALLBAGS)
				continue;

		if(bg->friendlyName)
			ret+=bmp_len(bg->friendlyName) + 20;
		ret+=24;	/* localKey ID */

		switch(bg->type){
		case OBJ_P12v1Bag_PKCS8:
			switch(((P12_KeyBag*)bg)->key->key_type){
			case KEY_RSA_PRV:
				i = (((P12_KeyBag*)bg)->key)->size*5; break;
			case KEY_DSA_PRV:
				i = DSAprv_estimate_der_size((Prvkey_DSA*)((P12_KeyBag*)bg)->key); break;
				break;
			case KEY_ECDSA_PRV:
				i = ECDSAprv_estimate_der_size((Prvkey_ECDSA*)((P12_KeyBag*)bg)->key); break;
			}
			ret+=i+128;
			break;
		case OBJ_P12v1Bag_CERT:
			i=ASN1_length(&(((P12_CertBag*)bg)->cert)->der[1],&j);
			ret+=i+j+64;
			break;
		case OBJ_P12v1Bag_CRL:
			i=ASN1_length(&(((P12_CRLBag*)bg)->crl)->der[1],&j);
			ret+=i+j+64;
			break;
		}
	}

	ret+=128;
	return ret;
}
