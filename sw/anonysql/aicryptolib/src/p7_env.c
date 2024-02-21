/* p7_env.c */
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
#include <time.h>

#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_rand.h"

#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_tool.h"

/* just use OBJ_CRYALGO_*, because of object identifier */
int default_p7env_cry_algo = OBJ_CRYALGO_RC2CBC;
int default_p7env_passwd_len = 40; /* bits */

int get_enc_algo(Key *key);	/* p7_sign.c */
unsigned char *get_random_bytes(int size);

/*-----------------------------------------------
  get PKCS#7 Enveloped-DATA
-----------------------------------------------*/
PKCS7 *P7m_encrypt_enveloped(PKCS7 *p7b,unsigned char *data,int data_len){
	PKCS7 *p7;
	P7_Envelope	*p7env;
	EncCntInfo	*ei;
	unsigned char *pass=NULL;
	int	plen,err=-1;

	if((p7=P7_new(OBJ_P7_ENVELP))==NULL) goto done;
	p7env = (P7_Envelope*)p7->cont;

	/* set version */
	p7env->version = 0;

	/* set password length with default value */
	plen = default_p7env_passwd_len >> 3; /* bits -> bytes */

	/* generate new (one time) password */
	if((pass=get_random_bytes(plen))==NULL) goto done;

	if(P7m_get_recipInfo(p7env->recipi,p7b,pass,plen)) goto done;

	/* set encryption algorithm before using P7m_get_encCnt func. */
	ei = p7env->encCnt;
	ei->enc_algo = default_p7env_cry_algo;
	ei->data = data;		/* just use ei->data and ei-> size temporary */
	ei->size = data_len;	/* after using P7m_get_encCnt(), ei->data will be different */
	if(P7m_get_encCnt(ei,pass,plen)) goto done;

	err=0;
done:
	if(pass){
		memset(pass,0,plen);
		FREE(pass);
	}
	if(err&&p7){P7_free(p7);p7=NULL;}
	return p7;
}

unsigned char *get_random_bytes(int size){
	unsigned char *ret;
	int i;
	if((ret=(unsigned char*)MALLOC(size))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7ENV+1,NULL);
		return NULL;
	}
	RAND_bytes(ret,size);
	for(i=0;i<size;i++) ret[i] |= 0x01;
	return ret;
}

int P7m_get_recipInfo(RecipInfo *recipi,PKCS7 *p7b,unsigned char *pass, int ps_size){
	P12_CertBag *cb;
	RecipInfo *rcp;
	Key	 *key;
	int	i,max,sn;

	if(P12_check_chain((PKCS12*)p7b,0)) goto error;
	max = P12_max_depth((PKCS12*)p7b,OBJ_P12v1Bag_CERT);
	if((cb=(P12_CertBag*)P12_find_bag((PKCS12*)p7b,OBJ_P12v1Bag_CERT,(unsigned char)max))==NULL)
		goto error;

	sn=cb->cert->serialNumber;
	key=cb->cert->pubkey;
	rcp = recipi;
	i=0;
	do{
		if((cb=(P12_CertBag*)P12_find_bag((PKCS12*)p7b,OBJ_P12v1Bag_CERT,(unsigned char)i))==NULL)
			goto error;

		rcp->version = 0;
		rcp->serialNum = sn;
		rcp->size = key->size;
		if(Cert_dncopy(&cb->cert->issuer_dn,&rcp->iss_dn)) goto error;
		if((rcp->iss_str =Cert_subject_str(&rcp->iss_dn))==NULL) goto error;
		if((rcp->enc_algo=get_enc_algo(key))<0) goto error;
		if((rcp->key =P7m_recip_get_key(key,pass,ps_size))==NULL) goto error;

		i++;
		if(i<=max){
			if((rcp->next=P7_recip_new())==NULL) goto error;
			rcp=rcp->next;
		}else
			break;
	}while(1);
	return 0;
error:
	P7_recip_free(recipi->next);
	recipi->next=NULL;
	return -1;
}

unsigned char *P7m_recip_get_key(Key *pubkey,unsigned char *pass, int ps_size){
	unsigned char *cry,*ret=NULL;
	int	sz,err=-1;

	sz = pubkey->size;

	/* set random number to cry */
	if((cry=get_random_bytes(sz))==NULL) goto done;

	/* set password */
	memcpy(&cry[sz-ps_size],pass,ps_size);
	cry[0]=0; cry[1]=2; cry[sz-ps_size-1]=0;

	if((ret=OK_do_sign(pubkey,cry,sz,NULL))==NULL) goto done;

	err=0;
done:
	if(cry){
		memset(cry,0,sz);
		FREE(cry);
	}
	return ret;
}

/*-----------------------------------------------
  get content data from PKCS#7 Enveloped-DATA
-----------------------------------------------*/
unsigned char *P7m_decrypt_enveloped(PKCS7 *p7, Cert *ct, Key *key){
	P7_Envelope	*p7env;
	RecipInfo *recipi;
	unsigned char *ret,*decry;
	int	i,len,err=-1;

	if((p7env=(P7_Envelope*)p7->cont)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_P7ENV+3,NULL);
		goto done;
	}
	if((recipi=p7env->recipi)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS7,ERR_PT_P7ENV+3,NULL);
		goto done;
	}

	ret=decry=NULL;
	do{
		/* check serial number and issuer */
		if(recipi->serialNum == ct->serialNumber)
			if(!strcmp(recipi->iss_str,ct->issuer)){
				if(ret) FREE(ret);
				if((ret=OK_do_sign(key,recipi->key,recipi->size,NULL))==NULL)
					goto done;
			}
		recipi = recipi->next;
	}while(recipi);

	if(ret==NULL){

		/* certificate or key is not matched with P7 issuer & serial num */
		OK_set_error(ERR_ST_UNMATCHEDPARAM,ERR_LC_PKCS7,ERR_PT_P7ENV+3,NULL);
		goto done;
	}

	/* get password for decryption (throuth PKCS#1 padding) */
	for(i=1;i<key->size;i++)
		if(!ret[i])	break;

	if(i==key->size){ /* decryption error */
		OK_set_error(ERR_ST_P1_BADPADDING,ERR_LC_PKCS7,ERR_PT_P7ENV+3,NULL);
		goto done;
	}

	i++;
	len = key->size -i;

	if((decry=P7m_decrypt_encCnt(p7env->encCnt,&ret[i],len))==NULL)
		goto done;

	err=0;
done:
	if(ret){memset(ret,0,key->size); FREE(ret);}
	return decry;
}


/*-----------------------------------------------
  encrypt and decrypt with RC2 key
-----------------------------------------------*/
int P7m_get_encCnt(EncCntInfo *ei,unsigned char *pass,int ps_size){
	unsigned char *ret=NULL,*plain=NULL;
	Key_RC2 *rc2k=NULL;
	Key_DES *desk=NULL;
	Key_3DES *des3k=NULL;
	int	sz,err=-1;

	/* set type and IV size*/
	ei->type    = OBJ_P7_DATA;
	ei->iv_size = 8;
	if((ei->iv=get_random_bytes(8))==NULL) goto done;

	switch(ei->enc_algo){
	case OBJ_CRYALGO_RC2CBC:
		switch(ps_size){
		case 16: ei->iter = 58;  break;
		case 8:  ei->iter = 120; break;
		default: ei->iter = 160; break;
		}
		if((rc2k=RC2key_new(ps_size,pass))==NULL) goto done;
		RC2_set_iv(rc2k,ei->iv);
		break;
	case OBJ_CRYALGO_DESCBC:
		if((desk=DESkey_new(ps_size,pass))==NULL) goto done;
		DES_set_iv(desk,ei->iv);
		break;
	case OBJ_CRYALGO_3DESCBC:
		if((des3k=DES3key_new_c(ps_size,pass))==NULL) goto done;
		DES3_set_iv(des3k,ei->iv);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS7,ERR_PT_P7ENV+4,NULL);
		goto done;
	}	

	sz=ei->size;
	if((plain=(unsigned char*)MALLOC(sz+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7ENV+4,NULL);
		goto done;
	}
	if((ret  =(unsigned char*)MALLOC(sz+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7ENV+4,NULL);
		goto done;
	}

	/* set padding */
	memcpy(plain,ei->data,sz);
	sz=RFC1423_enc_padding(8,sz,plain);

	switch(ei->enc_algo){
	case OBJ_CRYALGO_RC2CBC:
		RC2_cbc_encrypt(rc2k,sz,plain,ret);
		break;
	case OBJ_CRYALGO_DESCBC:
		DES_cbc_encrypt(desk,sz,plain,ret);
		break;
	case OBJ_CRYALGO_3DESCBC:
		DES3_cbc_encrypt(des3k,sz,plain,ret);
		break;
	}

	/* ei->data was just pointer of law data.
	 * so it is possible to hand a allocated (and encrypted) data to ei->data.
	 */
	ei->data=ret;
	ei->size=sz;
	err=0;
done:
	if(plain) FREE(plain);
	if(err&&ret) FREE(ret);
	DES3key_free(des3k);
	DESkey_free(desk);
	RC2key_free(rc2k);
	return err;
}

unsigned char *P7m_decrypt_encCnt(EncCntInfo *ei, unsigned char *pass,int ps_size){
	unsigned char *ret=NULL;
	Key_RC2 *rc2k=NULL;
	Key_DES *desk=NULL;
	Key_3DES *des3k=NULL;
	int	sz,err=-1;

	switch(ei->enc_algo){
	case OBJ_CRYALGO_RC2CBC:
		if((rc2k=RC2key_new(ps_size,pass))==NULL) goto done;
		RC2_set_iv(rc2k,ei->iv);
		break;
	case OBJ_CRYALGO_DESCBC:
		if((desk=DESkey_new(ps_size,pass))==NULL) goto done;
		DES_set_iv(desk,ei->iv);
		break;
	case OBJ_CRYALGO_3DESCBC:
		if((des3k=DES3key_new_c(ps_size,pass))==NULL) goto done;
		DES3_set_iv(des3k,ei->iv);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS7,ERR_PT_P7ENV+5,NULL);
		goto done;
	}

	sz=ei->size;
	if((ret=(unsigned char*)MALLOC(sz))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7ENV+5,NULL);
		goto done;
	}

	switch(ei->enc_algo){
	case OBJ_CRYALGO_RC2CBC:
		RC2_cbc_decrypt(rc2k,sz,ei->data,ret);
		break;
	case OBJ_CRYALGO_DESCBC:
		DES_cbc_decrypt(desk,sz,ei->data,ret);
		break;
	case OBJ_CRYALGO_3DESCBC:
		DES3_cbc_decrypt(des3k,sz,ei->data,ret);
		break;
	}

	/* check & clean padding */
	if(RFC1423_check_padding(sz,ret)) goto done;

	err=0;
done:
	DES3key_free(des3k);
	DESkey_free(desk);
	RC2key_free(rc2k);
	if(err&&ret){FREE(ret);ret=NULL;}
	return ret;
}


