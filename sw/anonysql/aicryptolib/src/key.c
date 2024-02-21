/* key.c */
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

#include "ok_x509.h"
#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_rc4.h"
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"

void key_print_dsaparam(DSAParam *pm);
void key_print_ecparam(ECParam *pm);


/*-----------------------------------------
  make new struct key
-----------------------------------------*/
Key *Key_new(int type){
	Key	*ret=NULL;
	switch(type){
	case KEY_RSA_PUB:
		ret = (Key*)RSApubkey_new();
		break;
	case KEY_RSA_PRV:
		ret = (Key*)RSAprvkey_new();
		break;
	case OBJ_CRYALGO_DESCBC:
	case KEY_DES:
		ret = (Key*)DESkey_new_();
		break;
	case OBJ_CRYALGO_3DESCBC:
	case KEY_3DES:
		ret = (Key*)DES3key_new_();
		break;
	case OBJ_CRYALGO_RC2CBC:
	case KEY_RC2:
		ret = (Key*)RC2key_new_();
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509KEY,ERR_PT_KEY,NULL);
		break;
	}
	return ret;
}

/*-----------------------------------------
  FREE struct key
-----------------------------------------*/
void Key_free(Key *key){
	if(key==NULL) return;

	switch(key->key_type){
	case KEY_RSA_PUB:
	case KEY_RSA_PRV:
		RSAkey_free(key);
		break;
	case KEY_DSA_PUB:
	case KEY_DSA_PRV:
		DSAkey_free(key);
		break;
	case KEY_ECDSA_PUB:
	case KEY_ECDSA_PRV:
		ECDSAkey_free(key);
		break;
	case KEY_DES:
		DESkey_free((Key_DES*)key);
		break;
	case KEY_3DES:
		DES3key_free((Key_3DES*)key);
		break;
	case KEY_RC2:
		RC2key_free((Key_RC2*)key);
		break;
#if _USE_RC4
	case KEY_RC4:
		RC4key_free((Key_RC4*)key);
		break;
#endif
	default:
		FREE(key);
		break;
	}
}

/*-----------------------------------------
  set symmentric key
-----------------------------------------*/
int Key_set(Key *key,unsigned char *passwd, int len){
	switch(key->key_type){
	case KEY_DES:  DESkey_set((Key_DES*)key,len,passwd); break;
	case KEY_3DES: DES3key_set_c((Key_3DES*)key,len,passwd); break;
	case KEY_RC2:  RC2key_set((Key_RC2*)key,len,passwd); break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509KEY,ERR_PT_KEY+2,NULL);
		return -1;
	}
	return 0;
}

/*-----------------------------------------
  set IV
-----------------------------------------*/
int Key_set_iv(Key *key,unsigned char *iv){
	switch(key->key_type){
	case KEY_DES:  DES_set_iv((Key_DES*)key,iv); break;
	case KEY_3DES: DES3_set_iv((Key_3DES*)key,iv); break;
	case KEY_RC2:  RC2_set_iv((Key_RC2*)key,iv); break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509KEY,ERR_PT_KEY+3,NULL);
		return -1;
	}
	return 0;
}

/*-----------------------------------------
  print struct key
-----------------------------------------*/
int Key_print(Key *key){
	Prvkey_RSA	*prv;
	Prvkey_DSA	*dsa;
	Prvkey_ECDSA	*ec;
    
	switch(key->key_type){
	case KEY_RSA_PRV:
		prv=(Prvkey_RSA*)key;
		printf("RSA Private Key:\nmodules:\n");
		LN_print2(prv->n,2);
		printf("publicExponent:\n");
		LN_print2(prv->e,2);
		printf("privateExponent:\n");
		LN_print2(prv->d,2);
		printf("prime1:\n");
		LN_print2(prv->p,2);
		printf("prime2:\n");
		LN_print2(prv->q,2);
		printf("exponent1:\n");
		LN_print2(prv->e1,2);
		printf("exponent2:\n");
		LN_print2(prv->e2,2);
		printf("coefficient:\n");
		LN_print2(prv->cof,2);
		break;
	case KEY_DSA_PRV:
		dsa=(Prvkey_DSA*)key;
		printf("DSA Private Key:\n");
		printf("w (pub) :\n");
		LN_print2(dsa->w,2);
		printf("k (prv) :\n");
		LN_print2(dsa->k,2);
		key_print_dsaparam(dsa->pm);
		break;
	case KEY_ECDSA_PRV:
		ec=(Prvkey_ECDSA*)key;
		printf("ECDSA Private Key:\n");
		printf("W.x (pub) :\n");
		LN_print2(ec->W->x,2);
		printf("W.y (pub) :\n");
		LN_print2(ec->W->y,2);
		printf("k (private key) :\n");
		LN_print2(ec->k,2);
		key_print_ecparam(ec->E);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509KEY,ERR_PT_KEY+1,NULL);
		return -1;
	}
	return 0;
}

void key_print_dsaparam(DSAParam *pm){
	printf("DSA Parameter:\n");
	printf("p (prime) :\n");
	LN_print2(pm->p,2);
	printf("q (prime) :\n");
	LN_print2(pm->q,2);
	printf("g (prime) :\n");
	LN_print2(pm->g,2);
}

void key_print_ecparam(ECParam *pm){
	char num[32];

	printf("Elliptic Curve Parameters: \n");
	if((pm->curve_type != ECP_ORG_primeParam) &&
	   (pm->curve_type != ECP_ORG_char2Param)){
		switch_str(pm->curve_type,num);
		printf("prime-field (Prime-p):\n");
		printf("  %s\n",num);
	}else{
		switch_str(pm->curve_type,num);
		printf("FieldID : ");
		switch(pm->type){
		case OBJ_X962_FT_PRIME:
		  printf(" prime-field (Prime-p):\n");
		  LN_print2(pm->p,2);
		  break;
		case OBJ_X962_FT_CHR2:
		  printf(" characteristic-two-field\n");
		  break;
		}

		/* curve */
		printf("Curve :\n");
		printf("a :\n");
		LN_print2(pm->a,2);
		printf("b :\n");
		LN_print2(pm->b,2);

		/* base */
		printf("Base point G :\n");
		printf("G.x :\n");
		LN_print2(pm->G->x,2);
		printf("G.y :\n");
		LN_print2(pm->G->y,2);

		/* order */
		printf("order of base point (n):\n");
		LN_print2(pm->n,2);

		/* cofactor */
		if(pm->h->top){
		  printf("cofactor ( h = #E(F)/n ) :\n");
		  LN_print2(pm->h,2);
		}
	}
}
