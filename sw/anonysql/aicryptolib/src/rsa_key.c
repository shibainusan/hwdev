/* rsa_key.c */
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

#include "key_type.h"
#include "ok_asn1.h"
#include "ok_rsa.h"
#include "ok_x509.h"

/*-----------------------------------------
  make new struct key
-----------------------------------------*/
Pubkey_RSA *RSApubkey_new(void){
	Pubkey_RSA	*ret;

	if((ret=(Pubkey_RSA*)MALLOC(sizeof(Pubkey_RSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RSA,ERR_PT_RSAKEY,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Pubkey_RSA));
	ret->key_type = KEY_RSA_PUB;

	if((ret->n=LN_alloc())==NULL) goto error;
	if((ret->e=LN_alloc())==NULL) goto error;
	return(ret);
error:
	RSAkey_free((Key*)ret);
	return NULL;
}

Prvkey_RSA *RSAprvkey_new(void){
	Prvkey_RSA	*ret;

	if((ret=(Prvkey_RSA*)MALLOC(sizeof(Prvkey_RSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RSA,ERR_PT_RSAKEY+1,NULL);
		return NULL;
	}

	memset(ret,0,sizeof(Prvkey_RSA));
	ret->key_type = KEY_RSA_PRV;

	if((ret->n  = LN_alloc())==NULL) goto error;
	if((ret->e  = LN_alloc())==NULL) goto error;
	if((ret->d  = LN_alloc())==NULL) goto error;
	if((ret->p  = LN_alloc())==NULL) goto error;
	if((ret->q  = LN_alloc())==NULL) goto error;
	if((ret->e1 = LN_alloc())==NULL) goto error;
	if((ret->e2 = LN_alloc())==NULL) goto error;
	if((ret->cof= LN_alloc())==NULL) goto error;

	return(ret);
error:
	RSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  FREE struct key
-----------------------------------------*/
void RSAkey_free(Key *key){
	Prvkey_RSA	*k;

	if(key==NULL) return;
	switch(key->key_type){
	case KEY_RSA_PUB:
		LN_free(((Pubkey_RSA*)key)->n);
		LN_free(((Pubkey_RSA*)key)->e);
		FREE((Pubkey_RSA*)key);
		break;
	case KEY_RSA_PRV:
		k = (Prvkey_RSA*)key;
		memset(k->d->num,0,sizeof(ULONG)*LN_MAX);
		memset(k->p->num,0,sizeof(ULONG)*LN_MAX);
		memset(k->q->num,0,sizeof(ULONG)*LN_MAX);
		memset(k->e1->num,0,sizeof(ULONG)*LN_MAX);
		memset(k->e2->num,0,sizeof(ULONG)*LN_MAX);
		memset(k->cof->num,0,sizeof(ULONG)*LN_MAX);
		LN_free(k->n);
		LN_free(k->e);
		LN_free(k->d);
		LN_free(k->p);
		LN_free(k->q);
		LN_free(k->e1);
		LN_free(k->e2);
		LN_free(k->cof);
		if(k->der) FREE(k->der);
		FREE((Prvkey_RSA*)key);
		break;
	}
}

/*-----------------------------------------
  Generate RSA private key. 
-----------------------------------------*/
int RSAprv_generate(Prvkey_RSA *ret,int byte){
	ULONG p1s[LN_MAX],q1s[LN_MAX],phis[LN_MAX];
	LNm	p1,q1,phi,*tmp;
	int	i,err;

	p1.num=p1s; q1.num=q1s; phi.num=phis;
	p1.size=q1.size=phi.size=LN_MAX;

	/* generate p and q */
	if(LN_prime(byte,ret->p,1)) goto error;
	if(LN_prime(byte,ret->q,1)) goto error;

	/* because LN_mod_inverse() might be faster */
	if(LN_cmp(ret->p,ret->q)<0){ /* if p < q */
		tmp=ret->p;
		ret->p = ret->q;
		ret->q = tmp;
	}

	/* set p1,q1,phi */
	LN_copy(ret->p,&p1);
	LN_copy(ret->q,&q1);

	/* p or q is prime, so last bit must have "1." */
	p1s[LN_MAX-1]&=0xfffffffe;	/* p1=p-1 */
	q1s[LN_MAX-1]&=0xfffffffe;	/* q1=q-1 */
	if(LN_multi(&p1,&q1,&phi)) goto error;

	LN_long_set(ret->e,0x10001L);			/* e = 0x10001 */
	err = LN_multi(ret->p,ret->q,ret->n);      	/* n =p*q */
	err|= LN_mod_inverse(ret->e,&phi,ret->d);	/* d = e^-1 mod phi */
	if(err) goto error;

	err = LN_div_mod(ret->d,&p1,&phi,ret->e1);	/* e1= d mod p-1 */
	err|= LN_div_mod(ret->d,&q1,&phi,ret->e2);	/* e2= d mod q-1 */
	err|= LN_mod_inverse(ret->q,ret->p,ret->cof);	/* cof = q^-1 mod p */
	if(err) goto error;

	ret->size=byte*2;

	if((ret->der=RSAprv_toDER(ret,NULL,&i))==NULL)
		goto error;
	return 0;
error:
	if(ret->der) FREE(ret->der);
	return -1;
}

/*-----------------------------------------
  Copy RSA private key to RSA pubkey
-----------------------------------------*/
void RSAprv_2pub(Prvkey_RSA *prv,Pubkey_RSA *pub){
	LN_copy(prv->n,pub->n);
	LN_copy(prv->e,pub->e);
	pub->size=prv->size;
}

/*-----------------------------------------
  duplicate RSA key structure
-----------------------------------------*/
Pubkey_RSA *RSApubkey_dup(Pubkey_RSA *src){
	Pubkey_RSA	*ret;

	if(src==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_RSA,ERR_PT_RSAKEY+3,NULL);
		return NULL;
	}
	if((ret=(Pubkey_RSA*)MALLOC(sizeof(Pubkey_RSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RSA,ERR_PT_RSAKEY+3,NULL);
		return NULL;
	}
	memcpy(ret,src,sizeof(Pubkey_RSA));

	if((ret->n=LN_clone(src->n))==NULL) goto error;
	if((ret->e=LN_clone(src->e))==NULL) goto error;
	return ret;
error:
	RSAkey_free((Key*)ret);
	return NULL;
}

Prvkey_RSA *RSAprvkey_dup(Prvkey_RSA *src){
	Prvkey_RSA	*ret;

	if(src==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_RSA,ERR_PT_RSAKEY+4,NULL);
		return NULL;
	}
	if((ret=(Prvkey_RSA*)MALLOC(sizeof(Prvkey_RSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RSA,ERR_PT_RSAKEY+4,NULL);
		return NULL;
	}

	memcpy(ret,src,sizeof(Prvkey_RSA));

	if((ret->n  = LN_clone(src->n))  ==NULL) goto error;
	if((ret->e  = LN_clone(src->e))  ==NULL) goto error;
	if((ret->d  = LN_clone(src->d))  ==NULL) goto error;
	if((ret->p  = LN_clone(src->p))  ==NULL) goto error;
	if((ret->q  = LN_clone(src->q))  ==NULL) goto error;
	if((ret->e1 = LN_clone(src->e1)) ==NULL) goto error;
	if((ret->e2 = LN_clone(src->e2)) ==NULL) goto error;
	if((ret->cof= LN_clone(src->cof))==NULL) goto error;
	if(src->der)
		if((ret->der=ASN1_dup(src->der))==NULL) goto error;
	return ret;
error:
	RSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  compare two RSA key structures
-----------------------------------------*/
int RSApubkey_cmp(Pubkey_RSA *k1,Pubkey_RSA *k2){
	int i;
	if(i=LN_cmp(k1->n,k2->n)) return i;
	if(i=LN_cmp(k1->e,k2->e)) return i;
	return 0;
}

int RSAprvkey_cmp(Prvkey_RSA *k1,Prvkey_RSA *k2){
	int i;
	if(i=LN_cmp(k1->n,k2->n)) return i;
	if(i=LN_cmp(k1->e,k2->e)) return i;
	if(i=LN_cmp(k1->p,k2->p)) return i;
	if(i=LN_cmp(k1->q,k2->q)) return i;
	return 0;
}

/*-----------------------------------------
  check if prv & pub is valid pair.
-----------------------------------------*/
int RSA_pair_cmp(Prvkey_RSA *prv,Pubkey_RSA *pub){
	int i;
	if(i=LN_cmp(prv->n,pub->n)) return i;
	if(i=LN_cmp(prv->e,pub->e)) return i;
	return 0;
}
