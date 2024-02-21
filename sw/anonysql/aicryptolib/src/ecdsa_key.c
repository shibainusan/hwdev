/* ecdsa_key.c */
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

#include <math.h>

#include "key_type.h"
#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_ecdsa.h"

/*-----------------------------------------
  make new struct key
-----------------------------------------*/
Pubkey_ECDSA *ECDSApubkey_new(void){
	Pubkey_ECDSA	*ret;

	if((ret=(Pubkey_ECDSA*)MALLOC(sizeof(Pubkey_ECDSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECDSA,ERR_PT_ECDSAKEY,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Pubkey_ECDSA));
	ret->key_type = KEY_ECDSA_PUB;

	if((ret->W=ECp_new())==NULL) goto error;
	/* ret->E: EC Parameter will be allocated at another point */

	return(ret);
error:
	ECDSAkey_free((Key*)ret);
	return NULL;
}

Prvkey_ECDSA *ECDSAprvkey_new(void){
	Prvkey_ECDSA	*ret;

	if((ret=(Prvkey_ECDSA*)MALLOC(sizeof(Prvkey_ECDSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECDSA,ERR_PT_ECDSAKEY+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Prvkey_ECDSA));
	ret->key_type = KEY_ECDSA_PRV;

	if((ret->W=ECp_new()) ==NULL) goto error;
	if((ret->k=LN_alloc())==NULL) goto error;
	/* ret->E: EC Parameter will be allocated at another point */

	return(ret);
error:
	ECDSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  FREE struct key
-----------------------------------------*/
void ECDSAkey_free(Key *key){
	if(key==NULL) return;
	switch(key->key_type){
	case KEY_ECDSA_PUB:
		ECp_free(((Pubkey_ECDSA*)key)->W);
		ECPm_free(((Pubkey_ECDSA*)key)->E);
		break;
	case KEY_ECDSA_PRV:
		ECp_free(((Prvkey_ECDSA*)key)->W);
		LN_free(((Prvkey_ECDSA*)key)->k);
		ECPm_free(((Prvkey_ECDSA*)key)->E);
		if(((Prvkey_ECDSA*)key)->der)
			FREE(((Prvkey_ECDSA*)key)->der);
		break;
	}
	FREE(key);
}

/*-----------------------------------------
  Generate ECDSA private key. 
-----------------------------------------*/
int ECDSAprv_generate(ECParam *E,Prvkey_ECDSA *ret){
	LNm *tmp,*rnd;
	int	i,err;

	tmp = E->buf[0]; rnd=E->buf[1];

	if((ret->E=ECPm_dup(E))==NULL) goto error;

	do{
		LN_long_set(E->G->z,1);
		err = LN_set_rand(rnd,E->nsize>>3,(unsigned short)(rand()*3));
		err|= LN_div_mod(rnd,E->n,tmp,ret->k);
		err|= ECp_pmulti(E,E->G,ret->k,ret->W);
		err|= ECp_proj2af(E,ret->W);
		if(err) goto error;
	}while((ret->W->x->top==0)&&(ret->W->y->top==0));

	ret->version=1;
	ret->size   =((E->psize-1)>>3)+1;

	if((ret->der=ECDSAprv_toDER(ret,NULL,&i))==NULL) goto error;

	return 0;
error:
	return -1;
}

/*-----------------------------------------
  Copy ECDSA private key to ECDSA pubkey
-----------------------------------------*/
int ECDSAprv_2pub(Prvkey_ECDSA *prv,Pubkey_ECDSA *pub){
	ECp_copy(prv->W,pub->W);

	if(pub->E) ECPm_free(pub->E);

	if(prv->E){
		if((pub->E=ECPm_dup(prv->E))==NULL) return -1;
	}
	pub->size=prv->size;
	return 0;
}

/*-----------------------------------------
  Duplicate keys
-----------------------------------------*/
Pubkey_ECDSA *ECDSApubkey_dup(Pubkey_ECDSA *pub){
	Pubkey_ECDSA *ret;

	if(pub==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECDSA,ERR_PT_ECDSAKEY+2,NULL);
		return NULL;
	}
	if((ret=ECDSApubkey_new())==NULL)
		return NULL;

	ECp_copy(pub->W,ret->W);
	if(pub->E){
		if((ret->E =ECPm_dup(pub->E))==NULL){
			ECDSAkey_free((Key*)ret);
			return NULL;
		}
	}
	ret->size=pub->size;

	return ret;
}

Prvkey_ECDSA *ECDSAprvkey_dup(Prvkey_ECDSA *prv){
	Prvkey_ECDSA *ret;

	if(prv==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECDSA,ERR_PT_ECDSAKEY+3,NULL);
		return NULL;
	}
	if((ret=ECDSAprvkey_new())==NULL)
		goto error;

	ECp_copy(prv->W,ret->W);
	LN_copy(prv->k,ret->k);
	if(prv->E){
		if((ret->E =ECPm_dup(prv->E))==NULL)
			goto error;
	}
	if(prv->der){
		if((ret->der=ASN1_dup(prv->der))==NULL)
			goto error;
	}
	ret->version = prv->version;
	ret->size    = prv->size;

	return ret;
error:
	ECDSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  compare two keys
-----------------------------------------*/
int ECDSApubkey_cmp(Pubkey_ECDSA *k1,Pubkey_ECDSA *k2){
	int i;
	LN_long_set(k1->W->z,1);
	LN_long_set(k2->W->z,1);
	if(i=ECp_cmp(k1->W,   k2->W)) return i;
	if(i=LN_cmp(k1->E->p, k2->E->p)) return i;
	if(i=LN_cmp(k1->E->n, k2->E->n)) return i;
	if(i=LN_cmp(k1->E->a, k2->E->a)) return i;
	if(i=LN_cmp(k1->E->b, k2->E->b)) return i;
	LN_long_set(k1->E->G->z,1);
	LN_long_set(k2->E->G->z,1);
	if(i=ECp_cmp(k1->E->G,k2->E->G)) return i;
	return 0;
}

int ECDSAprvkey_cmp(Prvkey_ECDSA *k1,Prvkey_ECDSA *k2){
	int i;
	LN_long_set(k1->W->z,1);
	LN_long_set(k2->W->z,1);
	if(i=ECp_cmp(k1->W,k2->W)) return i;
	if(i=LN_cmp(k1->k, k2->k)) return i;
	if(i=LN_cmp(k1->E->p, k2->E->p)) return i;
	if(i=LN_cmp(k1->E->n, k2->E->n)) return i;
	if(i=LN_cmp(k1->E->a, k2->E->a)) return i;
	if(i=LN_cmp(k1->E->b, k2->E->b)) return i;
	LN_long_set(k1->E->G->z,1);
	LN_long_set(k2->E->G->z,1);
	if(i=ECp_cmp(k1->E->G,k2->E->G)) return i;
	return 0;
}

int ECDSA_pair_cmp(Prvkey_ECDSA *prv,Pubkey_ECDSA *pub){
	int i;
	LN_long_set(prv->W->z,1);
	LN_long_set(pub->W->z,1);
	if(i=ECp_cmp(prv->W,   pub->W)) return i;
	if(i=LN_cmp(prv->E->p, pub->E->p)) return i;
	if(i=LN_cmp(prv->E->n, pub->E->n)) return i;
	if(i=LN_cmp(prv->E->a, pub->E->a)) return i;
	if(i=LN_cmp(prv->E->b, pub->E->b)) return i;
	LN_long_set(prv->E->G->z,1);
	LN_long_set(pub->E->G->z,1);
	if(i=ECp_cmp(prv->E->G,pub->E->G)) return i;
	return 0;
}
