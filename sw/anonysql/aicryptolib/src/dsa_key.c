/* dsa_key.c */
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

#include "ok_dsa.h"
#include "ok_asn1.h"

/*-----------------------------------
	allocate new DSAPubkey
------------------------------------*/
Pubkey_DSA *DSApubkey_new(void){
	Pubkey_DSA *ret;

	if((ret=(Pubkey_DSA*)MALLOC(sizeof(Pubkey_DSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSAKEY,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Pubkey_DSA));
	ret->key_type = KEY_DSA_PUB;

	if((ret->w=LN_alloc())==NULL) goto error;

	/* ret->pm: DSAParam is just pointer */

	return(ret);
error:
	DSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------
	allocate new DSAPrvkey
------------------------------------*/
Prvkey_DSA *DSAprvkey_new(void){
	Prvkey_DSA *ret;

	if((ret=(Prvkey_DSA*)MALLOC(sizeof(Prvkey_DSA)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSAKEY+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Prvkey_DSA));
	ret->key_type = KEY_DSA_PRV;

	if((ret->w=LN_alloc())==NULL) goto error;
	if((ret->k=LN_alloc())==NULL) goto error;

	/* ret->pm: DSAParam is just pointer */

	return(ret);
error:
	DSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  FREE struct key
-----------------------------------------*/
void DSAkey_free(Key *key){
	if(key==NULL) return;
	switch(key->key_type){
	case KEY_DSA_PUB:
		LN_free(((Pubkey_DSA*)key)->w);
		DSAPm_free(((Pubkey_DSA*)key)->pm);
		break;
	case KEY_DSA_PRV:
		LN_free(((Prvkey_DSA*)key)->w);
		LN_free(((Prvkey_DSA*)key)->k);
		DSAPm_free(((Prvkey_DSA*)key)->pm);
		if(((Prvkey_DSA*)key)->der)
			FREE(((Prvkey_DSA*)key)->der);
		break;
	}
	FREE(key);
}

/*-----------------------------------------
  Duplicate struct key
-----------------------------------------*/
Pubkey_DSA *DSApubkey_dup(Pubkey_DSA *org){
	Pubkey_DSA *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DSA,ERR_PT_DSAKEY+2,NULL);
		return NULL;
	}
	if((ret=DSApubkey_new())==NULL)
		return NULL;
	
	ret->size = org->size;

	LN_copy(org->w,ret->w);
	if(org->pm){
		if((ret->pm =DSAPm_dup(org->pm))==NULL){
			DSAkey_free((Key*)ret);
			return NULL;
		}
	}
	return ret;
}

Prvkey_DSA *DSAprvkey_dup(Prvkey_DSA *org){
	Prvkey_DSA *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DSA,ERR_PT_DSAKEY+3,NULL);
		return NULL;
	}
	if((ret=DSAprvkey_new())==NULL)
		goto error;

	ret->size   = org->size;
	ret->version= org->version;

	LN_copy(org->w,ret->w);
	LN_copy(org->k,ret->k);
	if(org->pm){
		if((ret->pm =DSAPm_dup(org->pm))==NULL)
			goto error;
	}
	if(org->der){
		if((ret->der=ASN1_dup(org->der))==NULL)
			goto error;
	}
	return ret;
error:
	DSAkey_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------
  Duplicate struct key
-----------------------------------------*/
int DSApubkey_cmp(Pubkey_DSA *k1, Pubkey_DSA *k2){
	int i;
	if(i=LN_cmp(k1->w,k2->w)) return i;
	if(i=LN_cmp(k1->pm->p,k2->pm->p)) return i;
	if(i=LN_cmp(k1->pm->g,k2->pm->g)) return i;
	if(i=LN_cmp(k1->pm->q,k2->pm->q)) return i;
	return 0;
}

int DSAprvkey_cmp(Prvkey_DSA *k1, Prvkey_DSA *k2){
	int i;
	if(i=LN_cmp(k1->w,k2->w)) return i;
	if(i=LN_cmp(k1->k,k2->k)) return i;
	if(i=LN_cmp(k1->pm->p,k2->pm->p)) return i;
	if(i=LN_cmp(k1->pm->g,k2->pm->g)) return i;
	if(i=LN_cmp(k1->pm->q,k2->pm->q)) return i;
	return 0;
}

int DSA_pair_cmp(Prvkey_DSA *prv, Pubkey_DSA *pub){
	int i;
	if(i=LN_cmp(prv->w,pub->w)) return i;
	if(i=LN_cmp(prv->pm->p,pub->pm->p)) return i;
	if(i=LN_cmp(prv->pm->g,pub->pm->g)) return i;
	if(i=LN_cmp(prv->pm->q,pub->pm->q)) return i;
	return 0;
}

/*-----------------------------------------
  generate DSA private key
-----------------------------------------*/
int DSAprv_generate(DSAParam *pm,Prvkey_DSA *ret){
	LNm *tmp1=NULL,*tmp2=NULL;
	int i,err=-1;

	LN_init_lexp_tv();
	if((tmp1=LN_alloc())==NULL) goto done;
	if((tmp2=LN_alloc())==NULL) goto done;

	do{ /* create one time password */
	    err  = LN_set_rand(tmp1, 20 /* byte */, (unsigned short)(rand()*3));
		err  = LN_div_mod(tmp1,pm->q,tmp2,ret->k);
		err |= LN_exp_mod(pm->g,ret->k,pm->p,ret->w);
		if(err) goto done;
	}while((ret->k->top==0)||(ret->w->top==0));

	ret->size    = LN_now_byte(pm->p);
	ret->version = 0;

	if(ret->pm==NULL)
		if((ret->pm=DSAPm_dup(pm))==NULL)
			goto done;

	if((ret->der=DSAprv_toDER(ret,NULL,&i))==NULL) goto done;

	err=0;
done:
	LN_free(tmp1); LN_free(tmp2);
	return err;
}


/*-----------------------------------------
  Copy DSA private key to DSA pubkey
-----------------------------------------*/
int DSAprv_2pub(Prvkey_DSA *prv,Pubkey_DSA *pub){
	LN_copy(prv->w,pub->w);

	if(pub->pm) DSAPm_free(pub->pm);

	if(prv->pm){
		if((pub->pm=DSAPm_dup(prv->pm))==NULL) return -1;
	}
	pub->size=prv->size;
	return 0;
}



