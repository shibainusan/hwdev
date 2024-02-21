/* large_exp.c */
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

#include "large_num.h"

static ULONG ds[LN_MAX],ts[LN_MAX];
static LNm	dv,tmp;

void LN_init_lexp_tv(){
	dv.num=ds;
	tmp.num=ts;
	dv.size =tmp.size =LN_MAX;
}

/*-----------------------------------------------
  ret = a + b mod n
-----------------------------------------------*/
int _LN_add_mod(LNm *a,LNm *b,LNm *n,LNm *ret, LNm *c){
	int	i;

	if(c==NULL) c=&tmp;

	if(LN_plus(a,b,c)) goto err;	/* c = a + b */
	if((i=LN_cmp(c,n))==0){
		LN_clean(ret);
	}else if(i>0){
		if(LN_minus(c,n,ret)) goto err;
	}else{
		LN_copy(c,ret);
	}
	return 0;
err:
	return -1;
}

/*-----------------------------------------------
  ret = a - b mod n
-----------------------------------------------*/
int _LN_sub_mod(LNm *a,LNm *b,LNm *n,LNm *ret,LNm *c){
	if(c==NULL) c=&tmp;

	if(LN_cmp(a,b)<0){
		if(LN_plus(a,n,c)) goto err;
		if(LN_minus(c,b,ret)) goto err;
	}else{
		if(LN_minus(a,b,ret)) goto err;
	}
	return 0;
err:
	return -1;
}

/*-----------------------------------------------
  ret = a * b mod n
-----------------------------------------------*/
int _LN_mul_mod(LNm *a,LNm *b,LNm *n,LNm *ret, LNm *t,LNm *d){
	if(t==NULL) t=&tmp;
	if(d==NULL) d=&dv;

	if(LN_multi(a,b,t)) goto err;	/* tmp = a*b */
	if(LN_div_mod(t,n,d,ret)) goto err;  /* ret = tmp mod n */
	return 0;
err:
	return -1;
}

/*-----------------------------------------------
  ret = a ^ 2 mod n
-----------------------------------------------*/
int _LN_sqr_mod(LNm *a,LNm *n,LNm *ret, LNm *t,LNm *d){	    
	if(t==NULL) t=&tmp;
	if(d==NULL) d=&dv;

	if(LN_sqr(a,t)) goto err;	/* tmp = a*b */
	if(LN_div_mod(t,n,d,ret)) goto err;  /* ret = tmp mod n */
	return 0;
err:
	return -1;
}


/* use window method for exp_mod */
/*-----------------------------------------------
  ret = x ^ e mod n
-----------------------------------------------*/
/* binary with (5bit) window method */
int LN_exp_mod(LNm *x,LNm *e,LNm *n,LNm *ret){
#ifdef USE_PTHREAD
	ULONG sv[18][LN_MAX];
	LNm lv[18];    
#else
	static ULONG sv[18][LN_MAX];
	static LNm lv[18];
#endif
	int i,j,l,r,er=0;
	ULONG *en;

	/** must be x->size = e->size = n->size = ret->size **/
	LN_init_lexp_tv();  /* this oparation is not thread-safe !! */
	for(i=0;i<18;i++){
		lv[i].num  = sv[i];
		lv[i].size = LN_MAX;
	}

	/* make lv[i] = x^(16+i) mod n */
	/* set lv[0] = x^16 */
	if(_LN_sqr_mod(x,n,&lv[0],&lv[16],&lv[17])) goto error;
	for(i=0;i<2;i++) if(_LN_sqr_mod(&lv[i],n,&lv[i+1],&lv[16],&lv[17])) goto error;
	if(_LN_sqr_mod(&lv[2],n,&lv[0],&lv[16],&lv[17])) goto error;

	/* set all table */
	for(i=0;i<15;i++)
		if(_LN_mul_mod(&lv[i],x,n,&lv[i+1],&lv[16],&lv[17])) goto error; /* lv[i+1] = lv[i]*x mod n */

	en= e->num;
	j = LN_now_bit(e);

	/* if j is bigger than 4, copy table data to ret */
	if(j>4){
		j--; l=j&0x1f; i=j>>5; i=LN_MAX-1-i; /* j mod 32 */

		if(l>3)	r = en[i] >> (l-4);
		else	r = (en[i] << (4-l))|(en[i+1] >> (28+l));

		r&=0xf;
		LN_copy(&lv[r], ret);
		j-=4;
	}else{
		LN_long_set(ret,1);
	}

	/* if bitmax > j > 4, use this routine */
	while(j>4){
		if(LN_check_bit(e,j)){
			/* ret = ret^32 mod n */
			er|=_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17]);
			er|=_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17]);
			er|=_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17]);
			er|=_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17]);
			er|=_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17]);
			if(er) goto error;

			j--; l=j&0x1f; i=j>>5; i=LN_MAX-1-i;

			if(l>3)	r = en[i] >> (l-4);
			else	r = (en[i] << (4-l))|(en[i+1] >> (28+l));

			r&=0xf;
			/* ret = ret*x^l mod n */
			if(_LN_mul_mod(ret,&lv[r],n,ret,&lv[16],&lv[17])) goto error;
			j-=4;
		}else{
			/* ret = ret^2 mod n */
			if(_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17])) goto error;
			j--;
		}
	}

	/* if j is less than 5, use this routine */
	while(j>0){
		/* ret = ret^2 mod n */
		if(_LN_sqr_mod(ret,n,ret,&lv[16],&lv[17])) goto error;

		if(LN_check_bit(e,j))
			/* ret = ret*x mod n */
			if(_LN_mul_mod(ret,x,n,ret,&lv[16],&lv[17])) goto error;
		j--;
	}
	return 0;
error:
	return -1;
}


