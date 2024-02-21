/* large_ext.c */
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
#include <math.h>

#include "large_num.h"


/*-----------------------------------------------
  large number Ext Euclid  (ret = b^-1 mod n)
-----------------------------------------------*/
int LN_ext_euclid(LNm *b,LNm *n,LNm *ret){
#ifdef USE_PTHREAD
    ULONG sv[7][LN_MAX];
    LNm lv[7];
#else
    static ULONG sv[7][LN_MAX];
    static LNm lv[7];
#endif
	LNm *n0,*b0,*t0,*mul,*q,*r,*tmp,*lnp;
	int i;

	for(i=0;i<7;i++){
		lv[i].num  = sv[i];
		lv[i].size = LN_MAX;
	}

	mul = &lv[0];
	n0 = &lv[1];
	b0 = &lv[2];
	t0 = &lv[3];
	q = &lv[4];
	r = &lv[5];
	tmp = &lv[6];

	LN_copy(b,b0);
	LN_clean(t0);
	LN_long_set(tmp,1);
	if(LN_div_mod(n,b,q,r)) goto err;

	while(r->top){
		if(LN_multi(q,tmp,mul)) goto err;

		if(LN_cmp(t0,mul)>=0){
			if(LN_minus(t0,mul,q)) goto err;
		}else{
			if(LN_plus(n,t0,n0)) goto err;
			if(LN_div_mod(mul,n,t0,ret)) goto err; /* use *ret temporary */
			if(LN_minus(n0,ret,q)) goto err;
		}

		lnp = t0;
		t0 = tmp; tmp = q; q = lnp;

		lnp = n0;
		n0 = b0;  b0  = r; r = lnp;

		if(LN_div_mod(n0,b0,q,r)) goto err;
	}

	if((b0->top!=1)||(b0->num[LN_MAX-1]!=1))
		LN_clean(tmp);

	LN_copy(tmp,ret);
	return 0;

err:
	return -1;
}

/*-----------------------------------------------
  large number Euclid for montgomery
-----------------------------------------------*/
void LNmt_euclid(LNm *b,LNm *n,LNmt_ctx *ctx){
	LNm *n0,*b0,*t0,*mul,*q,*r,*tmp,*rinv,*lnp;

	n0 =ctx->buf[0];
	b0 =ctx->buf[1];
	t0 =ctx->buf[2];
	mul=ctx->buf[3];
	q  =ctx->buf[4];
	r  =ctx->buf[5];
	tmp=ctx->buf[6];
	rinv=ctx->rinv;

	LN_copy(b,b0);
	LN_clean(t0);
	LN_long_set(tmp,1);
	LN_div_mod(n,b,q,r);

	while(r->top){
		LN_multi(q,tmp,mul);

		if(LN_cmp(t0,mul)>=0)
			LN_minus(t0,mul,q);
		else{
			LN_plus(n,t0,n0);
			LN_div_mod(mul,n,t0,rinv); /* use *ret temporary */
			LN_minus(n0,rinv,q);
		}

		lnp = t0;
		t0 = tmp; tmp = q; q = lnp;

		lnp = n0;
		n0 = b0;  b0  = r; r = lnp;

		LN_div_mod(n0,b0,q,r);
	}

	if((b0->top!=1)||(b0->num[LN_MAX-1]!=1))
		LN_clean(tmp);

	LN_copy(tmp,rinv);
	LN_multi(ctx->r,rinv,tmp);
	LN_long_sub(tmp,1);
	LN_div_mod(tmp,n,ctx->nd,t0);
}
