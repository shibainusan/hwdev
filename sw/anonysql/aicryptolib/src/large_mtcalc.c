/* large_mont.c */
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

void LN_MonPro(LNmt_ctx *ctx,LNm *a,LNm *b,LNm *ret){
	LNm *t,*m,*n,*u,*r,*tmp;
	ULONG *un,*tn,*mn;
	int	i,j,k,min;

	ULONG *ndn,cr,v;
	ULLONG e;
	/* initialize buffer */
	n  =ctx->n;
	r  =ctx->r;
	t  =ctx->buf[20];
	m  =ctx->buf[21];
	u  =ctx->buf[22];
	tmp=ctx->buf[23];
	un =u->num;
	tn =t->num;
	mn =m->num;

	/* Step 1: t = a * b */
	LN_multi(a,b,t);

	/* Step 2: m = t * n' mod r */
	/* LN_multi is actually wasting, because of mod r
	 * so just calculate less than r
	 */
	/* but LN_multi might use karatsuba method for multiplication */
#if 0
	LN_multi(t,ctx->nd,m);
	memset(mn,0,sizeof(ULONG)*(LN_MAX+1-r->top));
#else

	ndn = ctx->nd->num;
	i   = LN_MAX-1;
	min = LN_MAX+1-r->top;
	memset(mn,0,sizeof(ULONG)*LN_MAX);
	do{
		v=ndn[i];
		cr=0;
		k=i;
		j=LN_MAX-1;
		do{
			e = tn[j]; e*= v;
			e+= mn[k]; e+=cr;
			cr= (ULONG)(e >> 32);
			mn[k] = (ULONG)e;
			j--;
			k--;
		}while(k>=min);
		i--;
	}while(i>=min);

#endif
	m->top=LN_now_top(LN_MAX-r->top,m);

	/* Step 3: u = (t + m*n)/r */
	LN_multi(m,n,tmp);
	LN_plus(tmp,t,u);
	i  = LN_MAX-1;
	j  = LN_MAX-r->top;
	min= LN_MAX-u->top;
	while(min<=j){
		un[i]=un[j];
		un[j]=0;
		i--;
		j--;
	}
	u->top=LN_now_top(LN_MAX-r->top,u);

	/* Step 4: return u */
	if(LN_cmp(u,n)>=0)
		LN_minus(u,n,ret);
	else
		LN_copy(u,ret);
}

void LN_MonProSqr(LNmt_ctx *ctx,LNm *a,LNm *ret){
	LNm *t,*m,*n,*u,*r,*tmp;
	ULONG *un;
	int	i,j,k,min;

	ULONG *mn,*tn,*ndn,cr,v;
	ULLONG e;

	/* initialize buffer */
	n  =ctx->n;
	r  =ctx->r;
	t  =ctx->buf[20];
	m  =ctx->buf[21];
	u  =ctx->buf[22];
	tmp=ctx->buf[23];
	un =u->num;
	mn =m->num;
	tn =t->num;

	/* Step 1: t = a * b */
	LN_sqr(a,t);

	/* Step 2: m = t * n' mod r */
	/* LN_multi is actually wasting, because of mod r
	 * so just calculate less than r
	 */

		ndn = ctx->nd->num;
		i   = LN_MAX-1;
		min = LN_MAX+1-r->top;
		memset(mn,0,sizeof(ULONG)*LN_MAX);
		do{
			v=ndn[i];
			cr=0;
			k=i;
			j=LN_MAX-1;
			do{
				e = tn[j]; e*= v;
				e+= mn[k]; e+=cr;
				cr= (ULONG)(e >> 32);
				mn[k] = (ULONG)e;
				j--;
				k--;
			}while(k>=min);
			i--;
		}while(i>=min);

	m->top=LN_now_top(LN_MAX-r->top,m);

	/* Step 3: u = (t + m*n) /r */
	LN_multi(m,n,tmp);
	LN_plus(tmp,t,u);
	i  = LN_MAX-1;
	j  = LN_MAX-r->top;
	min= LN_MAX-u->top;
	while(min<=j){
		un[i]=un[j];
		un[j]=0;
		i--;
		j--;
	}
	u->top=LN_now_top(LN_MAX-r->top,u);

	/* Step 4: return u */
	if(LN_cmp(u,n)>=0)
		LN_minus(u,n,ret);
	else
		LN_copy(u,ret);
}

/*-----------------------------------------------
  ret = x ^ e mod n
-----------------------------------------------*/
/* binary with (5bit) window method */
/* I think LNm *n is not needed, but when I used ctx->n as n, *
 * this routine became pretty slowly... cache miss !?         */
void LNmt_exp_mod(LNmt_ctx *ctx,LNm *x,LNm *e,LNm *n, LNm *ret){
	LNm *lv[16],*xd,*tmp;
	int i,j;
	ULONG *en,*xn;

	/* initialize values */
	for(i=0;i<16;i++)
		lv[i]=ctx->buf[i];
	xd = ctx->buf[16];

	/* xd = x * r mod n */
	xn= x->num;
	en= xd->num;
	i = x->top;
	j = LN_MAX - i;
	i = i + (ctx->r->top - 1);
	xd->top = i;
	i = LN_MAX - i;
	while(j<LN_MAX){
		en[i]=xn[j];
		j++; i++;
	}
	LN_div_mod(xd,n,lv[0],lv[1]);
	tmp=lv[1]; lv[1]=xd; xd=tmp; /* exchange */


	/* make lv[i] = x^(16+i) mod n */
	/* set lv[0] = x^16 */
	LN_MonProSqr(ctx,xd,lv[0]);
	for(i=0;i<2;i++) LN_MonProSqr(ctx,lv[i],lv[i+1]);
	LN_MonProSqr(ctx,lv[2],lv[0]);

	/* set all table */
	for(i=0;i<15;i++)
		LN_MonPro(ctx,lv[i],xd,lv[i+1]); /* lv[i+1] = lv[i]*x mod n */

	en= e->num;
	j = LN_now_bit(e);

	/* if j is bigger than 4, copy table data to ret */
	if(j>4){
		int r,l;
		j--; l=j&0x1f; i=j>>5; i=LN_MAX-1-i; /* j mod 32 */

		if(l>3)	r = en[i] >> (l-4);
		else	r = (en[i] << (4-l))|(en[i+1] >> (28+l));

		r&=0xf;
		LN_copy(lv[r], ret);
		j-=4;
	}else{
		/* ret = 1 * r mod n */
		LN_div_mod(ctx->r,n,ctx->buf[19],ret);
	}
	/* if bitmax > j > 4, use this routine */
	while(j>4){
		if(LN_check_bit(e,j)){
			ULONG r,l;
			LN_MonProSqr(ctx,ret,ret);
			LN_MonProSqr(ctx,ret,ret);
			LN_MonProSqr(ctx,ret,ret);
			LN_MonProSqr(ctx,ret,ret);
			LN_MonProSqr(ctx,ret,ret);

			j--; l=j&0x1f; i=j>>5; i=LN_MAX-1-i;

			if(l>3)	r = en[i] >> (l-4);
			else	r = (en[i] << (4-l))|(en[i+1] >> (28+l));

			r&=0xf;
			LN_MonPro(ctx,ret,lv[r],ret); /* ret = ret*x^l mod n */
			j-=4;
		}else{	/* ret = ret^2 */
			LN_MonProSqr(ctx,ret,ret); /* ret = ret*ret mod n */
			j--;
		}
	}

	/* if j is less than 5, use this routine */
	while(j>0){
		LN_MonProSqr(ctx,ret,ret);

		if(LN_check_bit(e,j))
			LN_MonPro(ctx,ret,xd,ret); /* ret = ret*x mod n */

		j--;
	}

	LN_long_set(xd,1);
	LN_MonPro(ctx,ret,xd,ret);
}
