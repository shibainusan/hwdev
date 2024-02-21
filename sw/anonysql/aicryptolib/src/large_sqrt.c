/* large_sqrt.c */
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

int lucas_squences(LNm *n, LNm *P, LNm *Q, LNm *k, LNm *v, LNm *q);

/*-----------------------------------------------
  Evaluating Jacobi Symbols
  input: int a, odd int n>1
-----------------------------------------------*/
/* this algorithm is from P1363 */
int LN_jacobi(LNm *a, LNm *n){
	LNm *x,*y,*tmp1,*tmp2,*tmp;
	ULONG *xn,*yn;
	int j=1,k;

	x = LN_clone(a);
	y = LN_clone(n);
	yn= y->num;
	tmp1=LN_alloc();
	tmp2=LN_alloc();

	while((y->top>0)&&(yn[LN_MAX-1]>1)){
		if(y->top==1){
			ULONG ul;
			LN_long_mod(x,yn[LN_MAX-1],&ul);
			LN_long_set(tmp1,ul);
		}else
			LN_div_mod(x,y,tmp2,tmp1);	/* tmp1 = x mod y; */
		tmp=tmp1; tmp1=x; x=tmp;	/* exchange x,tmp1 */

		LN_rshift32(y,1,tmp2);		/* tmp2 = y / 2; */

/* for debug */
if(x->top==1)
	k=0;

		k=yn[LN_MAX-1]&0x7;

		/* if x > (y/2) */
		if(LN_cmp(x,tmp2)>0){
			LN_minus(y,x,tmp1);		/* x = y - x */
			if((k&0x3)==3) j=-j;

			tmp=tmp1; tmp1=x; x=tmp;	/* exchange x,tmp1 */
		}

		if(x->top==0){
			LN_long_set(x,1);
			LN_clean(y);
			j=0;
			break;
		}

		xn= x->num;
		while((x->top)&&((xn[LN_MAX-1]&0x3)==0)){
			LN_rshift32(x,2,tmp1);	/* x = x / 4 */
			tmp=tmp1; tmp1=x; x=tmp;	/* exchange x,tmp1 */
		}

		xn= x->num;
		if((x->top)&&((xn[LN_MAX-1]&0x1)==0)){ /* ? does it include (x->top) */
			LN_rshift32(x,1,tmp1);	/* x = x / 2 */
			if((k==3)||(k==5)) j=-j;
			tmp=tmp1; tmp1=x; x=tmp;	/* exchange x and tmp1 */
		}

		xn= x->num;
		if(((xn[LN_MAX-1]&0x3)==3)&&((k&0x3)==3))
			j=-j;

		tmp=y; y=x; x=tmp;	/* exchange x and y */
		yn= y->num;
	}

	LN_free(x); LN_free(y);
	LN_free(tmp1); LN_free(tmp2);
	return j;
}

/*---------------------------------------------------
  Calculate Squre Root (mod n) if possible...
  input:  int a, odd int n>1,
  output: ret = sqrt(a) (mod n) (other sqrt is n-ret)
        : 1...no solution, 0...get answer
		: -1...error
---------------------------------------------------*/
/* this algorithm is from P1363 */
int LN_mod_sqrt(LNm *a, LNm *n, LNm *ret){
	LNm *tmp1=NULL,*tmp2=NULL,*tmp3=NULL;
	ULONG *nn;
	int j,ok=-1;

#ifdef USE_PTHREAD
	LNm *t1=NULL,*t2=NULL;

	if((t1=LN_alloc())==NULL) goto done;
	if((t2=LN_alloc())==NULL) goto done;

#undef LN_mul_mod
#undef LN_sqr_mod
#define LN_mul_mod(a,b,n,ret)     _LN_mul_mod((a),(b),(n),(ret), t1,t2)
#define LN_sqr_mod(a,n,ret)       _LN_sqr_mod((a),(n),(ret), t1,t2)
#endif
	nn= n->num;
	if((tmp1=LN_alloc())==NULL) goto done;
	if((tmp2=LN_alloc())==NULL) goto done;
	if((tmp3=LN_alloc())==NULL) goto done;

	j=nn[LN_MAX-1]&0x7;

	ret->neg = 0;

	if((j&0x3)==3){
	/* I. n==3(mod4), n=4k+3 for positive integer k */
	/* just right shift >> 2, then I can get k */
		ok  = LN_rshift32(n,2,tmp1);
		ok |= LN_long_add(tmp1,1);
		ok |= LN_exp_mod(a,tmp1,n,ret);
		if(ok) goto done;	/* ret = a ^(k+1) mod n */
	}else if(j==5){
	/* II. n==5(mod8), n=8k+5 for positive integer k */
	/* same as I. */
		ok  = LN_rshift32(n,3,tmp1);	/* get k (tmp1) */
		ok |= LN_lshift32(a,1,tmp2);	/* tmp2 = 2 * a */
		ok |= LN_exp_mod(tmp2,tmp1,n,tmp3);	/* tmp3 = (2*a)^k mod n */
		if(ok) goto done;

		ok  = LN_sqr(tmp3,tmp1);
		ok |= LN_mul_mod(tmp2,tmp1,n,ret);	/* ret = (2*a)*(tmp3^2) mod n */
		if(ok) goto done;

		ok  = LN_long_sub(ret,1);
		ok |= LN_multi(tmp3,ret,tmp1);
		ok |= LN_mul_mod(tmp1,a,n,ret);		/* ret = a*tmp3*(ret-1) mod n */
		if(ok) goto done;
	}else if(j==1){
	/* III. n==1(mod8), n=8k+1 */
		LNm *v=NULL,*q=NULL;
		if((v=LN_alloc())==NULL) goto done3;
		if((q=LN_alloc())==NULL) goto done3;

		do{
			ok  = LN_set_rand(tmp1,8,(unsigned short)(rand()*3));	/* set P */
			if(ok) goto done3;

			LN_copy(n,tmp3);
			ok  = LN_long_sub(tmp3,1);
			ok |= LN_rshift32(tmp3,2,tmp2);	/* tmp2 (k) = (n-1)/4 */
			ok |= LN_exp_mod(a,tmp2,n,q);		/* q = g^tmp2 mod n */
			if(ok) goto done3;

			LN_copy(n,tmp3);
			ok  = LN_long_add(tmp3,1);
			ok |= LN_rshift32(tmp3,1,tmp2);	/* tmp2 (k) = (n+1)/2 */
			ok |= lucas_squences(n,tmp1,a,tmp2,v,tmp3);
			if(ok) goto done3;

			ok  = LN_rshift32(v,1,ret);
			ok |= LN_sqr_mod(ret,n,tmp2);
			if(ok) goto done3;

			if(!LN_cmp(tmp2,a)) break;
			if(q->top){
				OK_set_error(ERR_ST_LNM_NOSQRT,ERR_LC_LNM,ERR_PT_LNMSQRT,NULL);
				ok=1; break;}
		}while(1);
done3:
		LN_free(v);
		LN_free(q);
		if(ok) goto done;
	}else{
		OK_set_error(ERR_ST_LNM_NOSQRT,ERR_LC_LNM,ERR_PT_LNMSQRT,NULL);
		ok=1;
	}

	/* check ret */
	ok  = LN_sqr(ret,tmp1);
	ok |= LN_div_mod(tmp1,n,tmp2,tmp3);
	if(ok) goto done;

	if(LN_cmp(tmp3,a)){
		OK_set_error(ERR_ST_LNM_NOSQRT,ERR_LC_LNM,ERR_PT_LNMSQRT,NULL);
		ok=1;	/* no solution !! */
	}
done:
	LN_free(tmp1);
	LN_free(tmp2);
	LN_free(tmp3);
#ifdef USE_PTHREAD
	LN_free(t1);
	LN_free(t2);
#endif
	return ok;
}


/* this algorithm is from P1363 */
int lucas_squences(LNm *n, LNm *P, LNm *Q, LNm *k, LNm *v, LNm *q){
	LNm *v0=NULL,*v1=NULL,*q0=NULL,*q1=NULL,*tmp=NULL;
	int	i,err=-1;
#ifdef USE_PTHREAD
	LNm *t1=NULL,*t2=NULL;

	if((t1=LN_alloc())==NULL) goto done;
	if((t2=LN_alloc())==NULL) goto done;
#undef  LN_sub_mod
#undef  LN_mul_mod
#undef  LN_sqr_mod
#define LN_sub_mod(a,b,n,ret)     _LN_sub_mod((a),(b),(n),(ret), t1)
#define LN_mul_mod(a,b,n,ret)     _LN_mul_mod((a),(b),(n),(ret), t1,t2)
#define LN_sqr_mod(a,n,ret)       _LN_sqr_mod((a),(n),(ret), t1,t2)
#endif

	if((v0=LN_alloc())==NULL) goto done;
	LN_long_set(v0,2);
	if((v1=LN_clone(P))==NULL) goto done;
	if((q0=LN_alloc())==NULL) goto done;
	LN_long_set(q0,1);
	if((q1=LN_alloc())==NULL) goto done;
	LN_long_set(q1,1);
	if((tmp=LN_alloc())==NULL) goto done;

	i = LN_now_bit(k);

	do{
		err=-1;
		if(LN_mul_mod(q0,q1,n,q0)) goto done;

		err=0;
		if(LN_check_bit(k,i)){
			err |= LN_mul_mod(q0,Q,n,q1);	/* q1 = q0*Q mod n */
			err |= LN_mul_mod(v0,v1,n,tmp);/* v0 = v0*v1 - P*q0 mod n */
			err |= LN_mul_mod(q0,P,n,v);	/* use v tempolarily */
			err |= LN_sub_mod(tmp,v,n,v0);
			if(err) goto done;

			err |= LN_sqr_mod(v1,n,tmp);	/* v1 = v1^2 - 2*q1 mod n */
			err |= LN_lshift32(q1,1,q);	/* use v and q tempolarily */
			err |= LN_div_mod(q,n,v1,v);
			err |= LN_sub_mod(tmp,v,n,v1);
			if(err) goto done;
		}else{
			LN_copy(q0,q1);			/* q1 = q0 mod n */

			err |= LN_mul_mod(v0,v1,n,tmp);/* v1 = v0*v1 - P*q0 mod n */
			err |= LN_mul_mod(q0,P,n,v);	/* use v tempolarily */
			err |= LN_sub_mod(tmp,v,n,v1);
			if(err) goto done;

			err |= LN_sqr_mod(v0,n,tmp);	/* v0 = v0^2 - 2*q0 mod n */
			err |= LN_lshift32(q0,1,q);	/* use v and q tempolarily */
			err |= LN_div_mod(q,n,v0,v);
			err |= LN_sub_mod(tmp,v,n,v0);
			if(err) goto done;
		}
		i--;
	}while(i>0);

	LN_copy(v0,v);
	LN_copy(q0,q);
done:
	LN_free(q0);
	LN_free(q1);
	LN_free(v0);
	LN_free(v1);
	LN_free(tmp);
#ifdef USE_PTHREAD
	LN_free(t1);
	LN_free(t2);
#endif
	return err;
}

/*----------------------------------------------------------
  Calculate nearly Squre Root of a
  the answer ret will be a >= ret^2 
  In this function, I don't care if a is positive or not
----------------------------------------------------------*/
int LN_sqrt(LNm *a, LNm *ret){
	LNm *s=NULL,*t=NULL,*tmp;
	int	b,tp,err=-1;

	if((t=LN_alloc())==NULL) goto done;
	if((s=LN_alloc())==NULL) goto done;

	/* initialized number of square root */
	tp= LN_now_bit(a) - 1;
	b = (tp >> 1) & 0x1f;
	tp= tp >> 5;
	tp++;

	t->num[LN_MAX-tp] = 1 << b;
	t->top = tp;

	do{	/* use ret for temporary value */
		tmp=s; s=t; t=tmp;		/* s = t */
		if(LN_div_mod(a,s,t,ret)) goto done;	/* t = (s + a/s) / 2 */
		if(LN_plus(s,t,ret)) goto done;
		if(LN_rshift32(ret,1,t)) goto done;
	}while(LN_zcmp(t,s)<0);	/* while(t < s) */

	LN_copy(s,ret);
	err=0;
done:
	LN_free(s);
	LN_free(t);
	return err;
}
