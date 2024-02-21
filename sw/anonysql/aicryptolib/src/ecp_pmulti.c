/* ecp_pmulti.c */
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

#include "ok_ecc.h"

/*-----------------------------------
	(EC_Point)ret = k * A;
------------------------------------*/
/* binary with (4bit) NAF window method */
/* Use E->buf[] 9. 0-8 are in padd and psub */
int ECp_pmulti(ECParam *E, ECp *A, LNm *k, ECp *ret){
	int i,hi,ki,hl,err;
	LNm *h;
	ECp *ptBuf[10];
	ECp *r2,*rr,*tmp;

	LN_init_lexp_tv();
	for(i=0;i<10;i++) ptBuf[i]=E->pbf[i];

	ret->infinity=0;

	/* initializing table */
	err  = ECp_pdouble(E,A,ptBuf[2]);			/* 2A */
	err |= ECp_pdouble(E,ptBuf[2],ptBuf[1]);	/* 4A */
	err |= ECp_padd(E,ptBuf[2],ptBuf[1],ptBuf[0]);	/* 6A */
	if(err) goto error;

	for(i=0;i<4;i++)
		if(ECp_padd(E,ptBuf[i],A,ptBuf[i+1])) goto error;
		
	for(i=0;i<5;i++){
		hi=9-i;
		ECp_copy(ptBuf[i],ptBuf[hi]);
		if(LN_minus(E->p,ptBuf[i]->y,ptBuf[hi]->y)) goto error;
	}

	h=E->buf[9];
	if(LN_long_multi(k,3,h)) goto error;
	hl = LN_now_bit(h)-1;

	r2= E->pbf[10];
	rr= E->pbf[11];
	ECp_copy(A,rr);
	while(hl>4){
		ki = LN_check_bit(k,hl);
		hi = LN_check_bit(h,hl);

		if((hi==0)^(ki==0)){
			if(ECp_ppow2(E,rr,4,rr)) goto error;

			i=((hi==0)&&(ki))*5;

			ki = LN_check_bit(k,hl-2);
			hi = LN_check_bit(h,hl-2);
			i+=2 - (((hi==0)&&(ki))<<1) + (((hi)&&(ki==0))<<1);

			ki = LN_check_bit(k,hl-3);
			hi = LN_check_bit(h,hl-3);
			i+= - ((hi==0)&&(ki)) + ((hi)&&(ki==0));
#if 0
if(i==0xa){
	LN_print(k);
	LN_print(h);
	printf("(%d) ki=%d,hi=%d\n",hl-3,ki,hi);
}
#endif
			if(ECp_padd(E,rr,ptBuf[i],r2)) goto error;
			hl-=4;
		}else{
			if(ECp_pdouble(E,rr,r2)) goto error;
			hl--;		
		}

		tmp=r2; r2=rr; rr=tmp; /* exchange rr and r2 */
	}

	/* if hl is less than 4, use this routine */
	while(hl>1){
		if(ECp_pdouble(E,rr,r2)) goto error;

		ki = LN_check_bit(k,hl);
		hi = LN_check_bit(h,hl);

		if((hi)&&(ki==0)){
			if(ECp_padd(E,r2,A,rr)) goto error;
		}else if((hi==0)&&(ki)){
			if(ECp_psub(E,r2,A,rr)) goto error;
		}else{
			tmp=r2; r2=rr; rr=tmp;} /* exchange rr and r2 */
		hl--;
	}

	ECp_copy(rr,ret);
	return 0;
error:
	return -1;
}


int ECp_ppow2(ECParam *E, ECp *A, int k, ECp *ret){
	LNm *w,*m,*s,*t,*t1,*t2,*p,*a;
	LNm *rx,*ry,*rz,*b1,*b2;
	int i,err;

	a = E->a; p = E->p;
	w =E->buf[0]; m =E->buf[1]; s =E->buf[2];
	t =E->buf[3]; t1=E->buf[4]; t2=E->buf[5];
	rx=ret->x; ry=ret->y; rz=ret->z;

#ifdef USE_PTHREAD
	/* these are just temporary buffer for calculation */
	b1=E->buf[10]; b2=E->buf[11];
#else
	/* initialize temporary values in large_exp.c */
	LN_init_lexp_tv();
	b1=b2=NULL;
#endif

	ret->infinity=0;

	if((A->infinity)||(A->y->top==0)||(A->z->top==0)){
		LN_long_set(ret->x,1);
		LN_long_set(ret->y,1);
		LN_clean(ret->z);
		ret->infinity = 1;
		return 0;
	}

	ECp_copy(A,ret);

	for(i=0;i<k;i++){
		if(i==0){
			err = _LN_sqr_mod(rz,p,w,b1,b2);		/* w = a*z^4 mod p */
			err|= _LN_sqr_mod(w,p,t1,b1,b2);
			err|= _LN_mul_mod(t1,a,p,w,b1,b2);
		}else{
			err = LN_lshift32(w,1,t1);		/* w = 2*t*w mod p */
			err|= _LN_mul_mod(t1,t,p,w,b1,b2);
		}
		if(err) goto error;

		err  = _LN_sqr_mod(rx,p,m,b1,b2);	/* m = 3*x^2 + w mod p */
		err |= LN_long_multi(m,3,t1);
		err |= _LN_add_mod(t1,w,p,m,b1);
		if(err) goto error;

		err  = LN_lshift32(rx,2,t2);		/* t2 = 4*x */
		err |= _LN_sqr_mod(ry,p,t1,b1,b2);	/* s = 4*x*y^2 mod p */
		err |= _LN_mul_mod(t1,t2,p,s,b1,b2);
		if(err) goto error;

		err  = _LN_sqr_mod(t1,p,t,b1,b2);	/* t = 8*y^4 mod p */
		err |= LN_lshift32(t,3,t1);
		err |= LN_div_mod(t1,p,t2,t);
		if(err) goto error;

		err  = LN_sqr(m,t1);			/* rx = m^2 - 2*s mod p */
		err |= LN_lshift32(s,1,rx);
		err |= LN_minus(t1,rx,t2);
		err |= LN_div_mod(t2,p,t1,rx);
		if(err) goto error;

		err  = LN_lshift32(ry,1,t2);
		err |= LN_multi(t2,rz,t1);		/* rz = 2 * ry * rz mod p */
		err |= LN_div_mod(t1,p,t2,rz);
		if(err) goto error;

		err  = _LN_sub_mod(s,rx,p,ry,b1);	/* ry = m*(s - x) - t mod p */
		err |= _LN_mul_mod(m,ry,p,t1,b1,b2);
		err |= _LN_sub_mod(t1,t,p,ry,b1);
		if(err) goto error;
	}
	return 0;
error:
	OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCPMUL+1);
	return -1;
}

