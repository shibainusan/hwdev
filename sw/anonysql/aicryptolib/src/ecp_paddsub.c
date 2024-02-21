/* ecp_paddsub.c */
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
	(EC_Point)ret = 2A
------------------------------------*/
int ECp_pdouble(ECParam *E, ECp *A, ECp *ret){
	LNm *t1,*t2,*t3,*t4,*t5,*tmp,*pt,*p;
	LNm *ax,*ay,*az,*b1,*b2;
	int err;

	p = E->p;
	t1=E->buf[0]; t2=E->buf[1]; t3=E->buf[2]; 
	t4=E->buf[3]; t5=E->buf[4]; tmp=E->buf[5];
	ax=A->x; ay=A->y; az=A->z; 

#ifdef USE_PTHREAD
	/* these are just temporary buffer for calculation */
	b1=E->buf[10]; b2=E->buf[11];
#else
	/* initialize temporary values in large_exp.c */
	LN_init_lexp_tv();
	b1=b2=NULL;
#endif
	
	ret->infinity=0;

	if((A->infinity)||(ay->top==0)||(az->top==0)){
		LN_long_set(ret->x,1);
		LN_long_set(ret->y,1);
		LN_clean(ret->z);
		ret->infinity = 1;
		return 0;
	}

	LN_copy(E->a,t4);
	if(LN_long_add(t4,3)) goto error;

	/* LN_mul_mod and LN_sqr_mod can use same value as a
	 * return value and submit value
	 */
#if 1	/* oh, boy... this routine is slower than bottom one... */
	if(!LN_cmp(p,t4)){
		err  = LN_sqr(az,t4);				/* t4 = az^2 mod p */
		err |= LN_minus(ax,t4,t5);			/* t5 = ax - t4 mod p */
		err |= LN_plus(ax,t4,tmp);			/* t4 = ax + t4 mod p */
		if(err) goto error;

		pt = tmp; tmp = t4; t4 = pt;
		err  = LN_multi(t4,t5,tmp);		/* t5 = t4 * t5 mod p */
		err |= LN_long_multi(tmp,3,t5);	/* t4 = 3 * t5 mod p */
		if(t5->neg){
			err |= LN_div_mod(t5,p,tmp,t3);
			err |= LN_plus(p,t3,t4);
		}else{
			err |= LN_div_mod(t5,p,tmp,t4);	/* = M */
		}
		if(err) goto error;
	}else{
		err  = LN_long_sub(t4,3);			/* t4 = a */
		err |= LN_sqr(az,tmp);				/* t5 = az^4 mod p */
		err |= LN_sqr(tmp,t5);
		if(err) goto error;
		err  = LN_multi(t4,t5,t3);		/* t3 = t4 * t5 mod p */
		err |= LN_sqr(ax,t4);				/* t4 = ax^2 mod p */
		err |= LN_long_multi(t4,3,tmp);	/* t4 = 3*t4 + t3 mod p */
		err |= LN_plus(tmp,t3,t4);
		if(err) goto error;

		pt = t4; t4 = tmp; tmp = pt;
		if(tmp->neg){
			err  = LN_div_mod(tmp,p,t4,t3);
			err |= LN_plus(p,t3,t4);
		}else{
			err  = LN_div_mod(tmp,p,t5,t4);	/* = M */
		}
		if(err) goto error;
	}

	err  = LN_multi(ay,az,t3);				/* t3 = ay * az */
	err |= LN_lshift32(t3,1,tmp);
	err |= LN_div_mod(tmp,p,t3,ret->z);	/* ret->z = 2 *ay *az mod p */
	if(err) goto error;

	err  = LN_sqr(ay,t2);					/* t2 = ay^2 mod p */
	err |= LN_multi(ax,t2,t5);				/* t5 = t2 * ax mod p */
	err |= LN_lshift32(t5,2,tmp);			/* tmp= 4 * t5 */
	err |= LN_div_mod(tmp,p,t3,t5);		/* = S */
	if(err) goto error;

	err  = LN_sqr(t4,t1);					/* t1 = M^2 mod p   */
	err |= LN_lshift32(t5,1,t3);			/* t3 = 2 * S mod p */
	err |= LN_minus(t1,t3,tmp);			/* tmp could be negative rarely */
	if(tmp->neg){
		err |= LN_div_mod(tmp,p,t1,t3);
		err |= LN_plus(p,t3,ret->x);		/* ret->x = M^2 - 2*S */
	}else{
		err |= LN_div_mod(tmp,p,t3,ret->x);
	}
	if(err) goto error;

	err  = LN_sqr(t2,t3);					/* t2 = t2^2 mod p  */
	err |= LN_lshift32(t3,3,tmp);			/* t2 = 8 * t2 mod p */
	err |= LN_div_mod(tmp,p,t3,t2);		/* = T (8 * ay^4)   */
	if(err) goto error;

	err  = _LN_sub_mod(t5,ret->x,p,tmp,b1);		/* tmp = S - ret->x */
	err |= _LN_mul_mod(tmp,t4,p,t5,b1,b2);		/* t5 = tmp * M	    */
	err |= _LN_sub_mod(t5,t2,p,ret->y,b1);		/* ret->y = t5 - T  */
	if(err) goto error;
#else
	if(!LN_cmp(p,t4)){
		_LN_sqr_mod(az,p,t4,b1,b2);		/* t4 = az^2 mod p */
		_LN_sub_mod(ax,t4,p,t5,b1);		/* t5 = ax - t4 mod p */
		_LN_add_mod(ax,t4,p,tmp,b1);	/* t4 = ax + t4 mod p */
		pt = tmp; tmp = t4; t4 = pt;
		LN_multi(t4,t5,tmp);		/* t5 = t4 * t5 mod p */
		LN_long_multi(tmp,3,t5);	/* t4 = 3 * t5 mod p */
		LN_div_mod(t5,p,tmp,t4);	/* = M */
	}else{
		LN_long_sub(t4,3);			/* t4 = a */
		_LN_sqr_mod(az,p,tmp,b1,b2);		/* t5 = az^4 mod p */
		LN_sqr(tmp,t5);
		_LN_mul_mod(t4,t5,p,t5,b1,b2);		/* t5 = t4 * t5 mod p */
		_LN_sqr_mod(ax,p,t4,b1,b2);		/* t4 = ax^2 mod p */
		LN_long_multi(t4,3,tmp);	/* t4 = 3*t4 + t5 mod p */
		LN_plus(tmp,t5,t4);
		pt = t4; t4 = tmp; tmp = pt;
		LN_div_mod(tmp,p,t5,t4);	/* = M */
	}

	_LN_mul_mod(ay,az,p,t3,b1,b2);			/* t3 = ay * az */
	LN_lshift32(t3,1,tmp);
	LN_div_mod(tmp,p,t3,ret->z);	/* ret->z = 2 *ay *az mod p */

	_LN_sqr_mod(ay,p,t2,b1,b2);			/* t2 = ay^2 mod p */
	_LN_mul_mod(ax,t2,p,t5,b1,b2);			/* t5 = t2 * ax mod p */
	LN_lshift32(t5,2,tmp);			/* tmp= 4 * t5 */
	LN_div_mod(tmp,p,t3,t5);		/* = S */

	_LN_sqr_mod(t4,p,t1,b1,b2);			/* t1 = M^2 mod p   */
	LN_lshift32(t5,1,tmp);			/* t3 = 2 * S mod p */
	LN_div_mod(tmp,p,ret->x,t3);
	_LN_sub_mod(t1,t3,p,ret->x,b1);		/* ret->x = M^2 - 2*S */

	_LN_sqr_mod(t2,p,t2,b1,b2);			/* t2 = t2^2 mod p  */
	LN_lshift32(t2,3,tmp);			/* t2 = 8 * t2 mod p */
	LN_div_mod(tmp,p,t3,t2);		/* = T (8 * ay^4)   */

	_LN_sub_mod(t5,ret->x,p,tmp,b1);	/* tmp = S - ret->x */
	_LN_mul_mod(tmp,t4,p,t5,b1,b2);		/* t5 = tmp * M	    */
	_LN_sub_mod(t5,t2,p,ret->y,b1);		/* ret->y = t5 - T  */
#endif
	return 0;
error:
	OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCPADD);
	return -1;
}

/*-----------------------------------
	(EC_Point)ret = A + B
------------------------------------*/
int ECp_padd_diffs(ECParam *E, ECp *A, ECp *B, ECp *ret){
	LNm *t1,*t2,*t3,*t4,*t5,*t6,*t7,*tmp,*pt,*p;
	LNm *ax,*ay,*az,*bx,*by,*bz,*b1,*b2;
	int err;

	p = E->p;
	t1=E->buf[0]; t2=E->buf[1]; t3=E->buf[2]; 
	t4=E->buf[3]; t5=E->buf[4]; t6=E->buf[5];
	t7=E->buf[6]; tmp=E->buf[7];
	ax=A->x; ay=A->y; az=A->z; bx=B->x; by=B->y; bz=B->z; 

#ifdef USE_PTHREAD
	/* these are just temporary buffer for calculation */
	b1=E->buf[10]; b2=E->buf[11];
#else
	/* initialize temporary values in large_exp.c */
	LN_init_lexp_tv();
	b1=b2=NULL;
#endif

	ret->infinity=0;

	if((bz->top==1)&&(bz->num[LN_MAX-1]==1)){
		/* bz == 1 */
		LN_copy(ax,t1);			/* U0 = ax * bz^2 */
		LN_copy(ay,t2);			/* S0 = ay * bz^3 */
	}else{
		err  = _LN_sqr_mod(bz,p,t7,b1,b2);
		err |= _LN_mul_mod(t7,ax,p,t1,b1,b2);	/* U0 = ax * bz^2 */
		err |= _LN_mul_mod(t7,bz,p,t7,b1,b2);
		err |= _LN_mul_mod(t7,ay,p,t2,b1,b2);	/* S0 = ay * bz^3 */
		if(err) goto error;
	}
	if((az->top==1)&&(az->num[LN_MAX-1]==1)){
		/* az == 1 */
		LN_copy(bx,t4);			/* U1 = bx * az^2 */
		LN_copy(by,t5);			/* S1 = by * az^3 */
	}else{
		err  = _LN_sqr_mod(az,p,t7,b1,b2);
		err |= _LN_mul_mod(t7,bx,p,t4,b1,b2);	/* U1 = bx * az^2 */
		err |= _LN_mul_mod(t7,az,p,t7,b1,b2);
		err |= _LN_mul_mod(t7,by,p,t5,b1,b2);	/* S1 = by * az^3 */
		if(err) goto error;
	}
	err  = _LN_sub_mod(t1,t4,p,t3,b1);	/* W (t3) = U0 - U1 mod p */
	err |= _LN_sub_mod(t2,t5,p,t6,b1);	/* R (t6) = S0 - S1 mod p */
	if(err) goto error;

	if(t3->top==0){
		if(t6->top==0){
			LN_clean(ret->x);
			LN_clean(ret->y);
			LN_clean(ret->z);
		}else{
			LN_long_set(ret->x,1);
			LN_long_set(ret->y,1);
			LN_clean(ret->z);
		}
		return 0;
	}
	 /* M = t2 + t5 */

	err  = _LN_add_mod(t1,t4,p,tmp,b1);	/* T (t1) = U0 + U1 */
	pt = tmp; tmp = t1; t1 = pt;

	err |= _LN_add_mod(t2,t5,p,tmp,b1);	/* M (t2) = S0 + S1 */
	if(err) goto error;

	pt = tmp; tmp = t2; t2 = pt;
	pt = t3; t3 = t4; t4 = pt;	/* t4 <== t3 (W) */
	pt = t6; t6 = t5; t5 = pt;	/* t5 <== t6 (R) */

	if((bz->top!=1)||(bz->num[LN_MAX-1]!=1))
		err =_LN_mul_mod(az,bz,p,t3,b1,b2);
	else
		LN_copy(az,t3);

	err |= _LN_mul_mod(t3,t4,p,ret->z,b1,b2);	/* ret->z = az * bz * W */
	err |= _LN_sqr_mod(t4,p,t7,b1,b2);		/* t7 = W^2 */
	err |= _LN_mul_mod(t4,t7,p,t4,b1,b2);		/* t4 = W^3 */
	if(err) goto error;

	err  = _LN_mul_mod(t1,t7,p,t7,b1,b2);		/* t7 = T * W^2 */
	err |= _LN_sqr_mod(t5,p,t1,b1,b2);		/* t1 = R^2 */
	err |= _LN_sub_mod(t1,t7,p,ret->x,b1);	/* ret->x = R^2 - TW^2 */
	if(err) goto error;

	err |= LN_lshift32(ret->x,1,tmp);
	err |= LN_div_mod(tmp,p,t3,t1);	/* t1 = 2 * ret->x */
	err |= _LN_sub_mod(t7,t1,p,tmp,b1);	/* tmp (V) = TW^2 - 2*ret->x */ 
	if(err) goto error;

	err |= _LN_mul_mod(t5,tmp,p,t5,b1,b2);	/* t5 = R * V */
	err |= _LN_mul_mod(t2,t4,p,t4,b1,b2);		/* t4 = M * W^3 */
	err |= _LN_sub_mod(t5,t4,p,t2,b1);		/* t2 = RV - MW^3 */
	if(err) goto error;
	err |= LN_rshift32(p,1,tmp);
	err |= LN_long_add(tmp,1);			/* get 2^(-1) mod p */
	err |= _LN_mul_mod(tmp,t2,p,ret->y,b1,b2);/* ret->y = 2^(-1) * (RV - MW^3) */
	if(err) goto error;
	return 0;
error:
	OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCPADD+1);
	return -1;
}

int ECp_padd(ECParam *E, ECp *A, ECp *B, ECp *ret){
	if(A->z->top==0){ ECp_copy(B,ret); return 0;}
	if(B->z->top==0){ ECp_copy(A,ret); return 0;}

	if(ECp_padd_diffs(E,A,B,ret)) return -1;
	if((ret->x->top==0)&&(ret->y->top==0)&&(ret->z->top==0))
		if(ECp_pdouble(E,B,ret)) return -1;
	return 0;
}

/*----------------------------------------
    (EC_Point)ret = A - B
----------------------------------------*/
int ECp_psub(ECParam *E, ECp *A, ECp *B, ECp *ret){
	LNm *tmp,*by = E->buf[8];
	int err=-1;

	if(LN_minus(E->p,B->y,by)) goto done;
	tmp=B->y; B->y=by;
	err=ECp_padd(E,A,B,ret);
	B->y=tmp;
done:
	if(err) OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCPADD+2);
	return 0;
}

