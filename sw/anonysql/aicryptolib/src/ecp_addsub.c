/* ecp_addsub.c */
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
	(EC_Point)ret = A + B;
------------------------------------*/
int ECp_add(ECParam *E, ECp *A, ECp *B, ECp *ret){
	LNm *ta,*tb,*tc,*lmd,*p;
	LNm *x0,*y0,*x1,*y1,*t1,*t2;
	int err=0;

	p = E->p;
	ta=E->buf[0]; tb=E->buf[1]; tc=E->buf[2]; lmd=E->buf[3];
	x0=A->x; y0=A->y; x1=B->x; y1=B->y;

#ifdef USE_PTHREAD
	/* these are just temporary buffer for calculation */
	t1=E->buf[10]; t2=E->buf[11];
#else
	LN_init_lexp_tv();
	t1=t2=NULL;
#endif

	if(A->infinity){ ECp_copy(B,ret); return 0;}
	if(B->infinity){ ECp_copy(A,ret); return 0;}

	ret->infinity=0;

	if(LN_cmp(x0,x1)){
		/* L = (y0-y1)/(x0-x1); */
		err  = _LN_sub_mod(y0,y1,p,ta,t1);		/* ta = (y0 - y1) mod p */
		err |= _LN_sub_mod(x0,x1,p,tb,t1);		/* tb = (x0 - x1) mod p */
		err |= LN_mod_inverse(tb,p,tc);	/* tc = tb^-1 mod p*/
		if(err) goto done;
		err  = _LN_mul_mod(ta,tc,p,lmd,t1,t2);	/* lmd = (ta * tb^-1) mod p */
		if(err)	goto done;
	}else if(LN_cmp(y0,y1)||(y1->top == 0)){
		ret->infinity=1; return 0;
	}else{
		/* L = (3*x1^2 + a)/(2*y1) */
		err  = _LN_sqr_mod(x1,p,ta,t1,t2);	/* ta = x1 * x1 mod p */
		err |= LN_long_multi(ta,3,tb);		/* tb = 3 * x1^2 */
		err |= LN_plus(E->a,tb,ta);		/* ta = 3 * x1^2 + a */
		if(err) goto done;
		err  = LN_lshift32(y1,1,tc);		/* tb = 2 * y1 */
		err |= LN_div_mod(tc,p,lmd,tb);
		err |= LN_mod_inverse(tb,p,tc);	/* tc = tb^-1 mod p */
		if(err) goto done;
		err  =_LN_mul_mod(ta,tc,p,lmd,t1,t2);	/* lmd = (ta * tb^-1) mod p */
		if(err) goto done;
	}

	/* x2 = L^2 - x0 - x1 */
	/* LN_sub_mod() doesn't divide modulo p, so I need to do it here */
	err  = _LN_sqr_mod(lmd,p,ta,t1,t2);			/* ta = lmd^2 mod p */
	err |= _LN_sub_mod(ta,x0,p,tb,t1);			/* tb = (ta - x0) mod p */
	err |= _LN_sub_mod(tb,x1,p,ret->x,t1);		/* retx = (tb - x1) mod p */
	if(err) goto done;

	/* y2 = (x1-x2)*L - y1 */
	err  = _LN_sub_mod(x1,ret->x,p,ta,t1);
	err |= _LN_mul_mod(ta,lmd,p,tb,t1,t2);
	err |= _LN_sub_mod(tb,y1,p,ret->y,t1);
done:
	if(err) OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCADD);
	return err;
}

/*----------------------------------------
    (EC_Point)ret = A - B;
----------------------------------------*/
int ECp_sub(ECParam *E, ECp *A, ECp *B, ECp *ret){
	LNm *tmp,*by = E->buf[8];  /* use same buffer as ECp_psub */
	int err=-1;

	if(LN_minus(E->p,B->y,by)) goto done;
	tmp=B->y; B->y=by;
	err=ECp_add(E,A,B,ret);
	B->y=tmp;

done:
	if(err) OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCADD+1);
	return err;
}

