/* ecp_tool.c */
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
	copy EC point "from" to "to"
------------------------------------*/
void ECp_copy(ECp *from, ECp *to){
	LN_copy(from->x,to->x);
	LN_copy(from->y,to->y);
	LN_copy(from->z,to->z);
	to->infinity=from->infinity;
}

/*-------------------------------------------
	compare EC Points
	if a and b are same point, return 0.
	0,1bit...x, 2,3bit...y
-------------------------------------------*/
int ECp_cmp(ECp *a, ECp *b){
	int	ret=0,i;

	if(a->infinity!=b->infinity)
		ret|=0x80;
	if(i=LN_cmp(a->x,b->x)){
		(i>0)?(ret|=0x1):(ret|=0x2);
	}
	if(i=LN_cmp(a->y,b->y)){
		(i>0)?(ret|=0x4):(ret|=0x8);
	}
	if(i=LN_cmp(a->z,b->z)){
		(i>0)?(ret|=0x10):(ret|=0x20);
	}
	return ret;
}

/*---------------------------------------------
	point conversion : projective to affine
---------------------------------------------*/
int ECp_proj2af(ECParam *E, ECp *a){
	LNm *q,*r,*t1,*t2;
	int err;

#ifdef USE_PTHREAD
        t1=E->buf[10]; t2=E->buf[11];
#else
        t1=t2=NULL;
#endif

	/* LN_init_lexp_tv() should be executed already */
	if((a->infinity)||(a->z->top==0)){
		a->infinity = 1;
		LN_long_set(a->x,1);
		LN_long_set(a->y,1);
		LN_clean(a->z);
		return 0;
	}

	q=E->buf[0]; r=E->buf[1];
	err  = _LN_sqr_mod(a->z,E->p,q,t1,t2);		/* q = (a->z)^2 */
	err |= LN_mod_inverse(q,E->p,r);		/* r = ((a->z)^2)^-1 */
	err |= _LN_mul_mod(a->x,r,E->p,a->x,t1,t2);
	if(err) goto error;

	err  = _LN_mul_mod(q,a->z,E->p,q,t1,t2);			/* q = (a->z)^3 */
	err |= LN_mod_inverse(q,E->p,r);
	err |= _LN_mul_mod(a->y,r,E->p,a->y,t1,t2);
	if(err) goto error;

	LN_long_set(a->z,1);
	return 0;
error:
	OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCTOOL);
	return -1;
}

/*---------------------------------------------
	print EC Point
---------------------------------------------*/
void ECp_print(ECp *a){
	if(a->infinity){
		printf("point...infinity");
	}else{
		printf("x :"); LN_print(a->x);
		printf("y :"); LN_print(a->y);
		printf("z :"); LN_print(a->z);
	}
}
