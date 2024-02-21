/* large_add.c */
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

#include "large_num.h"


/*-----------------------------------------------
  large number multiplication
-----------------------------------------------*/
int LN_multi(LNm *a, LNm *b, LNm *ret){
	int at=a->top,bt=b->top;

	if((at+bt)>=LN_MAX){
		OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMMUL,NULL);
		return -1;
	}

#ifndef USE_PTHREAD
	if((at == bt)&&(at > KARATSUBA_TH))
		/* a and b have enough bit length */
		LN_multi_kara(a,b,ret);
	else
#endif
		/* a and b have small bit length */
		LN_multi_std(a,b,ret);
	return 0;
}

void LN_multi_std(LNm *a,LNm *b,LNm *ret){
	ULONG *c,*d,*r;
	int i,k,a_min,b_min;

	/** must be a->size = b->size = ret->size **/

	r = ret->num;
	memset(r,0,sizeof(ULONG)*LN_MAX);

	a_min =a->top; b_min =b->top;
	if(!(a_min && b_min)){
		ret->top=0;
		return;
	}

	a_min = LN_MAX -a_min;
	b_min = LN_MAX -b_min;
	c = a->num;
	d = b->num;
	i = LN_MAX-1;

	do{
		int j;
		ULONG	cr,v;
		
		v=c[i];
		cr=0;
		k=i;
		j=LN_MAX-1;

		do{
			ULLONG e;

			e = (ULLONG)v * d[j];
			e+= r[k]; e+=cr;
			cr= (ULONG)(e >> 32);
			r[k] = (ULONG)e;
			j--;
			k--;
		}while(j>=b_min);

		r[k] = cr;
		i--;
	}while(i>=a_min);

	ret->neg = a->neg ^ b->neg;

	if(r[k])
		ret->top = LN_MAX-k;
	else
		ret->top = LN_MAX-k-1;
}



#if 0
/*-----------------------------------------------
  large number multi
-----------------------------------------------*/
void LN_multi(LNm *a,LNm *b,LNm *ret){
	LNm	*r;
	int bb;

	/** must be a->size = b->size = ret->size **/
	r = LN_alloc();

	if(!(a->top && b->top)){
		ret->top=0;
		return;
	}

	bb = LN_now_bit(b)-1;
	LN_copy(a,ret);
	while(bb>0){
		LN_lshift32(ret,1,r);

		if(LN_check_bit(b,bb))
			LN_plus(r,a,ret);
		else
			LN_copy(r,ret);
		bb--;
	}

	ret->top = LN_now_top(LN_MAX-(a->top+b->top),ret);
}

#endif
