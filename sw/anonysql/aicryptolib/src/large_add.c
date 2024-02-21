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
  large number plus
-----------------------------------------------*/
int LN_plus(LNm *a,LNm *b,LNm *ret){
	int i,j;

	i=(a->neg<<1) + b->neg;

	if(LN_zcmp(a,b)>=0){
		j = 0;
	}else{
		LNm *tmp;
		j = 1;
		tmp=a; a=b; b=tmp;	/* exchange a and b */
	}
	
	switch(i){
	case 0:	/* + , + */
		if(LN_zplus(a,b,ret)) goto error;
		ret->neg = 0;
		break;
	case 1:	/* + , - */
		LN_zminus(a,b,ret);
		ret->neg = j;
		break;
	case 2:	/* - , + */
		LN_zminus(a,b,ret);
		ret->neg = (1^j) & (ret->top!=0);
		break;
	case 3:	/* - , - */
		if(LN_zplus(a,b,ret)) goto error;
		ret->neg = 1;
		break;
	}
	return 0;
error:
	OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMADD,NULL);
	return -1;
}

int LN_zplus(LNm *a,LNm *b,LNm *ret){
	ULONG *c,*d,*r;
	int i,j,tm,bm,top,bot;

	/** must be a->size = b->size = ret->size **/

	r = ret->num;
	i = a->top; j = b->top;

	if(i>j){
		top=i; bot=j;
		c = a->num; d = b->num;
	}else{
		top=j; bot=i;
		c = b->num; d = a->num;
	}
	if((i>=LN_MAX)&&(j>=LN_MAX)){
		if((c[0]+d[0])<c[0]){return -1;}/* BOF */
	}

	tm = LN_MAX-top;
	bm = LN_MAX-bot;
	i  = LN_MAX-1;
	j  = 0;

	while(i>=bm){ /* add bottom */
		ULLONG e;
		e = c[i]; e+=d[i]; e+=j;

		r[i] = (ULONG) e;
		j = (ULONG)(e >> 32);
		i--;
	}
	while(i>=tm){ /* add upside */
		r[i] = c[i]+j;
		j = (r[i]<(unsigned)j);
		i--;
	}
	if(j){
		r[i] = 1;
		top++;
	}

	ret->top = top;
	return 0;
}


#if 0
    ULONG m,n;
    n = c[i];
    m = d[i];
    /*  if n is 0, n and j should be same. but if n was 0xffffffff,
	I might get carry from this addtion */
    n+= j;
    j = (n<j);
    n+= m;
    j = (n<m) + j;	/* get carry */

    r[i] = n;
    i--;
#endif
