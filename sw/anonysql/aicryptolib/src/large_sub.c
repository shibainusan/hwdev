/* large_sub.c */
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

/*-----------------------------------------------
  large number minus
-----------------------------------------------*/
int LN_minus(LNm *a,LNm *b,LNm *ret){
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
		LN_zminus(a,b,ret);
		ret->neg = j;
		break;
	case 1:	/* + , - */
		if(LN_zplus(a,b,ret)) goto error;
		ret->neg = 0;
		break;
	case 2:	/* - , + */
		if(LN_zplus(a,b,ret)) goto error;
		ret->neg = 1;
		break;
	case 3:	/* - , - */
		LN_zminus(a,b,ret);
		ret->neg = (1^j) & (ret->top!=0);
		break;
	}
	return 0;
error:
	OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMSUB,NULL);
	return -1;
}

void LN_zminus(LNm *a,LNm *b,LNm *ret){
	ULONG *c,*d,*r;
	int i;

	/** must be a->size = b->size = ret->size **/
	/** a must be bigger than b **/
	i = a->top;
	if(!i){ /* a == b == 0 */
		ret->top=0;
		return;
	}

	c = a->num;
	d = b->num;
	r = ret->num;
#if 1
/*	memcpy(r,c,sizeof(ULONG)*LN_MAX); */
	for(i=LN_MAX-i;i<LN_MAX;i++)	r[i]=c[i];

	i =LN_MAX-b->top;
	while(i<LN_MAX){
		ULONG k;
		
		k = d[i];
		r[i]-=k;
		if(c[i]<k){
			k=i-1;

			while(!r[k]){
				r[k]=0xffffffff; k--;
			}
			r[k]--;
		}
		i++;
	}
#endif
	ret->top=LN_now_top(LN_MAX-a->top,ret);
}


#if 0 /* this one is old routine of above */
	memset(r,0,sizeof(ULONG)*LN_MAX);

	tp=i=LN_MAX-e;
	e=0;
	do{
		ULLONG o;
		o = e; o<<=32; o|=c[i];
		/* e=d[i]; we cant do it !? */
		if(o>=d[i]){  
			o-=d[i];
			r[i-1]=(ULONG)(o >> 32);
		}else{
			int j=i-1;

			do{
				r[j]=0xffffffff; j--;
			}while(!r[j]);
			r[j]--;

			o+= 0x100000000L;
			o-= d[i];
		}
		e=(ULONG)o;
		i++;
	}while(i<LN_MAX);
	r[i-1]=e;
#endif
