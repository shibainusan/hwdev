/* large_long.c */
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
#include <string.h>

#include "large_num.h"

/*-----------------------------------------------
  set a word to a big integer
-----------------------------------------------*/
void LN_long_set(LNm *in,ULONG num){
	ULONG *ul=in->num;

	memset(ul,0,sizeof(ULONG)*LN_MAX);
	ul[LN_MAX-1] =num;
	in->top =(num!=0);
	in->neg =0;
}

/*-----------------------------------------------
  add a word to a big integer
-----------------------------------------------*/
int LN_long_add(LNm *in,ULONG add){
	if(in->neg){
		/* in->neg flag might be changed */
		LN_long_zsub(in,add);
	}else{
		/* in->neg flag is kept */
		if(LN_long_zadd(in,add)) goto error;
	}
	return 0;
error:
	OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMLONG,NULL);
	return -1;
}

int LN_long_zadd(LNm *in,ULONG add){
	ULONG *lp;
	int i;

	lp = in->num;
	i  = LN_MAX-1;
	lp[i]+= add;

	if(lp[i]<add){ /* carry out */
		do{
			i--; lp[i]++;
		}while((lp[i]==0)&&(i>0));
	}

	if((i==0)&&(lp[i]==0)) return -1; /* overflow */
	i=LN_MAX-i;
	if(in->top<i) in->top = LN_MAX-i;
	return 0;
}

/*-----------------------------------------------
  subtract a word from a big integer
-----------------------------------------------*/
int LN_long_sub(LNm *in,ULONG sub){
	if(in->neg){
		/* in->neg flag is kept */
		if(LN_long_zadd(in,sub)) goto error;
	}else{
		/* in->neg flag might be changed */
		LN_long_zsub(in,sub);
	}
	return 0;
error:
	OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMLONG+1,NULL);
	return -1;
}

void LN_long_zsub(LNm *in,ULONG sub){
	ULONG *lp;
	int i;

	lp = in->num;
	i = LN_MAX-1;
	if(lp[i]>=sub){
		lp[i]-=sub;
	}else if(in->top == 1){
		lp[i] = sub - lp[i];
		in->neg ^= 1;
	}else{
		int j=i-1;

		while(!lp[j]){ lp[j]=0xffffffff; j--;}
		lp[j]--;

		lp[i]++;
		lp[i]+= 0xffffffff-sub;
	}
}

/*-----------------------------------------------
  multiple a big integer by a word
-----------------------------------------------*/
int LN_long_multi(LNm *in,ULONG k,LNm *ret){
	ULONG *c,*r,cr,v;
	int i,a_min;

	/** must be a->size = b->size = ret->size **/
	r = ret->num;
	
	a_min =in->top;
	if((a_min==0)||(k==0)){
		ret->neg=0;
		ret->top=0;
		return 0;
	}

	a_min = LN_MAX -a_min;
	c = in->num;

	i = LN_MAX-1;
	v=k;
	cr=0;

	do{
		ULLONG e;

		e = c[i]; e*=v;
		e+= cr;
		r[i] = (ULONG)e;
		cr= (ULONG)(e >> 32);
		i--;
	}while(i>=a_min);

	ret->neg = in->neg;

	if(cr){
		if(i<0) goto error;
		r[i]=cr;
		ret->top = LN_MAX-i;
	}else
		ret->top = LN_MAX-a_min;

	return 0;
error:
	OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMLONG+2,NULL);
	return -1;
}

/*-----------------------------------------------
		 divide a big integer by a word
-----------------------------------------------*/
int LN_long_div(LNm *in,ULONG div,LNm *ret){
	ULONG *lp,*rn;
	ULLONG m;
	int i,tp;

	if(div==0){
		OK_set_error(ERR_ST_LNM_DIVBYZERO,ERR_LC_LNM,ERR_PT_LNMLONG+3,NULL);
		return -1;
	}

	lp = in->num;
	tp = in->top;
	i  = LN_MAX-tp;
	rn = ret->num;

	m    =lp[i]%div;
	rn[i]=lp[i]/div;
	i++;

	while(i<LN_MAX){
		m <<=32;
		m |= lp[i];
		rn[i]=(ULONG)(m/div);
		m    =(ULONG)(m%div);

		i++;
	}

	ret->neg = in->neg;

	if(rn[LN_MAX-tp])
		ret->top = tp;
	else
		ret->top = tp-1;
	return 0;
}

/*-----------------------------------------------
  get a word modulo from a big integer
-----------------------------------------------*/
int LN_long_mod(LNm *in,ULONG div,ULONG *mod){
	ULONG *lp;
	ULLONG m;
	int i;

	if(div==0){
		OK_set_error(ERR_ST_LNM_DIVBYZERO,ERR_LC_LNM,ERR_PT_LNMLONG+3,NULL);
		return -1;
	}

	lp = in->num;
	i  = LN_MAX-in->top;

	m =lp[i]%div;
	i++;

	while(i<LN_MAX){
	    m =(ULONG)(((m<<32)|lp[i])%div);
		i++;
	}

	*mod = (ULONG)m;
	return 0;
}

