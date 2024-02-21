/* large_karasqr.c */
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

void karatsuba_sqr_rec(ULONG *a, ULONG *sum, ULONG *r, int d);
ULONG karatsuba_sqr_t1(ULONG *a, ULONG *sum, ULONG *r, int d1, int d2);
void sqr_4blocks(ULONG *a, ULONG *r);
void sqr_3blocks(ULONG *a, ULONG *r);
void sqr_2blocks(ULONG *a, ULONG *r);

/* large_kara.c */
ULONG karatsuba_add(ULONG *a0,ULONG *sum, int d1, int d2);
ULONG karatsuba_sub(ULONG *a, int alen, ULONG *b, int blen);

/*-----------------------------------------------
  Karatsuba-Ofman multiplication 
-----------------------------------------------*/
void LN_sqr_kara(LNm *a, LNm *ret){
	ULONG	buf[LN_MAX*2];
	ULONG	*an,*rn;
	int	at,d;

	an=a->num;
	rn=ret->num;
	d =a->top;

	at=LN_MAX-d;
	karatsuba_sqr_rec(&an[at],rn,buf,d);
	at-=d;

	memcpy(&rn[at],buf,d<<3);		/* sizeof(ULONG)*(d*2) */

	ret->neg = 0;
	d<<=1;
	ret->top = d - (rn[at]==0);
}

void karatsuba_sqr_rec(ULONG *a, ULONG *sum, ULONG *r, int d){
	int d1,d2,tmp;
	ULONG cc,cr;

	d2 = d>>1;	/* d / 2 */
	d1 = d-d2;
	tmp= d1<<1;	/* d1 * 2 */

	switch(d){
	case 9:
		/* do sqr_5blocks(a,r) */
		karatsuba_sqr_rec(a,sum,r,d1);
		sqr_4blocks(&a[d1],&r[tmp]);
		break;
	case 8:
		sqr_4blocks(a,r);
		sqr_4blocks(&a[d1],&r[tmp]);
		break;
	case 7:
		sqr_4blocks(a,r);
		sqr_3blocks(&a[d1],&r[tmp]);
		break;
	case 6:
		sqr_3blocks(a,r);
		sqr_3blocks(&a[d1],&r[tmp]);
		break;
	case 5:
		sqr_3blocks(a,r);
		sqr_2blocks(&a[d1],&r[tmp]);
		break;

	default:
		/* t0 = a0 * b0 */
		karatsuba_sqr_rec(a,sum,r,d1);

		/* t2 = a1 * b1 */
		karatsuba_sqr_rec(&a[d1],sum,&r[tmp],d2);
		break;
	}
	/* u0 = (a0+a1) * (b0+b1) */
	/* t1 = u0 - t0 - t2 */
	/* t1 is calculated to &r[tmp<<1] with tmp length.
	 * and return carry out.
	 */
	cc = karatsuba_sqr_t1(a,sum,r,d1,d2);

	{/* ret = t0*w^2 + t1*w + t2 */
		int	i,j;

		i  =tmp-1;
		j  =(tmp<<1);
		j +=i;
		i +=d2;
		cr =0;
		do{
			ULLONG e;
			e = r[i]; e+=r[j]; e+=cr;

			r[i] = (ULONG) e;
			cr = (ULONG)(e >> 32);
			i--;
			j--;
		}while(i>=d2);

		cc+=cr;
		r[i]+=cc;
		if(r[i]<cc)
			do{ i--; r[i]++;}while(!r[i]);
	}
}

ULONG karatsuba_sqr_t1(ULONG *a, ULONG *sum, ULONG *r, int d1, int d2){
	int cc,tmp,tmp2;
	int	i,j;
	ULONG cr;

	tmp =d1<<1;
	tmp2=tmp<<1;

	/* check carry both a and b */
	/* add sum as a carry */
	cc = karatsuba_add(a,sum,d1,d2);

	/* (2^32+s0)(2^32+s0) = 2^64 +2^32*s0 +2^32*s0 +s0*s0 */
	switch(d1){
	case 4:
		sqr_4blocks(sum,&r[tmp2]);
		break;
	case 3:
		sqr_3blocks(sum,&r[tmp2]);
		break;
	default:
		karatsuba_sqr_rec(sum,&sum[tmp],&r[tmp2],d1);
		break;
	}

	if(cc){
		i  =tmp2+d1-1;
		j  =d1-1;
		cr =0;
		do{
			ULLONG e;
			e = r[i]; e+=cr;
			/* e += 2*sum[j] */
			cr=sum[j]; e+=cr; e+=cr;

			r[i] = (ULONG) e;
			cr = (ULONG)(e >> 32);
			i--;
			j--;
		}while(j>=0);
		cc+=cr;
	}

	/* t1 = u0 - t0 - t2 */
	d1<<=1; d2<<=1;
	cc-=karatsuba_sub(&r[tmp2],d1,r,d1);
	cc-=karatsuba_sub(&r[tmp2],d1,&r[tmp],d2);

	return cc;
}


#define SqrAdd(x,c1,c2,c3)					\
	t = (ULLONG)x * x;						\
	t1= (ULONG)(t >> 32);					\
	t2= (ULONG) t;							\
	c3+= t2; t1+=(c3<t2);					\
	c2+= t1; c1+=(c2<t1);

#define MulAdd2(x,y,c1,c2,c3)				\
	t = (ULLONG)x * y;						\
	t1= (ULONG)(t >> 32);					\
	t2= (ULONG) t;							\
	c1+=((t1&0x80000000)>>31);				\
	t1= (t1<<1) | ((t2&0x80000000)>>31);	\
	t2<<=1;									\
	c3+= t2; t1+=(c3<t2);					\
	c2+= t1; c1+=(c2<t1);

void sqr_2blocks(ULONG *a, ULONG *r){
	ULLONG t;
	ULONG a0,a1;
	ULONG t1,t2,c1,c2,c3;

	a0=a[0]; a1=a[1];
	c1=c3=0;

	t = (ULLONG)a1 * a1;
	r[3]= (ULONG) t;
	c2= (ULONG)(t >> 32);

	MulAdd2(a0,a1,c3,c1,c2);
	r[2]=c2; c2=0;

	SqrAdd(a0,c2,c3,c1);
	r[1]=c1;
	r[0]=c3;
}

void sqr_3blocks(ULONG *a, ULONG *r){
	ULLONG t;
	ULONG a0,a1,a2;
	ULONG t1,t2,c1,c2,c3;

	a0=a[0]; a1=a[1]; a2=a[2];
	c1=c3=0;

	t = (ULLONG)a2 * a2;
	r[5]= (ULONG) t;
	c2= (ULONG)(t >> 32);

	MulAdd2(a1,a2,c3,c1,c2);
	r[4]=c2; c2=0;

	MulAdd2(a0,a2,c2,c3,c1);
	SqrAdd(a1,c2,c3,c1);
	r[3]=c1; c1=0;

	MulAdd2(a0,a1,c1,c2,c3);
	r[2]=c3; c3=0;

	SqrAdd(a0,c3,c1,c2);
	r[1]=c2;
	r[0]=c1;
}

void sqr_4blocks(ULONG *a, ULONG *r){
	ULLONG t;
	ULONG a0,a1,a2,a3;
	ULONG t1,t2,c1,c2,c3;

	a0=a[0]; a1=a[1]; a2=a[2]; a3=a[3];
	c1=c3=0;

	t = (ULLONG)a3 * a3;
	r[7]= (ULONG) t;
	c2= (ULONG)(t >> 32);

	MulAdd2(a2,a3,c3,c1,c2);
	r[6]=c2; c2=0;

	MulAdd2(a1,a3,c2,c3,c1);
	SqrAdd(a2,c2,c3,c1);
	r[5]=c1; c1=0;

	MulAdd2(a0,a3,c1,c2,c3);
	MulAdd2(a1,a2,c1,c2,c3);
	r[4]=c3; c3=0;

	MulAdd2(a0,a2,c3,c1,c2);
	SqrAdd(a1,c3,c1,c2);
	r[3]=c2; c2=0;

	MulAdd2(a0,a1,c2,c3,c1);
	r[2]=c1; c1=0;

	SqrAdd(a0,c1,c2,c3);
	r[1]=c3;
	r[0]=c2;
}
