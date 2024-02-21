/* large_kara.c */
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

void karatsuba_rec(ULONG *a, ULONG *b, ULONG *sum, ULONG *r, int d);
ULONG karatsuba_get_t1(ULONG *a, ULONG *b, ULONG *sum, ULONG *r, int d1, int d2);
void multi_4blocks(ULONG *a, ULONG *b, ULONG *r);
void multi_3blocks(ULONG *a, ULONG *b, ULONG *r);
void multi_2blocks(ULONG *a, ULONG *b, ULONG *r);
/* return carry out or not */
ULONG karatsuba_add(ULONG *a0,ULONG *sum, int d1, int d2);
ULONG karatsuba_sub(ULONG *a, int alen, ULONG *b, int blen);

/*-----------------------------------------------
  Karatsuba-Ofman multiplication 
-----------------------------------------------*/
void LN_multi_kara(LNm *a, LNm *b, LNm *ret){
	ULONG	buf[LN_MAX*2];
	ULONG	*an,*bn,*rn;
	int	at,d;

	an=a->num;
	bn=b->num;
	rn=ret->num;
	d =a->top;

	/* it must be at==bt !! */

	at=LN_MAX-d;
	karatsuba_rec(&an[at],&bn[at],rn,buf,d);
	at-=d;

	/* ret->num has some garbages top of them.
	 * but just ignore them.
	 */
	memcpy(&rn[at],buf,d<<3);		/* sizeof(ULONG)*(d*2) */

	ret->neg = a->neg ^ b->neg;
	/* ret->top = LN_now_top(at,ret);*/
	d<<=1;
	ret->top = d - (rn[at]==0);
}

void karatsuba_rec(ULONG *a, ULONG *b, ULONG *sum, ULONG *r, int d){
	int d1,d2,tmp;
	ULONG cc,cr;

	d2 = d>>1;	/* d / 2 */
	d1 = d-d2;
	tmp= d1<<1;	/* d1 * 2 */

	switch(d){
	case 9:
		/* do multi_5blocks(a,b,r) */
		karatsuba_rec(a,b,sum,r,d1);
		multi_4blocks(&a[d1],&b[d1],&r[tmp]);
		break;
	case 8:
		multi_4blocks(a,b,r);
		multi_4blocks(&a[d1],&b[d1],&r[tmp]);
		break;
	case 7:
		multi_4blocks(a,b,r);
		multi_3blocks(&a[d1],&b[d1],&r[tmp]);
		break;
	case 6:
		multi_3blocks(a,b,r);
		multi_3blocks(&a[d1],&b[d1],&r[tmp]);
		break;
	case 5:
		multi_3blocks(a,b,r);
		multi_2blocks(&a[d1],&b[d1],&r[tmp]);
		break;

	default:
		/* t0 = a0 * b0 */
		karatsuba_rec(a,b,sum,r,d1);

		/* t2 = a1 * b1 */
		karatsuba_rec(&a[d1],&b[d1],sum,&r[tmp],d2);
		break;
	}
	/* u0 = (a0+a1) * (b0+b1) */
	/* t1 = u0 - t0 - t2 */
	/* t1 is calculated to &r[tmp<<1] with tmp length.
	 * and return carry out.
	 */
	cc = karatsuba_get_t1(a,b,sum,r,d1,d2);

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

ULONG karatsuba_get_t1(ULONG *a, ULONG *b, ULONG *sum, ULONG *r, int d1, int d2){
	int ac,bc,cc,tmp,tmp2;
	int	i,j;
	ULONG cr;

	tmp =d1<<1;
	tmp2=tmp<<1;

	/* check carry both a and b */
	/* add sum as a carry */
	ac = karatsuba_add(a,sum,d1,d2);
	bc = karatsuba_add(b,&sum[d1],d1,d2);
	cc = (ac&&bc);

	/* (2^32+s0)(2^32+s1) = 2^64 +2^32*s0 +2^32*s1 +s0*s1 */
	switch(d1){
	case 4:
		multi_4blocks(sum,&sum[d1],&r[tmp2]);
		break;
	case 3:
		multi_3blocks(sum,&sum[d1],&r[tmp2]);
		break;
	default:
		karatsuba_rec(sum,&sum[d1],&sum[tmp],&r[tmp2],d1);
		break;
	}

	if(ac){
		i  =tmp2+d1-1;
		j  =tmp-1;		/* bc's */
		cr =0;
		do{
			ULLONG e;
			e = r[i]; e+=sum[j]; e+=cr;

			r[i] = (ULONG) e;
			cr = (ULONG)(e >> 32);
			i--;
			j--;
		}while(j>=d1);
		cc+=cr;
	}
	if(bc){
		i  =tmp2+d1-1;
		j  =d1-1;
		cr =0;
		do{
			ULLONG e;
			e = r[i]; e+=sum[j]; e+=cr;

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


#define MulAdd(x,y,c1,c2,c3)				\
	t = (ULLONG)x * y;						\
	t1= (ULONG)(t >> 32);					\
	t2= (ULONG) t;							\
	c3+= t2; t1+=(c3<t2);					\
	c2+= t1; c1+=(c2<t1);

void multi_2blocks(ULONG *a, ULONG *b, ULONG *r){
	ULLONG t;
	ULONG a0,a1,b0,b1;
	ULONG t1,t2,c1,c2,c3;

	a0=a[0]; a1=a[1];
	b0=b[0]; b1=b[1];
	c1=c3=0;

	t = (ULLONG)a1 * b1;
	r[3]= (ULONG) t;
	c2= (ULONG)(t >> 32);

	MulAdd(a0,b1,c3,c1,c2);
	MulAdd(a1,b0,c3,c1,c2);
	r[2]=c2; c2=0;

	MulAdd(a0,b0,c2,c3,c1);
	r[1]=c1;
	r[0]=c3;
}

void multi_3blocks(ULONG *a, ULONG *b, ULONG *r){
	ULLONG t;
	ULONG a0,a1,a2,b0,b1,b2;
	ULONG t1,t2,c1,c2,c3;

	a0=a[0]; a1=a[1]; a2=a[2];
	b0=b[0]; b1=b[1]; b2=b[2];
	c1=c3=0;

	t = (ULLONG)a2 * b2;
	r[5]= (ULONG) t;
	c2= (ULONG)(t >> 32);

	MulAdd(a1,b2,c3,c1,c2);
	MulAdd(a2,b1,c3,c1,c2);
	r[4]=c2; c2=0;

	MulAdd(a0,b2,c2,c3,c1);
	MulAdd(a1,b1,c2,c3,c1);
	MulAdd(a2,b0,c2,c3,c1);
	r[3]=c1; c1=0;

	MulAdd(a0,b1,c1,c2,c3);
	MulAdd(a1,b0,c1,c2,c3);
	r[2]=c3; c3=0;

	MulAdd(a0,b0,c3,c1,c2);
	r[1]=c2;
	r[0]=c1;
}

void multi_4blocks(ULONG *a, ULONG *b, ULONG *r){
	ULLONG t;
	ULONG a0,a1,a2,a3,b0,b1,b2,b3;
	ULONG t1,t2,c1,c2,c3;

	a0=a[0]; a1=a[1]; a2=a[2]; a3=a[3];
	b0=b[0]; b1=b[1]; b2=b[2]; b3=b[3];
	c1=c3=0;

	t = (ULLONG)a3 * b3;
	r[7]= (ULONG) t;
	c2= (ULONG)(t >> 32);

	MulAdd(a2,b3,c3,c1,c2);
	MulAdd(a3,b2,c3,c1,c2);
	r[6]=c2; c2=0;

	MulAdd(a1,b3,c2,c3,c1);
	MulAdd(a2,b2,c2,c3,c1);
	MulAdd(a3,b1,c2,c3,c1);
	r[5]=c1; c1=0;

	MulAdd(a0,b3,c1,c2,c3);
	MulAdd(a1,b2,c1,c2,c3);
	MulAdd(a2,b1,c1,c2,c3);
	MulAdd(a3,b0,c1,c2,c3);
	r[4]=c3; c3=0;

	MulAdd(a0,b2,c3,c1,c2);
	MulAdd(a1,b1,c3,c1,c2);
	MulAdd(a2,b0,c3,c1,c2);
	r[3]=c2; c2=0;

	MulAdd(a0,b1,c2,c3,c1);
	MulAdd(a1,b0,c2,c3,c1);
	r[2]=c1; c1=0;

	MulAdd(a0,b0,c1,c2,c3);
	r[1]=c3;
	r[0]=c2;
}


/* sum = a0 + a1 */
ULONG karatsuba_add(ULONG *a0,ULONG *sum, int d1, int d2){
	ULONG *a1,cr;

	/* in this case, d1 must be same or bigger than d2 */
	a1 = &a0[d1]; d1--; d2--;
	cr = 0;
	do{
		ULLONG e;
		e = a0[d1]; e+=a1[d2]; e+=cr;

		sum[d1] = (ULONG) e;
		cr = (ULONG)(e >> 32);
		d1--;
		d2--;
	}while(d2>=0);

	if(d1==0){
		sum[d1] = a0[d1]+cr;
		cr = (a0[d1]<cr);
	}
	return  cr;
}

/* a = a - b */
ULONG karatsuba_sub(ULONG *a, int alen, ULONG *b, int blen){
	ULONG cr=0;
	int i,j;
	
	i = alen - blen;
	j = 0;
	while(i<alen){
		ULONG n;
		int k;
		
		n = b[j];
		k = (a[i] < n);
		a[i] -= n;

		if(k){
			if(i>0){
				k=i-1;

				while((!a[k])&&(k>0)){
					a[k]=0xffffffff; k--;
				}
				if((k==0)&&(a[k]==0)) cr++;
				a[k]--;
			}else
				cr++;
		}
		i++; j++;
	}
	return cr;
}



#if 0 /* not use this any more */
void karatsuba_min_even(ULONG *a, ULONG *b, ULONG *r){
	ULONG a0,b0,a1,b1,s0,s1;
	ULLONG t0,t1,t2,t3,u0;
	ULONG ac,bc,cc;

	a0=a[0]; a1=a[1]; b0=b[0]; b1=b[1];
#if 1

	t3=a1; t3*=b1;
	t2=a1; t2*=b0;
	t1=a0; t1*=b1;
	t0=a0; t0*=b0;

	r[3]=(ULONG)t3;
	u0 = t3>>32;
	u0+= (ULONG)t1;
	u0+= (ULONG)t2;
	r[2]=(ULONG)u0;
	u0 = u0>>32;
	u0+= t1>>32;
	u0+= t2>>32;
	u0+= (ULONG)t0;
	r[1]=(ULONG)u0;
	u0 = u0>>32;
	u0+= t0>>32;
	r[0]=(ULONG)u0;
#else
	s0=a0-a1; s1=b1-b0;
	ac=(a0<a1);
	bc=(b1<b0);
	cc=-(ac^bc);
	if(ac) s0=-s0;
	if(bc) s1=-s1;

	t0=a0; t0*=b0;
	t2=a1; t2*=b1;
	t1=s0; t1*=s1;
/*	if((a0>a1)^(b1>b0))
		t1=-t1;*/

	if(cc) t1=-t1;
	t1+=t0;
	cc+=(t1<t0);
	t1+=t2;
	cc+=(t1<t2);

	r[3]=(ULONG)t2;
	u0 = t2>>32;
	u0+= (ULONG)t1;
	r[2]=(ULONG)u0;
	u0 = u0>>32;
	u0+= t1>>32;
	u0+= (ULONG)t0;
	r[1]=(ULONG)u0;
	u0 = u0>>32;
	u0+= t0>>32;
	u0+= cc;
	r[0]=(ULONG)u0;
#endif
}
#endif
