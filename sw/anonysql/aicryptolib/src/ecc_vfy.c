/* ecc_vfy.c */
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
#include "ok_ecc.h"

int check_hasse_bound(ECParam *E);
int check_MOV_condition(ECParam *E);


/*--------------------------------------------
	Verify EC Parameters
	output : 0 ... no problem
	       : -1... aicrypto error
		   : others... verification error
--------------------------------------------*/
/* this algorithm is based on P1363 */
int ECPm_verify_parameter(ECParam *E){
	LNm *a=NULL,*b=NULL,*c=NULL;
	ECp *k=NULL;
	int vfy=-1,err,iter;

	if((a=LN_alloc())==NULL) goto done;
	if((b=LN_alloc())==NULL) goto done;
	if((c=LN_alloc())==NULL) goto done;
	if((k=ECp_new()) ==NULL) goto done;

	/* 1. check cofactor k */
	if(E->h->top==0){ /* cofactor is not provided */
		err = LN_sqrt(E->p,a);
		err|= LN_lshift32(a,2,b);
		if(err) goto done;
		if(LN_cmp(E->n,b)<=0){vfy=10; goto done;}

	}else{
	/* 2. check r < sqrt(q)+1, then r divides k or not */
		err  = LN_sqrt(E->p,a);
		err |= LN_long_add(a,1);
		if(err) goto done;
		if(LN_cmp(E->n,a)<0){
			if(LN_div_mod(E->h,E->n,b,c)) goto done;
			if(c->top==0){vfy=20; goto done;} /* r divids k ! */
		}

	/* 3. verify cofactor */
	/* In the case of CM generation, I don't need to do
	   this valification...so just check (sqrt(q)-1)^2 <= #E <= (sqrt(q)+1)^2 */
		err=check_hasse_bound(E);
		if(err<0) goto done;
		if(err>0){vfy=30; goto done;}
	}


	/* 4. check r is an odd and that r>2, check primality of r*/
	iter = 5440 / E->nsize;
	err=_LN_miller_rabin(E->n,iter,0 ,a,b,c);
	if(err<0) goto done;
	if(err>0){vfy=40; goto done;}

	/* 5. if q is prime... */
	/* 5.1 check primality of p */
	iter = 5440 / E->psize;
	err=_LN_miller_rabin(E->p,iter,0 ,a,b,c);
	if(err<0) goto done;
	if(err>0){vfy=51; goto done;}

	/* 5.2 check a and b are 0<=a <p, 0<= b <p */
	if(E->a->neg||E->b->neg||(LN_cmp(E->a,E->p)>=0)||(LN_cmp(E->b,E->p)>=0))
		{vfy=52; goto done;}

	/* 5.3 pseudo-random... not needed */
	/* 5.4 check 4a^3 + 27b^2 mod p */
	err  = LN_sqr(E->a,a);
	err |= LN_multi(E->a,a,b);
	err |= LN_lshift32(b,2,c);
	if(err) goto done;

	err  = LN_sqr(E->b,a);
	err |= LN_long_multi(a,27,b);
	if(err) goto done;

	err  = LN_plus(c,b,a);
	err |= LN_div_mod(a,E->p,b,c);
	if(err) goto done;
	if(c->top==0){vfy=54; goto done;}

	/* 5.5 check G != infinity */
	if(E->G->infinity){vfy=55; goto done;}

	/* 5.6 check x and y are 0<=x <p, 0<= y <p*/
	if(E->G->x->neg||E->G->y->neg||
		(LN_cmp(E->G->x,E->p)>=0)||(LN_cmp(E->G->y,E->p)>=0))
		{vfy=56; goto done;}

	/* 5.7 check y^2 = x^3 + a*x + b (mod p) */
	err  = LN_sqr(E->G->x,a);
	err |= LN_multi(E->G->x,a,b);
	err |= LN_multi(E->a,E->G->x,a);
	if(err) goto done;
	err  = LN_plus(a,b,c);
	err |= LN_plus(c,E->b,a);
	err |= LN_div_mod(a,E->p,b,c);
	if(err) goto done;

	err  = LN_sqr(E->G->y,a);
	err |= LN_div_mod(a,E->p,E->buf[0],b);
	if(err) goto done;
	/* b should equal c */
	if(LN_cmp(b,c)){vfy=57; goto done;}

	/* 5.8 check rG = infinity */
	if(ECp_multi(E,E->G,E->n,k)) goto done;
	if(!k->infinity){vfy=58; goto done;}

	/* 5.9.1 check MOV condition */
	err=check_MOV_condition(E);
	if(err<0) goto done;
	if(err>0){vfy=591; goto done;}

	/* 5.9.2 check trace ...(just check r=p or not..) */
	if(!LN_cmp(E->p,E->n)){vfy=592; goto done;}

	/* 6. if q is 2^m...(not supported) */

	/* Yoo, finish now! verify ok!! */
	vfy=0;

done:
	LN_free(a);
	LN_free(b);
	LN_free(c);
	ECp_free(k);
	return vfy;
}

/* (sqrt(q)-1)^2 <= #E <= (sqrt(q)+1)^2 */
int check_hasse_bound(ECParam *E){
	LNm *a,*b,*u;
	int err=-1;

	if((a=LN_alloc())==NULL) goto done;
	if((b=LN_alloc())==NULL) goto done;
	if((u=LN_alloc())==NULL) goto done;

	err  = LN_multi(E->n,E->h,u);	/* #E */
	err |= LN_sqrt(E->p,a);
	err |= LN_long_sub(a,1);
	err |= LN_sqr(a,b);
	if(err) goto done;

	if(LN_cmp(b,u)>0){err=1; goto done;}

	err  = LN_sqrt(E->p,a);
	err |= LN_long_add(a,1);
	err |= LN_sqr(a,b);
	if(err) goto done;

	if(LN_cmp(u,b)>0){err=1;}

done:
	LN_free(a);
	LN_free(b);
	LN_free(u);
	return err;
}

/* check MOV condition based P1363 A.12.1 */
int check_MOV_condition(ECParam *E){
	LNm *t,*t1,*t2;
	int i,iter,err;

	t=E->buf[9];
	iter = E->psize/17;

#ifdef USE_PTHREAD
	/* these are just temporary buffer for calculation */
	t1=E->buf[10]; t2=E->buf[11];
#else
	LN_init_lexp_tv();
	t1=t2=NULL;
#endif

	LN_long_set(t,1);
	i=0;
	do{
		if(err=_LN_mul_mod(t,E->p,E->n,t,t1,t2)) break;

		if((t->neg==0)&&(t->top==1)&&(t->num[LN_MAX-1]==1))
			{err=1; break;}
		i++;
	}while(i<iter);

	return err;
}
