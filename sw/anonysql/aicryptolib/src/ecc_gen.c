/* ecc_gen.c */
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

#include "ok_io.h"
#include "large_num.h"

#include "ok_asn1.h"
#include "ok_ecc.h"

#define MAX_D	3
#define CM_ITER_TH	64

#define BASE_POINT_TEST_MAX	10
#define CURVE_AB_TEST_MAX	8

		
static ULONG  D[MAX_D+2] = {11  ,19 ,43   ,67     ,163};
static ULONG J0[MAX_D] = {32768,884736,110592000};

int calc_ec_params(ECParam *E,int num);
int find_nearly_prime(LNm *ode, LNm *r, LNm *k);
int calc_p_and_r(ECParam *E,int size);

/*-----------------------------------
	Generation of EC Parameters
------------------------------------*/
/* this algorithm is from ...
 * [1] F. Morain, "Building cyclic elliptic curves modulo large primes,"
 *     D. W. Davies,editor,Advances in Cryptology - EUROCRYPT '91,
 *     Lecture Notes in Computer Science 547 (1991),Springer-Verlag,328-336.
 * [2] Miyaji,A.,"Elliptic Curve Cryptosystems Immune to Any Reduction into
 *     the Discrete Logarithm Problem," IEICE Trans.,E76-A,1,pp.50-54(1993)
 * [3] Akiyama,M.,"A Key Generation for Elliptic Curve Cryptosystems Using
 *     Deterministic Primality Test," SCIS'99 pp.773-778(1999)
 */
ECParam *ECPm_gen_parameter(int size){
	ECParam *ret=NULL;
	int	dn,err=-1;

	if(size <= 0) goto done;

	if((ret=ECPm_new())==NULL) goto done;

	printf("generating new ec parameter\n");
	do{
		err=-1;
		/* dn should be 0,1,2 -> D[11,19,43] */
		if((dn=calc_p_and_r(ret,size))<0) goto done;
		
		/* check (4p-w^2)/D = V^2 */
		printf("\np      : ");LN_print(ret->p);
		printf("r      : ");LN_print(ret->n);
		printf("k      : ");LN_print(ret->h);

		err  = LN_lshift32(ret->p,2,ret->buf[1]);
		err |= LN_sqr(ret->buf[0],ret->buf[2]);
		err |= LN_minus(ret->buf[1],ret->buf[2],ret->buf[3]);
		if(err) goto done;
		err  = LN_long_div(ret->buf[3],D[dn],ret->buf[4]);
		err |= LN_sqrt(ret->buf[4],ret->buf[5]);
		err |= LN_sqr(ret->buf[5],ret->buf[6]);
		if(err) goto done;
		printf("4p     : ");LN_print(ret->buf[1]);
		printf("w      : ");LN_print(ret->buf[0]);
		printf("w^2    : ");LN_print(ret->buf[2]);
		printf("4p-w^2 : ");LN_print(ret->buf[3]);
		printf("v^2    : ");LN_print(ret->buf[4]);
		printf("v      : ");LN_print(ret->buf[5]);
		printf("v^2    : ");LN_print(ret->buf[6]);

		if(LN_cmp(ret->buf[4],ret->buf[6])){
			printf("invalid value of v!!\n");
			continue;
		}

		printf("size ok!!\n");
		ret->psize = LN_now_bit(ret->p);

		/* if dn==1, bad combination of p and r */
		if((err=calc_ec_params(ret,dn))<0) goto done;
	}while(err);

	ret->curve_type = ECP_ORG_primeParam;
	ret->nsize      = LN_now_bit(ret->n);
	ret->version    = 1;
	ret->type       = OBJ_X962_FT_PRIME;
	err=0;
done:
	if(ret&&err){ ECPm_free(ret); ret=NULL;}
	return ret;
}


int calc_ec_params(ECParam *E,int num){
	LNm *vz,*vz2,*vz3,*p,*r,*k,*tmp,*t2,*b1,*b2;
	ECp *g,*a=NULL,*b=NULL;
	int i,j,err=-1;

	LN_init_lexp_tv();
	/* 0 and 1 are used in ECp_x2y() */
	vz=E->buf[2]; vz2=E->buf[3]; vz3=E->buf[4];
	tmp=E->buf[5]; t2=E->buf[6];
	p=E->p; r=E->n; k=E->h; g=E->G;

	if((a=ECp_new())==NULL) goto done;
	if((b=ECp_new())==NULL) goto done;

#ifdef USE_PTHREAD
	b1=E->buf[10]; b2=E->buf[11];
#else
	b1=b2=NULL;
#endif

	i=0;
	err=0;
	do{
		if(err=LN_set_rand(vz,E->psize>>4,(unsigned short)rand()))
			goto done;

		err  = _LN_sqr_mod(vz,p,vz2,b1,b2);
		err |= _LN_mul_mod(vz,vz2,p,vz3,b1,b2);
		if(err) goto done;

		LN_long_set(tmp,J0[num]);
		err  = LN_long_add(tmp,1728);		/* 1728-J0 (J0<0) */
		err |= LN_mod_inverse(tmp,p,vz);
		if(err) goto done;

		LN_copy(p,tmp);
		err  = LN_long_sub(tmp,J0[num]);	/* J0 < 0 */
		err |= LN_long_multi(tmp,3,t2);	/* 3*J0 */
		err |= _LN_mul_mod(t2,vz,p,t2,b1,b2);	/* 3*J0/(1728-J0) mod p */
		err |= _LN_mul_mod(t2,vz2,p,E->a,b1,b2);
		if(err) goto done;

		err  = LN_lshift32(tmp,1,t2);	/* 2*J0 */
		err |= _LN_mul_mod(t2,vz,p,t2,b1,b2);	/* 3*J0/(1728-J0) mod p */
		err |= _LN_mul_mod(t2,vz3,p,E->b,b1,b2);
		if(err) goto done;

		printf("checking parameters of ...\n");
		printf("E->a : ");LN_print(E->a);
		printf("E->b : ");LN_print(E->b);

		j=0;
		do{
			a->infinity = 0;
			g->infinity = 0;

			do{
				err  = LN_set_rand(vz,E->psize>>3,(unsigned short)rand());
				err |= LN_div_mod(vz,p,tmp,a->x);
				if(err) goto done;

				err=ECp_x2y(E,a->x,a->y,0);
				if(err<0) goto done;
				if(err>0){err=0; continue;}

				if(err=ECp_multi(E,a,k,g)) goto done;
	
				if(g->infinity)
					continue;

				break;
			}while(1);

			LN_long_set(g->z,1);
			err  = ECp_pmulti(E,g,r,a);
			err |= ECp_proj2af(E,a);
			if(err) goto done;

			if(a->infinity)	break;

			j++;
		}while(j<BASE_POINT_TEST_MAX);

		if(a->infinity)	break;
		i++;
	}while(i<CURVE_AB_TEST_MAX);

	err=(i>=CURVE_AB_TEST_MAX);
done:
	ECp_free(a);
	ECp_free(b);
	LN_clean(g->z);
	return err;
}

int find_nearly_prime(LNm *ode, LNm *r, LNm *k){
	int	i,err=-1;
	LNm *s=NULL,*t=NULL,*u=NULL,*tmp;
	ULONG m;

	if((s=LN_alloc())==NULL) goto done;
	if((t=LN_alloc())==NULL) goto done;
	if((u=LN_alloc())==NULL) goto done;
	LN_copy(ode,t);
	LN_long_set(s,1);

	/* ode must be odd integer. therefore, it's not
	 * necessary to check whether ode is times of 2 or not.
	 */

	/* check prime more than 2 */
	for(i=0;i<PRIME_MAX;i++){
		if(err=LN_long_mod(t,prime[i],&m)) goto done;
		while(m==0){
printf("^");fflush(stdout);
			err |= LN_long_div(t,prime[i],u);
			tmp=u; u=t; t=tmp;
			err |= LN_long_multi(s,prime[i],u);
			tmp=u; u=s; s=tmp;
			err |= LN_long_mod(t,prime[i],&m);
			if(err) goto done;
		}
	}

printf("+");fflush(stdout);
#ifdef USE_PTHREAD
	err=_LN_miller_rabin(t,32,1,r,k,u);
#else
	err=LN_miller_rabin(t,32,1);
#endif
	if(err) goto done;

	LN_copy(t,r);
	LN_copy(s,k);

	/* check ode == r*k */
	if(err=LN_multi(r,k,t)) goto done;
	if(LN_zcmp(ode,t)){
		printf("error ode and t !!\n");
		err=-1;
	}

done:
	LN_free(s);
	LN_free(t);
	LN_free(u);
	return err;
}

int calc_p_and_r(ECParam *E,int size){
	LNm *w,*v,*d,*w1,*v1,*vd,*p,*r;
	int i,iter,dn,err=0;

	w=E->buf[0]; v=E->buf[1]; d=E->buf[2];
	w1=E->buf[3];v1=E->buf[4]; vd=E->buf[5];
	p=E->p; r=E->n;

	/* initialize temporary values for checking prime */
#ifndef USE_PTHREAD
	LN_init_prime_tv();
#endif
	iter = 5440 / size;	/* see large_prime.c */

	if(LN_set_rand(v,(size>>5)-1,(unsigned short)rand())) goto error;
	v->num[LN_MAX-1]|=0x1;

	if(LN_sqr(v,v1)) goto error;
	dn=rand() % MAX_D;

	do{
		ULONG m;

		dn= (dn+1)%MAX_D;
		if(LN_set_rand(w1,size>>4,(unsigned short)rand())) goto error;
		if(LN_lshift32(w1,1,w)) goto error;
		w->num[LN_MAX-1]|=0x1;	/* w must be odd integer */

printf(".");fflush(stdout);

		err  = LN_sqr(w,w1);
		err |= LN_long_multi(v1,D[dn],vd);
		err |= LN_plus(w1,vd,d);
		if(err) goto error;

		if((d->num[LN_MAX-1]&0x7)!=4)	/* 4p = W^2+DV^2 */
			continue;

		if(LN_rshift32(d,2,p)) goto error;
		/* p should be 3,5,7 mod 8, because square roots exist */
		m = p->num[LN_MAX-1] & 0x7;
		if(m==1) continue;

		/* prime test easily */
		for(i=0;i<PRIME_MAX;i++)
			if((err=LN_long_mod(p,prime[i],&m))<0) goto error;
		if(err>0) continue;

#ifdef USE_PTHREAD
		err=_LN_miller_rabin(p,iter,1,E->buf[9],E->buf[10],E->buf[11]);
#else
		err=LN_miller_rabin(p,iter,1);
#endif
		if(err>0) continue;
		if(err<0) goto error;

		LN_copy(p,d);
		err  = LN_long_add(d,1);
		err |= LN_minus(d,w,vd);
		if(err) goto error;

		err=find_nearly_prime(vd,r,E->h);
		if(err>0) continue;
		if(err<0) goto error;

		/* now we get number pair, p and r */
		break;
	}while(1);

	return dn;
error:
	return -1;
}


/*---------------------- just garbage ---------------------------*/
/* bottom codes are not used in the library, but these are
 * sometimes helpful to think about CM method for building
 * cyclic elliptic curves.
 */
#if 0

int calc_p_and_w(ECParam *E,int size){
	LNm *p,*d;
	int i,j,k;

	p=E->p; d=E->buf[1];

	/* get appropriate prime */
	for(;;){
		ULONG m;

		LN_prime(size>>3,p,0);
		m = p->num[LN_MAX-1] & 0x7;
		/* p should be 3,5,7 mod 8, because square roots exist */
		if((m==3)||(m==5)||(m==7))
			break;
	}

	/* select D randomly */
	j = rand() % MAX_D;

	/* D which are listed in this code are all prime and p=3 mod 8,
	 * so I don't need to list odd primes and calculate 
	 * the Jacobi symbol J followed A.14.2.3 in IEEE P1363
	 */
	i=0;
	do{
		LN_long_set(d,D[j]);

		/* Testing for CM Discriminants (prime case) */
		if((k=test_cm_discriminants(E,d,j)) != -1)
			return k;

		i++;
		j = (j+1) % MAX_D;
	}while(i<MAX_D);

	return -1;
}

int test_cm_discriminants(ECParam *E, LNm *d, int j){
	LNm *a,*b,*c,*dt,*x,*y,*t1,*t2,*tmp;
	LNm *w,*p,*r;
	ULONG k;
	int iter,nr;

	w=E->buf[0]; p=E->p; r=E->n;
	a=E->buf[2]; b=E->buf[3]; c=E->buf[4];dt=E->buf[9];
	x=E->buf[5]; y=E->buf[6];t1=E->buf[7];t2=E->buf[8];

	LN_minus(p,d,t1);	/* t1 = -d mod p */
	if(LN_mod_sqrt(t1,p,b))
		/* no square roots -- this shouldn't be happened */
		return -1;


	LN_copy(p,a);		/* a = p */
	LN_sqr(b,t2);		/* c = (b^2 + d) / p */
	LN_plus(t2,d,t1);
	LN_div_mod(t1,p,c,t2);

	LN_long_set(x,1);	/* x = 1 */
	LN_clean(y);		/* y = 0 */

	LN_lshift32(b,1,r);/* r = 2b */
	nr=r->neg; r->neg=0;

	iter = 0;
	/* loop until |2b| <= a <= c */
	while((LN_cmp(r,a)>0)||(LN_cmp(a,c)>0)){
		r->neg=nr;
		if((++iter)>CM_ITER_TH)
			return -1;

		LN_lshift32(c,1,w);		/* dt = (2b+c)/2c */
		LN_plus(r,c,t2);
		LN_div_mod(t2,w,dt,t1);
		/* if dt is negative, set smaller integer */
		if(dt->neg&&t1->top)
			LN_long_sub(dt,1);

		LN_multi(dt,x,t1);		/* t2 = dt*x + y */
		LN_plus(t1,y,t2);
		x->neg^=1;
//		tmp=x; x=y; y=tmp;		/* y = - x */
		LN_copy(x,y);
//		tmp=t2; t2=x; x=tmp;	/* x = t2 */
		LN_copy(t2,x);

		/* a=c; b=c*dt -b; c=c*dt^2 -2b*dt +a */
		LN_multi(c,dt,t1);
		LN_minus(t1,b,t2);
//		tmp=t2; t2=b; b=tmp;	/* b= c*dt - b */
		LN_copy(t2,b);
		LN_sqr(dt,t1);
		LN_multi(t1,c,t2);
		LN_multi(r,dt,t1);
		LN_plus(t2,a,r);
//		tmp=a; a=c; c=tmp;		/* a= c */
		LN_copy(c,a);
		LN_minus(r,t1,c);		/* c= c*dt^2+a -2b*dt */

		LN_lshift32(b,1,r);		/* r = 2b */
		nr=r->neg; r->neg=0;
	}

	if((D[j]==11)&&((a->top==1)&&(a->num[LN_MAX-1]==3))){
		y->neg^=1;
		tmp=x; x=y; y=tmp;
		tmp=a; a=c; c=tmp;
		b->neg^=1;
	}

	if(a->top==1){
		k=a->num[LN_MAX-1];
		if(k==1){
			LN_lshift32(x,1,w);	/* w = 2x */
			return j;
		}else if(k==4){
			LN_lshift32(x,2,t1);
			LN_multi(b,y,t2);
			LN_plus(t1,t2,w);	/* w = 4x + by */
			return j;
		}
	}

	return -1;
}
#endif
