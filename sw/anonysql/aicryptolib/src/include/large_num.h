/* large_num.h */
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

#ifndef __LARGE_NUM_H__
#define __LARGE_NUM_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "aiconfig.h"
#include "ok_err.h"

typedef struct large_num{
	ULONG *num;
	int  top;
	int  size;
	int  neg;		/* negative flag */
}LNm;

#define MTCTX_BUFNUM	24

typedef struct LNm_montgomery_context{
	int	k;			/* r^k  -- number of bit */
	LNm	*r;
	LNm	*rinv;		/* r^-1 -- actually don't need */
	LNm	*n;
	LNm	*nd;		/* r*r^-1 - n*nd = 1 */

	LNm	*buf[MTCTX_BUFNUM];	/* buffers for many functions */
}LNmt_ctx;

/*
 * set size of large_num->num ..long[];
 * this size (4128bit) can calculate 2048bit multiplication!
 * actually, big number division like (4096bit)/(2048bit) requires
 * 4128bit long buffer, ;(
 */
#define LN_MAX	129	/* 4128 bit */
/*
 * use Karatsuba-Ofman Algorithm for large number
 * multiplication. if a number is big enough (more than
 * KARATSUBA_TH), that algorithm is quite efficient :)
 */
#define KARATSUBA_TH	11	/* 352 bit */

/* large_prime.h */
extern const unsigned int prime[];
extern const unsigned short rands[];
#ifndef PRIME_MAX
# define PRIME_MAX	2000
#endif

/***** number calculation *****/
/* ret = a + b; */
int LN_plus(LNm *a,LNm *b,LNm *ret);
int LN_zplus(LNm *a,LNm *b,LNm *ret);
/* ret = a - b; */
int LN_minus(LNm *a,LNm *b,LNm *ret);
void LN_zminus(LNm *a,LNm *b,LNm *ret);

/* ret = a * b  */
int LN_multi(LNm *a,LNm *b,LNm *ret);
/* standerd multiplication */
void LN_multi_std(LNm *a,LNm *b,LNm *ret);
/* Karatsuba-Ofman multiplication */
void LN_multi_kara(LNm *a,LNm *b,LNm *ret);

/* ret = x ^ 2; */
int LN_sqr(LNm *x,LNm *ret);
/* standerd sqr */
void LN_sqr_std(LNm *x,LNm *ret);
/* Karatsuba-Ofman multiplication */
void LN_sqr_kara(LNm *a,LNm *ret);

/* div = a / b; */
int LN_div(LNm *a,LNm *b,LNm *div);
/* mod = a % b; */
int LN_mod(LNm *a,LNm *b,LNm *mod);
int LN_div_mod(LNm *a,LNm *b,LNm *div,LNm *mod);



/***** large_sys.c *****/
LNm *LN_alloc();
void LN_free(LNm *a);

/* size is int(32bit) size */
LNm *LN_alloc_u32(int size,ULONG *l);
/* size is short[] size */
LNm *LN_alloc_s(int size,unsigned short *s);
/* byte is char[] size */
LNm *LN_alloc_c(int byte,unsigned char *c);


/***** large_tool.c *****/
/*  this is compare function
 *    a > b then return 1;
 *    a = b then return 0;
 *    a < b then return -1;
 */
int LN_cmp(LNm *a,LNm *b);
/*  absolute  */
int LN_zcmp(LNm *a,LNm *b);
int LN_now_top(int top,LNm *a);
int LN_now_byte(LNm *a);
int LN_now_bit(LNm *a);

/*  large number check bit (0 or 1)
 *  (if bit is 0...ret 0, 1...ret 1);
 */
int LN_check_bit(LNm *a,int bit);

void LN_copy(LNm *f,LNm *t); /* f..from, t..to */
LNm *LN_clone(LNm *a);

void LN_print(LNm *a);
void LN_print2(LNm *a,int space);


/***** large_set.c *****/
/* size is long[] size */
int LN_set_num(LNm *a,int size,ULONG *s);
int LN_get_num(LNm *a,int size,ULONG *s);

/* size is short[] size */
int LN_set_num_s(LNm *a,int size,unsigned short *s);

/* byte is char[] size */
int LN_set_num_c(LNm *a,int byte,unsigned char *c);
int LN_get_num_c(LNm *a,int byte,unsigned char *c);

/* execute a = 0 */
void LN_clean(LNm *a);

/* size is long[] size */
int LN_reset_size(LNm *a,int s);


/***** large_prime.c *****/
/* get probably prime */
int LN_set_probrand(LNm *a,int byte,unsigned short iv);
/* get prime number <print is flag of terminal output> */
int LN_prime(int byte,LNm *ret,int print);
/* if return 1, then n is composit */
int _LN_miller_rabin(LNm *n,int iter,int print,LNm *n1,LNm *a,LNm *b);
#define LN_miller_rabin(n,iter,print)     _LN_miller_rabin((n),(iter),(print),NULL,NULL,NULL)

/* execute this function before using LN_miller_rabin().. */
void LN_init_prime_tv();


/***** large_rand.c *****/
/* very easy random function */
int LN_set_rand(LNm *a, int byte, unsigned short iv);


/***** large_sqrt.c *****/
/* 1 .. there are two squre roots (mod n)
 * 0 .. one squre root (mod n)
 * -1.. no squre root (mod n)
 */
int LN_jacobi(LNm *a, LNm *n); /* this doesn't work >:( */
/* return 0 .. no error */
int LN_mod_sqrt(LNm *a, LNm *n, LNm *ret);
/* get nearly square root of a.
 * the answer ret will be a >= ret^2 
 */
int LN_sqrt(LNm *a, LNm *ret);

/***** large_ext.c *****/
#define LN_mod_inverse(a,b,c)	LN_ext_euclid((a),(b),(c))
int LN_ext_euclid(LNm *b,LNm *n,LNm *ret);


/***** large_shift.c *****/
/* void LN_rshift(LNm *a,int s,LNm *ret); */
/* s must be smaller than 32 */
int LN_rshift32(LNm *a,int s,LNm *ret);
int LN_lshift32(LNm *a,int s,LNm *ret);

/***** large_exp.c *****/
/* initialize temporary values */
void LN_init_lexp_tv();
/* under 4 functions require to execute   */
/*   LN_init_lexp_tv() before using them. */
int _LN_add_mod(LNm *a,LNm *b,LNm *n,LNm *ret, LNm *c);
int _LN_sub_mod(LNm *a,LNm *b,LNm *n,LNm *ret,LNm *c);
int _LN_mul_mod(LNm *a,LNm *b,LNm *n,LNm *ret, LNm *t,LNm *d);
int _LN_sqr_mod(LNm *a,LNm *n,LNm *ret, LNm *t,LNm *d);

#define LN_add_mod(a,b,n,ret)     _LN_add_mod((a),(b),(n),(ret), NULL)
#define LN_sub_mod(a,b,n,ret)     _LN_sub_mod((a),(b),(n),(ret), NULL)
#define LN_mul_mod(a,b,n,ret)     _LN_mul_mod((a),(b),(n),(ret), NULL,NULL)
#define LN_sqr_mod(a,n,ret)       _LN_sqr_mod((a),(n),(ret), NULL,NULL)


/* ret = x^e mod n */
int LN_exp_mod(LNm *x,LNm *e,LNm *n,LNm *ret);

/***** large_long.c *****/
void LN_long_set(LNm *in,ULONG num);
int LN_long_add(LNm *in,ULONG add);
int LN_long_sub(LNm *in,ULONG sub);
int LN_long_zadd(LNm *in,ULONG add);
void LN_long_zsub(LNm *in,ULONG sub);
int LN_long_multi(LNm *in,ULONG k,LNm *ret);
int LN_long_div(LNm *in,ULONG div,LNm *ret);
int LN_long_mod(LNm *in,ULONG div,ULONG *mod);

/* montgomery reduction */
/***** large_mont.c *****/
LNmt_ctx *LNmt_ctx_new();
LNmt_ctx *LNmt_get_ctx(LNm *n);
void LNmt_ctx_free(LNmt_ctx *ctx);


#ifdef  __cplusplus
}
#endif

#endif /* __LARGE_NUM_H__ */
