/* large_mont.c */
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
  alloc and FREE montgomery context.
-----------------------------------------------*/
LNmt_ctx *LNmt_ctx_new(){
	LNmt_ctx *ctx;
	int	i;

	ctx = (LNmt_ctx*)MALLOC(sizeof(LNmt_ctx));
	ctx->r = LN_alloc();
	ctx->rinv = LN_alloc();
	ctx->n  = LN_alloc();
	ctx->nd = LN_alloc();
	for(i=0;i<MTCTX_BUFNUM;i++)
		ctx->buf[i]=LN_alloc();

	return ctx;
}

void LNmt_ctx_free(LNmt_ctx *ctx){
	int i;
	for(i=0;i<MTCTX_BUFNUM;i++)
		LN_free(ctx->buf[i]);
	LN_free(ctx->nd);
	LN_free(ctx->n);
	LN_free(ctx->rinv);
	LN_free(ctx->r);
	FREE(ctx);
}

/*-----------------------------------------------
  get new montgomery context.
  n must be 32*i bit...
-----------------------------------------------*/
LNmt_ctx *LNmt_get_ctx(LNm *n){
	LNmt_ctx *ctx;
	int	i,j;

	ctx = LNmt_ctx_new();
	/* copy n */
	LN_copy(n,ctx->n);
	/* r should be 1 bit bigger than n. */
	ctx->k = i = LN_now_bit(n);	/* n has k,k-1,...,0 */
	ctx->r->top = j = (i>>5) +1;
	ctx->r->num[LN_MAX-j] = 1<< (i&0x1f);

	LNmt_euclid(ctx->r,n,ctx);

	return ctx;
}
