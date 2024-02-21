/* ecp_addsub.c */
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

#include "ok_ecc.h"

/*-----------------------------------
	(EC_Point)ret = k * A;
------------------------------------*/
/* binary with (4bit) NAF window method */
int ECp_multi(ECParam *E, ECp *A, LNm *k, ECp *ret){
	int	i,hi,ki,hl,err;
	ECp *ptBuf[10];
	ECp *r2,*rr,*tmp;
	LNm *h;

	LN_init_lexp_tv();
	for(i=0;i<10;i++) ptBuf[i]=E->pbf[i];

	ret->infinity=0;

	/* initializing table */
	err  = ECp_add(E,A,A,ptBuf[2]);				/* 2A */
	err |= ECp_add(E,ptBuf[2],ptBuf[2],ptBuf[1]);	/* 4A */
	err |= ECp_add(E,ptBuf[2],ptBuf[1],ptBuf[0]);	/* 6A */
	if(err) goto error;

	for(i=0;i<4;i++)
		if(ECp_add(E,ptBuf[i],A,ptBuf[i+1])) goto error;

	for(i=0;i<5;i++){
		hi=9-i;
		ECp_copy(ptBuf[i],ptBuf[hi]);
		if(LN_minus(E->p,ptBuf[i]->y,ptBuf[hi]->y)) goto error;
	}

	h=E->buf[9];
	if(LN_long_multi(k,3,h)) goto error;
	hl = LN_now_bit(h)-1;

	r2= E->pbf[10];
	rr= E->pbf[11];
	ECp_copy(A,rr);
	LN_clean(r2->z);
	while(hl>4){
		ki = LN_check_bit(k,hl);
		hi = LN_check_bit(h,hl);

		if((hi==0)^(ki==0)){
			err  = ECp_add(E,rr,rr,r2);
			err |= ECp_add(E,r2,r2,rr);
			err |= ECp_add(E,rr,rr,r2);
			err |= ECp_add(E,r2,r2,rr);
			if(err) goto error;

			i=((hi==0)&&(ki))*5;

			ki = LN_check_bit(k,hl-2);
			hi = LN_check_bit(h,hl-2);
			i+=2 - (((hi==0)&&(ki))<<1) + (((hi)&&(ki==0))<<1);

			ki = LN_check_bit(k,hl-3);
			hi = LN_check_bit(h,hl-3);
			i+= - ((hi==0)&&(ki)) + ((hi)&&(ki==0));

			if(ECp_add(E,rr,ptBuf[i],r2)) goto error;
			hl-=4;
		}else{
			if(ECp_add(E,rr,rr,r2)) goto error;
			hl--;		
		}

		tmp=r2; r2=rr; rr=tmp; /* exchange rr and r2 */
	}

	/* if hl is less than 4, use this routine */
	while(hl>1){
		if(ECp_add(E,rr,rr,r2)) goto error;

		ki = LN_check_bit(k,hl);
		hi = LN_check_bit(h,hl);

		if((hi)&&(ki==0)){
			if(ECp_add(E,r2,A,rr)) goto error;
		}else if((hi==0)&&(ki)){
			if(ECp_sub(E,r2,A,rr)) goto error;
		}else{
			tmp=r2; r2=rr; rr=tmp;} /* exchange rr and r2 */
		hl--;
	}

	ECp_copy(rr,ret);
	return 0;
error:
	return -1;
}

#if 1
int ECp_multi_bin(ECParam *E, ECp *A, LNm *k, ECp *ret){
	ECp *r2,*rr,*tmp;
	LNm *h;
	int	hi,ki,hl;

	h=E->buf[6];
	if(LN_long_multi(k,3,h)) goto error;
	hl = LN_now_bit(h)-1;

	r2= E->pbf[10];
	rr= E->pbf[11];
	ECp_copy(A,rr);
	LN_clean(r2->z);
	while(hl>1){
		if(ECp_add(E,rr,rr,r2)) goto error;

		ki = LN_check_bit(k,hl);
		hi = LN_check_bit(h,hl);

		if((hi)&&(ki==0)){
			if(ECp_add(E,r2,A,rr)) goto error;
		}else if((hi==0)&&(ki)){
			if(ECp_sub(E,r2,A,rr)) goto error;
		}else{
			tmp=r2; r2=rr; rr=tmp;} /* exchange rr and r2 */
		hl--;
	}

	ECp_copy(rr,ret);
	return 0;
error:
	return -1;
}

#endif

/*----------------------------------------
    (EC_Point)ret = -k * A;
----------------------------------------*/
int ECp_multi_posi(ECParam *E, ECp *A, LNm *k, ECp *ret){
	LNm *tmp,*by = E->buf[7];
	int err=-1;

	if(LN_minus(E->p,A->y,by)) goto done;
	tmp=A->y; A->y=by;
	err=ECp_multi(E,A,k,ret);
	A->y=tmp;
done:
	return err;
}
