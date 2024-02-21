/* ecp_conv.c */
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


/*-------------------------------------------------------------------------
    Creates an EC Point from Octet String
	context of octet string is defined in ANSI X9.62-1998 or IEEE P1363.
-------------------------------------------------------------------------*/
ECp *ECp_OS2P(ECParam *E,unsigned char *os,int len){
	ECp *ret;
	int	i;

	ret=ECp_new();
	switch(*os){
	case 0: /* point at infinity */
		ret->infinity = 1;
		break;

	case 2: /* compressed point */
	case 3:
		LN_set_num_c(ret->x,len-1,&os[1]);
		i=(*os)-2;
		if(ECp_x2y(E,ret->x,ret->y,i)){
			ECp_free(ret);
			return NULL;
		}
		break;

	case 4: /* uncompressed point */
	case 6:
	case 7:
		i = len>>1;	/* (len-1)/2 */
		LN_set_num_c(ret->x,i,&os[1]);
		LN_set_num_c(ret->y,i,&os[1+i]);
		break;

	default:
		ECp_free(ret);
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ECC,ERR_PT_ECCCONV,NULL);
		return NULL;
	}
	return ret;
}


unsigned char *ECp_P2OS(ECp *p,int type,int *ret_len){
	unsigned char *ret;
	int xl,yl,len;

	xl    = LN_now_byte(p->x);
	yl    = LN_now_byte(p->y);
	len   = (xl>yl)?(xl):(yl);

	if((ret=MALLOC(len*2+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECC,ERR_PT_ECCCONV+1,NULL);
		goto error;		
	}
	memset(ret,0,len*2+2);
	ret[0] = (p->infinity)?(0):(type);

	switch(ret[0]){
	case 0: /* point at infinity */
		*ret_len = 1;
		break;
	case 2: /* compressed point */
	case 3:
		ret[0] = 2 + (char)(p->y->num[LN_MAX-1]&0x1); /* check odd y */
		if(LN_get_num_c(p->x,xl,&ret[1])) goto error;
		*ret_len = 1 + xl;
		break;

	case 4: /* uncompressed point */
	case 6:
	case 7:
		if(LN_get_num_c(p->x,len,&ret[1])) goto error;
		if(LN_get_num_c(p->y,len,&ret[len+1])) goto error;
		*ret_len = 1 + len*2;
		break;

	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ECC,ERR_PT_ECCCONV+1,NULL);
		goto error;
	}
	return ret;
error:
	if(ret) FREE(ret);
	return NULL;
}

/*-------------------------------------------------------------------------
	calculate EC Point (y) from (x)
	output : 0...no error, 1...no sqr root, -1...error
-------------------------------------------------------------------------*/
int ECp_x2y(ECParam *E, LNm *x, LNm *y, int odd_y){
	LNm *tmp1,*tmp2,*t1,*t2,*p;
	int	ybit,err;

	tmp1=E->buf[0]; tmp2=E->buf[1]; p=E->p;
	t1=E->buf[10]; t2=E->buf[11];

	/* y^2 = x^3 + a*x + b */
	err  = _LN_sqr_mod(x,p,tmp1,t1,t2);
	err |= _LN_mul_mod(tmp1,x,p,tmp2,t1,t2);  /* tmp2 = x^3 mod p*/
	err |= _LN_add_mod(tmp2,E->b,p,tmp1,t1);  /* tmp1 = (x^3 + b) mod p*/
	if(err) goto error;

	err  = _LN_mul_mod(E->a,x,p,tmp2,t1,t2);	/* tmp2 = (a * x) mod p */
	err |= _LN_add_mod(tmp1,tmp2,p,y,t1);	/* y = (x^3 + a*x + b) mod p */
	if(err) goto error;

	err  = LN_mod_sqrt(y,p,tmp1);
	if(err>0) return 1; /* there is no square root */
	if(err<0) goto error;

	/* check tmp1 (y) is odd or even */
	ybit=tmp1->num[LN_MAX-1]&0x1;

	if((odd_y&&ybit)||((odd_y==0)&&(ybit==0))){
		LN_copy(tmp1,y);
	}else{
		if(LN_minus(p,tmp1,y)) goto error;
	}
	return 0;
error:
	OK_set_errorlocation(ERR_LC_ECC,ERR_PT_ECCCONV+2);
	return -1;
}


