/* large_sqr.c */
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

/*-----------------------------------------------
  ret = x ^ 2
-----------------------------------------------*/
int LN_sqr(LNm *x, LNm *ret){
	if((x->top<<1)>LN_MAX){
		OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMSQR,NULL);
		return -1;
	}
#ifndef __WINDOWS__
# ifndef USE_PTHREAD
	if(x->top > KARATSUBA_TH)
		/* x have enough bit length */
		LN_sqr_kara(x,ret);
	else
# endif
#endif
		/* x have small bit length */
		LN_sqr_std(x,ret);
	return 0;
}


/*-----------------------------------------------
  ret = x ^ 2
-----------------------------------------------*/
void LN_sqr_std(LNm *x,LNm *ret){
	ULONG *xn,*rn;
	int i,k,r,xmin;

	rn = ret->num;
	memset(rn,0,sizeof(ULONG)*LN_MAX);
	
	xmin =x->top;
	if(xmin==0){
		ret->top=0;
		return;
	}

	xmin = LN_MAX -xmin;
	xn = x->num;
	i = LN_MAX-1;
	r = i;

	do{
		ULLONG o;
		ULONG d,p,tmp;
		int j;

#ifndef __WINDOWS__
		p=xn[i]; o= (ULLONG) p * p; o+=rn[r];

		rn[r]=(ULONG)o;
		d=(ULONG)(o>>32);

		j=i-1;
		k=r-1;
		tmp=0;

		while(j>=xmin){
			ULLONG c;

			c=tmp;
			o=(ULLONG)p * xn[j];

			(o&0x8000000000000000LL)?(tmp=1):(tmp=0);
			o<<=1;
			o+=rn[k]; o+=d; o+=(c<<32);

			rn[k]=(ULONG)o;
			d=(ULONG)(o>>32);

			k--;
			j--;
		};

#else
	__asm{
;	p=xn[i]; o=p; o*=p; o+=rn[r];
;	ebx=i, ecx=r;
	mov		ebx,dword ptr [i]
;	p=xn[i];
	mov		esi,dword ptr [xn]
	mov		ecx,dword ptr [r]
	mov		eax,dword ptr [esi+4*ebx]
	mov		dword ptr [p],eax
;	edx:eax = edx*edx (p*p)
	mul		eax
;	o+=rn[r]
	mov		esi,dword ptr [rn]
	add		eax,dword ptr [esi+4*ecx]
	adc		edx,0
;	rn[r]=(ULONG)o, d=(ULONG)(o>>32)
	mov		dword ptr [esi+4*ecx],eax
	mov		dword ptr [d],edx
;	ecx = k, ebx = j, edi = tmp
	xor		edi,edi
	dec		ebx
	dec		ecx
LOOP_BEGIN:
;	if(j<xmin) jump ...
	mov		eax,dword ptr [xmin]
	cmp		ebx,eax
	jb		LOOP_END
;	esi = xn[j], eax = p
	mov		esi,dword ptr [xn]
	mov		eax,dword ptr [p]
	mov		edx,dword ptr [esi+ebx*4]
;   edx:eax = eax*edx
	mul		edx
	xor		esi,esi
	shld	esi,edx,1
	push	esi
	shld	edx,eax,1
	shl		eax,1
;	o+=rn[k];
	mov		esi,dword ptr [rn]
	mov		esi,dword ptr [esi+ecx*4]
	add		eax,esi
	adc		edx,0
;	o+=d;
	mov		esi,dword ptr [d]
	add		eax,esi
	adc		edx,0
;	o+=(c<<32);
	add		edx,edi
	pop		edi
;	rn[k]=(ULONG)o (eax);
	mov		esi,dword ptr [rn]
	mov		dword ptr [esi+ecx*4],eax
;	d=(ULONG)(o>>32);
	mov		dword ptr [d],edx
;	j--; k--;
	dec		ebx			;j
	dec		ecx			;k
	jmp		LOOP_BEGIN
LOOP_END:
	mov		dword ptr [tmp],edi
	mov		dword ptr [k],ecx
	}
#endif

		rn[k]+=d;
		rn[k-1]=tmp;

		i--;
		r-=2;
	}while(i>=xmin);

	ret->neg = 0;
	/* last rn[k-1] must be 0 so... */
	if(rn[k])
		ret->top = LN_MAX-k;
	else
		ret->top = LN_MAX-k-1;
}




