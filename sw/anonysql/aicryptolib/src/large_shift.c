/* large_shift.c */
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

#include "large_num.h"

/*-----------------------------------------------
  large number shift right (a >> s)
  * s must be less than 32...
-----------------------------------------------*/
int LN_rshift32(LNm *a,int s,LNm *ret){
	ULONG *an,*rn;
	int i,tp;

	if((s<0)||(s>32)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSHF,NULL);
		return -1;
	}
	an =a->num;
	rn =ret->num;
	tp =a->top;
#ifndef __WINDOWS__
	i  =LN_MAX-tp;

	rn[i] = an[i] >> s;
	i++;
	while(i<LN_MAX){
		ULLONG o;
		o  = an[i-1]; o<<=32; o|=an[i]; /* o=e[i-1]<<32 | e[i]; */
		o>>= s;
		rn[i] = (ULONG)o;
		i++;
	}

  if(rn[LN_MAX-tp])
	ret->top = tp;
  else
	ret->top = tp-1;
#else
	__asm{
;	edi=i, ecx=s, esi=*an, edx=*rn
	mov		edi,LN_MAX
	sub		edi,dword ptr[tp]
	push	edi
	mov		esi,dword ptr [an]
	mov		edx,dword ptr [rn]
	mov		ecx,dword ptr [s]
;	rn[i] = an[i] >> s;
	mov		eax,dword ptr [esi+4*edi]
	shr		eax,cl
	mov		dword ptr [edx+4*edi],eax
;	i++
	inc		edi
LOOP_BEGIN:
;	if(i>=LN_MAX) jump ...
	cmp		edi,LN_MAX
	jnb		LOOP_END
;	eax=an[i-1];
	mov		eax,dword ptr [esi+4*edi-4]
	mov		ebx,dword ptr [esi+4*edi]
	shrd	ebx,eax,cl
	mov		dword ptr [edx+4*edi],ebx
;	i++
	inc		edi
	jmp		LOOP_BEGIN
LOOP_END:
	pop		edi
	mov		eax,dword ptr [edx+4*edi]
	sub		eax,1
	mov		esi,dword ptr [tp]
	sbb		esi,0
	mov		dword ptr[tp],esi
	}

	ret->top = tp;
#endif
	ret->neg = a->neg;
	return 0;
}

/*-----------------------------------------------
  large number shift left (a << s)
  * s must be less than 32...
-----------------------------------------------*/
int LN_lshift32(LNm *a,int s,LNm *ret){
	ULONG *an,*rn;
	int i,tp,min;

	if((s<0)||(s>32)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSHF+1,NULL);
		return -1;
	}
	an =a->num;
	rn =ret->num;
	tp =a->top;
#ifndef __WINDOWS__
	i  =LN_MAX-1;
	min=i-tp;
	an[min]=0;

	rn[i] = an[i] << s;
	i--;
	s = 32-s;
	do{
		ULLONG o;
		o  = an[i]; o<<=32; o|=an[i+1]; /* o=e[i-1]<<32|e[i]; */
		o>>= s;
		rn[i] = (ULONG)o;
		i--;
	}while(i>=min);

	if(rn[min])
		ret->top = tp+1;
	else
		ret->top = tp;
#else
	__asm{
;	edi=i, ecx=s, esi=*an, edx=*rn
;	i  =LN_MAX-1;
	mov		edi,LN_MAX-1
;	min=LN_MAX-1-tp;
	mov		esi,dword ptr [an]
	mov		ecx,LN_MAX-1
	sub		ecx,dword ptr [tp]
;	an[min]=0
        mov             dword ptr[esi+4*ecx],0
	mov		dword ptr[min],ecx
        mov             ecx,dword ptr [s]
	mov		edx,dword ptr [rn]
	mov		ecx,dword ptr [s]

;	rn[i] = an[i] << s;
	mov		eax,dword ptr [esi+4*edi]
	shl		eax,cl
	mov		dword ptr [edx+4*edi],eax
;	i--;
	dec		edi
LOOP_BEGIN:
;	eax=an[i]; ebx=an[i+1]
	mov		eax,dword ptr [esi+4*edi]
	mov		ebx,dword ptr [esi+4*edi+4]
	shld	eax,ebx,cl
	mov		dword ptr [edx+4*edi],eax
;	i--;
	dec		edi
;	if(i>=min) jump ...
	cmp		edi,dword ptr [min]
	jnb		LOOP_BEGIN
;
	mov		edi,dword ptr [min]
	mov		eax,dword ptr [edx+4*edi]
	add		eax,0xffffffff
	mov		esi,dword ptr [tp]
	adc		esi,0
	mov		dword ptr[tp],esi
	}

	ret->top = tp;
#endif
	ret->neg = a->neg;
	return 0;
}


/*-----------------------------------------------
  large number shift right (a>>s)
-----------------------------------------------*/
#if 0 /* I wouldn't use this function */
void LN_rshift(LNm *a,int s,LNm *ret){
	ULONG *e,*r;
	ULLONG o;
	int i,j,mod,las;

	/* must be a->size == ret->size */
	i = s>>5;
	mod = s&0x1f;
	r =ret->num;
	e =a->num;

	las=LN_MAX-a->top;
	i  =LN_MAX-1-i;
	j  =LN_MAX-1;
	do{
		o  = e[i-1]; o<<=32; o|=e[i]; /* o=e[i-1]<<32|e[i]; */
		o>>= mod;
		r[j] = (ULONG)o;
		i--;
		j--;
	}while(i>=las);

  if(r[j+1])	ret->top = LN_MAX-(j+1);
  else		ret->top = LN_MAX-(j+2);
}
#endif
