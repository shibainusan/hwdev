/* des.c */
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

#include "aiconfig.h"

#include <stdio.h>

#include "ok_des.h"

extern Sboxc;

#ifdef __WINDOWS__
void des_crypto_asm(ULONG* a, ULONG* b, ULLONG *keyL,
					int init, int end, int dt){
	__asm{
; ebx = *a ... means "l"
	mov		edx,dword ptr [a]
	mov		ebx,dword ptr [edx]

; ecx = *b ... means "r"
	mov		edx,dword ptr [b]
	mov		ecx,dword ptr [edx]
	mov		edi,dword ptr [init]	; edi=init, "i=0"
	mov		eax,dword ptr [end]		; eax=end
	mov		edx,dword ptr [dt]		; edx=dt

LOOP_TOP:
	push	edi		; init
	push	eax		; end
	push	edx		; dt
	push	ebx
; edx = keyL[i]
	mov		esi,dword ptr [keyL]
	mov		edx,dword ptr [esi+edi*8]	; left  32 bit
	mov		ebx,dword ptr [esi+edi*8+4]	; right 32 bit

; -------------- no.1 --------------
; ((r)<<5)|((r)>>27)
	mov		esi,ecx
	shl		esi,5
	mov		eax,ecx
	shr		eax,27
	or		esi,eax
; esi^(key)>>42 ...but actually, ebx>>10
	mov		eax,ebx
	shr		eax,10
	xor		esi,eax
	push	ebx		; keep key [right 32 bit]
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	mov		edi,dword ptr [ebx+eax*4]
; -------------- no.2 --------------
; (r)>>23
	mov		esi,ecx
	shr		esi,23
; esi^(key)>>36 ...but actually [key right 32 bit]>>4
	pop		eax
	push	eax		; keep key [right 32 bit]
	shr		eax,4
	xor		esi,eax
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+100h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]
; -------------- no.3 --------------
; (r)>>19
	mov		esi,ecx
	shr		esi,19
; esi^(key)>>30 ...but actually (([key right 32 bit]<<2)&0x3c)|([key left 32 bit]>>30)
	pop		ebx
	shl		ebx,2
	mov		eax,edx
	shr		eax,30
	or		eax,ebx
	xor		esi,eax
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+200h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]

; -------------- no.4 --------------
; (r)>>15
	mov		esi,ecx
	shr		esi,15
; esi^(key)>>24
	mov		eax,edx
	shr		eax,24
	xor		esi,eax
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+300h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]
; -------------- no.5 --------------
; (r)>>11
	mov		esi,ecx
	shr		esi,11
; esi^(key)>>18
	mov		eax,edx
	shr		eax,18
	xor		esi,eax
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+400h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]
; -------------- no.6 --------------
; (r)>>7
	mov		esi,ecx
	shr		esi,7
; esi^(key)>>12
	mov		eax,edx
	shr		eax,12
	xor		esi,eax
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+500h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]
; -------------- no.6 --------------
; (r)>>3
	mov		esi,ecx
	shr		esi,3
; esi^(key)>>6
	mov		eax,edx
	shr		eax,6
	xor		esi,eax
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+600h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]
; -------------- no.7 --------------
; ((r)<<1)|((r)>>31)
	mov		esi,ecx
	shl		esi,1
	mov		eax,ecx
	shr		eax,31
	or		esi,eax
; esi^(key)
	xor		esi,edx
; (((ti)>>4)&0x02)|((ti)&0x01)
	mov		ebx,esi
	sar		ebx,4
	and		ebx,2
	mov		eax,esi
	and		eax,1
	or		ebx,eax
	shl		ebx,6		; 4*16 byte shift
	add		ebx,offset Sboxc+700h
; ((ti)>>1)&0x0f
	mov		eax,esi
	sar		eax,1
	and		eax,0Fh
	or		edi,dword ptr [ebx+eax*4]

; tmp = l ^ edi
	pop		ebx		;	get "l"
	xor		edi,ebx
	mov		ebx,ecx	;	l = r
	mov		ecx,edi

	pop		edx		;	get "dt"
	pop		eax		;	get "end"
	pop		edi		;	get	"i"
	add		edi,edx	;	edi+=edx

	cmp		edi,eax	; if(edi!=end) jump LOOP_TOP
	jne		LOOP_TOP

	mov		eax,dword ptr [a]
	mov		dword ptr [eax],ebx	; *a=l
	mov		eax,dword ptr [b]
	mov		dword ptr [eax],ecx	; *b=r
	}
}
#endif

