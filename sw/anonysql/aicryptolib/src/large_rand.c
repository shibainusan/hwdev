/* large_rand.c */
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

#include "ok_rand.h"
#include "large_num.h"

/*-----------------------------------------------
  very easy way to get a big random number
-----------------------------------------------*/
int LN_set_rand(LNm *a,int byte,unsigned short iv){
	unsigned char *cp;
	ULONG l;
	int	i,j;

	/* set random bytes */
	j = (LN_MAX<<2);
	memset(a->num,0,sizeof(ULONG)*LN_MAX);

	cp = (unsigned char*)a->num;
	if(RAND_bytes(&cp[j-byte],byte)) return -1;

	/* top bit must be "1" */
	if(byte&0x3){
		i = LN_MAX -1 -(byte>>2);

		switch(byte&0x3){
		case 1: l=(ULONG)cp[j-byte]; break;
		case 2: l=(ULONG)(cp[j-byte]<<8)|(cp[j-byte+1]); break;
		case 3: l=(ULONG)(cp[j-byte]<<16)|(cp[j-byte+1])|(cp[j-byte+2]); break;
		}
		a->num[i] = l;
		a->top = LN_now_top(i,a);
	}else{
		i = LN_MAX - (byte>>2);
		a->top = LN_now_top(i,a);
	}
	return 0;
}



