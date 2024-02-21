/* large_sys.c */
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
  allocate large number
-----------------------------------------------*/
LNm *LN_alloc_(int size){
	LNm *ret;

	if((ret=(LNm*)MALLOC(sizeof(LNm)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_LNM,ERR_PT_LNMSYS,NULL);
		return NULL;
	}
	if((ret->num=(ULONG*)MALLOC(sizeof(ULONG)*size))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_LNM,ERR_PT_LNMSYS,NULL);
		LN_free(ret); return NULL;
	}
	ret->size = size;
	ret->top  = 0;
	ret->neg  = 0;
	memset(ret->num,0,sizeof(ULONG)*size);
	return(ret);
}

LNm *LN_alloc(void){
  return LN_alloc_(LN_MAX);
}

/*-----------------------------------------------
  allocate large number with int 32bit
-----------------------------------------------*/
LNm *LN_alloc_u32(int size,ULONG *l){
	LNm *ret;
	int tp=LN_MAX-size;

	if((ret=LN_alloc())==NULL) return NULL;
	memcpy(&(ret->num[tp]),l,sizeof(ULONG)*size);
	ret->top = LN_now_top(tp,ret);
	return(ret);
}

/*-----------------------------------------------
  allocate large number with short[]
  (size is long size);
-----------------------------------------------*/
LNm *LN_alloc_s(int size,unsigned short *s){
	LNm *ret;

	if((ret=LN_alloc())==NULL) return NULL;
	LN_set_num_s(ret,size,s);
	return(ret);
}

/*-----------------------------------------------
  allocate large number with char[]
  (size is long size);
-----------------------------------------------*/
LNm *LN_alloc_c(int byte,unsigned char *c){
	LNm *ret;

	if((ret=LN_alloc())==NULL) return NULL;
	LN_set_num_c(ret,byte,c);
	return(ret);
}

/*-----------------------------------------------
  FREE large number
-----------------------------------------------*/
void LN_free(LNm *a){
	if(a){
		if(a->num) FREE(a->num);
		FREE(a);
	}
}
