/* large_set.c */
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
  set large number (set a=*s)
-----------------------------------------------*/
int LN_set_num(LNm *a,int size,ULONG *l){
	int tp=LN_MAX-size;
	ULONG *an;

	if((size>LN_MAX)||(size<0)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSET,NULL);
		return -1;
	}
	an=a->num;
	memset(an,0,sizeof(ULONG)*LN_MAX);
	memcpy(&an[tp],l,sizeof(ULONG)*size);
	a->neg = 0;
	a->top = LN_now_top(tp,a);
	return 0;
}

/*-----------------------------------------------
  get large number (get *s=a)
-----------------------------------------------*/
int LN_get_num(LNm *a,int size,ULONG *s){
    if((size>LN_MAX)||(size<0)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSET+1,NULL);
		return -1;
	}
    memcpy(s,&(a->num[LN_MAX-size]),sizeof(ULONG)*size);
    return 0;
}

/*-----------------------------------------------
  set large number
-----------------------------------------------*/
int LN_set_num_c(LNm *a,int byte,unsigned char *c){
	ULONG *l;
	int i,j,b;

	l = a->num;
	b = byte;
	j = b&0x03;
	b >>= 2;

	if((b>LN_MAX)||(b<0)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSET+2,NULL);
		return -1;
	}
 
	memset(l,0,sizeof(ULONG)*LN_MAX);
	switch(j){
	case 1:
		l[LN_MAX-1-b] = c[0];
		break;
	case 2:
		l[LN_MAX-1-b] = (c[0]<<8)|c[1];
		break;
	case 3:
		l[LN_MAX-1-b] = (c[0]<<16)|(c[1]<<8)|c[2];
		break;
	}

	for(i=LN_MAX-b;i<LN_MAX;i++,j+=4)
		l[i]=((ULONG)c[j]<<24)|(c[j+1]<<16)|(c[j+2]<<8)|c[j+3];

	a->neg = 0;
	a->top = LN_now_top(LN_MAX-1-b,a);
	return 0;
}

/*-----------------------------------------------
  get large number (get *s=a)
-----------------------------------------------*/
int LN_get_num_c(LNm *a,int byte,unsigned char *c){
	ULONG *l;
	int i,j,b,o;

	if((byte>=(LN_MAX*sizeof(ULONG)))||(byte<0)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSET+3,NULL);
		return -1;
	}

	l = a->num;
	b = byte;
	j = byte-1;
	b&= 0x03;
	i = LN_MAX-1;
	while(j>b){
		o = l[i];
		c[j-3] =(unsigned char)(o >>24);
		c[j-2] =(unsigned char)(o >>16);
		c[j-1] =(unsigned char)(o >>8);
		c[j  ] =(unsigned char) o;
		i--;
		j-=4;
	};

	o = l[i];
	switch(b){
	case 1:
		c[j] = (unsigned char) o;;
		break;
	case 2:
		c[j-1] = (unsigned char)(o >>8);
		c[j]   = (unsigned char) o;
		break;
	case 3:
		c[j-2] = (unsigned char)(o >>16);
		c[j-1] = (unsigned char)(o >>8);
		c[j]   = (unsigned char) o;
		break;
	}
	return 0;
}

/*-----------------------------------------------
  set large number
-----------------------------------------------*/
int LN_set_num_s(LNm *a,int size,unsigned short *s){
	ULONG *l;
	int	i,j,sz,hsz;

	if((size>=(LN_MAX*2))||(size<0)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMSET+4,NULL);
		return -1;
	}

	sz  = size;
	hsz = (sz+1)>>1;
	j   = LN_MAX-hsz;
	l   = a->num;
	i   = sz&0x1;

	memset(l,0,sizeof(ULONG)*LN_MAX);
	if(i){ /* size is odd */
		l[j] = (ULONG)*s;
		j++;
	}

	while(j<LN_MAX){
		l[j] =(s[i]<<16)|(s[i+1]);
		i+=2;
		j++;
	}
	a->neg = 0;
	a->top = LN_now_top(LN_MAX-hsz,a);
	return 0;
}

/*-----------------------------------------------
  clean large number (set a=0)
-----------------------------------------------*/
void LN_clean(LNm *a){
    memset(a->num,0,sizeof(ULONG)*LN_MAX);
    a->neg = 0;
    a->top = 0;
}

/*-----------------------------------------------
  size optimize
-----------------------------------------------*/
int LN_reset_size(LNm *a,int s){
	ULONG *c;

	if((c=(ULONG*)MALLOC(sizeof(ULONG)*s))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_LNM,ERR_PT_LNMSET+6,NULL);
		return -1;
	}
	if(a->size>s)
		memcpy(c,&(a->num[a->size-s]),sizeof(ULONG)*s);
	else{
		memset(c,0,sizeof(ULONG)*s);
		memcpy(&c[s-a->size],a->num,sizeof(ULONG)*a->size);
	}
	FREE(a->num);

	a->num  = c;
	a->size = s;
	a->neg  = 0;
	a->top  = LN_now_top(0,a);
	return 0;
}
