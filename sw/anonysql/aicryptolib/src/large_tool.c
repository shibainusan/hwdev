/* large_tool.c */
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
  large number (now) top
-----------------------------------------------*/
int LN_now_top(int top,LNm *a){
	ULONG	*an;
	int i=top;

	if((i<0)||(i>=LN_MAX)) i=0;
	an=(ULONG*)a->num;
	do{
		if(an[i])	break;
		i++;
	}while(i<LN_MAX);

	return(LN_MAX-i);
}

/*-----------------------------------------------
  large number (now) byte size
-----------------------------------------------*/
int LN_now_byte(LNm *a){
	int top,num;
/*	top = LN_now_top(0,a); */
	top = a->top;
	num = a->num[LN_MAX-top];
	top = top<<2; /* top*=4 */

	if(0xffff0000 & num){
		if(!(0xff000000 & num))
			top--;
	}else{
		if(0x0000ff00 & num)
			top-=2;
		else
			top-=3;
	}
	return top;
}

/*-----------------------------------------------
  large number (now) bit size
-----------------------------------------------*/
int LN_now_bit(LNm *a){
  const int bits[]={4,3,2,2,1,1,1,1,0,0,0,0,0,0,0,0};
  int ret,s,t;

/*  a->top = t = LN_now_top(0,a); */
  t = a->top;
  ret = sizeof(ULONG)*8*t;
  s = a->num[LN_MAX-t];

  (s & 0xffff0000)?(s>>=16):(ret-=16);

  if(s & 0xff00){
    if(s & 0xf000)
      ret -= bits[(s>>12)&0xf];
    else
      ret -= 4 +bits[(s>>8)&0xf];
  }else{
    if(s & 0x00f0)
      ret -= 8 +bits[(s>>4)&0xf];
    else
      ret -= 12 +bits[s&0xf];
  }
  return(ret);
}

/*-----------------------------------------------
  large number check bit (0 or 1)
  (if bit is 0...ret 0, 1...ret ??);
  most right bit number is 1 not 0.
-----------------------------------------------*/
int LN_check_bit(LNm *a,int bit){
	ULONG s;
	int b=bit;

	b--;
	s = a->num[LN_MAX-1-(b>>5)];
	return(s & (1<<(b&0x1f)));
}

/*-----------------------------------------------
  large number compare (a>b) ...  1; (a==b) ... 0;
                       (a<b) ... -1;
-----------------------------------------------*/
int LN_cmp(LNm *a,LNm *b){
	ULONG *an,*bn;
	int  i,at,r;

	/** must be a->size = b->size 
	if(a->size != b->size)
		return -2; /* error */
	/* check negative flag */
	at = a->neg;
	i  = b->neg;

	if(at ^ i){
		if(at < i)	return 1;
		else		return -1;
	}
	r  = (at)?(-1):(1);

	at = a->top;
	i  = b->top;
	if(at > i)
		return r;
	if(at < i)
		return -r;

	an = a->num;
	bn = b->num;
  
	i=LN_MAX-at;
	while(i<LN_MAX){
		ULONG ai=an[i],bi=bn[i];
		if(ai > bi)
			return r;
		if(ai < bi)
			return -r;
		i++;
	};
	return 0;
}

int LN_zcmp(LNm *a,LNm *b){
	ULONG *an,*bn;
	int  i,at;

	at = a->top;
	i  = b->top;
	if(at > i)
		return 1;
	if(at < i)
		return -1;

	an = a->num;
	bn = b->num;
  
	i=LN_MAX-at;
	while(i<LN_MAX){
		ULONG ai=an[i],bi=bn[i];
		if(ai > bi)
			return 1;
		if(ai < bi)
			return -1;
		i++;
	};
	return 0;
}

/*-----------------------------------------------
  copy large number
    .. must be already alloc t;
    .. must be t->size == f->size;
-----------------------------------------------*/
void LN_copy(LNm *f,LNm *t){
  memcpy(t->num,f->num,sizeof(ULONG)*LN_MAX);
  t->neg = f->neg;
  t->top = f->top;
}

/*-----------------------------------------------
  clone large number
-----------------------------------------------*/
LNm *LN_clone(LNm *a){
  LNm *ret;

  if((ret=LN_alloc(LN_MAX))==NULL) return NULL;
  memcpy(ret->num,a->num,sizeof(ULONG)*LN_MAX);
  ret->neg = a->neg;
  ret->top = a->top;
  return(ret);
}


/*-----------------------------------------------
  print large number
-----------------------------------------------*/
void LN_print(LNm *a){
	int i;

	if(a==NULL)
		printf("NULL\n");
	else{
		if(a->neg)	printf("-0x");
		else		printf("+0x");
		for(i=LN_MAX-a->top;i<LN_MAX;i++){
			printf("%.8x",a->num[i]);
		}
		printf(", t=%d\n",a->top);
	}
}

void LN_print2(LNm *a,int space){
	ULONG *n;
	char	sp[16];
	int	i,j;
  
	memset(sp,' ',space);
	sp[space]=0;

	if(a==NULL){
		printf("%sNULL\n",sp);
	}else{
		n=a->num;
		for(j=0,i=LN_MAX-a->top;i<LN_MAX;i++,j++){
			if(!j) printf("%s",sp);
			printf("%.2x:%.2x:%.2x:%.2x:",(unsigned char)(n[i]>>24),(unsigned char)(n[i]>>16),
				(unsigned char)(n[i]>>8),(unsigned char)n[i]);

			if(j==4){ j=-1; printf("\n");}
		}
		if(j!=0) printf("\n");
	}
}

void LN_debug_print(LNm *a){
	int i;

	if(a==NULL)
		printf("NULL\n");
	else{
		for(i=a->size-a->top;i<a->size;i++){
			printf("0x%.8x,",a->num[i]);
		}
	printf(", t=%d\n",a->top);
	}
}
