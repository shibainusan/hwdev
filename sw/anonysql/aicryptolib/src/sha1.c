/* sha1.c */
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
#include <string.h>
#include "ok_sha1.h"


#define f1(B,C,D)       (((B)&(C))|((~(B))&(D)))	/* 0  <= t <= 19 */
#define f2(B,C,D)       ((B)^(C)^(D))             	/* 20 <= t <= 39 */
#define f3(B,C,D)       (((B)&(C))|((B)&(D))|((C)&(D)))	/* 40 <= t <= 59 */
#define f4(B,C,D)       ((B)^(C)^(D))			/* 60 <= t <= 79 */


#define K1      0x5A827999      /* 0  <= t <= 19 */
#define K2      0x6ED9EBA1      /* 20 <= t <= 39 */
#define K3      0x8F1BBCDC      /* 40 <= t <= 59 */
#define K4      0xCA62C1D6      /* 60 <= t <= 79 */


#define S(X,n)	(((X)<<n)|((X)>>(32-n)))

static long	initH[]={
    0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};


static void sha1_trans(ULONG *w,ULONG *H);
static void clear_w(ULONG *w);
static void set_w(unsigned char *in,ULONG *w,int max);
static void calc_w(ULONG *w);
static void set_length(int len,ULONG *w);

void uc2ul(unsigned char *in,ULONG *w,int max);
void ul2uc(ULONG *w,unsigned char *ret);

/*-----------------------------------------------
    SHA1 function.(return 160bit char)
-----------------------------------------------*/
void OK_SHA1(int len,unsigned char *in,unsigned char *ret){
	SHA1_CTX ctx;

	if(len<=0) return;
	SHA1init(&ctx);
	SHA1update(&ctx,in,len);
	SHA1final(ret,&ctx);
}

/*-----------------------------------------------
    SHA1 functions
-----------------------------------------------*/
void SHA1init(SHA1_CTX *ctx){
  int	i;

  for(i=0;i<5;i++)
    ctx->H[i]=initH[i];
  ctx->len=0;
  ctx->mod=0;
}

void SHA1update(SHA1_CTX *ctx, unsigned char *in, int len){
  ULONG w[80];
  ULONG *H;
  unsigned char *dat;
  int i,mod,tmp;

  if((in==NULL)||(len<0)) return;

  H = ctx->H;
  ctx->len += len;
  dat = ctx->dat;
  mod = ctx->mod;

  if((len+mod-64)<=0){
    ctx->mod = len+mod;
    memcpy(&dat[mod],in,len);
  }else{
    memcpy(&dat[mod],in,64-mod);
    set_w(dat,w,64);
    calc_w(w);
    sha1_trans(w,H);

    tmp = len-64;
    for(i=64-mod;i<tmp;i+=64){
      set_w(&in[i],w,64);
      calc_w(w);
      sha1_trans(w,H);
    }
    ctx->mod = len-i;
    memcpy(dat,&in[i],ctx->mod);
  }
}

void SHA1final(unsigned char *ret,SHA1_CTX *ctx){
  ULONG w[80];
  ULONG *H;
  int	mod;

  H = ctx->H;
  mod = ctx->mod;
  if(mod>=56){
      set_w(ctx->dat,w,mod);
      calc_w(w);
      sha1_trans(w,H);

      clear_w(w);
      if(mod==64) w[0]=0x80000000L;
      set_length(ctx->len,w);
      calc_w(w);
      sha1_trans(w,H);
  }else{
      set_w(ctx->dat,w,mod);
      set_length(ctx->len,w);
      calc_w(w);
      sha1_trans(w,H);
  }
  ul2uc(ctx->H,ret);
}

/*-----------------------------------------------
  char <--> long (max must be a multiple 4)
-----------------------------------------------*/
void uc2ul(unsigned char *in,ULONG *w,int max){
  int i,j;
  for(i=0,j=0;j<max;i++,j+=4)
    w[i] = ((ULONG)in[j]<<24)|((ULONG)in[j+1]<<16)|
	((ULONG)in[j+2]<<8)|(ULONG)in[j+3];
}
void ul2uc(ULONG *H,unsigned char *ret){
  int i,j;
  for(i=j=0;i<5;i++,j+=4){
    ret[j  ] = (unsigned char)(H[i]>>24);
    ret[j+1] = (unsigned char)(H[i]>>16);
    ret[j+2] = (unsigned char)(H[i]>>8);
    ret[j+3] = (unsigned char) H[i];
  }
}

/*-----------------------------------------------
  set w[]
-----------------------------------------------*/
void set_w(unsigned char *in,ULONG *w,int max){
  int div,mod;

  /* clear w */
  memset(w,0,sizeof(long)*16);

  /* set w */
  if(max==64)
    uc2ul(in,w,max);
  else{
    div = max/4;
    mod = max%4;
    uc2ul(in,w,max-mod);

    switch(mod){
      case 0:
	w[div] = (ULONG)0x80000000L;
	break;
      case 1:
	w[div] = (ULONG)(in[max-1]<<24)|(ULONG)0x800000L;
	break;
      case 2:
	w[div] = (ULONG)(in[max-2]<<24)|(ULONG)(in[max-1]<<16)|
	    (ULONG)0x8000L;
     	break;
      case 3:
	w[div] = (ULONG)(in[max-3]<<24)|(ULONG)(in[max-2]<<16)|
	    (ULONG)(in[max-1]<<8)|(ULONG)0x80L;
	break;
    }
  }
}

static void clear_w(ULONG *w){
    memset(w,0,sizeof(long)*16);
}
static void calc_w(ULONG *w){
  int i;
  for(i=16;i<80;i++)
    w[i] = S(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
}
static void set_length(int len,ULONG *w){
  w[15] = len<<3;
}

/*-----------------------------------------------
    SHA1 transrate.
-----------------------------------------------*/
static void sha1_trans(ULONG *w,ULONG *H){
  ULONG A,B,C,D,E,TEMP;
  int	i;

  A=H[0]; B=H[1]; C=H[2]; D=H[3]; E=H[4];
  for(i=0;i<20;i++){
    TEMP = S(A,5) + f1(B,C,D) + E + w[i] + K1;
    E=D; D=C; C=S(B,30); B=A; A=TEMP;
/* printf("-- %.8x, %.8x, %.8x, %.8x, %.8x,\n",A,B,C,D,E); */
  }
  for(;i<40;i++){
    TEMP = S(A,5) + f2(B,C,D) + E + w[i] + K2;
    E=D; D=C; C=S(B,30); B=A; A=TEMP;
  }
  for(;i<60;i++){
    TEMP = S(A,5) + f3(B,C,D) + E + w[i] + K3;
    E=D; D=C; C=S(B,30); B=A; A=TEMP;
  }
  for(;i<80;i++){
    TEMP = S(A,5) + f4(B,C,D) + E + w[i] + K4;
    E=D; D=C; C=S(B,30); B=A; A=TEMP;
  }

  H[0]+=A; H[1]+=B; H[2]+=C; H[3]+=D; H[4]+=E;
}

