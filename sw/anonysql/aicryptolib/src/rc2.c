/* rc2.c */
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

#include "ok_rc2.h"


/*---------------------------------
    RC2 encryptograph
---------------------------------*/
void RC2_encrypt(unsigned short *in,unsigned short *ret,unsigned short *S){
  unsigned short w0,w1,w2,w3,sw;
  int i;

  w0=in[0]; w1=in[1]; w2=in[2]; w3=in[3];
  for(i=0;i<64;){
    sw = w0 + ( w1 & (~w3) ) + ( w2 & w3 ) + S[i]; i++;
    w0 = (sw<<1)|(sw>>15);
    sw = w1 + ( w2 & (~w0) ) + ( w3 & w0 ) + S[i]; i++;
    w1 = (sw<<2)|(sw>>14);
    sw = w2 + ( w3 & (~w1) ) + ( w0 & w1 ) + S[i]; i++;
    w2 = (sw<<3)|(sw>>13);
    sw = w3 + ( w0 & (~w2) ) + ( w1 & w2 ) + S[i]; i++;
    w3 = (sw<<5)|(sw>>11);

    if((i==20)||(i==44)){
      w0 += S[ w3 & 63 ];
      w1 += S[ w0 & 63 ];
      w2 += S[ w1 & 63 ];
      w3 += S[ w2 & 63 ];
    }
  }
  ret[0]=w0; ret[1]=w1; ret[2]=w2; ret[3]=w3;
}

/*---------------------------------
    RC2 decryptograph
---------------------------------*/
void RC2_decrypt(unsigned short *in,unsigned short *ret,unsigned short *S){
  unsigned short w0,w1,w2,w3;
  int i;

  w0=in[0]; w1=in[1]; w2=in[2]; w3=in[3];

  for(i=63;i>0;){
    w3 = ((w3<<11)|(w3>>5));
    w3 = ((w3) - ( w0 & (~w2) ) - ( w1 & w2 ) - S[i])&0xffff; i--;
    w2 = ((w2<<13)|(w2>>3));
    w2 = ((w2) - ( w3 & (~w1) ) - ( w0 & w1 ) - S[i])&0xffff; i--;
    w1 = ((w1<<14)|(w1>>2));
    w1 = ((w1) - ( w2 & (~w0) ) - ( w3 & w0 ) - S[i])&0xffff; i--;
    w0 = ((w0<<15)|(w0>>1));
    w0 = ((w0) - ( w1 & (~w3) ) - ( w2 & w3 ) - S[i])&0xffff; i--;

    if((i==43)||(i==19)){
      w3 = (w3-S[ w2 & 63 ])&0xffff;
      w2 = (w2-S[ w1 & 63 ])&0xffff;
      w1 = (w1-S[ w0 & 63 ])&0xffff;
      w0 = (w0-S[ w3 & 63 ])&0xffff;
    }
  }
  ret[0]=w0; ret[1]=w1; ret[2]=w2; ret[3]=w3;
}

