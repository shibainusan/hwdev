/* rc4.c */
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
#include <stdlib.h>
#include <string.h>

#include "ok_rc4.h"

#if _USE_RC4

/*-----------------------------------------------
  RC4 stream cipher encryption & decryption
-----------------------------------------------*/
void RC4_do_crypt(Key_RC4 *key,int len,unsigned char *in,unsigned char *ret){ 
  unsigned char x,y,*state,swap;
  int i;
   
  x = key->x;     
  y = key->y;     
   
  state = key->state;
  for(i=0; i<len; i++){
    /* x = (x + 1) % 256; */
    /* x should be 0 to 256 because it is uchar */
    x++;

    /* y = (state[x] + y) % 256; */
    /* y should be 0 to 256 because it is uchar */
    y += state[x];

    /* swap byte */
    swap     = state[x];
    state[x] = state[y];
    state[y] = swap;

    /* xorIndex = (state[x] + state[y]) % 256; */
    /* swap is 'old' state[x] and it is uchar */
    swap += state[x];
      
    ret[i] = in[i]^state[swap];
  }
  key->x = x;     
  key->y = y;
}

/*-----------------------------------------------
  RC4 return initialized state
-----------------------------------------------*/
void RC4_init_state(Key_RC4 *key){
  if(key==NULL) return;
  memcpy(key->state,key->init_st,256);
  key->x = key->y = 0;
}

#endif /* _USE_RC4 */
