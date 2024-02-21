/* rc4key.c */
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

void init_rc4_key(Key_RC4 *rc4,int len,unsigned char *key);

/*-----------------------------------------------
  RC4 Key new.
-----------------------------------------------*/
Key_RC4 *RC4key_new(int len, unsigned char *key){
  Key_RC4 *ret;

  if((ret=(Key_RC4*)MALLOC(sizeof(Key_RC4)))==NULL){
    OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RC4,ERR_PT_RC4KEY,NULL);
    return NULL;
  }

  ret->key_type = KEY_RC4;
  
  init_rc4_key(ret,len,key);
  return ret;
}

void init_rc4_key(Key_RC4 *rc4,int len,unsigned char *key){
  unsigned char tmp;
  unsigned char idx1,idx2,*state;
  int i;

  state = rc4->state;
  for(i=0; i<256; i++) state[i] = i;

  rc4->x = rc4->y = 0;

  idx1 = idx2 = 0;
  for(i=0; i<256; i++){
    /* buffer might be overflow, because idx2 is just uchar
     * but I don't need to care about it. idx2 should be 0 to 256 :-)
     */
    idx2 += key[idx1];
    idx2 += state[i];

    /* swap byte */
    tmp         = state[i];
    state[i]    = state[idx2];
    state[idx2] = tmp;
      
    idx1 ++;
    idx1 %= len;
  }
  memcpy(rc4->init_st,state,256);
}

/*-----------------------------------------------
  RC4 Key duplicate
-----------------------------------------------*/
Key_RC4 *RC4key_dup(Key_RC4 *org){
  Key_RC4 *ret;

  if(org==NULL){
    OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_RC4,ERR_PT_RC4KEY+1,NULL);
    return NULL;
  }
  if((ret=(Key_RC4*)MALLOC(sizeof(Key_RC4)))==NULL){
    OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RC4,ERR_PT_RC4KEY+1,NULL);
    return NULL;
  }
  memcpy(ret,org,sizeof(Key_RC4));
  return ret;
}

/*-----------------------------------------------
  RC4 Key FREE.
-----------------------------------------------*/
void RC4key_free(Key_RC4 *key){
  if(key==NULL) return;
  memset(key,0,sizeof(Key_RC4));
  FREE(key);
}

#endif /* _USE_RC4 */

