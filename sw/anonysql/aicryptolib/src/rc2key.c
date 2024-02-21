/* rc2key.c */
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

#include "key_type.h"
#include "ok_rc2.h"

static unsigned short beale[]={
  71, 194,  38,1701,  89,  76,  11,  83,1629,  48,  94,  63, 132,  16, 111,  95,
  84, 341, 975,  14,  40,  64,  27,  81, 139, 213,  63,  90,1120,   8,  15,   3,
 126,2018,  40,  74, 758, 485, 604, 230, 436, 664, 582, 150, 251, 284, 308, 231,
 124, 211, 486, 225, 401, 370,  11, 101, 305, 139, 189,  17,  33,  88, 208, 193,
 145,   1,  94,  73, 416, 918, 263,  28, 500, 538, 356, 117, 136, 219,  27, 176,
 130,  10, 460,  25, 485,  18, 436,  65,  84, 200, 283, 118, 320, 138,  36, 416,
 280,  15,  71, 224, 961,  44,  16, 401,  39,  88,  61, 304,  12,  21,  24, 283,
 134,  92,  63, 246, 486, 682,   7, 219, 184, 360, 780,  18,  64, 463, 474, 131,
 160,  79,  73, 440,  95,  18,  64, 581,  34,  69, 128, 367, 460,  17,  81,  12,
 103, 820,  62, 110,  97, 103, 862,  70,  60,1317, 471, 540, 208, 121, 890, 346,
  36, 150,  59, 568, 614,  13, 120,  63, 219, 812,2160,1780,  99,  35,  18,  21,
 136, 872,  15,  28, 170,  88,   4,  30,  44, 112,  18, 147, 436, 195, 320,  37,
 122, 113,   6, 140,   8, 120, 305,  42,  58, 461,  44, 106, 301,  13, 408, 680,
  93,  86, 116, 530,  82, 568,   9, 102,  38, 416,  89,  71, 216, 728, 965, 818,
   2,  38, 121, 195,  14, 326, 148, 234,  18,  55, 131, 234, 361, 824,   5,  81,
 623,  48, 961,  19,  26,  33,  10,1101, 365,  92,  88, 181, 275, 346, 201, 206
};

static unsigned short pad[]={
 158, 186, 223,  97,  64, 145, 190, 190, 117, 217, 163,  70, 206, 176, 183, 194,
 146,  43, 248, 141,   3,  54,  72, 223, 233, 153,  91, 210,  36, 131, 244, 161,
 105, 120, 113, 191, 113,  86,  19, 245, 213, 221,  43,  27, 242, 157,  73, 213,
 193,  92, 166,  10,  23, 197, 112, 110, 193,  30, 156,  51, 125,  51, 158,  67,
 197, 215,  59, 218, 110, 246, 181,   0, 135,  76, 164,  97,  47,  87, 234, 108,
 144, 127,   6,   6, 222, 172,  80, 144,  22, 245, 207,  70, 227, 182, 146, 134,
 119, 176,  73,  58, 135,  69,  23, 198,   0, 170,  32, 171, 176, 129,  91,  24,
 126,  77, 248,   0, 118,  69,  57,  60, 190, 171, 217,  61, 136, 169, 196,  84,
 168, 167, 163, 102, 223,  64, 174, 178, 166, 239, 242, 195, 249,  92,  59,  38,
 241,  46, 236,  31,  59, 114,  23,  50, 119, 186,   7,  66, 212,  97, 222, 182,
 230, 118, 122,  86, 105,  92, 179, 243, 255, 189, 223, 164, 194, 215,  98,  44,
  17,  20,  53, 153, 137, 224, 176, 100, 208, 114,  36, 200, 145, 150, 215,  20,
  87,  44, 252,  20, 235, 242, 163, 132,  63,  18,   5, 122,  74,  97,  34,  97,
 142,  86, 146, 221, 179, 166, 161,  74,  69, 182,  88, 120, 128,  58,  76, 155,
  15,  30,  77, 216, 165, 117, 107,  90, 169, 127, 143, 181, 208, 137, 200, 127,
 170, 195,  26,  84, 255, 132, 150,  58, 103, 250, 120, 221, 237,  37,   8,  99
};

static unsigned char sBox[256];

void init_sBox(void);
void init_key(int len,unsigned char *key,unsigned short *S);

/*---------------------------------
    RC2 key_new
---------------------------------*/
Key_RC2 *RC2key_new_(){
	Key_RC2 *ret;

	if((ret=(Key_RC2*)MALLOC(sizeof(Key_RC2)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RC2,ERR_PT_RC2KEY,NULL);
		return NULL;
	}
	ret->key_type = KEY_RC2;
	return ret;
}

int RC2key_set(Key_RC2 *rck,int len,unsigned char *key){
	init_sBox();
	init_key(len,key,rck->S);
	return 0;
}

Key_RC2 *RC2key_new(int len,unsigned char *key){
	Key_RC2 *ret;

	if((ret=RC2key_new_())==NULL) goto error;
	if(RC2key_set(ret,len,key)) goto error;
	return ret;
error:
	RC2key_free(ret);
	return NULL;
}

/*---------------------------------
    RC2 key duplicate
---------------------------------*/
Key_RC2 *RC2key_dup(Key_RC2 *org){
	Key_RC2 *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_RC2,ERR_PT_RC2KEY+1,NULL);
		return NULL;}

	if((ret=(Key_RC2*)MALLOC(sizeof(Key_RC2)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RC2,ERR_PT_RC2KEY+1,NULL);
		return NULL;}
	memcpy(ret,org,sizeof(Key_RC2));
	return(ret);
}

/*---------------------------------
    RC2 key_free
---------------------------------*/
void RC2key_free(Key_RC2 *key){
	if(key==NULL) return;
	memset(key,0,sizeof(Key_RC2));
	FREE(key);
}

/*---------------------------------
    RC2 set iv
---------------------------------*/
void RC2_set_iv(Key_RC2 *key,unsigned char *ivc){
	uc2usLE(8,ivc,key->iv);
	uc2usLE(8,ivc,key->oiv);
}

/*---------------------------------
  init sBox and key.
---------------------------------*/
void init_sBox(void){
	int i;
	for(i=0;i<256;i++)
		sBox[i] = (unsigned char)(beale[i] % 256) ^ pad[i];
}

void init_key(int len,unsigned char *key,unsigned short *S){
	unsigned char Sc[128],c;
	unsigned int ui;
	int i,j,bits;

	if((len<0)||(len>128)) len=128;
	bits = len*8;

	for(j=0;j<len;j++)
		Sc[j] = key[j];
	for(c=Sc[j-1],i=0;j<128;i++,j++)
		c = Sc[j] = sBox[ (Sc[i]+c) % 256 ];

#if 0 /* this is normal key generation */
	Sc[0] = sBox[Sc[0]];
#else /* BSAFE version */
	j=(bits+7)>>3;
	i=128-j;
	ui= (0xff>>(-bits & 0x07));

	c=Sc[i]=sBox[ Sc[i]&ui ];
	while(i--)
		c=Sc[i]=sBox[ Sc[i+j]^c ];
#endif

	for(i=j=0;j<64;j++,i+=2)
		S[j] = (Sc[i])|(Sc[i+1]<<8);
}

/*---------------------------------
  Tool: cast uchar <-> ushort
---------------------------------*/
void uc2usLE(int clen,unsigned char *in,unsigned short *ret){
	int	i,j;

	for(i=j=0;j<clen;i++,j+=2){
		ret[i] = (in[j])|(in[j+1]<<8);
	}
}

void us2ucLE(int slen,unsigned short *in,unsigned char *ret){
	int i,j;
	/* little endian */
	for(i=j=0;i<slen;i++,j+=2){
		ret[j  ]=(unsigned char)(in[i]);
		ret[j+1]=(unsigned char)(in[i]>>8);
	}
}

