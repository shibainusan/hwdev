/* hmac.c */
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
#include <string.h>

#include "ok_md5.h"
#include "ok_sha1.h"
#include "ok_hmac.h"

/*-----------------------------------------------
    HMAC-MD5 function.(return 128bit char)
-----------------------------------------------*/
void HMAC_MD5(int txtlen,unsigned char *txt,
	      int keylen,unsigned char *key,unsigned char *ret){
	unsigned char k_ipad[64];
	unsigned char k_opad[64];
	unsigned char tk[16];
	MD5_CTX ctx;
	int i;

	if(keylen>64){
		OK_MD5(keylen,key,tk);
		key = tk;
		keylen = 16;
	}

	memset(k_ipad,0,64);
	memset(k_opad,0,64);
	memcpy(k_ipad,key,keylen);
	memcpy(k_opad,key,keylen);

	for(i=0; i<64;i++){
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	MD5Init(&ctx);
	MD5Update(&ctx,k_ipad,64);
	MD5Update(&ctx,txt,txtlen);
	MD5Final(ret,&ctx);

	MD5Init(&ctx);
	MD5Update(&ctx,k_opad,64);
	MD5Update(&ctx,ret,16);
	MD5Final(ret,&ctx);
}

/*-----------------------------------------------
    HMAC-SHA1 function.(return 160bit char)
-----------------------------------------------*/
void HMAC_SHA1(int txtlen,unsigned char *txt,
	      int keylen,unsigned char *key,unsigned char *ret){
	unsigned char k_ipad[64];
	unsigned char k_opad[64];
	unsigned char tk[20];
	SHA1_CTX ctx;
	int i;

	if(keylen>64){
		OK_SHA1(keylen,key,tk);
		key = tk;
		keylen = 20;
	}

	memset(k_ipad,0,64);
	memset(k_opad,0,64);
	memcpy(k_ipad,key,keylen);
	memcpy(k_opad,key,keylen);

	for(i=0; i<64;i++){
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	SHA1init(&ctx);
	SHA1update(&ctx,k_ipad,64);
	SHA1update(&ctx,txt,txtlen);
	SHA1final(ret,&ctx);

	SHA1init(&ctx);
	SHA1update(&ctx,k_opad,64);
	SHA1update(&ctx,ret,20);
	SHA1final(ret,&ctx);
}
