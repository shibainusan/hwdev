/* des.c */
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
 *	this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *	this list of conditions and the following disclaimer in the documentation
 *	and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *	display the following acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *	acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	 Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
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

#include "ok_des.h"

#define C2LL(i)	\
	l =((long)in[i  ]<<24)|((long)in[i+1]<<16)|((long)in[i+2]<<8)|((long)in[i+3]);\
	r =((long)in[i+4]<<24)|((long)in[i+5]<<16)|((long)in[i+6]<<8)|((long)in[i+7]);\
	o =((ULLONG)l<<32)|(ULLONG)r;

#define LL2C(i)	\
	out[i  ] = (unsigned char)(o>>56);\
	out[i+1] = (unsigned char)(o>>48);\
	out[i+2] = (unsigned char)(o>>40);\
	out[i+3] = (unsigned char)(o>>32);\
	out[i+4] = (unsigned char)(o>>24);\
	out[i+5] = (unsigned char)(o>>16);\
	out[i+6] = (unsigned char)(o>>8 );\
	out[i+7] = (unsigned char) o;

extern ULLONG DES2Crypto(ULLONG blockL,ULLONG *keyL);
extern ULLONG DES2Plain(ULLONG blockL,ULLONG *keyL);

/*---------------------------------
  DES EDE3 ECB mode encryptograph
---------------------------------*/
void DES3_ecb_encrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	c,*list1,*list2,*list3;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	for(i=0;i<len;i++){
		c = DES2Crypto(in[i],list1);
		c = DES2Plain(c,list2);
		out[i] = DES2Crypto(c,list3);
	}
}

void DES3_ecb_encrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG	o,*list1,*list2,*list3;
	ULONG	l,r;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	for(i=0;i<byte;i+=8){
		C2LL(i);
		o = DES2Crypto(o,list1);
		o = DES2Plain(o,list2);
		o = DES2Crypto(o,list3);
		LL2C(i);
	}
}

/*---------------------------------
  DES EDE3 CBC mode encryptograph
---------------------------------*/
void DES3_cbc_encrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	c,*list1,*list2,*list3;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	c = DES2Crypto((in[0]^key->iv),list1);
	c = DES2Plain(c,list2);
	c = out[0] = DES2Crypto(c,list3);

	for(i=1;i<len;i++){
		c = DES2Crypto((in[i]^c),list1);
		c = DES2Plain(c,list2);
		c = out[i] = DES2Crypto(c,list3);
	}
	key->iv = c;
}

void DES3_cbc_encrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG	o,v,*list1,*list2,*list3;
	ULONG	l,r;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	C2LL(0);
	o = DES2Crypto(o^key->iv,list1);
	o = DES2Plain(o,list2);
	o = v = DES2Crypto(o,list3);
	LL2C(0);

	for(i=8;i<byte;i+=8){
		C2LL(i);
		o = DES2Crypto((o^v),list1);
		o = DES2Plain(o,list2);
		o = v = DES2Crypto(o,list3);
		LL2C(i);
	}
	key->iv = v;
}

/*---------------------------------
  DES EDE3 ECB mode decryptograph
---------------------------------*/
void DES3_ecb_decrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	c,*list1,*list2,*list3;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	for(i=0;i<len;i++){
		c = DES2Plain(in[i],list3);
		c = DES2Crypto(c,list2);
		out[i] = DES2Plain(c,list1);
	}
}

void DES3_ecb_decrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG	o,*list1,*list2,*list3;
	ULONG	l,r;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	for(i=0;i<byte;i+=8){
		C2LL(i);
		o = DES2Plain(o,list3);
		o = DES2Crypto(o,list2);
		o = DES2Plain(o,list1);
		LL2C(i);
	}
}

/*---------------------------------
  DES EDE3 CBC mode decryptograph
---------------------------------*/
void DES3_cbc_decrypt_ll(Key_3DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	 c,prv,*list1,*list2,*list3;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	c = DES2Plain(in[0],list3);
	c = DES2Crypto(c,list2);
	out[0] = DES2Plain(c,list1)^key->iv;
	prv = in[0];

	for(i=1;i<len;i++){
		c = DES2Plain(in[i],list3);
		c = DES2Crypto(c,list2);
		out[i] = DES2Plain(c,list1)^prv;
		prv = in[i];
	}
	key->iv = prv;
}

void DES3_cbc_decrypt(Key_3DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG	 o,c,prv,*list1,*list2,*list3;
	ULONG	l,r;
	int i;

	list1=key->list1;
	list2=key->list2;
	list3=key->list3;

	C2LL(0);
	prv = o;
	o = DES2Plain(o,list3);
	o = DES2Crypto(o,list2);
	o = DES2Plain(o,list1)^key->iv;
	LL2C(0);

	for(i=8;i<byte;i+=8){
		C2LL(i);
		c = o;
		o = DES2Plain(o,list3);
		o = DES2Crypto(o,list2);
		o = DES2Plain(o,list1)^prv;
		prv = c;
		LL2C(i);
	}
	key->iv = prv;
}

#undef	C2LL
#undef	LL2C
