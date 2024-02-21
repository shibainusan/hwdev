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
	ECB-mode DES encryptograph
---------------------------------*/
void DES_ecb_encrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	*list;
	int i;

	list=key->list;
	for(i=0;i<len;i++)
		out[i] = DES2Crypto(in[i],list);
}

void DES_ecb_encrypt(Key_DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG	*list,o;
	ULONG r,l;
	int i;

	list=key->list;
	for(i=0;i<byte;i+=8){
		C2LL(i);
		o = DES2Crypto(o,list);
		LL2C(i);
	}
}

/*---------------------------------
	ECB-mode DES decryptograph
---------------------------------*/
void DES_ecb_decrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	*list;
	int i;

	list=key->list;
	for(i=0;i<len;i++)
		out[i] = DES2Plain(in[i],list);
}

void DES_ecb_decrypt(Key_DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG	*list,o;
	ULONG r,l;
	int i;

	list=key->list;
	for(i=0;i<byte;i+=8){
		C2LL(i);
		o = DES2Plain(o,list);
		LL2C(i);
	}
}

/*---------------------------------
	CBC-mode DES encryptograph
---------------------------------*/
void DES_cbc_encrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG	prv,*list;
	int i;

	list=key->list;
	prv = out[0] = DES2Crypto((in[0]^key->iv),list);
	for(i=1;i<len;i++){
		prv = out[i] = DES2Crypto((in[i]^prv),list);
	}
	key->iv = prv;
}

void DES_cbc_encrypt(Key_DES *key,int byte,unsigned char *in,unsigned char *out){
	ULLONG prv,*list,o;
	ULONG r,l;
	int i;

	list=key->list;
	C2LL(0);
	prv = o = DES2Crypto((o^key->iv),list);
	LL2C(0);
	for(i=8;i<byte;i+=8){
		C2LL(i);
		prv = o = DES2Crypto((o^prv),list);
		LL2C(i);
	}
	key->iv = prv;
}

/*---------------------------------
	CBC-mode DES decryptograph
---------------------------------*/
void DES_cbc_decrypt_ll(Key_DES *key,int len,ULLONG *in,ULLONG *out){
	ULLONG prv,*list;
	int i;

	list=key->list;
	out[0] = DES2Plain(in[0],list)^key->iv;
	prv = in[0];
	for(i=1;i<len;i++){
		out[i] = DES2Plain(in[i],list)^prv;
		prv = in[i];
	}
	key->iv = prv;
}

void DES_cbc_decrypt(Key_DES *key,int byte,unsigned char *in, unsigned char *out){
	ULLONG prv,o,n,*list;
	ULONG r,l;
	int i;

	list=key->list;
	C2LL(0);
	prv = o;
	o = DES2Plain(o,list)^key->iv;
	LL2C(0);
	for(i=8;i<byte;i+=8){
		C2LL(i);
		n = o;
		o = DES2Plain(o,list)^prv;
		prv = n;
		LL2C(i)
	}
	key->iv = prv;
}


/*---------------------------------
	CFB-mode DES encryptograph
	(k must be 1,2,4,8,16,32,64)
---------------------------------*/
void DES_cfb_encrypt_ll(Key_DES *key, int k, int len, ULLONG *in ,ULLONG *out){
	ULLONG	 l,c,r,inb,outb,mask,*list;
	int		i,j,k2,n;

	list=key->list;
	l = key->iv;
	k2 = 64 -k;
#ifdef __WINDOWS__
	mask = 0xffffffffffffffff >> k2;
#else
	mask = 0xffffffffffffffffLL >> k2;
#endif

	for(i=n=0;i<len;i++){
	  for(outb=0,j=k2;j>=0;j-=k){
		inb = (in[i]>>j) & mask;

		r = (DES2Crypto(l,list) >> k2) & mask;
		c = inb^r;
		l = (l<<k) | c;

		outb |= c << j;
	  }
	  out[i] = outb;
	}
}

/*---------------------------------
	CFB-mode DES decryptograph
	(k must be 1,2,4,8,16,32,64)
---------------------------------*/
void DES_cfb_decrypt_ll(Key_DES *key, int k, int len, ULLONG *in ,ULLONG *out){
	ULLONG	 l,c,r,inb,outb,mask,*list;
	int		 i,j,k2,n;

	list=key->list;
	l = key->iv;
	k2 = 64 -k;
#ifdef __WINDOWS__
	mask = 0xffffffffffffffff >> k2;
#else
	mask = 0xffffffffffffffffLL >> k2;
#endif
	for(i=n=0;i<len;i++){
	  for(outb=0,j=k2;j>=0;j-=k){
		inb = (in[i]>>j) & mask;

		r = (DES2Crypto(l,list) >> k2) & mask;
		c = inb^r;
		l = (l<<k) | inb;

		outb |= c << j;
	  }
	  out[i] = outb;
	}
}

#undef	C2LL
#undef	LL2C
