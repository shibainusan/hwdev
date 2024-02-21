/* rc2mode.c */
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

#include "ok_rc2.h"

extern void RC2_encrypt(unsigned short *in,unsigned short *ret,unsigned short *S);
extern void RC2_decrypt(unsigned short *in,unsigned short *ret,unsigned short *S);

/*---------------------------------
    ECB-mode RC2 encryptograph
---------------------------------*/
void RC2_ecb_encrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret){
	unsigned short *S,w[4];
	int	i,j,m;

	S = key->S;
	m = len % 4;

	if(m) len -=4;

	for(i=0;i<len;i+=4)
		RC2_encrypt(&in[i],&ret[i],S);

	if(m){
		memset(w,0,sizeof(short)*4);
		for(j=0;j<m;j++)
			w[j] = in[i+j];
		RC2_encrypt(w,&ret[i],S);
	}
}

/*---------------------------------
    ECB-mode RC2 encryptograph
---------------------------------*/
void RC2_ecb_decrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret){
	unsigned short *S,w[4];
	int i,j,m;

	S = key->S;
	m = len % 4;

	if(m) len -=4;

	for(i=0;i<len;i+=4)
		RC2_decrypt(&in[i],&ret[i],S);

	if(m){
		memset(w,0,sizeof(short)*4);
		for(j=0;j<m;j++)
			w[j] = in[i+j];
		RC2_decrypt(w,&ret[i],S);
	}
}

/*---------------------------------
    ECB-mode RC2 encryptograph
---------------------------------*/
void RC2_ecb_encrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret){
	unsigned short w[4],wr[4];
	int i,j,k;

	for(i=0;i<byte;i+=8){
		for(j=0;j<4;j++){
			k = i+j*2;
			w[j] = (in[k])|(in[k+1]<<8);
		}
    
		RC2_encrypt(w,wr,key->S);

		for(j=0;j<4;j++){
			k = i+j*2;
			ret[k  ] = (unsigned char)(wr[j]);
			ret[k+1] = (unsigned char)(wr[j]>>8);
		}
	}
}

/*---------------------------------
    ECB-mode RC2 encryptograph
---------------------------------*/
void RC2_ecb_decrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret){
	unsigned short w[4],wr[4];
	int i,j,k;

	for(i=0;i<byte;i+=8){
		for(j=0;j<4;j++){
			k = i+j*2;
			w[j] = (in[k])|(in[k+1]<<8);
		}

		RC2_decrypt(w,wr,key->S);

	    for(j=0;j<4;j++){
			k = i+j*2;
			ret[k  ] = (unsigned char)(wr[j]);
			ret[k+1] = (unsigned char)(wr[j]>>8);
	    }
	}
}

/*---------------------------------
    CBC-mode RC2 encryptograph
---------------------------------*/
void RC2_cbc_encrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret){
	unsigned short *S,*c,*i2,w[4];
	int i,j;

	S = key->S;
	for(j=0;j<4;j++) w[j]=in[j]^(key->iv[j]);
	c= ret;
	RC2_encrypt(w,ret,S);

	for(i=4;i<len;i+=4){
		i2= &in[i];
		for(j=0;j<4;j++) w[j]=i2[j]^c[j];
		c=  &ret[i];
		RC2_encrypt(w,c,S);
	}
	for(j=0;j<4;j++) key->iv[j]=c[j];	/* set new iv */
}

/*---------------------------------
    CBC-mode RC2 encryptograph
---------------------------------*/
void RC2_cbc_decrypt_s(Key_RC2 *key,int len,unsigned short *in,unsigned short *ret){
	unsigned short *S,*c,*i2,*r2,w[4];
	int   i,j;

	S = key->S;
	RC2_decrypt(in,w,S);
	for(j=0;j<4;j++) ret[j]=w[j]^(key->iv[j]);
	c=in;

	for(i=4;i<len;i+=4){
		i2= &in[i];
		RC2_decrypt(i2,w,S);
		r2= &ret[i];
		for(j=0;j<4;j++) r2[j]=w[j]^c[j];
		c=  i2;
	}
	for(j=0;j<4;j++) key->iv[j]=c[j];	/* set new iv */
}

/*---------------------------------
    CBC-mode RC2 encryptograph
---------------------------------*/
void RC2_cbc_encrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret){
	unsigned short *S,w[4],win[4],tr[4];
	int   i,j,k;

	S = key->S;
	for(j=0;j<4;j++){  
		k = j*2;
		win[j] = (in[k])|(in[k+1]<<8);	/* little endian */
		w[j]=win[j]^(key->iv[j]);
	}

	RC2_encrypt(w,tr,S);
	for(j=0;j<4;j++){
		k = j*2;
		ret[k  ] = (unsigned char)(tr[j]);
		ret[k+1] = (unsigned char)(tr[j]>>8);
	}

	for(i=8;i<byte;i+=8){
		for(j=0;j<4;j++){
			k = i+j*2;
			win[j] = (in[k])|(in[k+1]<<8);	/* little endian */
			w[j]=win[j]^tr[j];
		}
		RC2_encrypt(w,tr,S);
		for(j=0;j<4;j++){
			k = i+j*2;
			ret[k  ] = (unsigned char)(tr[j]);
			ret[k+1] = (unsigned char)(tr[j]>>8);
		}
	}
	for(j=0;j<4;j++) key->iv[j]=tr[j];	/* set new iv */
}

/*---------------------------------
    CBC-mode RC2 encryptograph
---------------------------------*/
void RC2_cbc_decrypt(Key_RC2 *key,int byte,unsigned char *in,unsigned char *ret){
	unsigned short *S,w[4],win[4],tr[4],iv[4];
	int   i,j,k;

	S = key->S;
	for(j=0;j<4;j++){
		k = j*2;
		win[j] = (in[k])|(in[k+1]<<8);
		iv[j]  = win[j];
	}
	RC2_decrypt(win,w,S);
	for(j=0;j<4;j++){
		k = j*2;
		tr[j]=w[j]^(key->iv[j]);
		ret[k  ] = (unsigned char)(tr[j]);
		ret[k+1] = (unsigned char)(tr[j]>>8);
	}

	for(i=8;i<byte;i+=8){
		for(j=0;j<4;j++){
			k = i+j*2;
			win[j] = (in[k])|(in[k+1]<<8);
		}
		RC2_decrypt(win,w,S);
		for(j=0;j<4;j++){
			k = i+j*2;
			tr[j]=w[j]^iv[j];
			ret[k  ] = (unsigned char)(tr[j]);
			ret[k+1] = (unsigned char)(tr[j]>>8);
			iv[j]=win[j];
		}
	}
	for(j=0;j<4;j++) key->iv[j]=iv[j];	/* set new iv */
}
