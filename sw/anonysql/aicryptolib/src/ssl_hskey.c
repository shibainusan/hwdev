/* ssl_hskey.c */
/* Handshake procedures */
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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_rc2.h"
#include "ok_des.h"
#include "ok_ssl.h"


/*-----------------------------------------
  SSL Handshake (Generate Master Secret)
-----------------------------------------*/
void SSL_gen_mastersecret(SSLCTX *ctx){
	MD5_CTX		mctx;
	SHA1_CTX	sctx;
	int	i;
	unsigned char tmp[32];
	unsigned char hstr[4][4] = {"A","BB","CCC"};

	for(i=0;i<3;i++){
		SHA1init(&sctx);
		SHA1update(&sctx,hstr[i],i+1);
		SHA1update(&sctx,ctx->premaster,48);
		SHA1update(&sctx,ctx->chello->random,32);
		SHA1update(&sctx,ctx->shello->random,32);
		SHA1final(tmp,&sctx);

		MD5Init(&mctx);
		MD5Update(&mctx,ctx->premaster,48);
		MD5Update(&mctx,tmp,20);
		MD5Final(&(ctx->master_secret[i<<4]),&mctx);	/* [i*16] */
	}
}

/*-----------------------------------------
  SSL Handshake (Generate Master Secret)
-----------------------------------------*/
int SSL_gen_writekey(SSLCTX *ctx){
	MD5_CTX		mctx;
	SHA1_CTX	sctx;
	int	i,j,k;
	unsigned char tmp[32],keyblock[160],skey[32],ckey[32],siv[32],civ[32];
	unsigned char hstr[8][8] = {"A","BB","CCC","DDDD","EEEEE","FFFFFF","GGGGGGG"};

	for(i=0;i<7;i++){
		SHA1init(&sctx);
		SHA1update(&sctx,hstr[i],i+1);
		SHA1update(&sctx,ctx->master_secret,48);
		SHA1update(&sctx,ctx->shello->random,32);
		SHA1update(&sctx,ctx->chello->random,32);
		SHA1final(tmp,&sctx);

		MD5Init(&mctx);
		MD5Update(&mctx,ctx->master_secret,48);
		MD5Update(&mctx,tmp,20);
		MD5Final(&(keyblock[i<<4]),&mctx);	/* [i*16] */
	}
	/* set write MAC */
	if(i = ctx->cspec->hash_size){
		memcpy(ctx->client_write_MAC_secret,keyblock,i);
		memcpy(ctx->server_write_MAC_secret,&(keyblock[i]),i);
		i+= i;
	}
	/* set key */
	if(j = ctx->cspec->key_material){
		memcpy(ckey,&(keyblock[i]),j);
		memcpy(skey,&(keyblock[i+j]),j);
		i+= j+j;
		if(ctx->cspec->is_exportable){
			/* export crient key */
			MD5Init(&mctx);
			MD5Update(&mctx,ckey,j);
			MD5Update(&mctx,ctx->chello->random,32);
			MD5Update(&mctx,ctx->shello->random,32);
			MD5Final(ckey,&mctx);
			/* export crient key */
			MD5Init(&mctx);
			MD5Update(&mctx,skey,j);
			MD5Update(&mctx,ctx->shello->random,32);
			MD5Update(&mctx,ctx->chello->random,32);
			MD5Final(skey,&mctx);
			j = 16;
		}
	}
	/* set iv */
	if(k = ctx->cspec->IV_size){
		if(ctx->cspec->is_exportable){
			/* export crient IV */
			MD5Init(&mctx);
			MD5Update(&mctx,ctx->chello->random,32);
			MD5Update(&mctx,ctx->shello->random,32);
			MD5Final(civ,&mctx);
			/* export server IV */
			MD5Init(&mctx);
			MD5Update(&mctx,ctx->shello->random,32);
			MD5Update(&mctx,ctx->chello->random,32);
			MD5Final(siv,&mctx);	/* [i*16] */

		}else{
			memcpy(civ,&(keyblock[i]),k);
			memcpy(siv,&(keyblock[i+k]),k);
		}
	}

	switch(ctx->cspec->bulk_cipher_algorithm){
	case OBJ_CRYALGO_3DESCBC:
		ctx->ckey = (Key*)DES3key_new_c(24,ckey);
		ctx->skey = (Key*)DES3key_new_c(24,skey);
		DES3_set_iv((Key_3DES*)ctx->ckey,civ);
		DES3_set_iv((Key_3DES*)ctx->skey,siv);
		break;
	case OBJ_CRYALGO_DESCBC:
		ctx->ckey = (Key*)DESkey_new(j,ckey);
		ctx->skey = (Key*)DESkey_new(j,skey);
		DES_set_iv((Key_DES*)ctx->ckey,civ);
		DES_set_iv((Key_DES*)ctx->skey,siv);
		break;

	case OBJ_CRYALGO_RC2CBC:
		ctx->ckey = (Key*)RC2key_new(j,ckey);
		ctx->skey = (Key*)RC2key_new(j,skey);
		RC2_set_iv((Key_RC2*)(ctx->ckey),civ);
		RC2_set_iv((Key_RC2*)(ctx->skey),siv);
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_KEY,NULL);
		ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
		return -1;
	}
	if((ctx->ckey==NULL)||(ctx->skey==NULL)){
		ctx->errnum = SSL_AD_CLOSE_NOTIFY | (SSL_AL_FATAL<<8);
		return -1;
	}

	memset(keyblock,0,160);
	memset(skey,0,32);
	memset(ckey,0,32);
	memset(siv,0,32);
	memset(civ,0,32);
	return 0;
}


/*-----------------------------------------
  SSL Handshake (Calculate Hash)
-----------------------------------------*/
void SSL_hs_hashinit(SSLCTX *ctx){
	MD5Init(ctx->hsmsg_md5);
	SHA1init(ctx->hsmsg_sha1);
}

void SSL_hs_hashupdate(SSLCTX *ctx,unsigned char *in,int len){
	if(len<0) return;
	MD5Update(ctx->hsmsg_md5,in,len);
	SHA1update(ctx->hsmsg_sha1,in,len);
}

void SSL_hs_hashfinal(SSLCTX *ctx,unsigned char *md5,unsigned char *sha1){
	MD5Final(md5,ctx->hsmsg_md5);
	SHA1final(sha1,ctx->hsmsg_sha1);
}

