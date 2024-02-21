/* ssl_cs.c */
/* Cipher Spec */
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
#include <stdlib.h>
#include <string.h>

#include "ok_asn1.h"
#include "ok_ssl.h"

int set_cipher_spec(SSLCTX *ctx,int set);

/*-----------------------------------------
  SSL Change Cipher Spec
-----------------------------------------*/
int SSL_send_change_cipherspec(SSLCTX *ctx,int ch){
	unsigned char *buf;
	int	i;

	/* set change_cipherspec on wbuf, but it's not
	 * sent immediately. (not flushed)
	 */
	i   = ctx->wbuflen;
	buf = ctx->wbuf;
	/* content type (change cipher spec) */
	buf[i]= 20;
	/* protocol version */
	buf[i+1]= ctx->version.major;
	buf[i+2]= ctx->version.minor;
	/* length */
	buf[i+3]= 0; buf[i+4]= 1;
	/* set value */
	buf[i+5]= (unsigned char)ch;
	ctx->wbuflen+=6;

	if(set_cipher_spec(ctx,1)){
		ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
		return -1;
	}

	if((ctx->skey==NULL)&&(ctx->ckey==NULL))
		if(SSL_gen_writekey(ctx))
			return -1;

	return 0;
}


/* this procedure is usually called from SSL_read()
 * and automatically proceeded in SSL_read()
 */
int SSL_recv_change_cipherspec(SSLCTX *ctx,unsigned char *rbuf){

	/* check version */
	if((rbuf[1]!=3)||(rbuf[2])){
		OK_set_error(ERR_ST_BADVER,ERR_LC_SSL,ERR_PT_SSL_CS+1,NULL);
		ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
		return -1;
	}

	if(rbuf[5]==1){
		ctx->recv_cspec=1;
		if(set_cipher_spec(ctx,1)) return -1;

		if((ctx->skey==NULL)&&(ctx->ckey==NULL))
			if(SSL_gen_writekey(ctx))
				return -1;

	}else{
		ctx->recv_cspec=0;
		set_cipher_spec(ctx,0); /* clean cipher spec */
		if(ctx->skey){Key_free(ctx->skey);ctx->skey=NULL;}
		if(ctx->ckey){Key_free(ctx->ckey);ctx->ckey=NULL;}
	}
	return 0;
}


int set_cipher_spec(SSLCTX *ctx,int set){
	int ctype,calgo,cklen,halgo,hlen,ivlen;

	ctype=calgo=cklen=halgo=hlen=ivlen=0;
	if(set){
		/* change cipher spec */
		switch(ctx->shello->cipher_suites[1]){
		case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
			ctx->cspec->is_exportable = 1;
			ctype	= 1;	/* block */
			calgo	= OBJ_CRYALGO_RC2CBC;
			cklen	= 5;
			ivlen	= 8;
		case SSL_RSA_WITH_NULL_MD5:
			halgo	= OBJ_HASH_MD5;
			hlen	= 16;
			break;

		case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
			ctx->cspec->is_exportable = 1;
			cklen	= 5;
		case SSL_RSA_WITH_DES_CBC_SHA:
			calgo	= OBJ_CRYALGO_DESCBC;
			ctype	= 1;	/* block */
			cklen	= (cklen)?(cklen):(8);
			ivlen	= 8;
		case SSL_RSA_WITH_NULL_SHA:
			halgo	= OBJ_HASH_SHA1;
			hlen	= 20;
			break;
		
		case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
			ctype	= 1;	/* block */
			calgo	= OBJ_CRYALGO_3DESCBC;
			cklen	= 24;
			ivlen	= 8;
			halgo	= OBJ_HASH_SHA1;
			hlen	= 20;
			break;
		
		default:
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSL,ERR_PT_SSL_CS,NULL);
			ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
			return -1;	/* error */
		}

		ctx->cspec->bulk_cipher_algorithm = calgo;
		ctx->cspec->mac_algorithm	= halgo;
		ctx->cspec->cipher_type		= ctype;
		ctx->cspec->comp_meth		= 0;
		ctx->cspec->hash_size		= hlen;
		ctx->cspec->key_material	= cklen;
		ctx->cspec->IV_size			= ivlen;

	}else{
		memset(ctx->cspec,0,sizeof(SSLCipherSpec));
	}
	return 0;
}

void SSL_cspec_str(SSLCTX *ctx,char *buf){
	int i=ctx->shello->cipher_suites[1];
	switch(i){
	case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
		sprintf(buf,"SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 (%d)",i);
		break;
	case SSL_RSA_WITH_NULL_MD5:
		sprintf(buf,"SSL_RSA_WITH_NULL_MD5 (%d)",i);
		break;
	case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
		sprintf(buf,"SSL_RSA_EXPORT_WITH_DES40_CBC_SHA (%d)",i);
		break;
	case SSL_RSA_WITH_DES_CBC_SHA:
		sprintf(buf,"SSL_RSA_WITH_DES_CBC_SHA (%d)",i);
		break;
	case SSL_RSA_WITH_NULL_SHA:
		sprintf(buf,"SSL_RSA_WITH_NULL_SHA (%d)",i);
		break;
	case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
		sprintf(buf,"SSL_RSA_WITH_3DES_EDE_CBC_SHA (%d)",i);
		break;
	case SSL_NULL_WITH_NULL_NULL:
		sprintf(buf,"SSL_NULL_WITH_NULL_NULL (%d)",i);
		break;
	default:
		/* not supported */
		sprintf(buf,"SSL_UNKNOWN_ALGO (%d)",i);
		break;
	}
}
