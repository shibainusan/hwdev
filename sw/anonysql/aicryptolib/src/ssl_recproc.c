/* ctx_recproc.c */
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
#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_ssl.h"

#include "ok_md5.h"
#include "ok_sha1.h"
#include "ok_rc2.h"
#include "ok_des.h"

unsigned char pad_1[48]={
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
};

unsigned char pad_2[48]={
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c
};


/*-----------------------------------------
  message encode (ptxt => comp)
-----------------------------------------*/
int SSL_enc_ptxt2comp(SSLCTX *ctx){
	/* compression method is not supported */
	if(ctx->comp==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLREC,ERR_PT_SSLREC_PROC,NULL);
		return -1;
	}

	memcpy(ctx->comp->fragment,ctx->ptxt->fragment,ctx->ptxt->length);
	ctx->comp->type   = ctx->ptxt->type;
	ctx->comp->length = ctx->ptxt->length;
	return 0;
}

/*-----------------------------------------
  message encode (comp => ctxt)
-----------------------------------------*/
int SSL_enc_comp2ctxt(SSLCTX *ctx){
	unsigned char *pfg,*pad,*cry,*out,*mac;
	int i,j,k,plen,padlen;
	Key *key;

	if(ctx->cspec->comp_meth){
		pfg = ctx->comp->fragment;
		plen= ctx->comp->length;
	}else{
		pfg = ctx->ptxt->fragment;
		plen= ctx->ptxt->length;
	}
	cry = ctx->ctxt->content;
	out = ctx->ctxt->fragment;
	mac = ctx->ctxt->MAC;
	key = (ctx->serv)?(ctx->skey):(ctx->ckey);

	j = ctx->cspec->cipher_type;
	ctx->ctxt->type = ctx->ptxt->type;
	if(j){
		/* block cipher, so now we need to get random padding */
		pad = ctx->ctxt->padding;
		if(SSL_set_rand(pad,32)) return -1;
	}

	SSL_calc_mac(ctx,mac,plen,ctx->serv,1);
	for(i=7;i>=0;i--)
		if (++(ctx->wseq[i])) break;

	memcpy(cry,pfg,plen);
	memcpy(&(cry[plen]),mac,ctx->cspec->hash_size);
	plen += ctx->cspec->hash_size;

	if(j){
		/* set padding for block cipher.
		 * this padding type is *not* RFC1423 padding and
		 * padding information is added in SSL packet.
		 */
		j = plen & 0x7;	/* mod 8 (for DES,3DES,RC2) */
		padlen = (j)?(7-j):(7);
		for(k=0;k<padlen;k++)	cry[plen+k] = 0x80|pad[k];
		cry[plen+k] = (unsigned char)padlen;
		plen = plen+k+1;
	}

	ctx->ctxt->length = plen;

	/* encryption */
	switch(ctx->cspec->bulk_cipher_algorithm){
	case OBJ_CRYALGO_RC2CBC:
		RC2_cbc_encrypt((Key_RC2*)key,plen,cry,out);
		break;
	case OBJ_CRYALGO_DESCBC:
		DES_cbc_encrypt((Key_DES*)key,plen,cry,out);
		break;
	case OBJ_CRYALGO_3DESCBC:
		DES3_cbc_encrypt((Key_3DES*)key,plen,cry,out);
		break;
	default:
		ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLREC,ERR_PT_SSLREC_PROC+1,NULL);
		return -1;
	}
	return 0;
}


/*-----------------------------------------
  message encode (ctxt => buf)
-----------------------------------------*/
int SSL_set_ctxt2buf(SSLCTX *ctx,int mode){
	int plen,i,j;

	i = ctx->wbuflen;

	if(mode==SSL_HANDSHAKEv2){
		/* v2 client hello should be smaller than 256 byte */
		ctx->wbuf[i  ] = 0x80; j=2;
	}else{
		ctx->wbuf[i  ] = (unsigned char)mode;
		ctx->wbuf[i+1] = ctx->version.major;
		ctx->wbuf[i+2] = ctx->version.minor;
		j=5;
	}

	if(ctx->cspec->bulk_cipher_algorithm){
		plen = ctx->ctxt->length;
		memcpy(&(ctx->wbuf[i+j]),ctx->ctxt->fragment,plen);
	}else if(ctx->cspec->comp_meth){
		plen = ctx->comp->length;
		memcpy(&(ctx->wbuf[i+j]),ctx->comp->fragment,plen);
	}else{
		plen = ctx->ptxt->length;
		memcpy(&(ctx->wbuf[i+j]),ctx->ptxt->fragment,plen);
	}

	if(mode==SSL_HANDSHAKEv2){
		ctx->wbuf[i+1] = 0xff & plen;
	}else{
		ctx->wbuf[i+3] = 0xff &(plen>>8);
		ctx->wbuf[i+4] = 0xff & plen;
	}
	ctx->wbuflen   = i+j+plen;
	return 0;
}

/*-----------------------------------------
  message decode (comp => ptxt)
-----------------------------------------*/
int SSL_dec_comp2ptxt(SSLCTX *ctx){
	unsigned char *buf;
	int plen;
	/* data was encrypted */
	if(ctx->cspec->comp_meth){
		/* data was uncompressed */
		buf = ctx->comp->fragment;			/* data was decrypted */
		plen= ctx->comp->length;
	}else{
		/* data wasn't uncompressed */
		buf = ctx->ctxt->content;	/* data was decrypted */
		plen= ctx->ctxt->length;
	}
	ctx->ptxt->type		= ctx->ctxt->type;
	ctx->ptxt->length	= plen;
	ctx->ptxt->fragment	= ctx->rbuf;
	ctx->rpklen			= plen;
	/* compression is not supported now.
	 * so this memcpy is safety right now...
	 */
	memcpy(ctx->rbuf,buf,plen);

	return 0;
}

/*-----------------------------------------
  message decode (ctxt => comp)
-----------------------------------------*/
int SSL_dec_ctxt2comp(SSLCTX *ctx){
	unsigned char *buf;
	int plen;

	/* need to uncompress */
	if(ctx->recv_cspec)
		buf = ctx->ctxt->content;	/* data was decrypted */
	else
		buf = ctx->ctxt->fragment;			/* data wasn't decrypted */

	plen = ctx->ctxt->length;
	ctx->comp->length	= plen;
	memcpy(ctx->comp->fragment,buf,plen);

	return 0;
}

/*-----------------------------------------
  message decode (buf => ctxt)
-----------------------------------------*/
int SSL_set_buf2ctxt(SSLCTX *ctx){
	Key	*key;
	int plen;

	plen = ctx->ctxt->length;

	if(ctx->recv_cspec){

		key = (ctx->serv)?(ctx->ckey):(ctx->skey);

		switch(ctx->cspec->bulk_cipher_algorithm){
		case OBJ_CRYALGO_3DESCBC:
			DES3_cbc_decrypt((Key_3DES*)key,plen,ctx->ctxt->fragment,ctx->ctxt->content);
			break;
		case OBJ_CRYALGO_DESCBC:
			DES_cbc_decrypt((Key_DES*)key,plen,ctx->ctxt->fragment,ctx->ctxt->content);
			break;
		case OBJ_CRYALGO_RC2CBC:
			RC2_cbc_decrypt((Key_RC2*)key,plen,ctx->ctxt->fragment,ctx->ctxt->content);
			break;
		default:
			ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLREC,ERR_PT_SSLREC_PROC+4,NULL);
			return -1;
		}

	}else{
		ctx->ptxt->type		= ctx->ctxt->type;
		ctx->ptxt->length	= plen;
		ctx->ptxt->fragment	= ctx->rbuf;
		ctx->rpklen			= plen;
		memcpy(ctx->rbuf,ctx->ctxt->fragment,plen);
	}

	return 0;
}
