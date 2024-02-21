/* ssl_read.c */
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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/types.h>
#ifdef __WINDOWS__
#undef ULONG
#include <winsock2.h>
#include <io.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "ok_asn1.h"
#include "ok_ssl.h"

#define SSL_TRY_READ_ITER	20

extern unsigned char pad_1[48];
extern unsigned char pad_2[48];

int check_mac(SSLCTX *ctx, int ml);
int ssl_read_n(SSL *ssl, unsigned char *buf, int len);

/*-----------------------------------------
  read message with SSL
-----------------------------------------*/
int ssl_read_n(SSL *ssl, unsigned char *buf, int len){
	int i,j,ct;

	j=ct=0;
	while((j<len)&&(ct<SSL_TRY_READ_ITER)){
		if(ssl->ctx->cb->read_cb){
			if((i=ssl->ctx->cb->read_cb(ssl->sock,&buf[j],len-j))<0)
				goto error;

		}else{
#ifdef __WINDOWS__
			if((i=recv(ssl->sock,&buf[j],len-j,0))<0){
#else
			if((i=read(ssl->sock,&buf[j],len-j))<0){
#endif
				goto error;
			}
		}

		j+=i;
		ct++;
	}
	return j;
error:
	OK_set_error(ERR_ST_SOCKREAD,ERR_LC_SSL,ERR_PT_SSL_READ,NULL);
	ssl->ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_read(SSL *ssl, void *buf, size_t nbyte){
	int i,j,ml,slen;
	SSLCTX *ctx;

	if(ssl->mode){

		if((ctx=ssl->ctx)==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_READ+1,NULL);
			return -1;
		}

		/* receive message with SSL */
		if(ctx->rpklen>0){
			/* debug : 2nd timing of read */
			if(ctx->cb->read_debug)
			    ctx->cb->read_debug(ssl,1);

			/* still, read buffer (one packet) is not empty */
			if((slen=SSL_packet_read(ctx,buf,nbyte))<0)
				goto error;

		}else{
read_again1:
			ctx->rbuflen=0;

			/* read enough packet to get header */
			/* sometimes, time out might be occured...
			 * and that time just return actual gotten packet
			 */
			if((i=ssl_read_n(ssl,ctx->rbuf,5))<0) goto error;

			if(i<5){
			    ctx->rpklen = i;
			    ctx->ptxt->fragment = ctx->rbuf;
			    return SSL_packet_read(ctx,buf,nbyte);
			}

			/* ok, now we get SSL packet header and more :-)
			 * so what we will do is analizing packet and getting content length
			 *
			 * if no SSL header or fatal alert is coming, this procedure
			 * returns -1. process should be shutdown.
			 * if 0 is returned, packet is ChangeCipherSpec or warning alert !!
			 * else, content length would be returned.
			 */
			if((ml=SSL_analize_header(ctx,ctx->rbuf,&j))<0) goto error;

			if(ml==0)	/* last packet was change-cscpec or alert */
			    goto read_again1;

			ctx->ctxt->length = ml;
			ctx->rbuflen = ml+j;

			/* debug : 1st timing of read */
			if(ctx->cb->read_debug)
			    ctx->cb->read_debug(ssl,0);

			/* set content */
			memcpy(ctx->ctxt->fragment,&(ctx->rbuf[j]),ctx->ctxt->length);

			if(SSL_decode_packet(ctx)) goto error;

			if(check_mac(ctx,ml)) goto error;

			/* debug : 2nd timing of read */
			if(ctx->cb->read_debug)
			    ctx->cb->read_debug(ssl,1);

			/* it's ready to read !! */
			if((slen=SSL_packet_read(ctx,buf,nbyte))<0) goto error;

		}
	}else{
		/* receive message without SSL */
		if(ssl->ctx->cb->read_cb){
			slen=ssl->ctx->cb->read_cb(ssl->sock,buf,nbyte);
	    }else{
#ifdef __WINDOWS__
			slen=recv(ssl->sock,buf,nbyte,0);
#else
			slen=read(ssl->sock,buf,nbyte);
#endif
		}
	}
	return slen;
error:
	return -1;
}

int SSL_packet_read(SSLCTX *ctx, void *buf, size_t nbyte){
	int	len;

	len = ((unsigned)ctx->rpklen <= nbyte)?(ctx->rpklen):(nbyte);

	/* ptxt->fragment points out on the ctx->rbuf buffer */
	memcpy((char*)buf,ctx->ptxt->fragment,len);

	ctx->rpklen -= len;
	ctx->ptxt->fragment += len;

	return len;
}

/* return packet length or error -1 or read_again 0 */
int SSL_analize_header(SSLCTX *ctx,unsigned char *rbuf,int *hd_len){
	int	len,i;

	switch(rbuf[0]){
	/* caution! version2 recode doesn't have any specific information
	 * as SSLv2. it means that header has just lengh of content... >:(
	 * so, this "0x80" is dummy for v2 handshake.
	 */
	case 0x80:	/* v2 handshake (client hello) */
		len     = rbuf[1];
		*hd_len = 2;
		ctx->ctxt->type = SSL_HANDSHAKEv2;

		if(ssl_read_n(ctx->ssl,&(rbuf[5]),len-3)<0) goto error;

		break;

	case SSL_CHANGE_CIPHER_SPEC:	/* change cipher spec */
	case SSL_ALERT:			/* alert */
	case SSL_HANDSHAKE:		/* handshake */
	case SSL_APPLICATION_DATA:	/* application_data */
		/* check version */
		if((rbuf[1]!=0x3)||(rbuf[2])){
			OK_set_error(ERR_ST_BADVER,ERR_LC_SSL,ERR_PT_SSL_READ+2,NULL);
			ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
			goto error;
		}

		ctx->ctxt->type = rbuf[0];

		len     = (rbuf[3]<<8)|(rbuf[4]);
		*hd_len = 5;

		if(ssl_read_n(ctx->ssl,&(rbuf[5]),len)<0) goto error;

		if(rbuf[0]==SSL_ALERT){
			if((len = SSL_recv_alert(ctx,rbuf,&i))<0) goto error;

			*hd_len = 5+i;	/* header..5, content..? */

		}else if(rbuf[0]==SSL_CHANGE_CIPHER_SPEC){
			if(SSL_recv_change_cipherspec(ctx,rbuf)) goto error;

			*hd_len = 5+len;	/* header..5, content..1(?) */
			len = 0;
		}
		break;

	default:	/* not SSL header !! fatal error !! */
		OK_set_error(ERR_ST_SSL_BADHEADER,ERR_LC_SSL,ERR_PT_SSL_READ+2,NULL);
		ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
		goto error;
	}
	return len;
error:
	return -1;
}

/* decode packet */
int SSL_decode_packet(SSLCTX *ctx){
	int err=-1;

	if(SSL_set_buf2ctxt(ctx)) goto done;

	if(ctx->cspec->comp_meth)
		if(SSL_dec_ctxt2comp(ctx)) goto done;

	if(ctx->recv_cspec)
		if(SSL_dec_comp2ptxt(ctx)) goto done;

	err=0;
done:
	return err;
}

/* check mac error */
int check_mac(SSLCTX *ctx, int ml){
	unsigned char *buf,*mac,cmac[32];
	int plen,i;

	if(ctx->recv_cspec){
		buf = ctx->ptxt->fragment;
		plen= buf[ml-1] & 0x7;	/* get padding length (must less than 8) */
		mac = &buf[ml-1-plen-ctx->cspec->hash_size];

		ml -= (plen+1+ctx->cspec->hash_size);
		ctx->rpklen = ml;		/* now get real content length */

		if(SSL_calc_mac(ctx,cmac,ml,ctx->serv^1,0)) return -1;

		for(i=7;i>=0;i--)
			if (++(ctx->rseq[i])) break;

		if(memcmp(mac,cmac,ctx->cspec->hash_size)){
			ctx->errnum = SSL_AD_BAD_RECORD_MAC | (SSL_AL_FATAL<<8);
			OK_set_error(ERR_ST_SSL_BAD_RECORD_MAC,ERR_LC_SSL,ERR_PT_SSL_READ+3,NULL);
			return -1;
		}
	}
	return 0;
}

int SSL_calc_mac(SSLCTX *ctx, unsigned char *cmac,int len,int sv,int wt){
	unsigned char type,*frg,*wsec,*seq,tmp[32];

	frg  = (ctx->cspec->comp_meth)?(ctx->comp->fragment):(ctx->ptxt->fragment);
	wsec = (sv)?(ctx->server_write_MAC_secret):(ctx->client_write_MAC_secret);
	seq  = (wt)?(ctx->wseq):(ctx->rseq);
	type = (unsigned char)(ctx->ptxt->type);
	tmp[0] = (unsigned char)(len >> 8);
	tmp[1] = (unsigned char)(0xff & len);

	switch(ctx->cspec->mac_algorithm){
	case OBJ_HASH_SHA1:
		{
			SHA1_CTX ctx;

			SHA1init(&ctx);
			SHA1update(&ctx,wsec,20);
			SHA1update(&ctx,pad_1,40);
			SHA1update(&ctx,seq,8);
			SHA1update(&ctx,&type,1);
			SHA1update(&ctx,tmp,2);
			SHA1update(&ctx,frg,len);
			SHA1final(tmp,&ctx);

			SHA1init(&ctx);
			SHA1update(&ctx,wsec,20);
			SHA1update(&ctx,pad_2,40);
			SHA1update(&ctx,tmp,20);
			SHA1final(cmac,&ctx);
			break;
		}
	case OBJ_HASH_MD5:
		{
			MD5_CTX ctx;

			MD5Init(&ctx);
			MD5Update(&ctx,wsec,16);
			MD5Update(&ctx,pad_1,48);
			MD5Update(&ctx,seq,8);
			MD5Update(&ctx,&type,1);
			MD5Update(&ctx,tmp,2);
			MD5Update(&ctx,frg,len);
			MD5Final(tmp,&ctx);

			MD5Init(&ctx);
			MD5Update(&ctx,wsec,16);
			MD5Update(&ctx,pad_2,48);
			MD5Update(&ctx,tmp,16);
			MD5Final(cmac,&ctx);
			break;
		}
	default:
		ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSL,ERR_PT_SSL_READ+4,NULL);
		return -1;
	}
	return 0;
}



/*
 * I think SSL don't need to support "out-of-band" data...
 * hmm, not sure...
 */
#if 0
/*-----------------------------------------
  receive message with SSL
-----------------------------------------*/
int SSL_recv(SSL *ssl, void *msg, size_t len, int flags){
	int i;

	if(ssl==NULL) return -1;

	if(ssl->mode){
		/* receive message with SSL */
	}else{
		/* receive message without SSL */
		i=recv(ssl->sock,msg,len,flags);
	}
	return(i);
}
#endif
