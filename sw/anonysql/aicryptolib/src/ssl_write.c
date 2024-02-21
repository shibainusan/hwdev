/* ssl_write.c */
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

#include "ok_ssl.h"


/*-----------------------------------------
  write message with SSL
-----------------------------------------*/
int SSL_write(SSL *ssl, void *buf, size_t nbyte){
	int slen;
	SSLCTX *ctx;

	if(nbyte<=0) return 0;
	
	if(ssl->mode){
		/* write message with SSL */
		int	i,j,k;

		if((ctx=ssl->ctx)==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_WRITE,NULL);
			return -1;
		}

		/* send message with SSL */
		if((slen=SSL_encode_packet(ssl,buf,nbyte))<0)
			goto error;

		/* keep write buffer and don't send it */
		if(ssl->opt&SSL_OPT_KEEPWBUF)
			return slen;

		/* one SSL packet must be sent */
		i=ctx->wbuflen;
		j=0;
		do{
			if(ctx->cb->write_cb){
				if((k=ctx->cb->write_cb(ssl->sock,&(ctx->wbuf[j]),i))<0){
					OK_set_error(ERR_ST_SOCKWRITE,ERR_LC_SSL,ERR_PT_SSL_WRITE,NULL);
					goto error;
				}

			}else{
#ifdef __WINDOWS__
				if((k=send(ssl->sock,&(ctx->wbuf[j]),i,0))<0){
#else
				if((k=write(ssl->sock,&(ctx->wbuf[j]),i))<0){
#endif
					OK_set_error(ERR_ST_SOCKWRITE,ERR_LC_SSL,ERR_PT_SSL_WRITE,NULL);
					goto error;
				}
			}
			i-=k;
			j+=k;
		}while(i>0);

		ctx->wbuflen = 0;

	}else{
		/* write message without SSL */
		if(ssl->ctx->cb->write_cb)
		    slen=ssl->ctx->cb->write_cb(ssl->sock,buf,nbyte);
		else
#ifdef __WINDOWS__
		    slen=send(ssl->sock,buf,nbyte,0);
#else
		    slen=write(ssl->sock,buf,nbyte);
#endif
	}
	return slen;
error:
	ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_encode_packet(SSL *ssl, void *msg, size_t len){
	unsigned char *cp;
	SSLCTX *ctx;
	int slen;

	ctx  = ssl->ctx;
	slen = (len<=SSLMAXBUF)?(len):(SSLMAXBUF);

	/* set plain text */
	/* ptxt->fragment usually have read buffer pointer.
	 * so we need to reserve it first..
	 */
	cp = ctx->ptxt->fragment;
	ctx->ptxt->type		= ssl->mode;
	ctx->ptxt->fragment = (unsigned char*)msg;
	ctx->ptxt->length   = (ULONG)slen;

	/* debug : 1st timing of write */
	if(ctx->cb->write_debug)
	    ctx->cb->write_debug(ssl,0);

	/* set compressed data */
	if(ctx->cspec->comp_meth){
		if(SSL_enc_ptxt2comp(ctx)) goto error;
	}
	/* set cipher text */
	if(ctx->cspec->bulk_cipher_algorithm){
		if(SSL_enc_comp2ctxt(ctx)) goto error;
	}
	/* set SSL header & cipher text */
	if(SSL_set_ctxt2buf(ctx,ssl->mode)) goto error;

	/* set back read buffe pointer :-) */
	ctx->ptxt->fragment = cp;

	/* debug : 2nd timing of write */
	if(ctx->cb->write_debug)
	    ctx->cb->write_debug(ssl,1);

	return slen;
error:
	return -1;
}

/*-----------------------------------------
  flush SSL write buffer.
-----------------------------------------*/
int SSL_wflush(SSL *ssl){
	int slen,j,k;
	SSLCTX *ctx;

	if(ssl->mode==0)	return 0;

	ctx = ssl->ctx;

	slen=ctx->wbuflen;
	if(slen==0) return 0;

	j=0;
	do{
		if(ctx->cb->write_cb){
		    if((k=ctx->cb->write_cb(ssl->sock,&(ctx->wbuf[j]),slen-j))<0)
				goto error;

		}else{
#ifdef __WINDOWS__
		    if((k=send(ssl->sock,&(ctx->wbuf[j]),slen-j,0))<0){
#else
		    if((k=write(ssl->sock,&(ctx->wbuf[j]),slen-j))<0){
#endif
				goto error;
			}
		}
		j+=k;

	}while(j<slen);

	ctx->wbuflen = 0;
	return j;
error:
	OK_set_error(ERR_ST_SOCKWRITE,ERR_LC_SSL,ERR_PT_SSL_WRITE+1,NULL);
	ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
	return -1;
}

/*-----------------------------------------
  flush SSL write buffer.
-----------------------------------------*/
void SSL_clear_rwbuf(SSLCTX *ctx){
	if(ctx==NULL)	return;

	ctx->wbuflen=0;
	ctx->rbuflen=0;
	ctx->rpklen =0;
}



/*
 * I think SSL don't need to support "out-of-band" data...
 * hmm, not sure...
 */
#if 0
/*-----------------------------------------
  send message with SSL
-----------------------------------------*/
int SSL_send(SSL *ssl, void *msg, size_t len, int flags){
	int slen;

	if(ssl==NULL) return -1;

	if(ssl->mode){
		int	i,j,k;
		/* send message with SSL */
		slen = SSL_packet_gen(ssl,msg,len);

		/* one SSL packet must be sent */
		i=ssl->wbuflen;
		j=0;
		do{
			if((k=send(ssl->sock,&(ssl->wbuf[j]),i,flags))<0){
				slen=k; break;}
			i-=k;
			j+=k;
		}while(i>0);

	}else{
		/* send message without SSL */
		slen=send(ssl->sock,msg,len,flags);
	}
	return(slen);
}
#endif
