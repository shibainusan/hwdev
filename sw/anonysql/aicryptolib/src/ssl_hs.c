/* ssl_hs.c */
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

#include "ok_ssl.h"

/*-----------------------------------------
  do SSL Handshake now!
-----------------------------------------*/
int SSL_handshake(SSL *ssl){
	int i;
	/* do handshake */
	if(ssl_check_sslctx(ssl)) return -1;

	if(ssl->opt&SSL_SYS_SERVER){
		ssl->ctx->state = SSL_HT_WAIT_CLIENT_HELLO;
		if(i=SSL_sv_handshake(ssl))
			return i;
	}else{
		if(ssl->ctx->state!=SSL_HT_NULL)
			ssl->ctx->state = SSL_HT_CLIENT_HELLO;
		if(i=SSL_cl_handshake(ssl))
			return i;
	}
	return 0;	/* no error */
}

/*-----------------------------------------
  SSL Handshake at server
-----------------------------------------*/
int SSL_sv_handshake(SSL *ssl){
	SSLCTX *ctx;

	ctx = ssl->ctx;
	ssl->opt |= SSL_SYS_SERVER;	/* set server flag */

	for(;;){
		switch(ctx->state){
		case SSL_HT_HELLO_REQUEST:
			ssl->mode = SSL_HANDSHAKE;
			if(SSL_send_helloreq(ssl))
				goto hserror;
			ctx->state = SSL_HT_WAIT_CLIENT_HELLO;
			/* break; */

		case SSL_HT_WAIT_CLIENT_HELLO:
			/* wait for client_hello */
			ssl->mode = SSL_HANDSHAKE;
			if(SSL_recv_client_hello(ssl))
				goto hserror;

			ctx->state = SSL_HT_SERVER_HELLO;
			/* break; */

		case SSL_HT_SERVER_HELLO:
			/* hmmm, Netscape example says server_hello, certificate, and
			 * server_hello_done is sent by one handshake packet.
			 * but, I sent one handshake packet with one SSL packet same
			 * as OpenSSL */
			if(SSL_send_serv_hello(ssl))
				goto hserror;

			if(ssl->opt&SSL_SYS_RECONNECTION)
				ctx->state = SSL_HT_FINISHED;
			else
				ctx->state = SSL_HT_CERTIFICATE;
			break;

		case SSL_HT_CERTIFICATE:
			if(ctx->sp12){
				if(SSL_send_serv_cert(ssl))
					goto hserror;

				ctx->state = (ssl->opt&SSL_OPT_CERTREQ)?
								(SSL_HT_CERTIFICATE_REQUEST):(SSL_HT_SERVER_HELLO_DONE);
			}else
				ctx->state = SSL_HT_SERVER_KEY_EXCHANGE;
			break;

		case SSL_HT_SERVER_KEY_EXCHANGE:
			if(SSL_send_serv_keyexchange(ssl))
				goto hserror;

			/* this anonymous server can't send certificate request! */
			ctx->state = SSL_HT_SERVER_HELLO_DONE;
			break;

		case SSL_HT_CERTIFICATE_REQUEST:
			if(SSL_send_certreq(ssl))
				goto hserror;
			ctx->state = SSL_HT_SERVER_HELLO_DONE;
			/* break; */

		case SSL_HT_SERVER_HELLO_DONE:
			if(SSL_send_serv_hellodone(ssl))
				goto hserror;
			ctx->state = SSL_HT_WAIT_CLIENT_ANSWER;
			/* break; */

		case SSL_HT_WAIT_CLIENT_ANSWER:
			/* wait for client answers */
			/* certificate -- if no certificate, just ignore or send aleart. */
			if(SSL_recv_client_cert(ssl))
				goto hserror;

			/* client key exchange */
			if(SSL_recv_clikeyexchange(ssl))
				goto hserror;

			/* certificate verify */
			if(SSL_recv_client_certvfy(ssl))
				goto hserror;

			ctx->state = SSL_HT_WAIT_CLIENT_FINISH;
			break;

		case SSL_HT_WAIT_CLIENT_FINISH:
			/* get ChangeCipherSpec -- this one is automatically done with
			 * SSL_recv_finished() ( actually, it's done in SSL_read(). )
			 */
			/* client finished */
			if(SSL_recv_finished(ssl))
				goto hserror;

			if(ssl->opt&SSL_SYS_RECONNECTION){
				ctx->state = SSL_HT_NULL;
				return 0;
			}else
				ctx->state = SSL_HT_FINISHED;
			break;

		case SSL_HT_FINISHED:
			SSL_send_change_cipherspec(ctx,1);

			if(SSL_send_finished(ssl))
				goto hserror;

			ssl->mode  = SSL_APPLICATION_DATA;
			if(ssl->opt&SSL_SYS_RECONNECTION)
				ctx->state = SSL_HT_WAIT_CLIENT_FINISH;
			else{
				ctx->state = SSL_HT_NULL;
				return 0;
			}
			break;

		case SSL_HT_NULL:
			/* handshake has finished already. this one should not happen */
		default:
			OK_set_error(ERR_ST_BADSTATE,ERR_LC_SSLHS,ERR_PT_SSLHS,NULL);
			ctx->errnum=SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
			goto hserror;
		}
	}

hserror:
	/* send alert */
	SSL_send_alert(ssl,(ctx->errnum>>8),ctx->errnum&0xff);

	/* return */
	return ctx->errnum;
}

/*-----------------------------------------
  SSL Handshake at client
-----------------------------------------*/
int SSL_cl_handshake(SSL *ssl){
	SSLCTX *ctx;

	ctx = ssl->ctx;
	ssl->opt &= 0x7fff;	/* clear server flag */

	for(;;){
		switch(ctx->state){
		case SSL_HT_NULL:
			/* handshake has finished already. So this will happen with
			 * SSL re-connection mode.
			 */
		case SSL_HT_CLIENT_HELLO:
			/* set client_hello and send it */
			if(SSL_send_client_hello(ssl))
				goto hserror;

			ctx->state = SSL_HT_WAIT_SERVER_HELLO;
			/* break; */

		case SSL_HT_WAIT_SERVER_HELLO:
			if(SSL_recv_serv_hello(ssl))
				goto hserror;

			if(ssl->opt&SSL_SYS_RECONNECTION){
				ctx->state = SSL_HT_WAIT_SERVER_FINISH;
				break;}

			if(SSL_recv_serv_certificate(ssl))
				goto hserror;

			if(SSL_recv_serv_keyexchange(ssl))
				goto hserror;

			if(SSL_recv_serv_certreq(ssl))
				goto hserror;

			if(SSL_recv_serv_hellodone(ssl))
				goto hserror;

			if(ssl->opt&SSL_SYS_GOT_CERTREQ)
				ctx->state = SSL_HT_CERTIFICATE;
			else
				ctx->state = SSL_HT_CLIENT_KEY_EXCHANGE;
			break;

		case SSL_HT_CERTIFICATE:
			if(SSL_send_client_cert(ssl))
				goto hserror;

			ctx->state = SSL_HT_CLIENT_KEY_EXCHANGE;
			/* break; */

		case SSL_HT_CLIENT_KEY_EXCHANGE:
			if(SSL_send_client_keyexchange(ssl))
				goto hserror;

			if(ssl->opt&SSL_SYS_GOT_CERTREQ)
				ctx->state = SSL_HT_CERTIFICATE_VERIFY;
			else
				ctx->state = SSL_HT_FINISHED;
			break;

		case SSL_HT_CERTIFICATE_VERIFY:
			if(SSL_send_client_certvfy(ssl))
				goto hserror;

			ctx->state = SSL_HT_FINISHED;
			/* break; */

		case SSL_HT_FINISHED:
			SSL_send_change_cipherspec(ctx,1);

			if(SSL_send_finished(ssl))
				goto hserror;

			ssl->mode  = SSL_APPLICATION_DATA;
			if(ssl->opt&SSL_SYS_RECONNECTION){
				ctx->state = SSL_HT_NULL;
				return 0;
			}else
				ctx->state = SSL_HT_WAIT_SERVER_FINISH;
			/* break; */

		case SSL_HT_WAIT_SERVER_FINISH:
			/* wait for server finished */
			if(SSL_recv_finished(ssl))
				goto hserror;

			if(ssl->opt&SSL_SYS_RECONNECTION){
				ctx->state = SSL_HT_FINISHED;
				break;
			}else{
				ctx->state = SSL_HT_NULL;
				return 0;
			}
		default:
			OK_set_error(ERR_ST_BADSTATE,ERR_LC_SSLHS,ERR_PT_SSLHS+1,NULL);
			ctx->errnum=SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
			goto hserror;
		}
	}
  
hserror:
	/* send alert */
	SSL_send_alert(ssl,(ctx->errnum>>8),ctx->errnum&0xff);

	return ctx->errnum;
}

