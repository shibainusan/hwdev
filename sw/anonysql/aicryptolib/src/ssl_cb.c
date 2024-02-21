/* ssl_cb.c */
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

int ssl_check_sslctx(SSL *ssl);

/*-----------------------------------------
  set read callback function
-----------------------------------------*/
int SSL_set_read_cb(SSL *ssl, int (*cb)(int,char*,int)){
	if(ssl_check_sslctx(ssl)) return -1;
	ssl->ctx->cb->read_cb = cb;
	return 0;
}

/*-----------------------------------------
  set write callback function
-----------------------------------------*/
int SSL_set_write_cb(SSL *ssl, int (*cb)(int,char*,int)){
	if(ssl_check_sslctx(ssl)) return -1;
	ssl->ctx->cb->write_cb = cb;
	return 0;
}

/*-----------------------------------------
  set cert verification callback function
-----------------------------------------*/
int SSL_set_vfy_cb(SSL *ssl, int (*cb)(SSL*,Cert*)){
	if(ssl_check_sslctx(ssl)) return -1;
	ssl->ctx->cb->vfy_cb = cb;
	return 0;
}

/*-----------------------------------------
  set read debug callback function
-----------------------------------------*/
int SSL_set_readdebug_cb(SSL *ssl, int (*cb)(SSL*,int)){
	if(ssl_check_sslctx(ssl)) return -1;
	ssl->ctx->cb->read_debug = cb;
	return 0;
}

/*-----------------------------------------
  set write debug callback function
-----------------------------------------*/
int SSL_set_writedebug_cb(SSL *ssl, int (*cb)(SSL*,int)){
	if(ssl_check_sslctx(ssl)) return -1;
	ssl->ctx->cb->write_debug = cb;
	return 0;
}
