/* ssl_vfy.c */
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
  do SSL verification !
  output : 0 .. no error;
         : others .. error number
-----------------------------------------*/
int SSL_cert_verify(SSL *ssl,Cert *ct){
	SSLCTX *ctx;
	int ret=0;

	if((ctx=ssl->ctx)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_VFY,NULL);
		return -1;
	}
	/* depth is 8.
	 * so probably, we need to use rootCA certs for its verify.
	 */
	if(ctx->cb->vfy_cb){
		ret = ctx->cb->vfy_cb(ssl,ct);
    }else if(ctx->stm){
		ret = STM_verify_cert(ctx->stm,ct,ctx->vfy_type);
	}

	return ret;
}

/*-----------------------------------------
  set verification type
-----------------------------------------*/
int SSL_set_vfytype(SSL *ssl, int type){
    if(ssl_check_sslctx(ssl)) return -1;
    ssl->ctx->vfy_type = type;
	return 0;
}

/*-----------------------------------------
  set verification type
-----------------------------------------*/
int SSL_set_vfydepth(SSL *ssl, int depth){
    if(ssl_check_sslctx(ssl)) return -1;
    ssl->ctx->vfy_depth = depth;
	return 0;
}

/*-----------------------------------------
  set certificate list path
-----------------------------------------*/
int SSL_set_store(SSL *ssl,char *path){
	SSLCTX *ctx;
	char buf[128];

	if(ssl_check_sslctx(ssl)) return -1;
	ctx=ssl->ctx;

	if(path==NULL){
		path = buf;
#ifdef __WINDOWS__
		SNPRINTF (path,62,".\\certs");
#else
		SNPRINTF (path,62,"%s/certs",PREFIX);
#endif
	}

	if((ctx->stm = STM_open(path))==NULL) return -1;

	return 0;
}
