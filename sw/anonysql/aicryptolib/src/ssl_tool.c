/* ok_ssl.h */
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
#include "ok_x509.h"
#include "ok_tool.h"

/* alloc check of SSLCTX */
int ssl_check_sslctx(SSL *ssl){
    if(ssl==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_TOOL,NULL);
		return -1;
	}
    if(ssl->ctx==NULL)
        if(SSL_alloc_contexts(ssl))
            return -1;
    return 0;
}

/*-----------------------------------------
  SSL set server certificate & key
-----------------------------------------*/
int SSL_set_server_p12(SSL *ssl,char *fname,char *passwd){

	if(ssl_check_sslctx(ssl)) goto error;

	OK_set_passwd(passwd);
	if((ssl->ctx->sp12=P12_read_file(fname))==NULL) goto error;

	OK_clear_passwd();

	ssl->opt |= SSL_SYS_SERVER;     /* set server flag */
	if(P12_check_chain(ssl->ctx->sp12,0)) goto error;
	return 0;

error:
	return -1;
}

/*-----------------------------------------
  SSL set client certificate & key
-----------------------------------------*/
int SSL_set_client_p12(SSL *ssl,char *fname,char *passwd){

	if(ssl_check_sslctx(ssl)) goto error;

	OK_set_passwd(passwd);
	if((ssl->ctx->cp12=P12_read_file(fname))==NULL) goto error;

	OK_clear_passwd();

	if(P12_check_chain(ssl->ctx->cp12,0)) goto error;
	return 0;
error:
	return -1;
}

/*-----------------------------------------
  SSL get certificate
-----------------------------------------*/
Cert *SSL_get_scert(SSLCTX *ctx){
	Cert *ret=NULL;
	if(ctx==NULL) return NULL;
	if(ctx->sp12) ret=P12_get_usercert(ctx->sp12);
	return ret;
}

Cert *SSL_get_ccert(SSLCTX *ctx){
	Cert *ret=NULL;
	if(ctx==NULL) return NULL;
	if(ctx->cp12) ret=P12_get_usercert(ctx->cp12);
	return ret;
}

Cert *SSL_get_peer_cert(SSLCTX *ctx){
	Cert *ret=NULL;
	if(ctx==NULL) return NULL;
	if(ctx->serv){
	    if(ctx->cp12) ret=P12_get_usercert(ctx->cp12);
	}else{
	    if(ctx->sp12) ret=P12_get_usercert(ctx->sp12);
	}
	return ret;
}
