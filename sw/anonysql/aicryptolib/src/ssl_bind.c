/* ssl_bind.c */
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
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/types.h>
#ifdef __WINDOWS__
#undef ULONG
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "ok_ssl.h"

/*-----------------------------------------
  bind socket with SSL
-----------------------------------------*/
int SSL_bind(SSL *ssl, const struct sockaddr *name, int namelen){
	int i;
	if(ssl==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_BIND,NULL);
		return -1;
	}
	if(i=bind(ssl->sock,name,namelen)){
		OK_set_error(ERR_ST_SOCKBIND,ERR_LC_SSL,ERR_PT_SSL_BIND,NULL);
	}
	return i;
}

/*-----------------------------------------
  listen SSL connection
-----------------------------------------*/
int SSL_listen(SSL *ssl, int backlog){
	int i;
	if(ssl==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_BIND+1,NULL);
		return -1;
	}
	if(i=listen(ssl->sock,backlog)){
		OK_set_error(ERR_ST_SOCKLISTEN,ERR_LC_SSL,ERR_PT_SSL_BIND+1,NULL);
	}
	return i;
}


/*-----------------------------------------
  accept SSL connection
-----------------------------------------*/
SSL *SSL_accept(SSL *ssl, struct sockaddr *addr, int *addrlen){
	SSL *ret=NULL;
	int i;

	if(ssl==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_BIND+2,NULL);
		return NULL;
	}
	/* accept connection first */
	if((i=accept(ssl->sock,addr,addrlen))<0){
		OK_set_error(ERR_ST_ACCEPT,ERR_LC_SSL,ERR_PT_SSL_BIND+2,NULL);
		goto error;
	}
	if((ret=SSL_dup(ssl))==NULL) goto error;
	ret->sock = i;
	ret->opt |= SSL_SYS_SERVER;	/* set server flag */
	if(ssl->ctx) ret->ctx->top = ssl->ctx;

	if(ret->opt&SSL_OPT_IMMEDIATE){
		/* do handshake immediately after accept() */
		if(SSL_handshake(ret)) goto error;

		if(SSL_add_connect_list(ssl,ret)) goto error;
	}

	return ret;
error:
	SSL_free(ret);
	return NULL;
}

/*-----------------------------------------
  connect SSL
-----------------------------------------*/
int SSL_connect(SSL *ssl, const struct sockaddr *name, int namelen){
	int i;

	if(ssl==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_BIND+3,NULL);
		return -1;
	}

	/* connect server first */
	if(i=connect(ssl->sock,name,namelen)){
		OK_set_error(ERR_ST_CONNECT,ERR_LC_SSL,ERR_PT_SSL_BIND+3,NULL);
		return i;
	}
	ssl->opt &= 0x7fff;	/* clear server flag */

	if(ssl->opt&SSL_OPT_IMMEDIATE){
		/* do handshake */
		if(SSL_handshake(ssl)) return -1;
	}

	return 0;
}


/*-----------------------------------------
  alloc rest of buffers in SSL
-----------------------------------------*/
int SSL_alloc_contexts(SSL *ssl){
	SSLCTX *ctx;

	if(ssl->ctx==NULL){
		if((ctx = SSLCTX_new())==NULL) goto error;
		ssl->ctx = ctx;
	}else{
		ctx = ssl->ctx;
	}

	ctx->ssl = ssl;	/* set owner SSL into SSLCTX */

	if(ctx->ptxt==NULL)
		if((ctx->ptxt = SSL_Plaintext_new())==NULL) goto error;
	if(ctx->ctxt==NULL)
		if((ctx->ctxt = SSL_Ciphertext_new())==NULL) goto error;

	if((ctx->comp==NULL)&&(ctx->cspec->comp_meth))
		if((ctx->comp = SSL_Compressed_new())==NULL) goto error;

	if(ctx->chello==NULL)
		if((ctx->chello = SSL_ClientHello_new())==NULL) goto error;
	if(ctx->shello==NULL)
		if((ctx->shello = SSL_ServerHello_new())==NULL) goto error;

	if(ctx->cb==NULL)
		if((ctx->cb = SSLCB_new())==NULL) goto error;

	if(ctx->wbuf==NULL)
		if((ctx->wbuf = (unsigned char*)MALLOC(SSLMAXBUF+3072))==NULL) goto error;
	if(ctx->rbuf==NULL)
		if((ctx->rbuf = (unsigned char*)MALLOC(SSLMAXBUF+3072))==NULL) goto error;

	if(ctx->hsmsg_md5==NULL)
		if((ctx->hsmsg_md5 = (MD5_CTX*)MALLOC(sizeof(MD5_CTX)))==NULL) goto error;
	if(ctx->hsmsg_sha1==NULL)
		if((ctx->hsmsg_sha1 = (SHA1_CTX*)MALLOC(sizeof(SHA1_CTX)))==NULL) goto error;

	return 0;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL_BIND+4,NULL);
	SSLCTX_free(ssl->ctx);
	ssl->ctx=NULL;
	return -1;
}

/*-----------------------------------------
  SSL options
-----------------------------------------*/
void SSL_setopt(SSL *ssl, int flag){
	ssl->opt = (ssl->opt&0xff00)|(0x00ff & flag);
}

int SSL_getopt(SSL *ssl){
	return ssl->opt & 0x00ff;
}
