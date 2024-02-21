/* ssl_sock.c */
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

#include "ok_io.h"
#include "ok_ssl.h"


/*-----------------------------------
  get socket with SSL
-----------------------------------*/
SSL *SSL_socket(int af,int type,int protocol){
    SSL *ssl;

    if((ssl=SSL_new())==NULL) return NULL;

    if((ssl->sock = socket(af,type,protocol))<0){
		OK_set_error(ERR_ST_SOCKOPEN,ERR_LC_SSL,ERR_PT_SSL_SOCK,NULL);
		SSL_free(ssl);
		return NULL;
	}

    return ssl;
}


/*-----------------------------------
  close socket with SSL
-----------------------------------*/
int SSL_shutdown(SSL *ssl, int how){
	SSLCTX *ctx;

	if(ssl==NULL) return -1;
	if(ctx=ssl->ctx){
		/* send close_notify alert */
		if(SSL_send_alert(ssl,SSL_AL_WARNING,SSL_AD_CLOSE_NOTIFY))
			return -1;

		/* sleep 1 second, because shutdown might be executed
		 * before sending SSL CLOSE_NOTIFY. So, just wait for 
		 * 1 second.
		 */
#ifdef __WINDOWS__
		Sleep(1000);
#else
		sleep(1);
#endif

		if(ctx->ckey){Key_free(ctx->ckey);ctx->ckey=NULL;}
		if(ctx->skey){Key_free(ctx->skey);ctx->skey=NULL;}
	}
	return shutdown(ssl->sock, how);
}

/*-----------------------------------
  close socket with SSL
-----------------------------------*/
int SSL_close(SSL *ssl){
    if(ssl==NULL) return -1;

#ifdef __WINDOWS__
	return closesocket(ssl->sock);
#else
	return close(ssl->sock);
#endif
}

/*-----------------------------------
  set socket option with SSL
-----------------------------------*/
int SSL_setsockopt(SSL *ssl, int level, int optname, const void * optval, int optlen){
    if(ssl==NULL) return -1;

    return setsockopt(ssl->sock,level,optname,optval,optlen);
}

/*-----------------------------------
  get socket option with SSL
-----------------------------------*/
int SSL_getsockopt(SSL *ssl, int level, int optname, void  *optval, int *optlen){
    if(ssl==NULL) return -1;
    
    return getsockopt(ssl->sock,level,optname,optval,optlen);
}

