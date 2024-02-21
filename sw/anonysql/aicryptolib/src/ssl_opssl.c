/* ssl_opssl.c */
/*
 * In this file, there are compatible functions for OpenSSL.
 */
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


/*--------------------------------------------------
  set_verify (OpenSSL dummy)
--------------------------------------------------*/
int SSL_set_verify(SSL *ssl, int type, int (*cb)()){
    switch(type){
	case 0:
		if(SSL_set_vfytype(ssl,SSL_DONT_VERIFY)) goto error;
		break;
		/* actually, these are not compatible with OpenSSL
		 * ...but it's useful for me :-)
		 */
	case 1:
		if(SSL_set_vfydepth(ssl,1)) goto error;
		if(SSL_set_vfytype(ssl,SSL_ALLOW_SELF_SIGN|DONT_CHECK_REVOKED)) goto error;
		break;
	case 2:
		if(SSL_set_vfytype(ssl,SSL_ALLOW_SELF_SIGN|SSL_IF_NO_CRL_DONT_CHECK_REVOKED)) goto error;
		break;

	default:
	case 3:
		/* do full verification :-) */
		if(SSL_set_vfytype(ssl,0)) goto error;
		break;
	}

	if(SSL_set_vfy_cb(ssl,cb)) goto error;

	return 0;
error:
	return -1;
}
