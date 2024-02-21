/* ssl_rec.c */
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
  alloc & FREE & dup SSLPlaintext
-----------------------------------------*/
SSLPlaintext *SSL_Plaintext_new(void){
	SSLPlaintext *ret;

	if((ret = (SSLPlaintext*)MALLOC(sizeof(SSLPlaintext)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSLREC,ERR_PT_SSLREC,NULL);
		return NULL;
	}

	memset(ret,0,sizeof(SSLPlaintext));
	/* fragment pointer doesn't have allocated memory
	 * it's just buffer pointer for ctx->rbuf or something else.
	 */
	return ret;
}

void SSL_Plaintext_free(SSLPlaintext *pl){
	if(pl==NULL) return;

	/* fragment pointer doesn't have allocated memory
	 * it's just buffer pointer for ctx->rbuf or something else.
	 * so, don't need to FREE pl->fragment.
	 */
	
	FREE(pl);
}

SSLPlaintext *SSL_Plaintext_dup(SSLPlaintext *org){
	SSLPlaintext *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLREC,ERR_PT_SSLREC+1,NULL);
		return NULL;
	}
	if((ret = SSL_Plaintext_new())==NULL)
		return NULL;

	/* fragment doesn't have allocated memory
	 * so, just copy it.
	 */
	memcpy(ret,org,sizeof(SSLPlaintext));
	return ret;
}

/*-----------------------------------------
  alloc & FREE & dup SSLCompressed
-----------------------------------------*/
SSLCompressed *SSL_Compressed_new(void){
	SSLCompressed *ret;

	if((ret = (SSLCompressed*)MALLOC(sizeof(SSLCompressed)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSLREC,ERR_PT_SSLREC+2,NULL);
		return NULL;
	}

	memset(ret,0,sizeof(SSLCompressed));
	if((ret->fragment = (unsigned char*)MALLOC(SSLMAXBUF+1024))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSLREC,ERR_PT_SSLREC+2,NULL);
		FREE(ret);
		ret=NULL;
	}

	return ret;
}

void SSL_Compressed_free(SSLCompressed *cm){
	if(cm==NULL) return;

	if(cm->fragment){
		memset(cm->fragment,0,SSLMAXBUF+1024);
		FREE(cm->fragment);
	}
	FREE(cm);
}

SSLCompressed *SSL_Compressed_dup(SSLCompressed *org){
	SSLCompressed *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLREC,ERR_PT_SSLREC+3,NULL);
		return NULL;
	}
	if((ret = SSL_Compressed_new())==NULL)
		return NULL;

	memcpy(ret->fragment,org->fragment,SSLMAXBUF+1024);
	ret->type	= org->type;
	ret->length	= org->length;
	return ret;
}

/*-----------------------------------------
  alloc & FREE & dup SSLCiphertext
-----------------------------------------*/
SSLCiphertext *SSL_Ciphertext_new(void){
	SSLCiphertext *ret;

	if((ret = (SSLCiphertext*)MALLOC(sizeof(SSLCiphertext)))==NULL)
		goto error;

	memset(ret,0,sizeof(SSLCiphertext));
	if((ret->fragment = (unsigned char*)MALLOC(SSLMAXBUF+2400))==NULL)
		goto error;

	if((ret->content = (unsigned char*)MALLOC(SSLMAXBUF+2048))==NULL)
		goto error;
		
	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSLREC,ERR_PT_SSLREC+4,NULL);
	SSL_Ciphertext_free(ret);
	return NULL;
}

void SSL_Ciphertext_free(SSLCiphertext *ci){
	if(ci==NULL) return;

	if(ci->fragment){
		memset(ci->fragment,0,SSLMAXBUF+2400);
		FREE(ci->fragment);
	}
	if(ci->content){
		memset(ci->content,0,SSLMAXBUF+2048);
		FREE(ci->content);
	}
	memset(ci,0,sizeof(SSLCiphertext));
	
	FREE(ci);
}

SSLCiphertext *SSL_Ciphertext_dup(SSLCiphertext *org){
	unsigned char *fg,*ct;
	SSLCiphertext *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLREC,ERR_PT_SSLREC+5,NULL);
		return NULL;
	}
	if((ret = SSL_Ciphertext_new())==NULL)
		return NULL;

	fg =ret->fragment; ct =ret->content;
	memcpy(ret,org,sizeof(SSLCiphertext));
	ret->fragment=fg; ret->content=ct;

	if(org->fragment)
		memcpy(ret->fragment,org->fragment,SSLMAXBUF+2400);
	if(org->content)
		memcpy(ret->content,org->content,SSLMAXBUF+2048);

	return ret;
}

